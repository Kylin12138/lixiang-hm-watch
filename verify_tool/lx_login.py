"""PAKE 登录 —— 与 ArkTS 的 PakeLogin.ets 一一对应。

═══════════════════════════════════════════════════════════════
 协议（自研 PAKE，非标准 SRP）
═══════════════════════════════════════════════════════════════

  1. seed = sha256(password) as int mod 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF61
     → 32 hex

  2. POST /api/idps {seed, strategy:PASSWORD, connection:LI_USER, user_tip}
     → t_login_use {
         option:   "bcrypt$2a$10$",
         seeded:   <账号注册盐，32 hex>,
         snonce:   "HZ:<32 hex>"
       }

  3. salt    = "$2a$10$" + bcrypt_b64(16字节(seeded))      ← 22 字符盐体
     ed_priv = sha256( bcrypt(password, salt) )            ← 32 字节
     msg     = sha256( bytes(snonce后缀) ‖ bytes(cnonce) )
     proof   = Ed25519.sign(msg, ed_priv).hex()            ← 128 hex

  4. POST /api/login {proof:{cnonce,snonce,proof}}
     401(空体) = 密码错误
     成功 = Location: ...code=HZ.xxx&state=...
     风控 = Location 含 require=SMS_CODE

  5. POST /api/token {grant_type:authorization_code, code, code_verifier}
     → access_token（主 Bearer）+ refresh_token

═══════════════════════════════════════════════════════════════
 ★ 关键细节
═══════════════════════════════════════════════════════════════
 · bcrypt 用的自定义 base64 字母表："./ABC...xyz0-9"（注意开头是 "./"）
 · seeded 是账号注册时固化的盐，同账号恒定
 · 新设备首次需要短信验证 → 手表端做不了，走手机浏览器辅助登录
 · PKCE 必需：/api/auth 先注册 code_challenge(S256)
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
import uuid
from typing import Any
from urllib.parse import parse_qs, urlparse

import bcrypt as _bcrypt
import requests
from nacl import signing as _signing

from lx_const import (
    BASE_ID, BASE_ACCT, CLIENT_ID, LOGIN_AUDIENCE, LOGIN_SCOPE,
    REDIRECT_URI, SDK_VERSION, APP_VERSION, DEFAULT_UA,
    SEED_MOD, B64_BCRYPT,
)


class LoginError(RuntimeError):
    def __init__(self, step: str, status: int = 0, detail: str = "") -> None:
        self.step = step
        self.status = status
        self.detail = detail
        super().__init__(f"[{step}] HTTP {status} {detail}" if status
                         else f"[{step}] {detail}")


class NeedSmsCode(LoginError):
    """设备未受信任，需要短信验证 —— 走手机浏览器辅助登录。"""


class NeedPassword(LoginError):
    """账号/密码被拒。"""


# ── PAKE 原语 ─────────────────────────────────────────────────

def create_seed(password: str) -> str:
    """createSeed：sha256(password) mod SEED_MOD，补齐 32 hex。"""
    x = int(hashlib.sha256(password.encode()).hexdigest(), 16) % SEED_MOD
    return format(x, "032x")


def bcrypt_b64(data: bytes) -> str:
    """bcryptjs 的 encodeBase64（自定义字母表，无填充）。"""
    out: list[str] = []
    acc = 0
    bits = 0
    for byte in data:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 6:
            bits -= 6
            out.append(B64_BCRYPT[(acc >> bits) & 0x3F])
    if bits:
        out.append(B64_BCRYPT[(acc << (6 - bits)) & 0x3F])
    return "".join(out)


def seeded_to_salted_str(seeded_hex: str) -> str:
    """seeded(32hex) → 大整数 → 补齐 32hex → 16 字节 → bcrypt b64 (22 字符)。"""
    return bcrypt_b64(bytes.fromhex(format(int(seeded_hex, 16), "032x")))


def create_v2_proof(password: str, t_login_use: dict,
                    cnonce: str | None = None) -> dict:
    """依服务器 t_login_use 计算 proof。"""
    option = t_login_use.get("option") or t_login_use.get("kdf") or ""
    snonce = t_login_use.get("snonce")
    if not option or not snonce:
        raise LoginError("proof", detail=f"t_login_use 字段缺失: {list(t_login_use)}")

    salted_hex = t_login_use.get("salted")
    if salted_hex:
        salt_body = "".join(chr(b) for b in bytes.fromhex(salted_hex) if b)
    else:
        salt_body = seeded_to_salted_str(t_login_use["seeded"])

    salt_head = option[6:] if option.startswith("bcrypt") else option
    bc_hash = _bcrypt.hashpw(
        password.encode(), (salt_head + salt_body).encode()).decode()
    ed_priv = hashlib.sha256(bc_hash.encode()).digest()

    cn = cnonce or secrets.token_hex(16)
    msg = hashlib.sha256(
        bytes.fromhex(snonce.split(":")[-1]) + bytes.fromhex(cn)).digest()
    sig = _signing.SigningKey(ed_priv).sign(msg).signature
    return {"cnonce": cn, "snonce": snonce, "proof": sig.hex()}


# ── 登录客户端 ────────────────────────────────────────────────

class LixiangLogin:
    """手机号 + 密码登录，获取主 Bearer / refresh_token。"""

    def __init__(self, device_id: str | None = None,
                 user_agent: str = DEFAULT_UA, timeout: int = 20,
                 debug: bool = False) -> None:
        self.device_id = device_id or uuid.uuid4().hex
        self.user_agent = user_agent
        self.timeout = timeout
        self.debug = debug
        self._sess = requests.Session()
        self._sess.headers.update({
            "User-Agent": self.user_agent,
            "x-requested-with": "XMLHttpRequest",
        })
        for dom in ("account.lixiang.com", "id.lixiang.com"):
            self._sess.cookies.set("X-LX-Deviceid", self.device_id, domain=dom)
            self._sess.cookies.set("authli_device_id", self.device_id, domain=dom)
        self._sess.cookies.set("isapp", "1", domain="account.lixiang.com")

    def _idaas_headers(self) -> dict[str, str]:
        return {
            "idaas-data": (
                f"model_name=OpenHarmony;device_model=;device_id={self.device_id};"
                f"app_version={APP_VERSION};client_id={CLIENT_ID};"
                f"sdk_version={SDK_VERSION};timestamp={int(time.time() * 1000)}"
            ),
            "idaas-data-x": "source_url=registerAction=&pageUrl=&eventID=",
            "origin": BASE_ACCT,
            "referer": BASE_ACCT + "/",
        }

    def login(self, phone: str, password: str) -> dict:
        """完整登录，返回 /api/token 响应。"""
        phone_tip = phone if phone.startswith("+") else "+86" + phone

        # 1. PKCE 授权请求
        verifier = base64.urlsafe_b64encode(
            secrets.token_bytes(32)).rstrip(b"=").decode()
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        state = secrets.token_urlsafe(21)[:21]
        r = self._sess.post(
            f"{BASE_ID}/api/auth",
            data={
                "client_id": CLIENT_ID, "device_id": self.device_id,
                "response_type": "code", "redirect_uri": REDIRECT_URI,
                "offline_access": "true", "state": state,
                "audience": LOGIN_AUDIENCE, "scope": LOGIN_SCOPE,
                "code_challenge": challenge, "code_challenge_method": "S256",
            },
            headers={**self._idaas_headers(),
                     "content-type": "application/x-www-form-urlencoded"},
            timeout=self.timeout)
        if r.status_code not in (200, 300):
            raise LoginError("auth", r.status_code, r.text[:200])

        # 2. 打开登录页（初始化页面会话）
        self._sess.get(f"{BASE_ACCT}/login", params={
            "client_id": CLIENT_ID, "redirect_uri": REDIRECT_URI},
            headers={"accept": "text/html", "referer": BASE_ACCT + "/app-auth"},
            timeout=self.timeout)

        # 3. 设备注册
        r = self._sess.post(f"{BASE_ID}/api/devices", json={
            "client_id": CLIENT_ID, "device_id": self.device_id,
            "user_agent": self.user_agent, "model": "", "manufacturer": "",
            "os": "OpenHarmony", "os_version": "6.1", "screen_height": 843,
            "screen_width": 374, "app_version": APP_VERSION,
        }, headers=self._idaas_headers(), timeout=self.timeout)
        if r.status_code != 200:
            raise LoginError("devices", r.status_code, r.text[:200])

        # 4. PAKE 握手
        r = self._sess.post(f"{BASE_ID}/api/idps", json={
            "origin": BASE_ACCT, "connection": "LI_USER",
            "seed": create_seed(password), "strategy": "PASSWORD",
            "user_tip": phone_tip,
        }, headers=self._idaas_headers(), timeout=self.timeout)
        if r.status_code != 200:
            raise LoginError("idps", r.status_code, r.text[:200])
        t_login_use = (r.json() or {}).get("t_login_use") or {}
        if not t_login_use:
            raise LoginError("idps", detail=f"响应无 t_login_use: {r.text[:200]}")

        # 5. proof → 授权码
        proof = create_v2_proof(password, t_login_use)
        r = self._sess.post(f"{BASE_ID}/api/login", json={
            "client_id": CLIENT_ID, "connection": "LI_USER",
            "user_tip": phone_tip, "proof": proof,
        }, headers=self._idaas_headers(), timeout=self.timeout,
            allow_redirects=False)

        if r.status_code == 401:
            raise NeedPassword("login", 401, "密码错误或账号不存在")
        if r.status_code not in (200, 300, 302):
            raise LoginError("login", r.status_code, r.text[:200])

        location = r.headers.get("location") or ""
        if "require=SMS_CODE" in location:
            raise NeedSmsCode(
                "login", r.status_code,
                "密码正确但风控要求短信验证（需手机浏览器辅助登录建立设备信任）")

        code = ""
        q = parse_qs(urlparse(location).query) if location else {}
        if q.get("code"):
            code = q["code"][0]
        if not code:
            try:
                code = (r.json() or {}).get("code") or ""
            except Exception:
                code = ""
        if not code:
            raise LoginError("login", r.status_code,
                             f"响应无授权码: {location[:200]}")

        # 6. 换 token
        r = self._sess.post(f"{BASE_ID}/api/token", data={
            "client_id": CLIENT_ID, "grant_type": "authorization_code",
            "code": code, "code_verifier": verifier,
        }, headers={**self._idaas_headers(),
                    "content-type": "application/x-www-form-urlencoded"},
            timeout=self.timeout)
        if r.status_code != 200:
            raise LoginError("token", r.status_code, r.text[:200])
        # ★ 登录成功后立即把登录态 cookie 同步到父域
        #   换 scope token 时【必须】带 sso_token，否则永远 login_required
        self.sync_parent_domain_cookies()
        return r.json()

    # ---------- 登录会话 cookie（★ 关键：换 scope token 必须复用） ----------

    def export_session_cookies(self) -> list[dict]:
        """导出登录态 cookie（可 JSON 序列化），供下次启动复用会话。

        会话 cookie 有 ~13 天有效期，持久化后可免密码续用。
        """
        out: list[dict] = []
        for ck in self._sess.cookies:
            if not ck.value:
                continue
            try:
                exp = int(ck.expires) if ck.expires else 0
            except (TypeError, ValueError):
                exp = 0
            out.append({
                "name": str(ck.name),
                "value": str(ck.value),
                "domain": str(ck.domain or ""),
                "path": str(ck.path or "/"),
                "expires": exp,
            })
        return out

    def import_session_cookies(self, cookies) -> int:
        """装载持久化的 cookie；返回真正装入的条数（过期的丢弃）。"""
        now = time.time()
        n = 0
        for ck in cookies or []:
            if not isinstance(ck, dict):
                continue
            name = str(ck.get("name") or "")
            if not name:
                continue
            try:
                exp = int(ck.get("expires") or 0)
            except (TypeError, ValueError):
                exp = 0
            if exp and exp < now:
                continue
            # ★ domain 为空时不要显式传 None：requests 会拒绝该 cookie
            kw: dict = {"path": str(ck.get("path") or "/")}
            if ck.get("domain"):
                kw["domain"] = str(ck["domain"])
            try:
                self._sess.cookies.set(name, str(ck.get("value") or ""), **kw)
            except Exception:  # noqa: BLE001
                continue
            n += 1
        return n

    def sync_parent_domain_cookies(self) -> bool:
        """把登录态 cookie 同步到父域 `.lixiang.com`。

        ★ 这是整个 token 链的前提：
          服务端 Set-Cookie 把 sso_token 的域设成了 id.lixiang.com，
          而 /api/auth 换 scope token 时会校验会话 —— 不带 cookie 就返
          `error=login_required`（即便 Bearer 完全有效）。
          App 的做法（util/e.smali:1143）是注入到父域 .lixiang.com。

        返回 True 表示确实找到了 sso_token 并完成同步。
        """
        sso = ""
        for ck in self._sess.cookies:
            if ck.name == "sso_token" and ck.value:
                sso = ck.value
                break
        if not sso:
            return False
        for name, val in (("sso_token", sso),
                          ("isapp", "1"),
                          ("X-LX-Deviceid", self.device_id),
                          ("authli_device_id", self.device_id)):
            self._sess.cookies.set(name, val, domain=".lixiang.com", path="/")
        return True

    def refresh(self, refresh_token: str) -> dict:
        """用 refresh_token 换新的 access_token（免密码）。"""
        r = self._sess.post(f"{BASE_ID}/api/token", data={
            "client_id": CLIENT_ID,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }, headers={**self._idaas_headers(),
                    "content-type": "application/x-www-form-urlencoded"},
            timeout=self.timeout)
        if r.status_code != 200:
            raise LoginError("refresh", r.status_code, r.text[:200])
        return r.json()


def browser_login_url(device_id: str) -> tuple[str, str]:
    """生成手机浏览器辅助登录链接 → (主链接, 备用链接)。

    ★ 必须带 mode=h5：
        /app-auth 默认 mode=app 会跳到 App WebView 桥接页，普通浏览器里永久 loading。
    ★ audience 用 PAKE 登录的实测值 5iIapSfVJlln0vU0OzUCH9
      （用 VSS 的 audience 会走错授权分支）。
    """
    from urllib.parse import urlencode
    main = BASE_ACCT + "/app-auth?" + urlencode({
        "mode": "h5",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": LOGIN_SCOPE,
        "audience": LOGIN_AUDIENCE,
        "device_id": device_id,
    })
    alt = BASE_ACCT + "/app-auth?" + urlencode({
        "mode": "h5",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "device_id": device_id,
    })
    return main, alt


if __name__ == "__main__":
    # 自检：seed 与 bcrypt_b64 的确定性
    s1 = create_seed("test1234")
    s2 = create_seed("test1234")
    assert s1 == s2 and len(s1) == 32, "create_seed 异常"
    b = bcrypt_b64(bytes.fromhex("00" * 16))
    assert len(b) == 22, f"bcrypt_b64 长度应为 22，实际 {len(b)}"
    print("PAKE 模块 selftest: PASS")
    print("  seed(test1234) =", s1)
    print("  bcrypt_b64(16字节0) =", b)
