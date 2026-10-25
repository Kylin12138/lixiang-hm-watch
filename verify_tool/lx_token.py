"""token 换取链 —— 与 ArkTS 的 TokenManager.ets 一一对应。

═══════════════════════════════════════════════════════════════
 三条 token
═══════════════════════════════════════════════════════════════

  MESH (aud 1j0vgTqagJUHuT6nLmbTGx, ~15min)
    scope: remote-wakeup:wakeup veh-ctrl:cmd-send veh-ctrl:cmd-result-get vss:get-batch
    用途: cmd/send、cmd-result、wakeup 的 Authorization 【以及读实时信号】

  VAT  (aud 5Tc7yDrnMzALwc9Rytl9sp, ~20h)
    scope: remoteVehLockControl:<VIN> remoteVehAuth:<VIN> ...  ← 逐条列
    用途: cmd/send 的 body.token

  ★★★ 十号坑：VSS 不再单独换取
    VSS 与 MESH 同 audience，服务端只保留最后换取的那一条 →
    单独换 VSS 会顶掉 MESH，车控恒 401。故 vss() 直接复用 mesh()。

═══════════════════════════════════════════════════════════════
 换取方式（统一）
═══════════════════════════════════════════════════════════════

  POST https://id.lixiang.com/api/auth
    Authorization: Bearer <主 Bearer>
    Content-Type: application/x-www-form-urlencoded
    data: prompt=none, redirect_uri=..., scope=..., response_type=token,
          device_id=..., client_id=..., audience=...
  → 302，Location 的 fragment 里有 access_token

  ⚠️ 多请求 App 没有的 scope 会导致服务端【整批降级】
     （实测 14 个 scope 只给 8 个）—— 所以 scope 必须逐条精确列出。
"""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import parse_qs, urlparse

import requests

from lx_const import (
    BASE_ID, EP_AUTH, CLIENT_ID, REDIRECT_URI,
    AUD_MESH, SCOPE_MESH, AUD_VSS, SCOPE_VSS, AUD_VAT,
    AUD_SAOS_VEHICLE, SCOPE_SAOS_VEHICLE, vat_scope,
)


class TokenError(RuntimeError):
    """token 换取失败。"""


class _CachedToken:
    __slots__ = ("value", "expires_at")

    def __init__(self, value: str, ttl: float) -> None:
        self.value = value
        self.expires_at = time.time() + ttl

    def valid(self, skew: float = 30.0) -> bool:
        return bool(self.value) and time.time() < (self.expires_at - skew)


class TokenManager:
    """管理主 Bearer 与三个派生 token 的换取与缓存。

    main_bearer 由 PAKE 登录获得（或从本地持久化装载）。
    """

    def __init__(self, main_bearer: str, device_id: str,
                 vin: str = "", timeout: int = 20, debug: bool = False,
                 cookies: list[dict] | None = None) -> None:
        self.main_bearer = main_bearer
        self.device_id = device_id
        self.vin = vin
        self.timeout = timeout
        self.debug = debug
        self._mesh: _CachedToken | None = None
        self._vat: _CachedToken | None = None
        self._vss: _CachedToken | None = None
        self._sess = requests.Session()
        # ★ 登录态 cookie —— 换 scope token 时必须携带，否则 login_required
        if cookies:
            self.load_cookies(cookies)

    def load_cookies(self, cookies: list[dict]) -> int:
        """装载登录会话 cookie（来自 LixiangLogin.export_session_cookies）。

        幂等：同名同域覆盖。过期的丢弃。
        """
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
            kw: dict = {"path": str(ck.get("path") or "/")}
            if ck.get("domain"):
                kw["domain"] = str(ck["domain"])
            try:
                self._sess.cookies.set(name, str(ck.get("value") or ""), **kw)
            except Exception:  # noqa: BLE001
                continue
            n += 1
        return n

    # ---------- 底层换取 ----------

    def _exchange(self, scope: str, audience: str, ttl: float,
                  retry: int = 1) -> str:
        """用主 Bearer 换一个带 scope 的 token。"""
        data = {
            "prompt": "none",
            "redirect_uri": REDIRECT_URI,
            "scope": scope,
            "response_type": "token",
            "device_id": self.device_id,
            "client_id": CLIENT_ID,
            "audience": audience,
        }
        headers = {
            "Authorization": "Bearer " + self.main_bearer,
            "Content-Type": "application/x-www-form-urlencoded",
        }
        last_err = ""
        for attempt in range(retry + 1):
            try:
                r = self._sess.post(
                    BASE_ID + EP_AUTH, data=data, headers=headers,
                    timeout=self.timeout, allow_redirects=False)
            except requests.RequestException as err:
                last_err = f"网络错误: {err}"
                continue

            if self.debug:
                print(f"[auth] scope={scope[:60]}... → {r.status_code}")

            location = r.headers.get("location") or ""
            tok = self._extract_token(location)
            if tok:
                return tok

            # 有时 token 直接在 body 里
            try:
                j = r.json()
                tok = j.get("access_token") or ""
                if tok:
                    return tok
                last_err = f"响应无 token: {str(j)[:200]}"
            except Exception:
                last_err = (f"HTTP {r.status_code}，"
                            f"location={location[:200]}，body={r.text[:200]}")
        raise TokenError(f"换取 token 失败 (aud={audience[:12]}): {last_err}")

    @staticmethod
    def _extract_token(location: str) -> str:
        """从 302 Location 的 fragment（或 query）里取 access_token。"""
        if not location:
            return ""
        # fragment 形式: https://.../app-auth#access_token=xxx&...
        frag = ""
        if "#" in location:
            frag = location.split("#", 1)[1]
        elif "?" in location:
            frag = location.split("?", 1)[1]
        if not frag:
            return ""
        q = parse_qs(frag)
        v = q.get("access_token") or q.get("token") or []
        return v[0] if v else ""

    # ---------- 三个 token ----------

    def mesh(self, force: bool = False) -> str:
        """MESH token（~15 分钟）。"""
        if not force and self._mesh is not None and self._mesh.valid():
            return self._mesh.value
        # ttl 给 780s（13 分钟），比服务端的 15 分钟留足余量
        tok = self._exchange(SCOPE_MESH, AUD_MESH, 780.0)
        self._mesh = _CachedToken(tok, 780.0)
        return tok

    def vat(self, force: bool = False) -> str:
        """VAT token（~20h），scope 逐条列出命令+VIN。"""
        if not force and self._vat is not None and self._vat.valid():
            return self._vat.value
        if not self.vin:
            raise TokenError("换取 VAT token 需要 vin")
        tok = self._exchange(vat_scope(self.vin), AUD_VAT, 19 * 3600.0)
        self._vat = _CachedToken(tok, 19 * 3600.0)
        return tok

    def vss(self, force: bool = False) -> str:
        """VSS token（读实时信号用）。

        ★★★ 十号坑：VSS 与 MESH 是同一 audience (1j0vgTqagJUHuT6nLmbTGx)，
        服务端只认最后换取的那一条 —— 单独换 VSS 会把车控用的 MESH 顶掉
        （表现为 cmd/send 恒 401，error="invalid_token"）。
        所以这里直接复用 mesh()：SCOPE_MESH 已并入 vss:get-batch。
        """
        return self.mesh(force)

    def invalidate_all(self) -> None:
        """全部失效（401 自愈时调用）。"""
        self._mesh = None
        self._vat = None
        self._vss = None

    # ---------- 车辆列表 ----------

    def list_vehicles(self) -> list[dict]:
        """拉取账号下的车辆列表。"""
        tok = self._exchange(SCOPE_SAOS_VEHICLE, AUD_SAOS_VEHICLE, 780.0)
        from lx_const import API_APP, EP_SAOS_VEHICLES
        headers = {
            "Authorization": "Bearer " + tok,
            "Accept": "*/*",
            "Content-Type": "application/json",
        }
        r = requests.get(API_APP + EP_SAOS_VEHICLES, headers=headers,
                         timeout=self.timeout)
        if r.status_code != 200:
            raise TokenError(f"拉取车辆列表失败 HTTP {r.status_code}: {r.text[:300]}")
        j = r.json()
        data = j.get("data") or j
        if isinstance(data, dict):
            for key in ("vehicles", "list", "items"):
                if isinstance(data.get(key), list):
                    return data[key]
        if isinstance(data, list):
            return data
        return []
