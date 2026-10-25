"""keySuite 签名身份派生 —— 与 ArkTS 的 KeySuite.ets 一一对应。

═══════════════════════════════════════════════════════════════
 流程
═══════════════════════════════════════════════════════════════

   POST {API_APP}/ddes/v1-1/app/key-suite
   body: {deviceId, deviceKeyId, nonce, requestId, sign, timestamp}
     其中 sign = base64( RSA-PKCS1v15-SHA256( priv, "requestId:deviceId:deviceKeyId:nonce:timestamp" ) )

   响应:
     data.tempAesKey  (base64)   ← 被 RSA 公钥加密的临时 AES 密钥
     data.tempIv      (base64)
     data.keySuite.keySecret.hmacKey (base64)
     data.keySuite.keyId

   派生:
     RD  = RSA-PKCS1v15.decrypt(tempAesKey, priv)      ← 32 字节
     hac = AES-256-CTR(key=RD, iv=tempIv).decrypt(hmacKey)  ← 32 字节
     → (hac_key, keyId)

═══════════════════════════════════════════════════════════════
 ★★ 关键差异：keySuite 的 X-CHJ-Sign 与业务接口不同！
═══════════════════════════════════════════════════════════════

   业务接口:  sign = base64(HMAC-SHA256(...))
   keySuite:  sign = hex(HMAC-SHA256(...))          ← hexdigest！

   且签名文本的第 11 段不是 nonce，而是 **nonce.upper() + timestamp**。
   签名里的 keyId 段用的是 **boot_hac[:32]**（引导 hac 的前 32 个 hex 字符）。

   boot_hac 是随机值即可 —— 实测服务端不校验引导签名（全新装机无 hac）。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
import urllib.error
import urllib.request
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from lx_const import (
    API_APP, EP_KEY_SUITE_DDES, MAIN_DEVICE_KEY_ID,
    MAIN_RSA_PRIVATE_DER_B64, KEY_SUITE_VER,
)


class IdentityDeriveError(RuntimeError):
    """keySuite 派生失败。"""


def _b64decode(s: str) -> bytes:
    """容错 base64 解码（自动补 =）。"""
    return base64.b64decode(str(s) + "=" * (-len(str(s)) % 4))


def load_main_private_key():
    """加载主 App 的内置 RSA 私钥。"""
    der = base64.b64decode(MAIN_RSA_PRIVATE_DER_B64)
    return serialization.load_der_private_key(der, password=None)


def build_data_to_sign(request_id: str, xdev: str, kid: str,
                       nonce: str, ts: str) -> str:
    """body 的 RSA 签名原文。"""
    return ":".join([request_id, xdev, kid, nonce, ts])


def build_key_suite_request(
    xdev: str, kid: str, priv, bearer: str,
    request_id: str, nonce: str, ts: str, boot_hac_hex: str,
    ver: str = KEY_SUITE_VER,
) -> tuple[bytes, dict[str, str]]:
    """组装 keySuite 请求（body + headers），不发网络。"""
    data_to_sign = build_data_to_sign(request_id, xdev, kid, nonce, ts)
    sign = base64.b64encode(
        priv.sign(data_to_sign.encode(), padding.PKCS1v15(), hashes.SHA256())
    ).decode()

    # body 按 Gson 字母序字段排列
    body = (
        '{"deviceId":"%s","deviceKeyId":"%s","nonce":"%s",'
        '"requestId":"%s","sign":"%s","timestamp":"%s"}'
        % (xdev, kid, nonce, request_id, sign, ts)
    ).encode()

    md5b = base64.b64encode(hashlib.md5(body).digest()).decode()

    # ★ 第 3 段是 boot_hac_hex[:32]（不是 keyId），第 11 段是 nonce.upper()+ts
    dtsx = "\n".join([
        "prod", ver, boot_hac_hex[:32], xdev, "POST", "*/*", "zh-Hans-CN",
        md5b, "application/json", ts, nonce.upper() + ts,
    ])
    xsign = hmac.new(
        bytes.fromhex(boot_hac_hex), (dtsx + "\n").encode(), hashlib.sha256
    ).hexdigest()   # ★ hexdigest，不是 base64

    headers = {
        "Authorization": "Bearer " + bearer,
        "Content-Type": "application/json",
        "Content-MD5": md5b,
        "Accept": "*/*",
        "Content-Language": "zh-Hans-CN",
        "X-CHJ-Timestamp": ts,
        "X-CHJ-Nonce": nonce.upper(),
        "X-CHJ-Sign": xsign,
        "X-CHJ-Deviceid": xdev,
        "X-CHJ-Key": boot_hac_hex[:32],
        "X-CHJ-APP-Version": ver,
        "X-CHJ-Env": "prod",
        "X-CHJ-Version": ver,
    }
    return body, headers


def format_dk(temp_aes_key_b64: str, temp_iv_b64: str,
              hmac_key_b64: str, priv) -> bytes:
    """响应 → 32 字节 hac_key。

    RD  = RSA-PKCS1v15 解密 tempAesKey
    hac = AES-256-CTR(key=RD, iv=tempIv).decrypt(hmacKey)

    ★ 2026-10-14 实测确认（本机，随机 device_id）：
      该端点【不校验 bearer】，签名正确即返回 code=0。
      完整派生链路已跑通，得到 32 字节 hac。见 VERIFY_REPORT.md。
    """
    ta = _b64decode(temp_aes_key_b64)
    ti = _b64decode(temp_iv_b64)
    hk = _b64decode(hmac_key_b64)
    rd = priv.decrypt(ta, padding.PKCS1v15())
    dec = Cipher(algorithms.AES(rd), modes.CTR(ti)).decryptor()
    hac = dec.update(hk) + dec.finalize()
    if len(hac) != 32:
        raise IdentityDeriveError(f"formatDK 派生长度异常: {len(hac)} 字节")
    return hac


def parse_validity(j: dict) -> dict:
    """解析 keySuite 的有效期字段。

    ★ 2026-10-14 实测发现（参考项目未记录）：
        keySuite.validFrom   = 派生时刻
        keySuite.updateFrom  = +3 个月（建议更新）
        keySuite.validTo     = +4 个月（失效）

    → hac_key 派生一次可用 4 个月，应持久化缓存，
      在 updateFrom 之后择机重新派生，而不是每次启动都派生。
    """
    ks = ((j.get("data") or {}).get("keySuite") or {})
    return {
        "valid_from": ks.get("validFrom", 0),
        "valid_to": ks.get("validTo", 0),
        "update_from": ks.get("updateFrom", 0),
    }


def derive_identity(xdev: str, bearer: str, key_id: str | None = None,
                    timeout: int = 20, debug: bool = False,
                    with_validity: bool = False):
    """派生签名身份 → (hac_key_hex, key_id)。

    key_id 传入时用传入值作为 deviceKeyId；否则用 MAIN_DEVICE_KEY_ID。

    with_validity=True 时返回 (hac_key_hex, key_id, validity_dict)。

    ★ 2026-10-14 实测：bearer 可为任意无效值 —— 该端点不校验 bearer，
      只要 x-chj 签名与 body 的 RSA 签名正确即返回 code=0。
    """
    kid = key_id or MAIN_DEVICE_KEY_ID
    priv = load_main_private_key()
    ts = str(int(time.time() * 1000))
    request_id = uuid.uuid4().hex
    nonce = uuid.uuid4().hex
    boot_hac = secrets.token_hex(32)

    body, headers = build_key_suite_request(
        xdev, kid, priv, bearer, request_id, nonce, ts, boot_hac)

    req = urllib.request.Request(
        API_APP + EP_KEY_SUITE_DDES, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode()
    except urllib.error.HTTPError as err:
        raise IdentityDeriveError(
            f"keySuite HTTP {err.code}: {err.read().decode()[:300]}") from err
    except urllib.error.URLError as err:
        raise IdentityDeriveError(f"keySuite 网络错误: {err.reason}") from err

    if debug:
        print("[keySuite] raw:", raw[:500])

    try:
        j = json.loads(raw)
    except json.JSONDecodeError as err:
        raise IdentityDeriveError(f"keySuite 响应非 JSON: {raw[:200]}") from err

    if j.get("code") != 0:
        raise IdentityDeriveError(
            f"keySuite code={j.get('code')} msg={j.get('msg') or j.get('message') or ''}")

    dd = j.get("data") or {}
    ks = dd.get("keySuite") or {}
    sec = ks.get("keySecret") or {}
    for field, value in (("tempAesKey", dd.get("tempAesKey")),
                         ("tempIv", dd.get("tempIv")),
                         ("hmacKey", sec.get("hmacKey"))):
        if not value:
            raise IdentityDeriveError(f"keySuite 响应缺少字段: {field}")

    hac = format_dk(dd["tempAesKey"], dd["tempIv"], sec["hmacKey"], priv)
    out_key_id = ks.get("keyId") or kid
    if with_validity:
        return hac.hex(), out_key_id, parse_validity(j)
    return hac.hex(), out_key_id


if __name__ == "__main__":
    print("keySuite 模块加载 OK")
    print("  RSA 私钥可加载:", load_main_private_key() is not None)
    print("  keyId:", MAIN_DEVICE_KEY_ID)
