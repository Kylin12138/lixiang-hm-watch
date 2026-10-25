"""x-chj 签名 —— 与 ArkTS 的 Signer.ets 一一对应。

三步：content_md5 → string_to_sign(11段+\n) → HMAC-SHA256 → base64

★ 三个坑（每个都真实踩过）：
  1. HMAC key 必须是 hac_key 的原始 32 字节（不是 base64 文本的 encode()）
  2. 11 段末尾必须再补一个 "\n"
  3. header 名大小写敏感：Content-MD5（不是 Content-Md5）
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from typing import Any

from lx_const import (
    ENV, SIGN_APP_VERSION, DEFAULT_ACCEPT, DEFAULT_CONTENT_LANG,
    DEFAULT_CONTENT_TYPE, EMPTY_MD5, DEVICE_TYPE, MODEL_NAME, SIGN_UA,
)


def content_md5(body: str) -> str:
    """body 的 Content-MD5（base64）。空 body 返回预计算常量。"""
    if not body:
        return EMPTY_MD5
    return base64.b64encode(hashlib.md5(body.encode("utf-8")).digest()).decode()


def build_string_to_sign(
    key_id: str, device_id: str, method: str,
    md5_b64: str, timestamp: str, nonce: str,
    app_version: str = SIGN_APP_VERSION,
) -> str:
    """11 段 \n 拼接 + 末尾补 \n。"""
    parts = [
        ENV, app_version, key_id, device_id, method.upper(),
        DEFAULT_ACCEPT, DEFAULT_CONTENT_LANG, md5_b64,
        DEFAULT_CONTENT_TYPE, timestamp, nonce,
    ]
    return "\n".join(parts) + "\n"


class Signer:
    """x-chj 签名器。

    hac_key 传 bytes（原始字节）或 64 字符 hex 字符串均可。
    """

    def __init__(self, hac_key: bytes | str, key_id: str,
                 device_id: str, app_token: str = "",
                 app_version: str = SIGN_APP_VERSION) -> None:
        self._hac = self._normalize_key(hac_key)
        self._key_id = key_id
        self._device_id = device_id
        self._app_token = app_token
        self._app_version = app_version

    @staticmethod
    def _normalize_key(hac_key: bytes | str) -> bytes:
        """把 hac_key 归一成原始 32 字节。

        ★ 这里是最容易出错的地方：如果传进来的是 hex 字符串却直接
          .encode()，得到的是 64 字节的 ASCII —— 签名必然失败。
        """
        if isinstance(hac_key, bytes):
            if len(hac_key) == 32:
                return hac_key
            # 尝试当 hex 解析
            try:
                d = bytes.fromhex(hac_key.decode("ascii"))
                if len(d) == 32:
                    return d
            except Exception:
                pass
            return hac_key
        s = hac_key.strip()
        if len(s) == 64:
            try:
                return bytes.fromhex(s)
            except ValueError:
                pass
        try:
            d = base64.b64decode(s + "=" * (-len(s) % 4))
            if len(d) == 32:
                return d
        except Exception:
            pass
        return s.encode("utf-8")

    @property
    def hac_key(self) -> bytes:
        return self._hac

    @property
    def device_id(self) -> str:
        return self._device_id

    @property
    def key_id(self) -> str:
        return self._key_id

    def set_app_token(self, token: str) -> None:
        self._app_token = token

    def sign_request(self, method: str, body: str = "",
                     timestamp: str | None = None,
                     nonce: str | None = None) -> dict[str, str]:
        ts = timestamp or str(int(time.time() * 1000))
        nc = nonce or secrets.token_hex(16)
        m = content_md5(body)
        sts = build_string_to_sign(
            self._key_id, self._device_id, method, m, ts, nc, self._app_version)
        sig = base64.b64encode(
            hmac.new(self._hac, sts.encode("utf-8"), hashlib.sha256).digest()
        ).decode()
        return {"sign": sig, "timestamp": ts, "nonce": nc, "content_md5": m}

    def build_headers(self, method: str, body: str = "",
                      bearer: str = "", vin: str = "") -> dict[str, str]:
        """完整业务请求头（13 个 X-CHJ-* + Authorization + UA）。"""
        r = self.sign_request(method, body)
        h = {
            "X-CHJ-Env": ENV,
            "X-CHJ-APP-Version": self._app_version,
            "X-CHJ-Key": self._key_id,
            "X-CHJ-Deviceid": self._device_id,
            "X-CHJ-Timestamp": r["timestamp"],
            "X-CHJ-Nonce": r["nonce"],
            "X-CHJ-Sign": r["sign"],
            "Content-MD5": r["content_md5"],
            "Content-Type": DEFAULT_CONTENT_TYPE,
            "Content-Language": DEFAULT_CONTENT_LANG,
            "Accept": DEFAULT_ACCEPT,
            "X-CHJ-Version": self._app_version,
            "X-CHJ-DeviceType": DEVICE_TYPE,
            "X-CHJ-ModelName": MODEL_NAME,
            "X-CHJ-Tag": "1",
            "X-CHJ-TOKEN": self._app_token,
            "Authorization": f"Bearer {bearer}",
            "User-Agent": SIGN_UA,
        }
        if vin:
            h["X-CHJ-VIN"] = vin
        return h


# ─────────────────────────────────────────────────────────────
#  自检：用固定输入验证签名可复现
# ─────────────────────────────────────────────────────────────

def selftest() -> bool:
    """签名自检 —— 不联网，只验证确定性。"""
    key = bytes(range(32))
    sg = Signer(key, "kid_test", "dev_test", "tok_test")
    a = sg.sign_request("POST", '{"a":1}', timestamp="1700000000000", nonce="n" * 32)
    b = sg.sign_request("POST", '{"a":1}', timestamp="1700000000000", nonce="n" * 32)
    ok1 = a["sign"] == b["sign"]
    ok2 = a["content_md5"] == content_md5('{"a":1}')
    ok3 = content_md5("") == EMPTY_MD5
    # hex 与 bytes 两种输入必须等价
    sg2 = Signer(key.hex(), "kid_test", "dev_test", "tok_test")
    ok4 = sg2.sign_request("POST", '{"a":1}', timestamp="1700000000000",
                           nonce="n" * 32)["sign"] == a["sign"]
    sts = build_string_to_sign("kid_test", "dev_test", "POST",
                               a["content_md5"], "1700000000000", "n" * 32)
    ok5 = sts.endswith("\n") and sts.count("\n") == 11
    return ok1 and ok2 and ok3 and ok4 and ok5


if __name__ == "__main__":
    print("signer selftest:", "PASS" if selftest() else "FAIL")
