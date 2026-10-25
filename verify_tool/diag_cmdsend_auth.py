"""cmd/send 鉴权验证（零副作用）—— 确认车控通道 401 已修复。

原理：用【非法 cmdKey】调 cmd/send。
  · 若仍是 401  → 网关鉴权没通过（修复失败）
  · 若返回其它  → 网关鉴权已通过，请求进了业务层并被参数校验拒绝
非法 cmdKey 不在白名单，且 VAT token 的 scope 也不含它 → 绝无可能驱动车辆。
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import requests  # noqa: E402

from lx_const import (BASE_ID, EP_AUTH, CLIENT_ID, REDIRECT_URI,  # noqa: E402
                      AUD_MESH, SCOPE_MESH, SCOPE_VSS, AUD_VAT,
                      API_APP, EP_CMD_SEND, CTRL_DOMAIN, CMD_EXPIRE,
                      CMD_EXPIRE_MS, vat_scope)
from lx_signer import Signer  # noqa: E402

PREFS = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "..", ".tmp", "prefs_now.xml")


def load_prefs(path: str) -> dict:
    raw = open(path, encoding="utf-8").read()
    out: dict = {}
    for m in re.finditer(r'<(string|int|bool|double)\s+key="([^"]+)"\s*>([^<]*)</\1>', raw):
        out[m.group(2)] = m.group(3).replace("&quot;", '"').replace("&amp;", "&")
    return out


def main() -> int:
    p = load_prefs(PREFS)
    cookies = json.loads(p.get("session_cookies", "[]"))
    sess = requests.Session()
    for c in cookies:
        sess.cookies.set(str(c.get("name")), str(c.get("value") or ""),
                         domain=str(c.get("domain") or ""), path=str(c.get("path") or "/"))
    bearer, dev, vin = p["main_bearer"], p["device_id"], p["vin"]
    signer = Signer(p["hac_key"], p["key_id"], dev, "")

    def exch(scope: str, aud: str) -> str:
        r = sess.post(BASE_ID + EP_AUTH, data={
            "prompt": "none", "redirect_uri": REDIRECT_URI, "scope": scope,
            "response_type": "token", "device_id": dev,
            "client_id": CLIENT_ID, "audience": aud,
        }, headers={"Authorization": "Bearer " + bearer,
                    "content-type": "application/x-www-form-urlencoded"},
            timeout=20, allow_redirects=False)
        frag = dict(parse_qs(urlparse(r.headers.get("location", "")).fragment))
        return frag.get("access_token", [""])[0]

    mesh = exch(SCOPE_MESH + " " + SCOPE_VSS, AUD_MESH)
    vat = exch(vat_scope(vin), AUD_VAT)
    print(f"MESH+VSS len={len(mesh)}  VAT len={len(vat)}")
    print(f"VSS 复用: {'✅ 同一 token' if len(mesh) else '❌'}")

    body = json.dumps({
        "vin": vin, "cmdKey": "__diag_no_such_command__", "cmdData": {},
        "domain": CTRL_DOMAIN, "jobExpire": CMD_EXPIRE, "expire": CMD_EXPIRE,
        "expireAt": int(time.time() * 1000) + CMD_EXPIRE_MS, "token": vat,
    }, separators=(",", ":"), ensure_ascii=False)

    h = signer.build_headers("POST", body, mesh, vin)
    r = requests.post(API_APP + EP_CMD_SEND, data=body.encode("utf-8"),
                      headers=h, timeout=20)
    print(f"\ncmd/send（非法 cmdKey）→ HTTP {r.status_code}")
    print(f"  响应: {r.text[:300]}")
    if r.status_code == 401:
        print("\n❌ 仍 401 —— 鉴权未修复")
    elif r.status_code == 200:
        j = r.json()
        code = j.get("code")
        print(f"\n✅ 鉴权通过（进了业务层）。业务码 code={code}，"
              f"说明网关已接受 MESH → 车控通道恢复")
    else:
        print(f"\n✅ 非 401（{r.status_code}）—— 网关鉴权已通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
