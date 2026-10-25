"""换取顺序对照实验 —— 验证「MESH 与 VSS 同 audience 会互相顶掉」假设。

手表日志每次车控前都打印：
    [token] MESH len=22 VAT len=1388 VSS len=22
即每次都重新换取三条。而 MESH 与 VSS 的 audience 相同
（都是 1j0vgTqagJUHuT6nLmbTGx）→ 怀疑后换的 VSS 使先换的 MESH 失效。

对照：
  J1: MESH            → 探针
  J2: MESH → VSS      → 探针 MESH
  J3: MESH → VAT      → 探针 MESH
  J4: MESH → VSS → MESH（再换一次）→ 探针
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
                      AUD_MESH, SCOPE_MESH, AUD_VSS, SCOPE_VSS, AUD_VAT,
                      API_APP, EP_WAKEUP, EP_CMD_RESULT, vat_scope)
from lx_signer import Signer  # noqa: E402

PREFS = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "..", ".tmp", "prefs_now.xml")
RID = "00000000-0000-0000-0000-000000000000"


def load_prefs(path: str) -> dict:
    raw = open(path, encoding="utf-8").read()
    out: dict = {}
    for m in re.finditer(r'<(string|int|bool|double)\s+key="([^"]+)"\s*>([^<]*)</\1>', raw):
        out[m.group(2)] = m.group(3).replace("&quot;", '"').replace("&amp;", "&")
    return out


def build_session(cookies: list[dict]) -> requests.Session:
    s = requests.Session()
    for c in cookies:
        s.cookies.set(str(c.get("name")), str(c.get("value") or ""),
                      domain=str(c.get("domain") or ""), path=str(c.get("path") or "/"))
    return s


def exchange(sess: requests.Session, bearer: str, device_id: str,
             scope: str, audience: str) -> str:
    data = {
        "prompt": "none", "redirect_uri": REDIRECT_URI, "scope": scope,
        "response_type": "token", "device_id": device_id,
        "client_id": CLIENT_ID, "audience": audience,
    }
    r = sess.post(BASE_ID + EP_AUTH, data=data,
                  headers={"Authorization": "Bearer " + bearer,
                           "content-type": "application/x-www-form-urlencoded"},
                  timeout=20, allow_redirects=False)
    frag = dict(parse_qs(urlparse(r.headers.get("location", "")).fragment))
    return frag.get("access_token", [""])[0]


def probe_mesh(tok: str, signer: Signer, vin: str) -> str:
    if not tok:
        return "无 token"
    h2 = signer.build_headers("GET", "", tok, vin)
    r2 = requests.get(f"{API_APP}{EP_CMD_RESULT}/{RID}", headers=h2, timeout=20)
    if r2.status_code == 401:
        return "❌ 401 无效"
    return f"✅ 通过({r2.status_code})"


def main() -> int:
    p = load_prefs(PREFS)
    cookies = json.loads(p.get("session_cookies", "[]"))
    sess = build_session(cookies)
    bearer, dev, vin = p["main_bearer"], p["device_id"], p["vin"]
    signer = Signer(p["hac_key"], p["key_id"], dev, "")
    vscope = vat_scope(vin)

    print("=== J1: 只换 MESH ===")
    m1 = exchange(sess, bearer, dev, SCOPE_MESH, AUD_MESH)
    print(f"    MESH {m1[:24]} → {probe_mesh(m1, signer, vin)}")

    print("\n=== J2: 换 MESH 后再换 VSS，再用 MESH ===")
    m2 = exchange(sess, bearer, dev, SCOPE_MESH, AUD_MESH)
    print(f"    MESH {m2[:24]} 先探针 → {probe_mesh(m2, signer, vin)}")
    v2 = exchange(sess, bearer, dev, SCOPE_VSS, AUD_VSS)
    print(f"    VSS  {v2[:24]}")
    print(f"    MESH 换VSS后 → {probe_mesh(m2, signer, vin)}")

    print("\n=== J3: 换 MESH 后再换 VAT，再用 MESH ===")
    m3 = exchange(sess, bearer, dev, SCOPE_MESH, AUD_MESH)
    t3 = exchange(sess, bearer, dev, vscope, AUD_VAT)
    print(f"    MESH {m3[:24]}  VAT len={len(t3)}")
    print(f"    MESH 换VAT后 → {probe_mesh(m3, signer, vin)}")

    print("\n=== J4: MESH → VSS → 重新 MESH → 探针新 MESH ===")
    exchange(sess, bearer, dev, SCOPE_MESH, AUD_MESH)
    exchange(sess, bearer, dev, SCOPE_VSS, AUD_VSS)
    m4 = exchange(sess, bearer, dev, SCOPE_MESH, AUD_MESH)
    print(f"    MESH(新) {m4[:24]} → {probe_mesh(m4, signer, vin)}")

    print("\n=== J5: 复用 J1 的旧 MESH（间隔后再探）===")
    print(f"    MESH {m1[:24]} → {probe_mesh(m1, signer, vin)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
