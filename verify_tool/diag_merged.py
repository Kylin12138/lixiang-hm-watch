"""合并 scope 方案验证 —— MESH 与 VSS 共用一条 token。

根因（diag_order.py 实证）：
    同一 audience (1j0vgTqagJUHuT6nLmbTGx) 下服务端只保留【最新】token，
    换 VSS 会把先前换的 MESH 顶掉 → 车控 401。

方案：把 vss:get-batch 并入 MESH 的 scope 一次换取（与参考项目 app_config
      的 httpLiMeshServiceV2 一致），车控与 VSS 共用这一条 token。

本脚本验证：同一 token 连续通过 cmd-result 与 VSS get-batch，
且二者互不影响；同时打印 302 fragment 里服务端实际授予的 scope。
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
                      AUD_MESH, SCOPE_MESH, SCOPE_VSS, API_APP,
                      EP_CMD_RESULT, EP_VSS_BATCH)
from lx_signer import Signer  # noqa: E402

PREFS = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "..", ".tmp", "prefs_now.xml")
RID = "00000000-0000-0000-0000-000000000000"
SIG_LOCK = "Vehicle.Body.DoorLockStatus.MainDoor"
MERGED = SCOPE_MESH + " " + SCOPE_VSS


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
             scope: str, audience: str) -> tuple[str, dict, int]:
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
    flat = {k: v[0] for k, v in frag.items()}
    return flat.get("access_token", ""), flat, r.status_code


def probe_cmd(tok: str, signer: Signer, vin: str) -> str:
    h = signer.build_headers("GET", "", tok, vin)
    r = requests.get(f"{API_APP}{EP_CMD_RESULT}/{RID}", headers=h, timeout=20)
    return "❌ 401" if r.status_code == 401 else f"✅ {r.status_code}"


def probe_vss(tok: str, signer: Signer, vin: str) -> str:
    body = json.dumps({"vin": vin, "paths": [SIG_LOCK]}, separators=(",", ":"))
    h = signer.build_headers("POST", body, tok, vin)
    r = requests.post(API_APP + EP_VSS_BATCH, data=body.encode(),
                      headers=h, timeout=20)
    if r.status_code == 401:
        return "❌ 401"
    return f"✅ {r.status_code}  {r.text[:110]}"


def main() -> int:
    p = load_prefs(PREFS)
    cookies = json.loads(p.get("session_cookies", "[]"))
    sess = build_session(cookies)
    bearer, dev, vin = p["main_bearer"], p["device_id"], p["vin"]
    signer = Signer(p["hac_key"], p["key_id"], dev, "")

    print("=== 合并前：分开换取（复现现状）===")
    m, _, c1 = exchange(sess, bearer, dev, SCOPE_MESH, AUD_MESH)
    v, _, c2 = exchange(sess, bearer, dev, SCOPE_VSS, AUD_MESH)
    print(f"    MESH({c1}) len={len(m)}   VSS({c2}) len={len(v)}")
    print(f"    用 MESH → cmd-result {probe_cmd(m, signer, vin)}   / VSS → {probe_vss(v, signer, vin)}")

    print("\n=== 合并后：一次换取 4 个 scope ===")
    print(f"    scope = {MERGED}")
    t, frag, code = exchange(sess, bearer, dev, MERGED, AUD_MESH)
    keys = {k: (f"<len {len(vv)}>" if k == "access_token" else vv[:70])
            for k, vv in frag.items()}
    print(f"    HTTP {code}  fragment={keys}")
    print(f"    token len={len(t)}  {t[:40]}")
    print(f"    ① cmd-result（车控）  {probe_cmd(t, signer, vin)}")
    print(f"    ② VSS get-batch      {probe_vss(t, signer, vin)}")
    time.sleep(0.3)
    print(f"    ③ 再用同一 token 探车控（确认未被 VSS 顶掉） {probe_cmd(t, signer, vin)}")
    print(f"    ④ wakeup（Authorization 同 token）")
    wb = '{"source":"0x3B","bizId":"0"}'
    h = signer.build_headers("POST", wb, t, vin)
    r = requests.post(API_APP + "/iot-connect-manager-service/v2/wakeup",
                      data=wb.encode(), headers=h, timeout=20)
    print(f"       HTTP {r.status_code}  {r.text[:120]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
