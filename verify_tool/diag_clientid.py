"""client_id / scope 对照矩阵实验 —— 定位 IDaaS permission check failed 的根因。

参考项目 app_config.json 里 car-control 类 token 的配置是：
    { "type": "httpLiMeshServiceV2", "client": "", "audience": "1j0vgTqagJUHuT6nLmbTGx",
      "scope": [remote-wakeup:wakeup, veh-ctrl:cmd-result-get, veh-ctrl:cmd-send, vss:get-batch] }
而 VAT 才用 client "2AQClOaegaA7XecMSFx1p"。

本脚本对 4 种组合各换一次 token，然后打 wakeup（业务层鉴权探针）
与 cmd-result（只读探针），看哪种组合能通过。
"""

from __future__ import annotations

import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import requests  # noqa: E402

from lx_const import (BASE_ID, EP_AUTH, CLIENT_ID, REDIRECT_URI,  # noqa: E402
                      AUD_MESH, SCOPE_MESH, AUD_VSS, SCOPE_VSS,
                      API_APP, EP_WAKEUP, EP_CMD_RESULT)
from lx_signer import Signer  # noqa: E402

PREFS = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "..", ".tmp", "prefs_now.xml")


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
             client: str | None, scope: str, audience: str) -> tuple[str, str]:
    """返回 (token, 诊断信息)"""
    data = {
        "prompt": "none",
        "redirect_uri": REDIRECT_URI,
        "scope": scope,
        "response_type": "token",
        "device_id": device_id,
        "audience": audience,
    }
    if client is not None:
        data["client_id"] = client
    h = {"Authorization": "Bearer " + bearer,
         "Content-Type": "application/x-www-form-urlencoded"}
    r = sess.post(BASE_ID + EP_AUTH, data=data, headers=h, timeout=20,
                  allow_redirects=False)
    loc = r.headers.get("location") or ""
    frag = loc.split("#", 1)[1] if "#" in loc else (loc.split("?", 1)[1] if "?" in loc else "")
    from urllib.parse import parse_qs
    tok = ""
    q = parse_qs(frag)
    v = q.get("access_token") or q.get("token") or []
    tok = v[0] if v else ""
    note = f"HTTP {r.status_code}"
    if not tok:
        note += f" location={loc[:120]}"
    return tok, note


def probe(name: str, tok: str, signer: Signer, vin: str) -> None:
    print(f"\n--- [{name}] token len={len(tok)}  {tok[:40]}")
    if not tok:
        return
    # 探针 1: wakeup
    body = '{"source":"0x3B","bizId":"0"}'
    h = signer.build_headers("POST", body, tok, vin)
    r = requests.post(API_APP + EP_WAKEUP, data=body.encode(),
                      headers=h, timeout=20)
    print(f"    wakeup  → HTTP {r.status_code}  {r.text[:160]}")
    # 探针 2: cmd-result（只读）
    rid = "00000000-0000-0000-0000-000000000000"
    h2 = signer.build_headers("GET", "", tok, vin)
    r2 = requests.get(f"{API_APP}{EP_CMD_RESULT}/{rid}", headers=h2, timeout=20)
    verdict = "401 鉴权失败" if r2.status_code == 401 else f"鉴权通过（{r2.status_code}）"
    print(f"    cmd-result → HTTP {r2.status_code}  {verdict}  {r2.text[:120]}")
    www = r2.headers.get("www-authenticate")
    if www:
        print(f"    WWW-Authenticate: {www[:200]}")


def main() -> int:
    p = load_prefs(PREFS)
    cookies = json.loads(p.get("session_cookies", "[]"))
    sess = build_session(cookies)
    bearer = p["main_bearer"]
    dev = p["device_id"]
    vin = p["vin"]
    signer = Signer(p["hac_key"], p["key_id"], dev, "")

    print(f"main_bearer={bearer}  device_id={dev}  vin={vin}")
    print(f"cookies={len(cookies)}")

    scenarios: list[tuple[str, str | None, str]] = [
        ("A: client=主App, scope=3(现状)", CLIENT_ID, SCOPE_MESH),
        ("B: client=主App, scope=4(+vss)", CLIENT_ID, SCOPE_MESH + " " + SCOPE_VSS),
        ("C: client=空串,  scope=3", "", SCOPE_MESH),
        ("D: client=空串,  scope=4(+vss)", "", SCOPE_MESH + " " + SCOPE_VSS),
        ("E: 省略 client_id, scope=4", None, SCOPE_MESH + " " + SCOPE_VSS),
        ("F: 省略 client_id, scope=5(+task-master)", None,
         SCOPE_MESH + " " + SCOPE_VSS + " task-master"),
    ]

    for name, client, scope in scenarios:
        tok, note = exchange(sess, bearer, dev, client, scope, AUD_MESH)
        print(f"\n=== {name} ===")
        print(f"    换 token: {note}")
        probe(name, tok, signer, vin)
        time.sleep(0.5)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
