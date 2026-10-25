"""换 token 请求头对照实验 —— 定位 invalid_token 根因。

参考项目 _do_exchange 的请求头比我们多 5 个：
    idaas-data: model_name=OpenHarmony;device_id=..;app_version=8.22.0;
                client_id=..;sdk_version=0.0.0-snapshot-20240614055722;timestamp=..
    origin / referer: https://account.lixiang.com
    x-requested-with: XMLHttpRequest
    User-Agent: m01/8.22.0
本脚本对比「我们现有头」与「参考项目头」，并用同一探针验证 token 是否可用。
同时打印 302 fragment 的全部键（服务端实际授予的 scope / expires_in）。
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import uuid
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import requests  # noqa: E402

from lx_const import (BASE_ID, EP_AUTH, CLIENT_ID, REDIRECT_URI,  # noqa: E402
                      AUD_MESH, SCOPE_MESH, AUD_VSS, SCOPE_VSS,
                      API_APP, EP_WAKEUP, EP_CMD_RESULT)
from lx_signer import Signer  # noqa: E402

PREFS = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "..", ".tmp", "prefs_now.xml")
SDK_VERSION = "0.0.0-snapshot-20240614055722"
LOGIN_APP_VERSION = "8.22.0"
BASE_ACCT = "https://account.lixiang.com"


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


def idaas_headers(device_id: str) -> dict:
    return {
        "idaas-data": (
            f"model_name=OpenHarmony;device_id={device_id};"
            f"app_version={LOGIN_APP_VERSION};client_id={CLIENT_ID};"
            f"sdk_version={SDK_VERSION};timestamp={int(time.time() * 1000)}"
        ),
        "idaas-data-x": "source_url=registerAction=&pageUrl=&eventID=",
        "origin": BASE_ACCT,
        "referer": BASE_ACCT + "/",
        "x-requested-with": "XMLHttpRequest",
        "User-Agent": f"m01/{LOGIN_APP_VERSION}",
        "content-type": "application/x-www-form-urlencoded",
    }


def do_exchange(sess: requests.Session, bearer: str, device_id: str,
                scope: str, audience: str, use_idaas: bool,
                use_bearer: bool) -> tuple[str, dict, str]:
    data = {
        "prompt": "none", "redirect_uri": REDIRECT_URI, "scope": scope,
        "response_type": "token", "device_id": device_id,
        "client_id": CLIENT_ID, "audience": audience,
    }
    if use_idaas:
        h = idaas_headers(device_id)
    else:
        h = {"content-type": "application/x-www-form-urlencoded"}
    if use_bearer:
        h["Authorization"] = "Bearer " + bearer
    r = sess.post(BASE_ID + EP_AUTH, data=data, headers=h, timeout=20,
                  allow_redirects=False)
    loc = r.headers.get("location", "") or ""
    u = urlparse(loc)
    frag = dict(parse_qs(u.fragment))
    flat = {k: v[0] for k, v in frag.items()}
    return flat.get("access_token", ""), flat, f"HTTP {r.status_code}"


def probe(tok: str, signer: Signer, vin: str) -> str:
    if not tok:
        return "无 token"
    body = '{"source":"0x3B","bizId":"0"}'
    h = signer.build_headers("POST", body, tok, vin)
    r = requests.post(API_APP + EP_WAKEUP, data=body.encode(), headers=h, timeout=20)
    ok_wake = r.status_code == 200 and "250001" not in r.text
    rid = "00000000-0000-0000-0000-000000000000"
    h2 = signer.build_headers("GET", "", tok, vin)
    r2 = requests.get(f"{API_APP}{EP_CMD_RESULT}/{rid}", headers=h2, timeout=20)
    verdict = "❌ 401" if r2.status_code == 401 else f"✅ 鉴权通过({r2.status_code})"
    return (f"wakeup HTTP {r.status_code} {'✅' if ok_wake else '❌ ' + r.text[:90]}\n"
            f"        cmd-result {verdict}  {r2.text[:90]}")


def main() -> int:
    p = load_prefs(PREFS)
    cookies = json.loads(p.get("session_cookies", "[]"))
    sess = build_session(cookies)
    bearer, dev, vin = p["main_bearer"], p["device_id"], p["vin"]
    signer = Signer(p["hac_key"], p["key_id"], dev, "")

    cases = [
        ("G: 现有头（无论 Bearer）", False, True),
        ("H: +idaas-data 等（含 Bearer）", True, True),
        ("I: +idaas-data 等（无 Bearer，完全照抄参考）", True, False),
    ]

    for name, use_idaas, use_bearer in cases:
        print(f"\n=== {name} ===")
        tok, frag, note = do_exchange(sess, bearer, dev, SCOPE_MESH, AUD_MESH,
                                      use_idaas, use_bearer)
        keys = {k: (v[:60] if k != "access_token" else f"<len {len(v)}>")
                for k, v in frag.items()}
        print(f"    {note}  返回参数={keys}")
        print(f"    token len={len(tok)}  {tok[:40]}")
        print(f"    {probe(tok, signer, vin)}")
        time.sleep(0.4)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
