# -*- coding: utf-8 -*-
"""复现 /api/idps 的 412 —— 对照「已信任 device_id」vs「全新随机 device_id」

只走前 4 步，**不提交密码**（不碰 /api/login），所以不会触发风控/短信。
"""
from __future__ import annotations

import base64
import hashlib
import os
import secrets
import sys
import time

import requests

from lx_const import (BASE_ID, BASE_ACCT, CLIENT_ID, LOGIN_AUDIENCE,
                      LOGIN_SCOPE, REDIRECT_URI, SDK_VERSION, APP_VERSION,
                      DEFAULT_UA)
from lx_login import create_seed

# ★ 敏感信息一律从环境变量读取，源码里不留任何真实账号/设备号
#   用法：LX_PHONE=1xxxxxxxxxx LX_PASSWORD=xxxx TRUSTED_DEVICE=<device_id> python probe412.py trusted


def _norm_phone(raw: str) -> str:
    """把 11 位手机号转成 idps 需要的 +86 前缀形式；空值原样返回。"""
    digits = "".join(ch for ch in raw if ch.isdigit())
    if not digits:
        return ""
    return "+86" + digits if len(digits) == 11 else raw


PASSWORD = os.environ.get("LX_PASSWORD", "")
PHONE_TIP = _norm_phone(os.environ.get("LX_PHONE", ""))
TRUSTED_DEVICE = os.environ.get("TRUSTED_DEVICE", "")


def hdr(device_id: str) -> dict:
    return {
        "idaas-data": (
            f"model_name=OpenHarmony;device_model=;device_id={device_id};"
            f"app_version={APP_VERSION};client_id={CLIENT_ID};"
            f"sdk_version={SDK_VERSION};timestamp={int(time.time() * 1000)}"),
        "idaas-data-x": "source_url=registerAction=&pageUrl=&eventID=",
        "origin": BASE_ACCT,
        "referer": BASE_ACCT + "/",
    }


def probe(tag: str, device_id: str) -> None:
    print("\n" + "=" * 68)
    print(f"### {tag}")
    print(f"### device_id = {device_id}")
    print("=" * 68)

    s = requests.Session()
    s.headers.update({"User-Agent": DEFAULT_UA, "x-requested-with": "XMLHttpRequest"})
    for dom in ("account.lixiang.com", "id.lixiang.com"):
        s.cookies.set("X-LX-Deviceid", device_id, domain=dom)
        s.cookies.set("authli_device_id", device_id, domain=dom)
    s.cookies.set("isapp", "1", domain="account.lixiang.com")

    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    state = secrets.token_urlsafe(21)[:21]

    r = s.post(f"{BASE_ID}/api/auth", data={
        "client_id": CLIENT_ID, "device_id": device_id,
        "response_type": "code", "redirect_uri": REDIRECT_URI,
        "offline_access": "true", "state": state,
        "audience": LOGIN_AUDIENCE, "scope": LOGIN_SCOPE,
        "code_challenge": challenge, "code_challenge_method": "S256",
    }, headers={**hdr(device_id),
                "content-type": "application/x-www-form-urlencoded"}, timeout=20)
    print(f"[1] auth      -> {r.status_code}  {r.text[:150]}")

    r = s.get(f"{BASE_ACCT}/login",
              params={"client_id": CLIENT_ID, "redirect_uri": REDIRECT_URI},
              headers={"accept": "text/html",
                       "referer": BASE_ACCT + "/app-auth"}, timeout=20)
    print(f"[2] login页面 -> {r.status_code}  set-cookies={[c.name for c in s.cookies]}")

    r = s.post(f"{BASE_ID}/api/devices", json={
        "client_id": CLIENT_ID, "device_id": device_id,
        "user_agent": DEFAULT_UA, "model": "", "manufacturer": "",
        "os": "OpenHarmony", "os_version": "6.1", "screen_height": 843,
        "screen_width": 374, "app_version": APP_VERSION,
    }, headers=hdr(device_id), timeout=20)
    print(f"[3] devices   -> {r.status_code}  {r.text[:300]}")

    r = s.post(f"{BASE_ID}/api/idps", json={
        "origin": BASE_ACCT, "connection": "LI_USER",
        "seed": create_seed(PASSWORD), "strategy": "PASSWORD",
        "user_tip": PHONE_TIP,
    }, headers=hdr(device_id), timeout=20)
    print(f"[4] idps      -> {r.status_code}")
    interesting = {k: v for k, v in r.headers.items()
                   if k.lower() in ("content-type", "location", "set-cookie",
                                    "x-lx-error", "x-error", "server", "date")}
    print(f"    关键响应头 : {interesting}")
    print(f"    响应体     : {r.text[:800]!r}")


if __name__ == "__main__":
    if not PASSWORD or not PHONE_TIP:
        sys.exit("请先设置环境变量 LX_PHONE 与 LX_PASSWORD（本脚本不内置任何账号信息）")
    which = sys.argv[1] if len(sys.argv) > 1 else "new"
    if which == "new":
        probe("全新随机 device_id（= ArkTS 手表端行为）", secrets.token_hex(16))
    elif which == "trusted":
        if not TRUSTED_DEVICE:
            sys.exit("使用 trusted 模式需设置环境变量 TRUSTED_DEVICE=<device_id>")
        probe("已信任 device_id（= Python 侧行为）", TRUSTED_DEVICE)
    else:
        probe("指定 device_id", which)
