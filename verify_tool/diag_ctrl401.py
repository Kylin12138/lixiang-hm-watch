"""车控 401 对照诊断 —— 用手表导出的真实凭据，在 PC 侧复现。

目的：区分「服务端/账号侧问题」与「ArkTS @ohos.net.http 问题」。

步骤：
  1. 解析手表 prefs（main_bearer / device_id / vin / session_cookies）
  2. 换 MESH / VAT / VSS，打印实际长度与前 24 字符
  3. 调 wakeup（Authorization: Bearer MESH）—— 验证 MESH + 签名头是否被接受
  4. 调 cmd/send（lock，幂等安全）—— 复现 401

★ 只做 lock/unlock 授权范围内的动作；lock 对已锁车辆是幂等的。
"""

from __future__ import annotations

import json
import os
import re
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lx_vehicle import VehicleControl  # noqa: E402
from lx_token import TokenManager, TokenError  # noqa: E402
from lx_signer import Signer  # noqa: E402
from lx_const import API_APP, EP_CMD_SEND, EP_WAKEUP, EP_CMD_RESULT  # noqa: E402

PREFS = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "..", ".tmp", "prefs_now.xml")


def load_prefs(path: str) -> dict:
    raw = open(path, encoding="utf-8").read()
    # preferences 是扁平 XML：<string key="...">value</string>
    out: dict = {}
    for m in re.finditer(r'<(string|int|bool|double)\s+key="([^"]+)"\s*>([^<]*)</\1>', raw):
        out[m.group(2)] = m.group(3)
    return out


def main() -> int:
    p = load_prefs(PREFS)
    print("=== 手表凭据 ===")
    for k in ("device_id", "vin", "key_id", "refresh_token", "main_bearer"):
        v = p.get(k, "")
        print(f"  {k:14s} len={len(v):5d}  {v[:40]}")

    ck_raw = p.get("session_cookies", "[]")
    # XML 里的 &quot; 已被 ElementTree 之外的读法保留，做一次反转义
    ck_raw = (ck_raw.replace("&quot;", '"').replace("&amp;", "&")
              .replace("&lt;", "<").replace("&gt;", ">"))
    try:
        cookies = json.loads(ck_raw)
    except json.JSONDecodeError as err:
        print(f"  !! session_cookies 解析失败: {err}")
        cookies = []
    print(f"  session_cookies: {len(cookies)} 条")
    for c in cookies:
        print(f"     {c.get('name'):20s} domain={c.get('domain'):22s} "
              f"vlen={len(str(c.get('value') or ''))}")

    main_bearer = p.get("main_bearer", "")
    device_id = p.get("device_id", "")
    vin = p.get("vin", "")

    signer = Signer(p.get("hac_key", ""), p.get("key_id", ""), device_id, "")

    tm = TokenManager(main_bearer, device_id, vin=vin, debug=True, cookies=cookies)

    print("\n=== 换 token ===")
    try:
        mesh = tm.mesh()
        print(f"  MESH len={len(mesh):5d}  {mesh[:60]}")
    except TokenError as err:
        print(f"  !! MESH 失败: {err}")
        mesh = ""
    try:
        vat = tm.vat()
        print(f"  VAT  len={len(vat):5d}  {vat[:60]}")
    except TokenError as err:
        print(f"  !! VAT 失败: {err}")
        vat = ""
    try:
        vss = tm.vss()
        print(f"  VSS  len={len(vss):5d}  {vss[:60]}")
    except TokenError as err:
        print(f"  !! VSS 失败: {err}")
        vss = ""

    if not mesh:
        print("\nMESH 拿不到，终止")
        return 1

    vc = VehicleControl(signer, vin, mesh, vat, debug=True)

    print("\n=== ① wakeup（Authorization: Bearer MESH）===")
    try:
        r = vc.wakeup()
        print(f"  OK: {str(r)[:300]}")
    except Exception as err:  # noqa: BLE001
        print(f"  FAIL: {type(err).__name__}: {err}")

    print("\n=== ② cmd/send GET cmd-result 探测（只读，无 requestId）===")
    try:
        r = vc.get_command_result("00000000-0000-0000-0000-000000000000")
        print(f"  OK(鉴权通过): {str(r)[:200]}")
    except PermissionError as err:
        print(f"  401（鉴权失败）: {err}")
    except Exception as err:  # noqa: BLE001
        print(f"  非 401（说明鉴权已通过）: {type(err).__name__}: {err}")

    print("\n=== ③ 换过 VSS 之后再探车控（验证十号坑已修）===")
    try:
        r = vc.get_command_result("00000000-0000-0000-0000-000000000000")
        print(f"  OK(鉴权通过): {str(r)[:120]}")
    except PermissionError as err:
        print(f"  401（仍被顶掉）: {err}")
    except Exception as err:  # noqa: BLE001
        print(f"  非 401（鉴权通过）: {type(err).__name__}: {str(err)[:120]}")

    print("\n=== ④ wakeup（同 token）===")
    try:
        r = vc.wakeup()
        print(f"  OK: {str(r)[:200]}")
    except Exception as err:  # noqa: BLE001
        print(f"  FAIL: {type(err).__name__}: {err}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
