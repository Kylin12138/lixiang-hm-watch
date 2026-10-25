"""授权驾驶（remoteVehAuth）验证 —— 用手表真实凭据在 PC 侧跑。

分两段：

  段 1（无副作用）：换 VAT token → 解码 JWT payload → 打印 scope 列表
                   → 检查是否含 `remoteVehAuth:<VIN>`
        「scope 拿到了」是命令能被服务端接受的必要条件。
        若这一关都不过，说明服务端不认这个 scope（那就要退回 EXTENDED 方案）。

  段 2（★ 真车动作）：POST cmd/send {cmdKey:"remoteVehAuth", cmdData:{}} → 轮询
                     cmd-result 到 pushState=5/7，打印 resultCode/resultMsg。

用法：
    python diag_auth.py            # 两段都跑
    python diag_auth.py --scope    # 只跑段 1（绝不碰车）
"""

from __future__ import annotations

import base64
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lx_const import CMD_AUTH, vat_scope  # noqa: E402
from lx_signer import Signer  # noqa: E402
from lx_token import TokenManager, TokenError  # noqa: E402
from lx_vehicle import LiCommandError, VehicleControl  # noqa: E402

PREFS = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "..", ".tmp", "prefs_auth.xml")


def load_prefs(path: str) -> dict:
    raw = open(path, encoding="utf-8").read()
    out: dict = {}
    for m in re.finditer(r'<(string|int|bool|double)\s+key="([^"]+)"\s*>([^<]*)</\1>', raw):
        out[m.group(2)] = m.group(3)
    return out


def unescape(s: str) -> str:
    return (s.replace("&quot;", '"').replace("&amp;", "&")
             .replace("&lt;", "<").replace("&gt;", ">"))


def jwt_payload(tok: str) -> dict | None:
    """解 JWT 的 payload 段（不验签，只看内容）。"""
    parts = tok.split(".")
    if len(parts) < 2:
        return None
    seg = parts[1]
    seg += "=" * (-len(seg) % 4)
    try:
        raw = base64.urlsafe_b64decode(seg)
        obj = json.loads(raw.decode("utf-8", errors="replace"))
        return obj if isinstance(obj, dict) else None
    except Exception:  # noqa: BLE001
        return None


def main() -> int:
    scope_only = "--scope" in sys.argv

    p = load_prefs(PREFS)
    device_id = p.get("device_id", "")
    vin = p.get("vin", "")
    cookies = json.loads(unescape(p.get("session_cookies", "[]")))

    print("=== 手表凭据 ===")
    print(f"  device_id = {device_id}")
    print(f"  vin       = {vin}")
    print(f"  cookies   = {len(cookies)} 条")

    signer = Signer(p.get("hac_key", ""), p.get("key_id", ""), device_id, "")
    tm = TokenManager(p.get("main_bearer", ""), device_id, vin=vin,
                      debug=False, cookies=cookies)

    print("\n=== 本次请求的 VAT scope ===")
    print(f"  {vat_scope(vin)}")

    print("\n=== ① 换 VAT token ===")
    try:
        vat = tm.vat()
    except TokenError as err:
        print(f"  ✗ VAT 失败: {err}")
        return 1
    print(f"  VAT len={len(vat)}")

    pl = jwt_payload(vat)
    if pl is None:
        print("  （不是 JWT / 无法解码 payload，跳过 scope 检查）")
    else:
        # ★ 这个令牌的 claim 名是 `scopes`（复数、数组），不是标准的 `scope`
        sc = pl.get("scopes", pl.get("scope"))
        aud = pl.get("aud")
        print(f"  aud    = {aud}")
        print(f"  scopes = {sc}")
        sc_list = sc if isinstance(sc, list) else str(sc or "").split()
        want = f"remoteVehAuth:{vin}"
        print(f"\n  ★ 是否含 {want} ? "
              f"{'✅ 是' if want in sc_list else '❌ 否'}")
        # 顺带确认删掉的车窗 scope 确实没了
        print(f"  （已删除的 remoteVehWdwControl:{vin} 是否还在? "
              f"{'仍存在' if f'remoteVehWdwControl:{vin}' in sc_list else '✅ 已不存在'}）")
        if len(sc_list) < 4:
            print(f"  ⚠ 只授权了 {len(sc_list)} 个 scope（期望 4）→ 可能触发整批降级")

    if scope_only:
        print("\n--scope 模式：不触碰车辆，结束")
        return 0

    print("\n=== ② 换 MESH token（cmd/send 的 Authorization）===")
    try:
        mesh = tm.mesh()
    except TokenError as err:
        print(f"  ✗ MESH 失败: {err}")
        return 1
    print(f"  MESH len={len(mesh)}")

    vc = VehicleControl(signer, vin, mesh, vat, debug=True)

    print("\n=== ③ 下发「授权驾驶」remoteVehAuth {} ===")
    print("  ★ 真车动作：这会给车辆下授权驾驶指令")
    try:
        r = vc.auth_drive()
        print(f"  ✅ OK  requestId={r.get('requestId')} "
              f"pushState={r.get('pushState')} resultCode={r.get('resultCode')} "
              f"resultMsg={r.get('resultMsg')!r} timeout={r.get('timeout')}")
    except LiCommandError as err:
        print(f"  ✗ 命令失败: {err}")
        print(f"    requestId={getattr(err, 'request_id', None)} "
              f"resultCode={getattr(err, 'result_code', None)} "
              f"pushState={getattr(err, 'push_state', None)}")
        return 1
    except Exception as err:  # noqa: BLE001
        print(f"  ✗ {type(err).__name__}: {err}")
        return 1

    print("\n=== ④ 读回车辆状态（确认车辆仍正常，未被误动）===")
    try:
        from lx_vss import VssReader
        vr = VssReader(signer, vin, tm.vss(), debug=False)
        st = vr.read_state()
        print(f"  locked={st['locked']}  ac_on={st['ac_on']}  "
              f"ac_set_temp={st['ac_set_temp']}  inside_temp={st['inside_temp']}")
    except Exception as err:  # noqa: BLE001
        print(f"  读状态失败（不影响结论）: {type(err).__name__}: {err}")

    print(f"\n（下发内容核对：cmdKey={CMD_AUTH} cmdData={{}}）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
