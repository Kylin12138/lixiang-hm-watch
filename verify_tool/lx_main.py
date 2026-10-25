"""理想汽车协议验证工具 —— 主入口

═══════════════════════════════════════════════════════════════
 用法
═══════════════════════════════════════════════════════════════

  全部依赖：cryptography / bcrypt / pynacl / requests

  # 0. 环境自检（不联网）
  python lx_main.py doctor

  # 1. 登录（首次会提示需要短信验证，走浏览器辅助）
  python lx_main.py login --phone 138xxxxxxxx

  # 2. 派生签名身份（需要已登录）
  python lx_main.py derive

  # 3. 拉车辆列表，确认 VIN
  python lx_main.py vehicles

  # 4. 只读状态（安全，不改车）
  python lx_main.py status

  # 5. 下发命令（真车会动！）
  python lx_main.py cmd unlock      # 解锁
  python lx_main.py cmd lock        # 落锁
  python lx_main.py cmd auth        # 授权驾驶
  python lx_main.py cmd ac on --temp 26   # 开空调 26℃
  python lx_main.py cmd ac off      # 关空调
  python lx_main.py cmd find        # 寻车

═══════════════════════════════════════════════════════════════
 凭据落盘
═══════════════════════════════════════════════════════════════
  所有凭据存到 ./cred.json（明文，仅用于本地验证；手表端会用
  系统级加密存储）。文件已加入 .gitignore 建议。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any

CRED_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cred.json")


def load_cred() -> dict[str, Any]:
    if not os.path.exists(CRED_FILE):
        return {}
    with open(CRED_FILE, encoding="utf-8") as f:
        return json.load(f)


def save_cred(d: dict[str, Any]) -> None:
    with open(CRED_FILE, "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False, indent=2)
    try:
        os.chmod(CRED_FILE, 0o600)
    except Exception:
        pass


def merge_cred(**kw: Any) -> dict[str, Any]:
    d = load_cred()
    d.update(kw)
    save_cred(d)
    return d


def _require(cred: dict, *keys: str) -> None:
    missing = [k for k in keys if not cred.get(k)]
    if missing:
        print(f"✗ 缺少凭据: {', '.join(missing)}")
        print("  请先执行: python lx_main.py login --phone <手机号>")
        sys.exit(2)


# ═══════════════════════════════════════════════════════════════
#  各子命令
# ═══════════════════════════════════════════════════════════════

def cmd_doctor(args: argparse.Namespace) -> int:
    """环境与协议自检，不联网。"""
    print("═══ 环境自检 ═══")
    ok = True

    for mod, name in (("cryptography", "cryptography"),
                      ("bcrypt", "bcrypt"),
                      ("nacl", "PyNaCl"),
                      ("requests", "requests")):
        try:
            m = __import__(mod)
            ver = getattr(m, "__version__", "?")
            print(f"  ✓ {name:14s} {ver}")
        except ImportError:
            print(f"  ✗ {name:14s} 未安装")
            ok = False

    print("\n═══ 协议自检 ═══")
    from lx_signer import selftest as signer_st
    s1 = signer_st()
    print(f"  {'✓' if s1 else '✗'} 签名器（确定性 / 11段 / hex与bytes等价）")
    ok = ok and s1

    from lx_login import create_seed, bcrypt_b64
    a, b = create_seed("test"), create_seed("test")
    s2 = a == b and len(a) == 32
    print(f"  {'✓' if s2 else '✗'} PAKE create_seed")
    ok = ok and s2

    s3 = len(bcrypt_b64(bytes(16))) == 22
    print(f"  {'✓' if s3 else '✗'} bcrypt 自定义 base64（22 字符）")
    ok = ok and s3

    from lx_keysuite import load_main_private_key, MAIN_DEVICE_KEY_ID
    try:
        priv = load_main_private_key()
        s4 = priv.key_size == 2048
        print(f"  ✓ RSA 私钥加载（2048 位，keyId={MAIN_DEVICE_KEY_ID[:12]}...）")
    except Exception as err:
        s4 = False
        print(f"  ✗ RSA 私钥加载失败: {err}")
    ok = ok and s4

    from lx_const import vat_scope, VAT_SCOPE_REQUIRED, VAT_SCOPE_EXTENDED
    sc = vat_scope("TESTVIN")
    s5 = sc.count(":") == len(VAT_SCOPE_REQUIRED) and sc.endswith(":TESTVIN")
    print(f"  {'✓' if s5 else '✗'} VAT scope 生成"
          f"（默认 {len(VAT_SCOPE_REQUIRED)} 条 / 扩展 {len(VAT_SCOPE_EXTENDED)} 条）")
    ok = ok and s5

    print(f"\n结果: {'全部通过 ✓' if ok else '存在失败项 ✗'}")
    return 0 if ok else 1


def cmd_login(args: argparse.Namespace) -> int:
    """PAKE 登录。"""
    from lx_login import LixiangLogin, LoginError, NeedSmsCode, NeedPassword
    from lx_login import browser_login_url

    cred = load_cred()
    device_id = cred.get("device_id") or ""
    phone = (args.phone or cred.get("phone") or "").strip()

    if not phone:
        print("✗ 需要手机号：--phone 138xxxxxxxx")
        return 2

    # 首次：先生成 device_id 并给出浏览器辅助链接
    if not device_id:
        import uuid
        device_id = uuid.uuid4().hex
        merge_cred(device_id=device_id, phone=phone)
        print(f"已生成 device_id: {device_id}")
        main_url, alt_url = browser_login_url(device_id)
        print("\n═══ 首次登录：先用手机浏览器建立设备信任 ═══")
        print("在手机浏览器打开下面的链接，完成滑动验证 + 短信验证码：\n")
        print(f"  主链接: {main_url}\n")
        print(f"  备用:   {alt_url}\n")
        print("完成后回到这里继续（同一 device_id 之后就免短信了）。\n")

    password = args.password or os.environ.get("LX_PASSWORD") or ""
    if not password:
        import getpass
        password = getpass.getpass("理想账号密码: ")

    print(f"登录中… (device_id={device_id[:12]}...)")
    cli = LixiangLogin(device_id=device_id, debug=args.debug)
    try:
        tok = cli.login(phone, password)
    except NeedSmsCode as err:
        print(f"\n⚠️  {err.detail}")
        main_url, alt_url = browser_login_url(device_id)
        print("\n请在手机浏览器完成验证后重试：")
        print(f"  {main_url}\n")
        return 3
    except NeedPassword as err:
        print(f"\n✗ {err.detail}")
        return 4
    except LoginError as err:
        print(f"\n✗ 登录失败: {err}")
        return 5

    at = tok.get("access_token") or ""
    rt = tok.get("refresh_token") or ""
    if not at:
        print(f"✗ 响应无 access_token: {str(tok)[:300]}")
        return 6

    merge_cred(main_bearer=at, refresh_token=rt,
               bearer_time=time.time(), phone=phone)
    print("✓ 登录成功")
    print(f"  access_token: {at[:24]}… ({len(at)} 字符)")
    print(f"  refresh_token: {'有' if rt else '无'}")
    return 0


def cmd_derive(args: argparse.Namespace) -> int:
    """派生签名身份。"""
    from lx_keysuite import derive_identity, IdentityDeriveError

    cred = load_cred()
    _require(cred, "main_bearer", "device_id")

    print("派生签名身份中…")
    try:
        hac_hex, key_id = derive_identity(
            cred["device_id"], cred["main_bearer"], debug=args.debug)
    except IdentityDeriveError as err:
        print(f"✗ 派生失败: {err}")
        return 1

    merge_cred(hac_key=hac_hex, key_id=key_id)
    print("✓ 派生成功")
    print(f"  hac_key: {hac_hex[:16]}…（{len(hac_hex)} hex 字符 = 32 字节）")
    print(f"  key_id:  {key_id}")
    return 0


def cmd_vehicles(args: argparse.Namespace) -> int:
    """拉取车辆列表。"""
    from lx_token import TokenManager, TokenError

    cred = load_cred()
    _require(cred, "main_bearer", "device_id")

    tm = TokenManager(cred["main_bearer"], cred["device_id"],
                      debug=args.debug)
    try:
        vs = tm.list_vehicles()
    except TokenError as err:
        print(f"✗ {err}")
        return 1

    if not vs:
        print("⚠️  未返回车辆（账号下可能没有车辆）")
        return 0

    print(f"✓ 共 {len(vs)} 辆：\n")
    for i, v in enumerate(vs, 1):
        vin = v.get("vin") or v.get("VIN") or ""
        name = (v.get("vehicleName") or v.get("nickname")
                or v.get("name") or v.get("seriesName") or "?")
        model = v.get("modelId") or v.get("model") or ""
        print(f"  [{i}] {name}")
        print(f"      VIN:   {vin}")
        print(f"      model: {model}")
        if i == 1 and vin and not cred.get("vin"):
            merge_cred(vin=vin, vehicle_name=name, vehicle_model_id=model)
            print("      → 已自动保存第 1 辆为默认车辆")
    return 0


def _build_ctx(args: argparse.Namespace, need_vat: bool = True):
    """构造 (Signer, VehicleControl/VssReader) 上下文。"""
    from lx_signer import Signer
    from lx_token import TokenManager

    cred = load_cred()
    keys = ["main_bearer", "device_id", "hac_key", "key_id", "vin"]
    _require(cred, *keys)

    signer = Signer(cred["hac_key"], cred["key_id"],
                    cred["device_id"], app_token=cred.get("app_token", ""))
    tm = TokenManager(cred["main_bearer"], cred["device_id"],
                      cred["vin"], debug=args.debug)
    return cred, signer, tm


def cmd_status(args: argparse.Namespace) -> int:
    """只读车辆状态（安全操作）。"""
    from lx_vss import VssReader
    from lx_token import TokenError

    cred, signer, tm = _build_ctx(args)
    try:
        vss_tok = tm.vss()
    except TokenError as err:
        print(f"✗ 获取 VSS token 失败: {err}")
        return 1

    reader = VssReader(signer, cred["vin"], vss_tok, debug=args.debug)
    st = reader.read_state()

    def yn(v):
        return "?" if v is None else ("是" if v else "否")

    print(f"═══ 车辆状态 ({cred.get('vehicle_name', '')} / {cred['vin'][-6:]}) ═══")
    print(f"  车锁:      {'已落锁' if st['locked'] else '已解锁'}"
          if st['locked'] is not None else "  车锁:      ?")
    print(f"  空调:      {'开启' if st['ac_on'] else '关闭'}"
          if st['ac_on'] is not None else "  空调:      ?")
    print(f"  设定温度:  {st['ac_set_temp']}℃")
    print(f"  车内温度:  {st['inside_temp']}℃")

    if args.raw:
        print("\n═══ 原始信号 ═══")
        for k, v in (st.get("_raw") or {}).items():
            print(f"  {k} = {v}")
    return 0


def cmd_command(args: argparse.Namespace) -> int:
    """下发车控命令。"""
    from lx_vehicle import VehicleControl, LiCommandError
    from lx_token import TokenError

    cred, signer, tm = _build_ctx(args)
    try:
        mesh = tm.mesh()
        vat = tm.vat()
    except TokenError as err:
        print(f"✗ 获取 token 失败: {err}")
        return 1

    vc = VehicleControl(signer, cred["vin"], mesh, vat, debug=args.debug)

    action = args.action
    print(f"执行: {action} …")
    t0 = time.time()
    try:
        if action == "unlock":
            r = vc.unlock()
        elif action == "lock":
            r = vc.lock()
        elif action == "auth":
            r = vc.auth_drive()
        elif action == "ac":
            sub = (args.value or "on").lower()
            if sub in ("on", "开"):
                r = vc.ac_on(float(args.temp or 26))
            else:
                r = vc.ac_off()
        elif action == "find":
            r = vc.find_car()
        elif action == "flash":
            r = vc.flash_light()
        elif action == "whistle":
            r = vc.whistle()
        else:
            print(f"✗ 未知动作: {action}")
            return 2
    except LiCommandError as err:
        print(f"✗ 命令失败: {err}")
        return 1

    dt = time.time() - t0
    print(f"✓ 完成（{dt:.1f}s）")
    print(f"  requestId:  {r.get('requestId')}")
    print(f"  pushState:  {r.get('pushState')}"
          + ("  ← 未到终态但可能已生效" if r.get("timeout") else ""))
    print(f"  resultCode: {r.get('resultCode')}")
    if r.get("resultMsg"):
        print(f"  resultMsg:  {r.get('resultMsg')}")
    if args.debug:
        print(f"  raw: {json.dumps(r, ensure_ascii=False)[:600]}")
    return 0


def cmd_probe(args: argparse.Namespace) -> int:
    """探测各端点连通性（不触发车控）。"""
    from lx_token import TokenManager, TokenError

    cred = load_cred()
    _require(cred, "main_bearer", "device_id")

    tm = TokenManager(cred["main_bearer"], cred["device_id"],
                      cred.get("vin", ""), debug=True)
    print("═══ token 换取探测 ═══")
    for name, fn in (("MESH", tm.mesh), ("VSS", tm.vss)):
        try:
            t = fn()
            print(f"  ✓ {name}: {t[:28]}… ({len(t)} 字符)")
        except TokenError as err:
            print(f"  ✗ {name}: {err}")
    if cred.get("vin"):
        try:
            t = tm.vat()
            print(f"  ✓ VAT: {t[:28]}… ({len(t)} 字符)")
        except TokenError as err:
            print(f"  ✗ VAT: {err}")
    return 0


# ═══════════════════════════════════════════════════════════════

def main() -> int:
    p = argparse.ArgumentParser(
        prog="lx_main",
        description="理想汽车协议验证工具（参考 C3H3-AI/ha-lixiang 逆向结论）")
    p.add_argument("--debug", action="store_true", help="打印请求/响应详情")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("doctor", help="环境与协议自检（不联网）")

    sp = sub.add_parser("login", help="PAKE 登录")
    sp.add_argument("--phone", help="手机号")
    sp.add_argument("--password", help="密码（不传则交互输入）")

    sub.add_parser("derive", help="派生签名身份（keySuite）")
    sub.add_parser("vehicles", help="拉取车辆列表")
    sub.add_parser("probe", help="探测 token 换取链路")

    sp = sub.add_parser("status", help="只读车辆状态（安全）")
    sp.add_argument("--raw", action="store_true", help="打印原始信号")

    sp = sub.add_parser("cmd", help="下发车控命令")
    sp.add_argument("action",
                    choices=["unlock", "lock", "auth", "ac",
                             "find", "flash", "whistle"])
    sp.add_argument("value", nargs="?", help="ac: on/off")
    sp.add_argument("--temp", help="空调温度（16-28）")

    args = p.parse_args()

    fn = {
        "doctor": cmd_doctor, "login": cmd_login, "derive": cmd_derive,
        "vehicles": cmd_vehicles, "status": cmd_status,
        "cmd": cmd_command, "probe": cmd_probe,
    }[args.cmd]
    return fn(args)


if __name__ == "__main__":
    sys.exit(main())
