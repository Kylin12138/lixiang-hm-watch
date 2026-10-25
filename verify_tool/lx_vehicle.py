"""车控通道 —— 与 ArkTS 的 VehicleControl.ets 一一对应。

═══════════════════════════════════════════════════════════════
 完整车控流程
═══════════════════════════════════════════════════════════════

  ① POST /iot-connect-manager-service/v2/wakeup      ← 唤醒（可失败，不阻断）
     body: {"source":"0x3B","bizId":"0"}  header: Bearer MESH

  ② POST /ssp-vehicle-control-service/ssp-vehicle-control/cmd/send
     body: {vin, cmdKey, cmdData, domain:"xcu",
            jobExpire, expire, expireAt, token:<VAT>}
     header: Bearer MESH
     → 返回 requestId

  ③ GET .../cmd-result/{requestId}  每 2s 轮询，直到 pushState ∈ {5, 7}

═══════════════════════════════════════════════════════════════
 ★ 实战要点
═══════════════════════════════════════════════════════════════

 · jobExpire 服务端只校验 >= 1，但：
     短命令（锁/窗/寻车）   → 30 够用
     长命令（空调/座椅加热） → 必须 >= 900，用 30 会超时 ps=7 rc=空
 · body.token 必须是 VAT（不是 MESH，也不是 "0" 或空）
 · Authorization 必须是 MESH
 · pushState=7 但 resultCode ∈ {0,-8,-15} → 实际是成功（倒计时到期）
 · 超时未到终态（pushState=1）→ 不抛错！命令可能已生效
"""

from __future__ import annotations

import json
import time
from typing import Any

import requests

from lx_const import (
    API_APP, EP_WAKEUP, EP_CMD_SEND, EP_CMD_RESULT, CTRL_DOMAIN,
    CMD_EXPIRE, LONG_CMD_EXPIRE, CMD_EXPIRE_MS, LONG_CMD_EXPIRE_MS,
    LONG_RUNNING_CMD_KEYS, PUSH_STATE_SUCCESS, PUSH_STATE_FAILED,
    SUCCESS_RESULT_CODES, CMD_POLL_TIMEOUT, CMD_POLL_INTERVAL,
    ERR_JOB_CHANNEL, RESULT_CODE_HINTS,
    CMD_LOCK, CMD_AUTH, CMD_AC, CMD_SEARCH,
    AC_TYPE_FRONT, AC_COUNTDOWN, AC_MIN_TEMP, AC_MAX_TEMP, AC_DEFAULT_TEMP,
)
from lx_signer import Signer


def _as_int(v: Any) -> int | None:
    """服务端可能把 pushState 返回成 5 或 "5"，统一成 int。"""
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _is_success_code(rc: Any) -> bool:
    """resultCode 是否属于「视为成功」集合（-15 倒计时完成 / -8 同类特判）。"""
    if rc is None:
        return False
    try:
        return int(rc) in (0, -15, -8)
    except (TypeError, ValueError):
        return rc in SUCCESS_RESULT_CODES


class LiCommandError(RuntimeError):
    """车控命令执行失败。"""

    def __init__(self, message: str, *, request_id: str = "",
                 result_code: Any = None, push_state: Any = None) -> None:
        super().__init__(message)
        self.request_id = request_id
        self.result_code = result_code
        self.push_state = push_state


class VehicleControl:
    """车控客户端。

    signer : Signer 实例（已含 hac_key/keyId/deviceId/appToken）
    vin    : 车架号
    token_provider : 提供 MESH/VAT token 的对象（见 lx_token.py）
    """

    def __init__(self, signer: Signer, vin: str, mesh_token: str,
                 vat_token: str, timeout: int = 20, debug: bool = False) -> None:
        self.signer = signer
        self.vin = vin
        self._mesh = mesh_token
        self._vat = vat_token
        self.timeout = timeout
        self.debug = debug

    def set_tokens(self, mesh: str, vat: str) -> None:
        self._mesh = mesh
        self._vat = vat

    # ---------- 底层签名调用 ----------

    def _signed_call(self, method: str, path: str, body: str,
                     bearer: str) -> dict:
        headers = self.signer.build_headers(method, body, bearer, self.vin)
        url = API_APP + path
        if self.debug:
            print(f"[{method}] {url}")
            print("  body:", body[:300])
        if method.upper() == "GET":
            r = requests.get(url, headers=headers, timeout=self.timeout)
        else:
            r = requests.post(url, data=body.encode("utf-8"),
                              headers=headers, timeout=self.timeout)
        if self.debug:
            print(f"  → {r.status_code} {r.text[:400]}")
        if r.status_code == 401:
            raise PermissionError(f"401 未授权（token 可能过期）: {r.text[:200]}")
        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code}: {r.text[:300]}")
        try:
            return r.json()
        except json.JSONDecodeError as err:
            raise RuntimeError(f"响应非 JSON: {r.text[:200]}") from err

    # ---------- ① 唤醒 ----------

    def wakeup(self) -> dict:
        """远程唤醒（失败不阻断主流程）。"""
        body = json.dumps({"source": "0x3B", "bizId": "0"},
                          separators=(",", ":"))
        return self._signed_call("POST", EP_WAKEUP, body, self._mesh)

    # ---------- ② 下发命令 ----------

    def send_command_raw(self, cmd_key: str, cmd_data: dict | None = None) -> dict:
        """仅下发，不轮询。返回 cmd/send 的原始响应。"""
        je, je_ms = (LONG_CMD_EXPIRE, LONG_CMD_EXPIRE_MS) \
            if cmd_key in LONG_RUNNING_CMD_KEYS else (CMD_EXPIRE, CMD_EXPIRE_MS)
        now_ms = int(time.time() * 1000)
        body = {
            "vin": self.vin,
            "cmdKey": cmd_key,
            "cmdData": cmd_data if cmd_data is not None else {},
            "domain": CTRL_DOMAIN,
            "jobExpire": je,
            "expire": je,
            "expireAt": now_ms + je_ms,
            "token": self._vat,
        }
        payload = json.dumps(body, separators=(",", ":"), ensure_ascii=False)
        return self._signed_call("POST", EP_CMD_SEND, payload, self._mesh)

    # ---------- ③ 查询结果 ----------

    def get_command_result(self, request_id: str) -> dict:
        return self._signed_call(
            "GET", f"{EP_CMD_RESULT}/{request_id}", "", self._mesh)

    def _poll_result(self, request_id: str, timeout: float,
                     interval: float) -> dict:
        deadline = time.monotonic() + timeout
        last: dict = {}
        while time.monotonic() < deadline:
            try:
                last = self.get_command_result(request_id)
            except (PermissionError, RuntimeError) as err:
                if self.debug:
                    print("  轮询失败(重试):", str(err)[:100])
                time.sleep(interval)
                continue
            # ★ 与 ArkTS 侧一致：pushState 可能是 "5"（字符串），
            #   直接 `in (5, 7)` 会一直等到超时。
            if _as_int(last.get("pushState")) in (PUSH_STATE_SUCCESS,
                                                 PUSH_STATE_FAILED):
                return last
            time.sleep(interval)
        return last

    # ---------- 完整流程 ----------

    def send_command(self, cmd_key: str, cmd_data: dict | None = None,
                     *, wake: bool = True, poll: bool = True,
                     timeout: float = CMD_POLL_TIMEOUT,
                     poll_interval: float = CMD_POLL_INTERVAL) -> dict:
        """下发并等待结果。

        返回 {requestId, pushState, resultCode, resultMsg, cmdKey, cmdData}
        失败抛 LiCommandError。
        """
        if wake:
            try:
                self.wakeup()
            except Exception as err:
                if self.debug:
                    print("  唤醒失败(忽略):", str(err)[:100])

        resp = self.send_command_raw(cmd_key, cmd_data)
        request_id = (resp.get("requestId")
                      or (resp.get("data") or {}).get("requestId") or "")

        rc = resp.get("resultCode")
        if rc not in (None, 0):
            raise LiCommandError(
                f"命令下发被拒 ({cmd_key}): resultCode={rc} "
                f"msg={resp.get('resultMsg') or resp.get('message')}",
                request_id=request_id, result_code=rc)

        if not request_id:
            raise LiCommandError(
                f"命令下发无 requestId ({cmd_key}): "
                f"{json.dumps(resp, ensure_ascii=False)[:200]}")

        if not poll:
            return {"requestId": request_id, "cmdKey": cmd_key,
                    "cmdData": cmd_data or {}, "raw": resp,
                    "ok": True, "pushState": None}

        result = self._poll_result(request_id, timeout, poll_interval)
        result.update({"requestId": request_id, "cmdKey": cmd_key,
                       "cmdData": cmd_data or {}})
        ps = _as_int(result.get("pushState"))
        rc_final = result.get("resultCode")

        if ps == PUSH_STATE_SUCCESS:
            result["ok"] = True
            return result
        if ps == PUSH_STATE_FAILED:
            if _is_success_code(rc_final):
                result["ok"] = True
                return result
            try:
                rc_int = int(rc_final) if rc_final is not None else None
            except (TypeError, ValueError):
                rc_int = None
            hint = RESULT_CODE_HINTS.get(str(rc_final), "")
            msg = (result.get("msg") or result.get("resultMsg") or hint)
            fail = str(result.get("failReason") or "").strip()
            if fail and fail not in str(msg):
                msg = f"{msg}（{fail}）" if msg else fail
            extra = f" [JOB 通道：{hint}]" if rc_int == ERR_JOB_CHANNEL else ""
            raise LiCommandError(
                f"命令执行失败 ({cmd_key}): pushState={ps} "
                f"resultCode={rc_final} msg={msg}{extra}",
                request_id=request_id, result_code=rc_final, push_state=ps)

        # 超时未终态：命令可能已生效，不抛错
        result["ok"] = True
        result["timeout"] = True
        return result

    # ═══════════════════════════════════════════════════════════
    #  四个目标功能
    # ═══════════════════════════════════════════════════════════

    def lock(self, poll: bool = True, wake: bool = True) -> dict:
        """落锁。lockSw=0"""
        return self.send_command(CMD_LOCK, {"lockSw": "0"}, poll=poll, wake=wake)

    def unlock(self, poll: bool = True, wake: bool = True) -> dict:
        """解锁。lockSw=1"""
        return self.send_command(CMD_LOCK, {"lockSw": "1"}, poll=poll, wake=wake)

    def auth_drive(self, poll: bool = True, wake: bool = True) -> dict:
        """授权驾驶。

        ★ cmdData 必须是【空对象】{}（参考项目实测：
          App 实现类是 XHttpRemoteStartControl，cmdKey 却是 remoteVehAuth）。
        ★ 需要等结果 —— 这是一次真实授权，不能 fire-and-forget。
        """
        return self.send_command(CMD_AUTH, {}, poll=poll, wake=wake)

    def ac_on(self, temp: float = AC_DEFAULT_TEMP, poll: bool = True,
              wake: bool = True) -> dict:
        """开空调。

        ★ 类型陷阱：
            acCtrlTemp  必须是 Number（26 或 26.0）
            acCtrlValue / acCtrlType / acCountdownTimer 必须是 String
          传错会被服务端拒绝。
        ★ L6 Max 温度范围 16-28（不是通用的 16-30）。
        ★ poll：命令行脚本默认 True（可以等）。**手表端传 False** ——
          空调是 jobExpire=900 的长任务，锁车时需远程唤醒整车，
          等终态会把 UI 按钮锁死一分钟（见 lx_const.py CMD_POLL_TIMEOUT
          上方注释）。对齐 ArkTS 侧 Index.ets onAcTap()。
        """
        t = float(temp)
        t = max(AC_MIN_TEMP, min(AC_MAX_TEMP, t))
        data = {
            "acCtrlValue": "ON",
            "acCtrlType": AC_TYPE_FRONT,
            "acCountdownTimer": AC_COUNTDOWN,
            "acCtrlTemp": int(t) if t == int(t) else t,   # Number，不是字符串
        }
        return self.send_command(CMD_AC, data, poll=poll, wake=wake)

    def ac_off(self, poll: bool = True, wake: bool = True) -> dict:
        """关空调。关的时候不带 acCtrlTemp。

        ★ poll 语义同 ac_on：命令行默认 True，手表端传 False。
        """
        data = {
            "acCtrlValue": "OFF",
            "acCtrlType": AC_TYPE_FRONT,
            "acCountdownTimer": AC_COUNTDOWN,
        }
        return self.send_command(CMD_AC, data, poll=poll, wake=wake)

    def find_car(self, wake: bool = True) -> dict:
        """寻车（不等结果 —— App 也是 fire-and-forget）。

        ★ searchType 类型坑：寻车是字符串 "0"，闪灯是整数 1，鸣笛是整数 2
        """
        return self.send_command(CMD_SEARCH, {"searchType": "0"},
                                 poll=False, wake=wake)

    def flash_light(self, wake: bool = True) -> dict:
        """闪灯（附带功能，searchType=1 整数）。"""
        return self.send_command(CMD_SEARCH, {"searchType": 1},
                                 poll=False, wake=wake)

    def whistle(self, wake: bool = True) -> dict:
        """鸣笛（附带功能，searchType=2 整数）。"""
        return self.send_command(CMD_SEARCH, {"searchType": 2},
                                 poll=False, wake=wake)
