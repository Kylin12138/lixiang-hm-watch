"""VSS 实时信号读取 —— 与 ArkTS 的 VssReader.ets 一一对应。

端点：POST /ssp-cloud-vss-service/mobile/vss/get-batch
body：{"vin": "...", "paths": ["Vehicle.Body.DoorLockStatus.MainDoor", ...]}
header：Bearer <VSS token>（scope vss:get-batch）

返回：{"items":[{"path":"...","dp":{"value":...,"tsFormat":...}}]}
"""

from __future__ import annotations

import json
from typing import Any

import requests

from lx_const import API_APP, EP_VSS_BATCH, VSS_BATCH_SIZE
from lx_signer import Signer


# ── 功能相关的信号路径 ─────────────────────────────────────────
SIG_LOCK = "Vehicle.Body.DoorLockStatus.MainDoor"          # 0=落锁 非0=解锁
SIG_AC_ON = "Vehicle.Cabin.AC.FOffStatus"                  # 1=开 0=关（官方信号）
SIG_AC_FAN = "Vehicle.Cabin.AC.ExSpeedStatus"              # 风速（备用）
SIG_AC_SET_TEMP = "Vehicle.Cabin.AC.SetTemp"
SIG_AC_INSIDE_TEMP = "Vehicle.Cabin.AC.FrtACIncarTemp"

# 手表端一次拉取的完整路径集
DEFAULT_PATHS = [
    SIG_LOCK,
    SIG_AC_ON, SIG_AC_SET_TEMP, SIG_AC_INSIDE_TEMP,
]


class VssReader:
    def __init__(self, signer: Signer, vin: str, vss_token: str,
                 timeout: int = 20, debug: bool = False) -> None:
        self.signer = signer
        self.vin = vin
        self._vss = vss_token
        self.timeout = timeout
        self.debug = debug

    def set_token(self, token: str) -> None:
        self._vss = token

    def get_batch(self, paths: list[str]) -> dict[str, Any]:
        """读取一批信号 → {path: value}。

        分批（每批 50 条）+ 失败时二分降级，避免一条坏路径拖垮整批。
        """
        out: dict[str, Any] = {}
        for i in range(0, len(paths), VSS_BATCH_SIZE):
            chunk = paths[i:i + VSS_BATCH_SIZE]
            out.update(self._get_chunk(chunk))
        return out

    def _get_chunk(self, paths: list[str], depth: int = 0) -> dict[str, Any]:
        if not paths:
            return {}
        body = json.dumps({"vin": self.vin, "paths": paths},
                          separators=(",", ":"))
        headers = self.signer.build_headers("POST", body, self._vss, self.vin)
        try:
            r = requests.post(API_APP + EP_VSS_BATCH, data=body.encode("utf-8"),
                              headers=headers, timeout=self.timeout)
        except requests.RequestException as err:
            if depth < 4 and len(paths) > 1:
                mid = len(paths) // 2
                a = self._get_chunk(paths[:mid], depth + 1)
                a.update(self._get_chunk(paths[mid:], depth + 1))
                return a
            if self.debug:
                print("  VSS 请求异常:", str(err)[:120])
            return {}

        if r.status_code != 200:
            if depth < 4 and len(paths) > 1:
                mid = len(paths) // 2
                a = self._get_chunk(paths[:mid], depth + 1)
                a.update(self._get_chunk(paths[mid:], depth + 1))
                return a
            if self.debug:
                print(f"  VSS HTTP {r.status_code}: {r.text[:200]}")
            return {}

        try:
            j = r.json()
        except json.JSONDecodeError:
            return {}

        items = j.get("items")
        if not isinstance(items, list):
            items = (j.get("data") or {}).get("items") if isinstance(j.get("data"), dict) else None
        if not isinstance(items, list):
            return {}

        out: dict[str, Any] = {}
        for it in items:
            if not isinstance(it, dict):
                continue
            path = it.get("path") or ""
            dp = it.get("dp") or {}
            if path:
                out[path] = dp.get("value")
        return out

    # ---------- 语义化读取 ----------

    def read_state(self) -> dict[str, Any]:
        """读取需要回读状态的功能。"""
        raw = self.get_batch(DEFAULT_PATHS)
        return {
            "locked": self._is_locked(raw.get(SIG_LOCK)),
            "ac_on": self._is_ac_on(raw.get(SIG_AC_ON)),
            "ac_set_temp": self._as_float(raw.get(SIG_AC_SET_TEMP)),
            "inside_temp": self._as_float(raw.get(SIG_AC_INSIDE_TEMP)),
            "_raw": raw,
        }

    @staticmethod
    def _is_locked(v: Any) -> bool | None:
        """DoorLockStatus.MainDoor: 0 = 落锁，非 0 = 解锁。"""
        if v is None:
            return None
        try:
            return int(float(v)) == 0
        except (TypeError, ValueError):
            s = str(v).strip().upper()
            if s in ("LOCKED", "LOCK", "1"):
                return True
            if s in ("UNLOCKED", "UNLOCK", "0"):
                return False
            return None

    @staticmethod
    def _is_ac_on(v: Any) -> bool | None:
        """FOffStatus: 1 = 开，0 = 关。

        ★ 与 ArkTS 侧一致：未知值返回 None（不猜）。
          以前默认当「开」，服务端若下发新枚举会被误判成已开，
          UI 显示「关空调」，用户点一下反而把空调关了。
        """
        if v is None:
            return None
        try:
            n = int(float(v))
        except (TypeError, ValueError):
            s = str(v).strip().upper()
            if s in ("ON", "TRUE", "OPEN", "RUNNING"):
                return True
            if s in ("0", "OFF", "FALSE", "NONE", "CLOSED", ""):
                return False
            return None
        if n == 1:
            return True
        if n == 0:
            return False
        return None

    @staticmethod
    def _as_int(v: Any) -> int | None:
        try:
            return int(float(v))
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _as_float(v: Any) -> float | None:
        try:
            return float(v)
        except (TypeError, ValueError):
            return None
