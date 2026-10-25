"""离线集成测试 —— 不联网，用 mock 验证全链路数据流。

验证点：
  · 签名头完整且 11 段构造正确
  · cmd/send 的 body 结构（jobExpire 长短命令分级）
  · 4 个功能的 cmdKey/cmdData 类型正确
  · 响应解析（pushState 5/7、resultCode 特判、超时）
  · VSS 响应解析
"""

from __future__ import annotations

import json
import sys
import unittest
from unittest import mock

sys.path.insert(0, ".")

from lx_const import (  # noqa: E402
    CMD_LOCK, CMD_AUTH, CMD_AC, CMD_SEARCH,
    CMD_EXPIRE, LONG_CMD_EXPIRE, PUSH_STATE_SUCCESS, PUSH_STATE_FAILED,
)
from lx_signer import Signer, build_string_to_sign, content_md5, EMPTY_MD5  # noqa: E402
from lx_vehicle import VehicleControl, LiCommandError  # noqa: E402
from lx_vss import VssReader, SIG_LOCK, SIG_AC_ON, SIG_AC_SET_TEMP  # noqa: E402


class TestSigner(unittest.TestCase):

    def setUp(self):
        self.sg = Signer(bytes(range(32)), "kid", "dev", "tok")

    def test_string_to_sign_has_11_segments(self):
        sts = build_string_to_sign("kid", "dev", "POST", "md5", "123", "n")
        # 11 段 join 产生 10 个分隔符，末尾再补 1 个 = 11 个 \n
        self.assertTrue(sts.endswith("\n"))
        self.assertEqual(sts.count("\n"), 11)
        segs = sts.split("\n")
        self.assertEqual(len(segs), 12)          # 11 段 + 末尾空串
        self.assertEqual(segs[-1], "")           # 最后一段是空的
        self.assertEqual(segs[0], "prod")
        self.assertEqual(segs[4], "POST")
        self.assertEqual(segs[10], "n")          # 第 11 段是 nonce

    def test_method_uppercased(self):
        sts = build_string_to_sign("kid", "dev", "post", "md5", "123", "n")
        self.assertEqual(sts.split("\n")[4], "POST")

    def test_empty_body_md5(self):
        self.assertEqual(content_md5(""), EMPTY_MD5)

    def test_headers_complete(self):
        h = self.sg.build_headers("POST", '{"a":1}', "bearer_x", "VIN123")
        required = [
            "X-CHJ-Env", "X-CHJ-APP-Version", "X-CHJ-Key", "X-CHJ-Deviceid",
            "X-CHJ-Timestamp", "X-CHJ-Nonce", "X-CHJ-Sign", "Content-MD5",
            "Content-Type", "Content-Language", "Accept", "X-CHJ-Version",
            "X-CHJ-DeviceType", "X-CHJ-ModelName", "X-CHJ-Tag", "X-CHJ-TOKEN",
            "Authorization", "User-Agent", "X-CHJ-VIN",
        ]
        for k in required:
            self.assertIn(k, h, f"缺少请求头 {k}")
        self.assertEqual(h["Authorization"], "Bearer bearer_x")
        self.assertEqual(h["X-CHJ-VIN"], "VIN123")
        self.assertEqual(h["Content-MD5"], content_md5('{"a":1}'))

    def test_vin_omitted_when_empty(self):
        h = self.sg.build_headers("POST", "", "b", "")
        self.assertNotIn("X-CHJ-VIN", h)

    def test_hex_and_bytes_key_equivalent(self):
        a = self.sg.sign_request("POST", "x", "1", "n")["sign"]
        b = Signer(bytes(range(32)).hex(), "kid", "dev").sign_request(
            "POST", "x", "1", "n")["sign"]
        self.assertEqual(a, b)


class TestVehicleControlBody(unittest.TestCase):
    """用 mock 拦截 _signed_call，检查 body 构造。"""

    def setUp(self):
        signer = Signer(bytes(range(32)), "kid", "dev", "tok")
        self.vc = VehicleControl(signer, "VIN_TEST", "mesh_tok", "vat_tok")
        self.captured = []

    def _fake_call(self, method, path, body, bearer):
        self.captured.append({"method": method, "path": path,
                              "body": body, "bearer": bearer})
        if path.endswith("cmd/send"):
            return {"requestId": "req_123", "resultCode": 0}
        if "cmd-result" in path:
            return {"pushState": PUSH_STATE_SUCCESS, "resultCode": 0}
        return {"code": 0}

    def test_short_command_job_expire_30(self):
        with mock.patch.object(self.vc, "_signed_call", self._fake_call):
            self.vc.send_command(CMD_LOCK, {"lockSw": "1"}, wake=False)
        send = [c for c in self.captured if c["path"].endswith("cmd/send")][0]
        b = json.loads(send["body"])
        self.assertEqual(b["jobExpire"], CMD_EXPIRE)
        self.assertEqual(b["expire"], CMD_EXPIRE)
        self.assertEqual(b["domain"], "xcu")
        self.assertEqual(b["cmdKey"], CMD_LOCK)
        self.assertEqual(b["token"], "vat_tok")
        self.assertEqual(send["bearer"], "mesh_tok")
        self.assertEqual(b["vin"], "VIN_TEST")

    def test_aircon_job_expire_900(self):
        with mock.patch.object(self.vc, "_signed_call", self._fake_call):
            self.vc.send_command(CMD_AC, {"acCtrlValue": "ON"}, wake=False)
        send = [c for c in self.captured if c["path"].endswith("cmd/send")][0]
        b = json.loads(send["body"])
        self.assertEqual(b["jobExpire"], LONG_CMD_EXPIRE)

    def test_expire_at_is_future_ms(self):
        import time
        with mock.patch.object(self.vc, "_signed_call", self._fake_call):
            self.vc.lock(wake=False)
        send = [c for c in self.captured if c["path"].endswith("cmd/send")][0]
        b = json.loads(send["body"])
        self.assertGreater(b["expireAt"], int(time.time() * 1000))


class TestFourFeatures(unittest.TestCase):
    """四个功能的 cmdKey / cmdData 精确性。"""

    def setUp(self):
        signer = Signer(bytes(range(32)), "kid", "dev", "tok")
        self.vc = VehicleControl(signer, "VIN_TEST", "m", "v")
        self.bodies = []

    def _capture(self, method, path, body, bearer):
        if path.endswith("cmd/send"):
            self.bodies.append(json.loads(body))
            return {"requestId": "r", "resultCode": 0}
        if "cmd-result" in path:
            return {"pushState": PUSH_STATE_SUCCESS, "resultCode": 0}
        return {}

    def test_unlock(self):
        with mock.patch.object(self.vc, "_signed_call", self._capture):
            self.vc.unlock()
        b = self.bodies[-1]
        self.assertEqual(b["cmdKey"], "remoteVehLockControl")
        self.assertEqual(b["cmdData"], {"lockSw": "1"})

    def test_lock(self):
        with mock.patch.object(self.vc, "_signed_call", self._capture):
            self.vc.lock()
        b = self.bodies[-1]
        self.assertEqual(b["cmdData"], {"lockSw": "0"})

    def test_auth_drive_empty_data(self):
        """授权驾驶：cmdKey=remoteVehAuth，cmdData 必须是空对象。"""
        with mock.patch.object(self.vc, "_signed_call", self._capture):
            self.vc.auth_drive()
        b = self.bodies[-1]
        self.assertEqual(b["cmdKey"], "remoteVehAuth")
        self.assertEqual(b["cmdData"], {})
        # ★ 空 cmdData 走短命令有效期（不是 LONG_RUNNING_CMD_KEYS）
        self.assertEqual(b["jobExpire"], CMD_EXPIRE)

    def test_ac_on_temp_is_number(self):
        with mock.patch.object(self.vc, "_signed_call", self._capture):
            self.vc.ac_on(26)
        b = self.bodies[-1]
        self.assertEqual(b["cmdKey"], "remoteVehACSmartControl")
        self.assertEqual(b["cmdData"]["acCtrlValue"], "ON")
        self.assertEqual(b["cmdData"]["acCtrlType"], "frtACSw")
        self.assertEqual(b["cmdData"]["acCountdownTimer"], "15")
        # ★ 关键：acCtrlTemp 必须是 Number
        self.assertIsInstance(b["cmdData"]["acCtrlTemp"], (int, float),
                              "acCtrlTemp 必须是数字，不能是字符串")
        self.assertEqual(b["cmdData"]["acCtrlTemp"], 26)
        # 其他三个必须是字符串
        for k in ("acCtrlValue", "acCtrlType", "acCountdownTimer"):
            self.assertIsInstance(b["cmdData"][k], str, f"{k} 必须是字符串")

    def test_ac_off_no_temp(self):
        with mock.patch.object(self.vc, "_signed_call", self._capture):
            self.vc.ac_off()
        b = self.bodies[-1]
        self.assertEqual(b["cmdData"]["acCtrlValue"], "OFF")
        self.assertNotIn("acCtrlTemp", b["cmdData"])

    def test_ac_temp_clamped_to_16_28(self):
        """L6 Max 范围 16-28，超范围要夹紧。"""
        with mock.patch.object(self.vc, "_signed_call", self._capture):
            self.vc.ac_on(35)
        self.assertEqual(self.bodies[-1]["cmdData"]["acCtrlTemp"], 28)
        with mock.patch.object(self.vc, "_signed_call", self._capture):
            self.vc.ac_on(5)
        self.assertEqual(self.bodies[-1]["cmdData"]["acCtrlTemp"], 16)

    def test_find_car_search_type_is_string(self):
        with mock.patch.object(self.vc, "_signed_call", self._capture):
            self.vc.find_car()
        b = self.bodies[-1]
        self.assertEqual(b["cmdKey"], "remoteVehSearch")
        self.assertEqual(b["cmdData"], {"searchType": "0"})
        self.assertIsInstance(b["cmdData"]["searchType"], str)

    def test_flash_whistle_are_int(self):
        """闪灯/鸣笛的 searchType 是整数 —— 类型不一致是已知坑。"""
        with mock.patch.object(self.vc, "_signed_call", self._capture):
            self.vc.flash_light()
            self.vc.whistle()
        self.assertEqual(self.bodies[-2]["cmdData"], {"searchType": 1})
        self.assertEqual(self.bodies[-1]["cmdData"], {"searchType": 2})
        self.assertIsInstance(self.bodies[-2]["cmdData"]["searchType"], int)

    def test_find_car_does_not_poll(self):
        calls = []

        def _cap(method, path, body, bearer):
            calls.append(path)
            if path.endswith("cmd/send"):
                return {"requestId": "r", "resultCode": 0}
            return {}

        with mock.patch.object(self.vc, "_signed_call", _cap):
            r = self.vc.find_car()
        self.assertTrue(r["ok"])
        self.assertFalse(any("cmd-result" in c for c in calls),
                         "寻车不应轮询结果")


class TestResultHandling(unittest.TestCase):

    def setUp(self):
        signer = Signer(bytes(range(32)), "kid", "dev", "tok")
        self.vc = VehicleControl(signer, "VIN", "m", "v")

    def _mk(self, send_resp, poll_resp):
        def _call(method, path, body, bearer):
            if path.endswith("cmd/send"):
                return send_resp
            if "cmd-result" in path:
                return poll_resp
            return {}
        return _call

    def test_success(self):
        with mock.patch.object(self.vc, "_signed_call",
                               self._mk({"requestId": "r", "resultCode": 0},
                                        {"pushState": 5, "resultCode": 0})):
            r = self.vc.lock(wake=False)
        self.assertTrue(r["ok"])
        self.assertEqual(r["pushState"], 5)

    def test_failure_raises(self):
        with mock.patch.object(self.vc, "_signed_call",
                               self._mk({"requestId": "r", "resultCode": 0},
                                        {"pushState": 7, "resultCode": "-2",
                                         "resultMsg": "执行失败"})):
            with self.assertRaises(LiCommandError) as cm:
                self.vc.lock(wake=False)
        self.assertIn("pushState=7", str(cm.exception))

    def test_pushstate7_but_success_code_is_ok(self):
        """pushState=7 但 resultCode=-15（倒计时完成）→ 视为成功。"""
        with mock.patch.object(self.vc, "_signed_call",
                               self._mk({"requestId": "r", "resultCode": 0},
                                        {"pushState": 7, "resultCode": "-15"})):
            r = self.vc.ac_on(26, poll=True)
        self.assertTrue(r["ok"])

    def test_timeout_not_error(self):
        """轮询超时（未到终态）不应抛错 —— 命令可能已生效。"""
        with mock.patch.object(self.vc, "_signed_call",
                               self._mk({"requestId": "r", "resultCode": 0},
                                        {"pushState": 1})):
            r = self.vc.send_command("remoteVehLockControl", {"lockSw": "0"},
                                     wake=False, timeout=0.1, poll_interval=0.05)
        self.assertTrue(r["ok"])
        self.assertTrue(r.get("timeout"))

    def test_rejected_at_send(self):
        with mock.patch.object(self.vc, "_signed_call",
                               self._mk({"resultCode": 2009}, {})):
            with self.assertRaises(LiCommandError) as cm:
                self.vc.lock(wake=False)
            self.assertIn("命令下发被拒", str(cm.exception))

    def test_no_request_id_raises(self):
        with mock.patch.object(self.vc, "_signed_call",
                               self._mk({"resultCode": 0}, {})):
            with self.assertRaises(LiCommandError):
                self.vc.lock(wake=False)

    def test_job_channel_hint(self):
        with mock.patch.object(self.vc, "_signed_call",
                               self._mk({"requestId": "r", "resultCode": 0},
                                        {"pushState": 7, "resultCode": "2009"})):
            with self.assertRaises(LiCommandError) as cm:
                self.vc.send_command("remote_charge_control", {}, wake=False)
        self.assertIn("JOB", str(cm.exception))


class TestVss(unittest.TestCase):

    def setUp(self):
        signer = Signer(bytes(range(32)), "kid", "dev", "tok")
        self.vr = VssReader(signer, "VIN", "vss_tok")

    def test_parse_items(self):
        resp = {"items": [
            {"path": SIG_LOCK, "dp": {"value": 0}},
            {"path": SIG_AC_SET_TEMP, "dp": {"value": "22"}},
            {"path": SIG_AC_ON, "dp": {"value": 1}},
        ]}
        with mock.patch("requests.post") as m:
            m.return_value.status_code = 200
            m.return_value.json.return_value = resp
            out = self.vr.get_batch([SIG_LOCK, SIG_AC_SET_TEMP, SIG_AC_ON])
        self.assertEqual(out[SIG_LOCK], 0)
        self.assertEqual(out[SIG_AC_SET_TEMP], "22")

    def test_lock_semantics(self):
        self.assertTrue(VssReader._is_locked(0))       # 0 = 落锁
        self.assertFalse(VssReader._is_locked(1))      # 非0 = 解锁
        self.assertTrue(VssReader._is_locked("LOCKED"))
        self.assertFalse(VssReader._is_locked("UNLOCKED"))
        self.assertIsNone(VssReader._is_locked(None))

    def test_ac_semantics_foffstatus(self):
        """FOffStatus: 1=开 0=关（不是风速那个信号）。"""
        self.assertTrue(VssReader._is_ac_on(1))
        self.assertFalse(VssReader._is_ac_on(0))
        self.assertFalse(VssReader._is_ac_on("0"))
        self.assertIsNone(VssReader._is_ac_on(None))

    def test_read_state_full(self):
        resp = {"items": [
            {"path": SIG_LOCK, "dp": {"value": 0}},
            {"path": SIG_AC_SET_TEMP, "dp": {"value": 22}},
            {"path": SIG_AC_ON, "dp": {"value": 1}},
        ]}
        with mock.patch("requests.post") as m:
            m.return_value.status_code = 200
            m.return_value.json.return_value = resp
            st = self.vr.read_state()
        self.assertTrue(st["locked"])
        self.assertEqual(st["ac_set_temp"], 22.0)
        self.assertTrue(st["ac_on"])

    def test_bisect_on_failure(self):
        """整批失败时应二分降级，而不是全丢。"""
        calls = {"n": 0}

        def _fake_post(url, data=None, headers=None, timeout=None):
            calls["n"] += 1
            body = json.loads(data.decode())
            paths = body["paths"]
            r = mock.Mock()
            if len(paths) > 1:
                r.status_code = 400          # 整批失败 → 触发二分
                r.json.return_value = {}
                return r
            r.status_code = 200
            r.json.return_value = {"items": [
                {"path": paths[0], "dp": {"value": 42}}]}
            return r

        with mock.patch("requests.post", _fake_post):
            out = self.vr.get_batch(["p1", "p2", "p3", "p4"])
        self.assertEqual(len(out), 4, "二分降级后应救回全部 4 条")
        self.assertGreater(calls["n"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
