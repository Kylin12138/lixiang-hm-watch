# 贡献指南

感谢愿意一起把这东西做得更稳。这个项目碰的是**真车**，所以规矩比一般项目严一些。

## 提交之前

1. **先在 Python 侧验证，再改 ArkTS。**
   手表调试成本极高（装包慢、日志难抓、无断点）。协议相关的改动请先在
   `verify_tool/` 里跑通，再机械翻译到 `core/**/*.ets`。

2. **保持双轨同步。**
   `verify_tool/lx_*.py` 与 `LixiangWatch/entry/src/main/ets/core/**/*.ets` 是一一对应的：

   | Python | ArkTS |
   |---|---|
   | `lx_const.py` | `core/protocol/Constants.ets` |
   | `lx_signer.py` | `core/protocol/Signer.ets` |
   | `lx_keysuite.py` | `core/protocol/KeySuite.ets` |
   | `lx_login.py` | `core/protocol/PakeLogin.ets` + `LoginFlow.ets` |
   | `lx_token.py` | `core/protocol/TokenManager.ets` |
   | `lx_vehicle.py` | `core/control/VehicleControl.ets` |
   | `lx_vss.py` | `core/control/VssReader.ets` |

   改一边必须改另一边，否则两端行为会悄悄漂移。

3. **跑测试。**

   ```bash
   cd verify_tool && python test_offline.py     # 30 项，不联网，必须全绿
   source scripts/env.sh && lxbuild             # 必须 BUILD SUCCESSFUL 且无新增 ArkTS WARN
   ```

4. **ArkTS 严格模式不要绕过。**
   `arkts-no-spread`、`arkts-no-untyped-obj-literals` 等规则不是麻烦，是防止运行时踩坑。
   遇到必须绕的写法，请在 PR 里说明原因。

## 绝对不要提交的东西

| 路径 | 原因 |
|---|---|
| `verify_tool/cred.json` | 含 refresh_token / bearer / hac_key，等同车辆控制权 |
| `LixiangWatch/signature/**`（`README.md` 除外） | 证书与 Profile，等同应用身份 |
| `scripts/local.env` | 本机路径、内网 IP |
| `build-profile.json5` 里回填的 `signingConfigs` | 同上 |

提交前自查：

```bash
git diff --cached | grep -inE "password|token|bearer|hac_key|phone|1[3-9][0-9]{9}"
```

## 真车测试的边界

- **不要**为了验证顺手对别人的车或自己日常用车反复下发指令；
- 测试优先用 `lock` / `unlock`（可逆、可观察），**不要**随意触发鸣笛/寻车；
- 连续调用官方接口可能触发风控，请控制频率，两次调用至少间隔数秒；
- 如果你在 PR 里贴日志，请先删掉 VIN、车牌、手机号、device_id、token。

## UI 原则

界面只出现普通用户能看懂的话。**不要**把算法名、阶段名、错误原文、自检状态、
能力探测结果放进界面 —— 这些只写 `hilog`。面向用户的兜底文案是「请稍后重试」，
不要把服务端返回的原文回吐给用户。

## PR 流程

1. Fork → 开分支（`fix/xxx` 或 `feat/xxx`）；
2. 一个 PR 只做一件事，附带「改了什么 / 为什么 / 怎么验证的」；
3. 涉及协议的改动，请贴出 Python 侧与 ArkTS 侧的对拍结果；
4. 涉及界面的改动，请附手表截图（466×466）。

## Issue 模板

请尽量包含：

- 手表型号与 HarmonyOS 版本
- 应用版本（`AppScope/app.json5` 里的 `versionName`）
- 复现步骤
- `hilog` 里 `LixiangWatch:` 开头的相关日志（**已脱敏**）
- 期望行为与实际行为

## 许可证

提交代码即表示同意以 [MIT](LICENSE) 许可证发布你的贡献。
