# 理想汽车协议验证工具

在电脑上验证完整协议链路，跑通后再移植到手表端。
参考实现：[C3H3-AI/ha-lixiang](https://github.com/C3H3-AI/ha-lixiang)

---

## 为什么先做这个

手表端调试成本极高（装包慢、日志难抓、无断点）。
这份工具用 Python 把**完全相同的协议**在电脑上先跑通，
验证签名、身份派生、车控命令的参数是否与服务端匹配。
跑通之后 ArkTS 是机械翻译，出问题的概率大幅降低。

---

## 环境

```bash
# 已经建好的虚拟环境
<本地路径>

# 依赖（已装）：cryptography / bcrypt / pynacl / requests
```

## 使用顺序

```bash
cd verify_tool

# ① 自检（不联网，先确认环境没问题）
python lx_main.py doctor

# ② 登录 —— 首次需要手机浏览器辅助
python lx_main.py login --phone 138xxxxxxxx
#    首次会打印一个浏览器链接，在【手机浏览器】里打开，
#    完成滑动验证 + 短信验证码。之后同一 device_id 免验证。

# ③ 派生签名身份（keySuite）
python lx_main.py derive

# ④ 拉车辆列表，确认 VIN
python lx_main.py vehicles

# ⑤ 只读状态（安全，不改车）
python lx_main.py status --raw

# ⑥ 下发命令（真车会动！）
python lx_main.py cmd unlock          # 解锁
python lx_main.py cmd lock            # 落锁
python lx_main.py cmd auth            # 授权驾驶
python lx_main.py cmd ac on --temp 26 # 开空调 26℃
python lx_main.py cmd ac off          # 关空调
python lx_main.py cmd find            # 寻车
```

加 `--debug` 可看完整请求/响应。

---

## 模块对应关系

每个 Python 模块都有一个 ArkTS 孪生文件，两边常量必须同步：

| Python（验证工具） | ArkTS（手表端） | 职责 |
|---|---|---|
| `lx_const.py` | `core/protocol/Constants.ets` | 所有常量（唯一权威表） |
| `lx_signer.py` | `core/protocol/Signer.ets` | x-chj 签名 |
| `lx_keysuite.py` | `core/protocol/KeySuite.ets` | 身份派生 |
| `lx_login.py` | `core/protocol/PakeLogin.ets` | PAKE 登录 |
| `lx_token.py` | `core/protocol/TokenManager.ets` | token 换取 |
| `lx_vehicle.py` | `core/control/VehicleControl.ets` | 车控通道 |
| `lx_vss.py` | `core/control/VssReader.ets` | 状态读取 |
| `lx_main.py` | （无，仅验证用） | CLI 入口 |

---

## 四个功能对应的命令参数

| 功能 | cmdKey | cmdData | jobExpire |
|---|---|---|---|
| 解锁 | `remoteVehLockControl` | `{"lockSw":"1"}` | 30 |
| 落锁 | `remoteVehLockControl` | `{"lockSw":"0"}` | 30 |
| 授权驾驶 | `remoteVehAuth` | `{}`（空对象，不能省） | 30 |
| 开空调 | `remoteVehACSmartControl` | `{"acCtrlValue":"ON","acCtrlType":"frtACSw","acCountdownTimer":"15","acCtrlTemp":26}` | **900** |
| 关空调 | `remoteVehACSmartControl` | 同上但 `"OFF"`，无 `acCtrlTemp` | **900** |
| 寻车 | `remoteVehSearch` | `{"searchType":"0"}` | 30（不轮询） |

### 已记录的坑

1. **`acCtrlTemp` 必须是 Number**，其余三个字段必须是 String
2. **空调是长命令**，`jobExpire=30` 会超时（`ps=7 rc=空`），必须 900
3. **`searchType` 类型不一致**：寻车 `"0"` 字符串，闪灯 `1` / 鸣笛 `2` 整数
4. **L6 Max 温度范围 16–28℃**（不是通用文档写的 16–30）
5. **HMAC key 必须是原始 32 字节**，用 base64 文本 encode 会 100005
6. **签名 11 段末尾必须补 `\n`**
7. **keySuite 的 X-CHJ-Sign 用 hexdigest**，业务接口用 base64——两者不同

---

## 凭据文件

登录后凭据存到 `cred.json`（明文）。
**这个文件等同于你的车辆控制权，不要提交到 git、不要外发。**

字段：`device_id` / `phone` / `main_bearer` / `refresh_token` /
`hac_key` / `key_id` / `vin` / `vehicle_name`

手表端会用系统级加密存储替代这个文件。

---

## 排错

| 现象 | 含义 | 处理 |
|---|---|---|
| `code=100005` | 签名错误 | 检查 hac_key 是否原始字节、11 段是否补了 `\n` |
| `code=2009` | 命令走 JOB 通道 | 该命令 HTTP 不可达，本工具不支持 |
| `code=100035` | 服务暂时不可用 | 拿错了平台表（X 系调了 M 系端点） |
| `code=100012` | 无接口权限 | 同上，老平台 App API |
| `require=SMS_CODE` | 设备未受信任 | 走手机浏览器辅助登录 |
| `pushState=7` 但 `rc=0/-8/-15` | 实际成功 | 倒计时到期的特判 |
| 轮询超时 `pushState=1` | 未到终态 | 命令可能已生效，查状态确认 |
