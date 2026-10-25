# 理想汽车鸿蒙手表端车控 App（Lixiang HM Watch）—— 开发手记

> **项目名称**：理想汽车鸿蒙手表端车控 App（`Lixiang HM Watch`，仓库 `lixiang-hm-watch`）
> **定位**：为 **HarmonyOS 7 手表端**（`wearable`，API 26）开发的原生车控应用
> **适用设备**：华为 Watch 6（466×466 圆屏，NIZ-AL00）实机验证；其他圆屏机型未验证
> 功能：① 解闭车锁 ② 授权驾驶 ③ 开关空调 ④ 寻车
> 车型：理想 L6 Max
> 参考：[C3H3-AI/ha-lixiang](https://github.com/C3H3-AI/ha-lixiang)

---

## 一、当前进度

| 部分 | 状态 | 说明 |
|---|---|---|
| 协议逆向梳理 | ✅ 完成 | 登录/签名/身份派生/双 token/车控/VSS 全部理清 |
| Python 验证工具 | ✅ 完成 | 31 个离线测试全通过 |
| DevEco 工程骨架 | ✅ 完成 | 可打开、可编译的结构 |
| ArkTS 协议层 | ✅ 完成 | Constants/Signer/KeySuite/TokenManager（**已含 cookie 传递**） |
| ArkTS 车控层 | ✅ 完成 | VehicleControl（4 功能）/VssReader |
| ArkTS UI | ✅ 完成 | 主界面 + 状态显示 + 错误提示 + **登录页** |
| ArkTS 登录层 | ✅ 完成 | `PakeLogin.ets`（含 CookieJar）+ `LoginFlow.ets`（编排） |
| ArkTS bcrypt | ✅ 完成 | `crypto/Bcrypt.ets` 纯 ArkTS 移植，**自检通过**（见 §7.2） |
| **纯 ArkTS 密码学层** | ✅ **已完成** | `core/crypto/pure/` 五个原语（SHA/HMAC/AES/RSA/Ed25519），**413 项独立断言全通过**，与 Python 逐字节一致 |
| **双通道自动降级** | ✅ **已完成** | 桩环境自动切纯实现；`HarmonyCrypto.ets` 统一封装 + 运行时探测 |
| **ArkTS 编译** | ✅ **已完成** | **`lxbuild` BUILD SUCCESSFUL，signed HAP 656 KB**（2026-10-16 12:13） |
| **真车验证** | ✅ **已完成** | **解锁 + 落锁实测成功（2026-10-14 00:32）** |
| **Previewer 启动** | ✅ 已打通 | Wearable 通道跑起来了，参数 `-cr/-or 466*466`、`deviceType: wearable`（见 §6.3.3） |
| **Previewer 跑协议** | ✅ **已解决** | 原本因 crypto 桩实现跑不通；现已由**双通道降级**修复，离线冒烟 **53/0**（见 §6.3.4） |
| **真机 Watch 6 装机** | ✅ **已完成** | 装机运行，据此定位并修复七/八/九号坑（见 §6.3.6b） |
| **ArkTS 端到端真实验证** | ✅ **已通过** | 用应用真实代码直连真实服务端：登录 ✅ → 换 MESH/VAT/VSS token ✅ → 读车辆状态 ✅ |
| 手表端 4 功能实测 | ✅ **已通过** | 解闭锁 / 授权驾驶 / 寻车已在真机实测；空调待点（见 §7.2） |

### ★ 真车验证结果

```
VIN:   <VIN-已脱敏>   车牌: <车牌-已脱敏>   车型: 理想L6 Max
角色:  authorized (vehicleRoleId=15)

PAKE 登录        ✅
keySuite 派生    ✅  hac_key 32 字节
车辆列表         ✅
VSS 实时状态     ✅  8 个信号全命中
MESH/VAT token   ✅
cmd/send 轮询    ✅  pushState 1→5, resultCode 0
真车解锁         ✅  MainDoor 0→1，耗时 1.5s
真车落锁         ✅  MainDoor 1→0，耗时 0.54s
```

---

## 二、目录结构

```
LixiangWatch/                      ← DevEco 工程（用 DevEco Studio 打开）
├── AppScope/                      应用级配置
├── entry/src/main/
│   ├── module.json5               模块配置（deviceTypes: wearable）
│   ├── ets/
│   │   ├── entryability/          应用入口
│   │   ├── pages/Index.ets        ★ 主界面（4 个功能）
│   │   ├── common/AppState.ets    凭据管理 + 客户端装配
│   │   └── core/
│   │       ├── protocol/          ★ 协议层
│   │       │   ├── Constants.ets  所有常量（唯一权威表）
│   │       │   ├── Signer.ets     x-chj 签名
│   │       │   ├── KeySuite.ets   身份派生
│   │       │   └── TokenManager.ets  token 换取
│   │       ├── crypto/
│   │       │   ├── Codec.ets      base64/hex/utf8
│   │       │   ├── Bcrypt.ets     纯 ArkTS bcrypt（框架不提供）
│   │       │   ├── HarmonyCrypto.ets  ★ 双通道封装 + 能力探测
│   │       │   └── pure/          ★ 纯 ArkTS 密码学（不依赖 cryptoFramework）
│   │       │       ├── Sha.ets      SHA-256 / SHA-512 / MD5
│   │       │       ├── Hmac.ets     HMAC-SHA256/512 + HKDF
│   │       │       ├── Aes.ets      AES-256-CTR
│   │       │       ├── Rsa.ets      RSA-2048 PKCS#1 v1.5
│   │       │       └── Ed25519.ets  RFC 8032 签名
│   │       └── control/
│   │           ├── VehicleControl.ets  ★ 4 个功能
│   │           └── VssReader.ets       状态读取
│   └── resources/                 资源（字符串/颜色/图标）
└── verify_tool/                   验证工具（项目根，与工程平级）
    ├── lx_const.py                常量（与 Constants.ets 对应）
    ├── lx_signer.py               签名
    ├── lx_keysuite.py             身份派生
    ├── lx_login.py                PAKE 登录
    ├── lx_token.py                token 换取
    ├── lx_vehicle.py              ★ 4 个功能
    ├── lx_vss.py                  状态读取
    ├── lx_main.py                 CLI 入口
    └── test_offline.py            31 个离线测试
```

---

## 三、Python 与 ArkTS 的对应关系

每改一处协议，**两边必须同步**：

| Python | ArkTS | 状态 |
|---|---|---|
| `lx_const.py` | `Constants.ets` | ✅ 已同步 |
| `lx_signer.py` | `Signer.ets` | ✅ 已同步 |
| `lx_keysuite.py` | `KeySuite.ets` | ✅ 已同步 |
| `lx_token.py` | `TokenManager.ets` | ✅ 已同步 |
| `lx_vehicle.py` | `VehicleControl.ets` | ✅ 已同步 |
| `lx_vss.py` | `VssReader.ets` | ✅ 已同步 |
| `lx_login.py` | `PakeLogin.ets` | ⏳ ArkTS 侧待写 |

---

## 四、四个功能的命令参数（已核对）

| 功能 | cmdKey | cmdData | jobExpire |
|---|---|---|---|
| 解锁 | `remoteVehLockControl` | `{"lockSw":"1"}` | 30 |
| 落锁 | `remoteVehLockControl` | `{"lockSw":"0"}` | 30 |
| 授权驾驶 | `remoteVehAuth` | `{}`（空对象，不能省） | 30 |
| 开空调 | `remoteVehACSmartControl` | `{"acCtrlValue":"ON","acCtrlType":"frtACSw","acCountdownTimer":"15","acCtrlTemp":26}` | **900** |
| 关空调 | `remoteVehACSmartControl` | 同上 `"OFF"`，无 `acCtrlTemp` | **900** |
| 寻车 | `remoteVehSearch` | `{"searchType":"0"}` | 30（不轮询） |

---

## 五、已踩过的坑（全部已规避）

### ★★ 0 号坑（真车验证才发现，最致命）

**换 scope token 必须带登录态 cookie，否则恒返 `login_required`。**

```
POST https://id.lixiang.com/api/auth
  Authorization: Bearer <main_bearer>     ← 有效也不行！
  Cookie: sso_token=...; isapp=1; ...     ← ★ 缺这行就失败
→ 302  https://account.lixiang.com/app-auth?error=login_required
```

- 服务端 Set-Cookie 把 `sso_token` 的域设成 `id.lixiang.com`
- 换 token 时会**校验登录会话** → 不带 cookie 一律 `login_required`
- App 的做法（`util/e.smali:1143`）是注入到父域 `.lixiang.com`
- 参考项目 `li_api.py` 第 6 行早有记载（第一版实现漏掉了）

**修复位置**：
- Python：`lx_login.sync_parent_domain_cookies()`（login 后自动调）
  + `lx_token.TokenManager(cookies=...)`
- ArkTS：`TokenManager.ets` 的 `setCookies()` + `exchange()` 里的 `Cookie` 头
  + `AppState.ets` 的 `K_SESSION_COOKIES` 持久化

### 其他坑

1. **`acCtrlTemp` 必须是 Number**，`acCtrlValue`/`acCtrlType`/`acCountdownTimer` 必须是 String
2. **空调是长命令**，`jobExpire=30` 会超时（`ps=7 rc=空`），必须 900
3. **`searchType` 类型不一致**：寻车 `"0"` 字符串，闪灯 `1` / 鸣笛 `2` 整数
4. **L6 Max 温度范围 16–28℃**（不是通用文档的 16–30）
5. **HMAC key 必须是原始 32 字节**，用 base64 文本 encode() 会 100005
6. **签名 11 段末尾必须补 `\n`**
7. **keySuite 的 X-CHJ-Sign 用 hexdigest**，业务接口用 base64 —— 两者不同
8. **keySuite 签名第 3 段是 bootHac[:32]**，第 11 段是 `nonce.upper()+ts`
9. **VAT scope 按需最小化**：多请求没用的 scope 会导致服务端整批降级
10. **`pushState=7` 但 `rc ∈ {0,-8,-15}`** → 实际成功（倒计时到期）
11. **轮询超时不报错**：`pushState=1` 时命令可能已生效，报错会让用户重复点击
12. **空调状态用 `FOffStatus`**，不是 `ExSpeedStatus`（后者远程开空调时恒为 0）
13. **车辆列表接口也要 x-chj 签名头** ★（真车验证发现）
    `/saos-vehicle-api/v2-0/vehicles/basics` 不带签名返回
    `code:100002 缺少必要的请求参数: X-CHJ-Env,X-CHJ-Version,...`
    —— 参考项目的 `list_vehicles` 走的是另一条无签名路径

---

## 六、下一步

### 6.1 立即可以做的（不需要账号）

```bash
cd verify_tool
python lx_main.py doctor          # 环境自检，应该全通过
python test_offline.py            # 31 个测试，应该全 OK
```

### 6.2 真车验证 ✅ 已完成

```bash
# ① 登录（首次需手机浏览器完成滑动+短信建立设备信任）
python lx_main.py login --phone <手机号-已脱敏>

# ② 派生身份
python lx_main.py derive

# ③ 确认 VIN
python lx_main.py vehicles

# ④ 只读状态（安全）
python lx_main.py status --raw

# ⑤ 功能验证（车会动！）
python lx_main.py cmd unlock      ✅ 已验证
python lx_main.py cmd lock        ✅ 已验证
python lx_main.py cmd windows open        ⏳ 未验证（用户约束）
python lx_main.py cmd windows close       ⏳ 未验证
python lx_main.py cmd ac on --temp 26     ⏳ 未验证
python lx_main.py cmd ac off              ⏳ 未验证
python lx_main.py cmd find                ⏳ 未验证
```

### 6.3 还剩的事

1. ~~补写 `PakeLogin.ets`~~ ✅ 已完成（含 CookieJar 与父域同步）
2. ~~纯 ArkTS bcrypt~~ ✅ 已完成，`bcryptSelftest()` 通过
3. ~~命令行编译通过~~ ✅ 已完成，`assembleHap` BUILD SUCCESSFUL
4. **用 DevEco Studio 配置签名证书**（`build-profile.json5` 的
   `signingConfigs` 为空，现在产出的是 `entry-default-unsigned.hap`）← 下一步
5. 连接手表，编译安装
6. 手表上验证 4 个功能
7. （可选，需授权）验证 windows / ac / find 三个未测功能

### 6.3.1 命令行构建（已验证可用）

```bash
cd LixiangWatch
source ../scripts/env.sh     # 设 DEVECO_SDK_HOME / JAVA_HOME / PATH
lxbuild                      # = hvigor assembleHap --mode module -p product=default
lxhap                        # 打印 HAP 路径
```

产物：`entry/build/default/outputs/default/entry-default-unsigned.hap`
（接入纯实现后 **588 KB**，此前 452 KB —— 差值就是 `core/crypto/pure/`）

**★ `lxbuild` 必须在前台跑**：后台 subshell 里 `source env.sh` 会让
java 的 `spawn` 失败（`00308018`，exit=127）。

**★ 两个必需的环境变量**（缺任一个都失败）：

| 变量 | 缺了会怎样 | 值 |
|---|---|---|
| `DEVECO_SDK_HOME` | `00303217 Configuration Error` | `<DevEco>/sdk` |
| `JAVA_HOME` + PATH | `00308018 / spawn java ENOENT` | `<DevEco>/jbr`（**PATH 要加 POSIX 路径 `/c/...`**） |

### 6.3.2 电脑端模拟 —— 模拟器不可用，Previewer 可用 ⚠️

实测结论（2026-10-14）：

- **模拟器无法用**：
  `%LOCALAPPDATA%\Huawei\Emulator\deployed\lists.json` 里只有
  `foldable / tablet / phone / 2in1` 四类，**没有 wearable**；
  且 `system-image/` 目录与 `.img` 文件**都未下载**（实例只是占位配置）。
  → 想在模拟器里跑手表 UI 不可行。
- **可行的替代**：直接在 DevEco Studio 里点「Previewer」——
  IDE 自己会生成 `entry/.preview/` 并传正确参数。
  协议层已做**双通道降级**（见 6.3.4），Previewer 里现在能完整跑登录。
  或把 `module.json5` 的 `deviceTypes` 临时改成 `phone`，
  装到已有的 phone 模拟器上验证业务逻辑（前提是先下载镜像）。
- **不依赖二者的离线验证**：`node run_all.js`（见 6.3.6）。

### 6.3.3 Previewer 启动参数（已实测打通）✅

从 IDE 日志 `%LOCALAPPDATA%\Huawei\DevEcoStudio26.0\log\idea.log` 探明：

```
launchJsEngineArgs: {"-n":"entry", ..., "deviceResolution":"466*466"}
globalArgs: {"deviceType":"wearable", "sdkVersion":"26.0.0.105", "apiVersion":"26.0.0"}
```

**关键点：`-cr/-or`（分辨率）的格式是 `466*466`**（星号分隔），
不是逗号、x、冒号 —— 之前四种写法全报
`Launch -or/-cr or -fr parameters is not match regex`，
写对了就过。Watch 6 的表盘分辨率正是 466×466。

Previewer 里加载 `pages/Index` 成功，能力探测自检通过
（**注意 crypto 桩限制，见下一节；现已通过双通道降级解决**）。

### 6.3.4 Previewer 跑不通协议 —— crypto 全是桩实现 → **已修复 ✅**

在 Previewer 里触发登录，日志逐条打出：

```
The createMd       interface in the previewer is a mocked implementation
The updateSync     interface in the previewer is a mocked implementation
The digestSync     interface in the previewer is a mocked implementation
The createRandom   interface in the previewer is a mocked implementation
The generateRandomSync interface in the previewer is a mocked implementation
```

即：**`cryptoFramework` 在 Previewer 下全部是 mocked 桩实现，
同步接口一律返回【空的 Uint8Array】**（不抛异常，所以极易误判为"可用"）。

实测共 **13 类**接口被打桩（按日志出现次数排序）：

```
updateSync 41 · digestSync 31 · createMd 31 · generateRandomSync 25
createRandom 25 · initSync 20 · generateKeyPairSync 20 · doFinalSync 20
createSymKeyGenerator 20 · createAsyKeyGenerator 20 · convertKeySync 20
createMac 10 · createCipher 10
```

报错链（用户报的现象）：

```
能力探测: sha256=false md5=false hmac=false rsa=true aesCtr=false ed25519=true rng=false
[登录] PAKE 登录: 正在登录…
登录失败: [pake] 登录失败: Cannot convert string to a BigInt,because not allow
         Infinity, decimal points, or exponents
```

> `createSeed()` → `sha256Hex()` 返回空串 → `BigInt('0x')` 抛异常。
> `rsa=true` / `ed25519=true` 是**假阳性**（那两处探测当时只看"是否抛异常"）。

#### ★ 关键前提：`@ohos.net.http` 在 Previewer 里**是真的能联网的**

日志实证：

```
[login] GET  https://account.lixiang.com/login?...  → 200
[login] POST https://id.lixiang.com/api/devices     → 200
```

**所以 Previewer 跑不通只卡密码学，不卡网络** —— 这决定了下面的降级方案可行。

> 排查提醒：日志里可能**同时存在多个 Previewer 进程**（不同 pid），
> 只有打桩的那个会刷 mocked 日志。别被另一个进程的 `能力探测: ... =true` 带偏。

#### 修复方案：双通道自动降级（已实现并验证）

`HarmonyCrypto.isPureMode()` 启动时探测
（跑一次 `createMd + updateSync + digestSync`，看是否真的返回 32 字节）。
为真 → **整个密码学层切到纯 ArkTS 软件实现**。

纯实现位于 `entry/src/main/ets/core/crypto/pure/`，**不依赖 cryptoFramework**：

| 文件 | 内容 | 独立验证 |
|---|---|---|
| `Sha.ets` | SHA-256 / SHA-512（BigInt） / MD5（常量运行期算） | 44 ✅ |
| `Hmac.ets` | HMAC-SHA256/512 + HKDF-SHA256（RFC 5869） | 215 ✅ |
| `Aes.ets` | AES-256-CTR（S-box 运行期按 GF(2^8) 逆元算） | 67 ✅ |
| `Rsa.ets` | RSA-2048 PKCS#1 v1.5（CRT 优先 + PKCS#8 DER 自解析） | 23 ✅ |
| `Ed25519.ets` | RFC 8032（**只签名、不验签**，PAKE 不需要验签） | 64 ✅ |

设计要点：

- `RsaKeyHandle` 句柄类把 `cryptoFramework.PriKey` 隔离在底层，
  协议层只认 `RsaKeyHandle`（避免 ArkTS 类型泄漏到业务代码）
- 真机路径**优先硬件**；同时每处都校验**实际字节数**，不符则打日志降级
- `randomBytes()` 兜底 `Math.random`（**仅开发环境生效**，真机永不走此路径）
- `CryptoCapabilities.pureFallback` / `channel()` 标记当前生效通道；
  UI 上会显示一行小字「开发模式：密码学走软件实现」

体积代价：HAP `463182 → 587716` 字节（+124 KB）。

### 6.3.5 Previewer 里暴露并已修复的三个真 bug ✅

在 Previewer 上排查的过程中**修掉了三个真机也会中的坑**：

| # | 现象 | 根因 | 修复 |
|---|---|---|---|
| 一号坑 | `[auth] HTTP 405 Not Allowed`（nginx） | `@ohos.net.http` 的 **`maxRedirects` 默认 30**，会自动跟随 3xx；而 `/api/auth` 第一步返回 `300 {"location":".../login"}`，ArkTS 把 **POST** 带到了只收 GET 的 `/login` → 405 | 所有请求显式 `maxRedirects: 0`；并在 `call()` 里**吞掉 2300047**（maxRedirects=0 时遇 3xx 会抛这个错，而 300 是业务正常码） |
| 二号坑 | `[devices] HTTP 400` | `uuid4Hex()` → `randomBytes()` → `generateRandomSync().data` 在某些环境返回**空数组**，导致 `device_id=` 为空 | `randomBytes()` 长度校验 + 兜底 |
| 五号坑 | 登录成功但换 scope token 永远 `login_required` | `resp.header['set-cookie']` 是 **`string[]`**（一条 cookie 一个元素），而 `headerValue()` 对数组**只返回 `arr[0]`** → 除第一条外的 cookie 全丢（`sso_token` 常不在第一条） | 新增 `headerRaw()` 取原始值交给 `CookieJar.absorb()`；`absorb()` 字符串分支按 `/,\s*(?=[A-Za-z_][\w\-]*=)/` 拆分（不误伤 `Expires=Wed, 21 Oct …` 的逗号） |

> 注：`requests`(Python) 默认**不跟随 300**，所以 Python 侧从来没遇到过
> 一号坑 —— 这是"Python 通、ArkTS 405"的根因。

### 6.3.6b ★★★ 七 / 八号坑（真机 Watch 6 实测）：`maxRedirects: 0` 会连带丢掉整个响应头 ✅ 已修

**这是登录在真机上失败的直接原因。**

现象：登录页报 `[idps] HTTP 412 {"error":"invalid_auth_session"}`

根因链（Python 对照实验 100% 证实）：

1. `POST /api/auth` 返回 **300** + `Location: .../login`
   + `Set-Cookie: auth_session=BJ.xxx; Secure; HttpOnly; SameSite=None`
   （host-only，域 `id.lixiang.com`）
2. ArkTS 侧 `maxRedirects: 0` → http 模块遇 3xx **抛 2300047**，
   **此时拿不到 resp 对象** → catch 里合成的
   `{code:300, body:'', location:'', json:null}` 把 `Set-Cookie` **永久丢弃**
3. `/api/idps` 校验会话 → `412 {"error":"invalid_auth_session"}`

为什么 Python 从不复现：`requests` **不跟随 300**，正常吸收 Set-Cookie。

**对照实验**（`verify_tool/probe412.py`，用全新随机 device_id 也一样）：

| 条件 | `/api/idps` 返回 |
|---|---|
| cookie 完整（= Python 侧行为） | **200** |
| 手工删掉 `auth_session`（= ArkTS 行为） | **412** ← 逐字复现 |

**同一个机制还埋了两颗雷** —— 只修 412 的话，修完立刻会接着撞上：

| 位置 | 成败信号在哪 | 丢了会怎样 |
|---|---|---|
| `/api/login`（`redirect=false`） | 302 的 `Location`：`?code=HZ.xxx&state=...` | 误报「响应无授权码」 |
| `TokenManager.exchange`（`maxRedirects: 0`） | 302 的 `Location`：`?access_token=` / `?error=login_required` | MESH/VAT/VSS token 全换不到（且原本**连 catch 都没有**，直接把 `2300047` 抛给 UI） |

**修法**：订阅 `headersReceive` —— 官方文档明确该事件在**重定向判定之前**触发，
所以即便随后抛 2300047，响应头也已经到手：

```ts
let lastHeader: Record<string, string> = {};
httpReq.on('headersReceive', (h: Object) => {
  self.absorbHeaderEvent(h, host);                 // Set-Cookie → CookieJar
  lastHeader = PakeLoginHelper.flattenHeader(h);   // Location → 供异常路径重建 RawResp
});
...
catch (e) {
  if (err.code === 2300047) {
    await PakeLoginHelper.drain();   // ★ 等事件派发完，否则 destroy() 会把它取消掉
    return { code: 300, body: '', location: lastHeader['location'] ?? '', json: null };
  }
  throw err as Error;
}
```

> **★ `drain()` 是必需的**：`finally { httpReq.destroy() }` 会把**尚未派发**的
> 响应头事件取消掉，cookie 和 Location 就白捕获了。

其余三处 `maxRedirects: 0` 也补了 catch，把 `2300047` 转成可读错误
（`VehicleControl.signedCall` / `KeySuite.deriveIdentity` / `VssReader.getBatch`）。

**真实服务端验证**（`arkts/smoke_live*.js`，用**应用的真实代码**直连 `id.lixiang.com`，
全程不用手表）：

| 验证项 | 结果 |
|---|---|
| 登录 | ✅ 完整成功，拿到 `APP-221b5962…`，**未触发短信风控** |
| 换 scope token | ✅ MESH(22) / VAT(1388 字节 JWT) / VSS(21) **三个全换到** |
| 读车辆状态 | ✅ `locked=true`、四窗=0、`acOn=false`、设定 22℃ / 车内 29℃ |

日志实证授权码确实来自捕获的 Location：

```
[3xx] 命中 2300047 → 合成 300，location=https://account.lixiang.com/app-auth?code=BJ.4SLeYAR3s50G5h2Y5rFr10
```

### 6.3.7 ★★ 六号坑（真机 Watch 6 踩到）：能力探测的 try 块不能混装两件事

装机后登录页报「本机不支持 ED25519，无法登录」。根因在 `probeCapabilities()`：

```ts
try {
  c.ed25519 = ed25519Sign(...).length === 64;   // 已判成 true（纯实现兜底）
  if (c.ed25519) {
    cryptoFramework.createAsyKeyGenerator('Ed25519');   // ← 真机上抛异常
  }
} catch (e) {
  c.ed25519 = false;                             // ← 把 true 冲成 false
}
```

- Watch 6 的硬件 ED25519 **不可用**，`createAsyKeyGenerator('Ed25519')` 抛异常
- 异常被外层 catch 吞掉 → 误判「不可用」→ UI 误报
- **可用性判定与硬件判定必须各自独立 try**；新增 `caps.ed25519Hw` 单独承载硬件结论

**同时加固**：硬件 Ed25519 现在必须用 **RFC 8032 TEST 2 向量验语义**
（`ed25519HardwareUsable()`），通过才用；只验长度的话，语义错的硬件
（例如 Ed25519ph）也会"成功"返回 64 字节 → 服务端判 proof 错误 →
表现为「登录失败」且无从下手。验不过一律走已验证的纯实现。

### 6.3.8 真机排障：诊断行

手表端取日志很麻烦（`hdc -t COM4 shell` 报 `E001005`），
所以把自检结果**直接显示在登录页**：

```
真机 纯:OK sha:OK md5:OK hmac:OK aes:OK rsa:OK ed:OK edHw:N rng:OK ed纯:12ms | 硬件不可用(...)
```

| 字段 | 含义 |
|---|---|
| `纯:OK/FAIL` | 纯 ArkTS 实现整体自检（Ed25519 用 RFC 8032 向量比对） |
| `ed:OK/NO` | Ed25519 **功能**是否可用（= 硬件 OR 纯实现） |
| `edHw:Y/N` | 硬件是否可用（`N` 不代表功能不可用） |
| `ed纯:12ms` | 纯实现 Ed25519 自检耗时（区分「崩了」和「太慢」） |
| `\| 硬件不可用(...)` | 硬件探测失败的具体原因 |

登录失败时**原始报错不再被截断**，会完整显示在登录页。
ED25519 纯实现若抛异常，会带 `Ed25519 纯实现失败: xxx` 前缀，便于识别。

### 6.3.9 ★★★ 十号坑（真机 Watch 6）：MESH / VSS 同 audience 互顶 → 车控恒 401 ✅ 已修

**表象**：登录正常、读车态正常（VSS 实时温度），但**所有车控指令恒 401**
（`POST /ssp-vehicle-control/cmd/send`，
`WWW-Authenticate: Bearer realm=1j0vgTqagJUHuT6nLmbTGx,error="invalid_token"`）。

**真因**：服务端对**同一 audience 只保留最新一条 token**。
MESH 与 VSS 的 audience 相同（都是 `1j0vgTqagJUHuT6nLmbTGx`），
而 `ensureTokens()` 的顺序是 `MESH → VAT → VSS` ——
后换的 VSS 把 MESH 顶掉，`cmd/send` 拿失效 MESH 作 `Authorization` → 401。

对照矩阵（PC 侧真实服务端，用手表导出的凭据）：

| 场景 | 结果 |
|---|---|
| 只换 MESH → cmd-result | ✅ 200 |
| 换 MESH → 再换 **VSS**（同 audience）→ 用原 MESH | ❌ **401** |
| 换 MESH → 再换 VAT（不同 audience）→ 用原 MESH | ✅ 200 |
| 4 个 scope 合并一次换取 → cmd-result / VSS / wakeup | ✅ **全 200** |

**修法**（与官方 App `subTokenData` 的 `httpLiMeshServiceV2` 一致）：
把 `vss:get-batch` **并入 `SCOPE_MESH`** 一次换取，**车控与 VSS 共用同一条 token**：

```
remote-wakeup:wakeup veh-ctrl:cmd-send veh-ctrl:cmd-result-get vss:get-batch
```

- `Constants.ets`：`SCOPE_MESH` 合并 4 个 scope
- `TokenManager.ets`：`vss()` → `return await this.mesh()`
- `AppState.ensureTokens()`：`vss.setToken(meshTok)`，**绝不再单独换 VSS**
- `lx_const.py` / `lx_token.py`：Python 侧同步（双轨约定）

**真机实测**：解锁、落锁各成功一次（VSS 实时回读「已解锁」/「已锁」），全程无 401。

#### 排查中被证伪的假设（勿重走）

| 曾经的怀疑 | 证伪依据 |
|---|---|
| `X-CHJ-TOKEN` 传空被 `@ohos.net.http` 跳过 | Python（`app_token=''`）cmd/send 一样 **200** |
| `client_id` 应传空（参考项目 `"client": ""`） | 传空/省略 → 换取直接 **HTTP 400** |
| 缺少 `idaas-data` 请求头 | 该头属 `/api/login`；`/api/auth` 加不加结果相同 |
| device_id 信任度 / 签名算法 | PC 侧两组 device_id 均 200 |
| `MESH len=22` 是坏值 | 官方 App 抓包同为不透明短 token（前缀 `HZ:`，我们是 `BJ:`） |

> **排查捷径**：手表凭据明文在
> `/data/app/el2/100/base/com.kylin.lixianghmwatch/haps/entry/preferences/lixiang_watch_store`
> （root 可读）。导出后在 PC 侧就能做完整对照实验，**不必反复让用户在真机上试错**。
> 验证 `cmd/send` 鉴权又不想动车：发**非法 `cmdKey`**（如 `__diag__`），
> 401 消失即说明网关已放行。

### 6.3.10 ★★★ 十一号坑：`@Builder` 基本类型参数不刷新 → 按钮文案与行为相反 ✅ 已修

`@Builder funcCard(key, label, icon, active, onTap)` 里 label/icon/active 是
**传值快照**，父组件状态变化后**不重渲染**：

- 症状：车**已锁**（顶部显示「已锁」）时按钮仍显示「**落锁**」，
  但 `onLockTap()` 读的是**最新**状态 → 点下去实际执行 **unlock()**
- **文案与行为相反**，用户以为是锁车，实际是解锁 —— 危险的功能误导
- 修法：`@Builder` 只收 `key`，label/icon/active 在**内部实时计算**
  （`cardLabel(key)` / `cardIcon(key)` / `cardActive(key)` 读 `this.xxx` 才响应式）

### 6.3.11 功能变更（2026-10-16）：删车窗 → 加「授权驾驶」✅ 真机实测通过

**需求**：删除「开关车窗」，新增「授权驾驶」。

**实现**（双轨同步，Python 与 ArkTS 一一对应）：

| 项 | 值 |
|---|---|
| cmdKey | `remoteVehAuth` |
| cmdData | `{}`（**空对象也必须传**，不能省略或传 `null`） |
| jobExpire | 30（短命令，**不**属于 `LONG_RUNNING_CMD_KEYS`） |
| 是否轮询 | **是** —— 真实授权动作，不能 fire-and-forget |
| VAT scope | `remoteVehAuth:<VIN>`（替换原 `remoteVehWdwControl:<VIN>`） |

**命名的坑（照参考项目记录）**：App 的实现类是 `XHttpRemoteStartControl`
（远程启动），但 cmdKey 用的是 `remoteVehAuth`（Auth = 授权驾驶）。
功能名按用户口径叫**授权驾驶**。

**没有可回读的状态**：`remoteStartStatus.startStatus` 这个信号只存在于
**M 系平台**（`requires="platform:1"`），L6 是 X 系（platform=2）读不到。
所以 UI 上做成**一次性动作按钮**（同「寻车」），不做开关态。

**二次确认（安全设计）**：授权驾驶是安全敏感操作（误触可能让别人开走车），
且按钮紧邻「解闭锁」。所以：
1. 第一次点 → 按钮变「**再点确认**」并高亮，toast 提示
2. 3 秒内再点 → 真正下发；**3 秒不点自动解除**
3. 任何**其他车控动作**开始时会 `disarmAuth()` ——
   避免「先点了别的按钮、再点这个以为是第一次」而直接授权的场景

**验证结论（真车，2026-10-16 13:23）**：

```
VAT scopes = [remoteVehAuth:<VIN>, remoteVehACSmartControl:<VIN>,
              remoteVehLockControl:<VIN>, remoteVehSearch:<VIN>]
             ← 4 个全给，未触发整批降级；wdw 已不在列表
POST cmd/send {cmdKey:"remoteVehAuth", cmdData:{}} → 200 requestId
cmd-result: pushState=1 已下发 → pushState=5 执行成功 resultCode=0
手表端连点两次 → toast「授权驾驶成功」，车态未受影响
```

**排查提示**：VAT token 的 scope claim 名是 **`scopes`（复数、数组）**，
不是标准的 `scope` —— 按 `scope` 取会得到 `None`，误判成「没授权」。

### 6.3.6 离线验证工具（本机可跑，不依赖 Previewer）

`<本地路径>\lxtest\`（自建的 node 测试脚手架，未随仓库提供）

```
node run_all.js                      # 全量：原语层 + 协议层
node arkts/build.js && node --check arkts/bundle.js   # 只做语法检查
```

- `arkts/runner.js` —— **ArkTS in Node 运行器**：把协议层真实 `.ets`
  抽成可执行代码，并注入**忠实复刻 Previewer 行为**的桩
  （`cryptoFramework` 全返空 + `http` 复刻 `maxRedirects` 语义）
- `arkts/smoke.js` —— 冒烟测试，**50 通过 / 0 失败**
- `pure/run_all.js` —— 5 个原语套件，**413 通过 / 0 失败**

与 Python 侧**逐字节对拍**（同一固定输入，两边结果必须完全相同）：

```
sha256('abc')                    = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
sign(POST,'{"a":1}',ts=1700000000000,nonce='n'×32)
                                 = LDvhtvQnFLj3UZL3Z7SITX9CF7+6KDAxDjBGOaIrin4=
真实 hac_key 的 sign              = ACPMEBrDCcmEC2iakNWehqKED3o4oZhH76qEf3NJ5QU=
createSeed('<密码-已脱敏>')      = 30a9707104e941c69948fa5724020a31
seededToSaltedStr                = KIjuaORnOaYXQNnVH.GIKO
```

### 6.4 手表端首次运行注意

- 首次打开会进**登录页**（手机号 + 密码），登录成功后凭据存入
  `preferences`（应用私有）。
- 若提示"需要短信验证"，说明该 device_id 未被信任 —— 先在**手机官方
  App** 里登录一次（同一账号），再回到手表重试。这是理想的风控行为，
  不是代码问题。
- **hac_key 有效期 4 个月**，到期需重新登录派生。

---

## 七、待确认的技术风险

### 7.1 ED25519 在手表端的可用性 ⚠️

华为官方文档中：
- "手机、平板、PC/TV、**智能穿戴**" → 支持 ED25519
- "**轻量级**智能穿戴" → **不支持** ED25519

Watch 6 跑完整 HarmonyOS 7，代码里用 `probeCapabilities()` 运行时探测。

> ### ★★ 2026-10-14 真机实测结论：**Watch 6 的硬件 ED25519 不可用**
>
> 装机后登录页报「本机不支持 ED25519」→ 反推
> `cryptoFramework.createAsyKeyGenerator('Ed25519')` 在真机上**抛异常**。
> 所以 Watch 6 落在**第二档**（轻量级智能穿戴口径），与文档预期相反。
>
> **这不再是阻塞项**：`core/crypto/pure/Ed25519.ets` 是完整自洽的纯 ArkTS
> 实现（RFC 8032 逐字节验证），`ed25519Sign()` 会自动切过去。
>
> 另外把「硬件是否可用」和「功能是否可用」彻底拆开：
> `caps.ed25519` = 功能可用（含纯实现兜底），`caps.ed25519Hw` = 硬件可用。

> ⚠️ **注意**：**Previewer 上探测出的 `ed25519=true` 不可信** ——
> 那里 `cryptoFramework` 全是 mocked 桩实现（见 §6.3.4），
> 只验"能拿到私钥对象"，不验密钥是否真实可用。

#### ★ 该风险已降级为"性能问题"而非"功能问题"

`core/crypto/pure/Ed25519.ets` 是完全自洽的纯 ArkTS 实现
（RFC 8032 TEST 1/2/3 逐字节吻合，实测 **4.5 ms/次**）。
`HarmonyCrypto.ed25519Sign()` 在硬件不可用时**自动降级到它**。

所以：
- **硬件可用** → 走硬件，快
- **硬件不可用 / 是桩** → 走纯实现，**仍然能登录成功**（次级别延迟可忽略）

`probeCapabilities()` 里的 `ed25519` 字段现在反映的是
"**是否有任一通道可用**"，不再等价于"硬件支持"。真机上若探测到
走的是纯实现，`pureFallback` 会被置位（有日志）。

**影响范围**：只有"重新登录"需要 ED25519（PAKE proof）。
已登录用户走 refresh_token 时不碰它。
所以即使 ED25519 不可用，App 装好后日常车控仍能正常工作。

### 7.2 bcrypt 依赖 —— 已解决 ✅

ArkTS 侧登录需要 bcrypt，官方 SDK 不提供。**已自写纯 ArkTS 移植**
（`core/crypto/Bcrypt.ets`，约 620 行），并用 bcryptjs / Python bcrypt
**双向对拍通过**（含空串、`<密码-已脱敏>`、中文密码共 4 组）。

```ts
import { defaultBcrypt, bcryptSelftest } from '../core/crypto/Bcrypt';
bcryptSelftest();   // → true
```

**移植过程踩的坑（唯一 bug，很隐蔽）**：
base64 解码的循环上界不能写成 `Math.min(len, s.length)`。
22 字符 salt 那样只会解出 12 字节（应 16），后 4 字节被清零，
导致 `eksKey` 输入错、全链路错。正确写法：

```ts
while (off < s.length - 1 && out.length < len) { ... }
```

**性能预期**：cost=10 在手表 CPU 上约几百毫秒（bcrypt 固有开销），
登录时会明显卡一下，属正常。

### 7.3 VSS 信号路径可能随 OTA 变化

信号路径（如 `Vehicle.Body.DoorLockStatus.MainDoor`）来自参考项目的
`signals.py`（自动生成，2437 行）。理想 OTA 后可能新增/改名。
遇到"某个状态读不到"时，先用 `python lx_main.py status --raw` 看实际返回。

---

## 八、安全提醒

- `verify_tool/cred.json` 等同于**车辆控制权**，不要提交 git、不要外发
- ArkTS 端用 `@ohos.data.preferences` 存储，属应用私有目录
- 如需更强保护，可叠加 HUKS 加密（`@ohos.security.huks`），
  但会增加复杂度，建议先跑通再加

---

## 九、参考项目的关键文件（需要复查时）

```
_ref_ha_lixiang/custom_components/lixiang_auto/
├── const.py                所有端点常量
├── signer.py               x-chj 签名
├── key_suite.py            身份派生（含 RSA 私钥）
├── pake_login.py           PAKE 登录
├── li_api.py               ★ 最大文件（2563 行），所有业务接口
├── lock.py / cover.py / climate.py / button.py   4 个功能实体
├── signals.py              VSS 信号表（2437 行）
└── app_config/sub_token_data.json   token 权威配置
_ref_ha_lixiang/docs/skills/lixiang-reverse-engineering/SKILL.md
                            ★ 逆向总结，通道地图，错误码对照
```
