# 验证报告

> 执行时间：2026-10-14 00:23（离线+签名） / 00:32（真车）
> 环境：本机（Windows），Python 3.13.12 venv `<本地路径>

---

## 零、总览

| 部分 | 是否需要账号 | 状态 |
|---|---|---|
| A. 离线自检 | 不需要 | ✅ 已完成 |
| B. 网络 + 签名链路实测 | 不需要 | ✅ 已完成 |
| **C. 真车完整车控链路** | **需要账号** | ✅ **已完成（真车解锁/落锁成功）** |

**结论：协议层已 100% 打通，真车实测解锁 + 落锁均成功。**

---

## 一、验证范围说明

本报告分三部分：

| 部分 | 是否需要账号 | 状态 |
|---|---|---|
| A. 离线自检 | 不需要 | ✅ 已完成 |
| B. 网络 + 签名链路实测 | 不需要 | ✅ 已完成（**重大收获**） |
| C. 完整车控链路 | **需要你的账号** | ✅ **真车验证通过** |

**B 部分的意外收获**：keySuite 端点**不校验 bearer**，
用随机 `device_id` + 无效 token 就能拿到完整的密钥材料。
这意味着签名构造的正确性可以完全离线验证 —— 已全部跑通。

---

## 二、A. 离线自检结果

### 环境

```
✓ cryptography   50.0.2
✓ bcrypt         5.0.0
✓ PyNaCl         1.6.2
✓ requests       2.34.2
```

### 协议自检

```
✓ 签名器（确定性 / 11段 / hex与bytes等价）
✓ PAKE create_seed
✓ bcrypt 自定义 base64（22 字符）
✓ RSA 私钥加载（2048 位）
✓ VAT scope 生成（默认 4 条 / 扩展 12 条）

结果: 全部通过 ✓
```

### 单元测试

```
Ran 31 tests in 0.104s
OK
```

覆盖：签名 11 段构造、Content-MD5、请求头完整性、4 个功能的
cmdKey/cmdData 精确值、acCtrlTemp 类型、jobExpire 长短命令分级、
pushState 5/7 判定、resultCode -8/-15 特判、轮询超时不报错、
VSS 响应解析、二分降级。

---

## 三、B. 网络与签名链路实测

### B.1 服务器连通性

```
OK  id.lixiang.com        -> 106.13.245.14    79ms
OK  account.lixiang.com   -> 39.91.182.35     63ms
OK  api-app.lixiang.com   -> 27.221.38.35     63ms

HTTPS: HTTP 200, server=nginx
```

### B.2 keySuite 端到端实测 ★

**方法**：随机 `device_id` + 随机 `boot_hac` + 无效 bearer，打 keySuite。

**结果**：

```
HTTP 200
{"code":0,"success":true,"msg":"success","data":{...}}
```

**这个结果证明了 4 件事**：

1. ✅ **RSA 私钥正确** —— body 的 `sign` 字段通过了服务端验证
2. ✅ **keySuite 的 x-chj 签名配方正确** ——
   `hexdigest` + `nonce.upper()+ts` + `boot_hac[:32]` 三段特殊构造全对
3. ✅ **`boot_hac` 用随机值可以** —— 证实参考项目"服务端不校验引导签名"的结论
4. ✅ **服务端不校验 bearer** —— keySuite 只需签名正确

### B.3 完整 CSP 派生实测

```
响应字段:
  keySuite.keyId            22004f3b97dc4f0a155a3d00... (32 字符)
  keySuite.keySecret.aesKey     44 字符
  keySuite.keySecret.hmacKey    44 字符
  keySuite.validFrom        2026-10-14 00:23:44
  keySuite.validTo          2027-02-11 00:23:44
  keySuite.updateFrom       2027-01-12 00:23:44
  tempAesKey                344 字符
  tempIv                    16 字节
  spPublicKey               392 字符  ← 参考项目未使用
  spPublicKeySign           344 字符  ← 参考项目未使用
  sign                      344 字符  ← 参考项目未使用
```

**派生过程**：
```
RD  = RSA-PKCS1v15(tempAesKey, priv)            ← 解密成功
hac = AES-256-CTR(RD, tempIv).decrypt(hmacKey)  ← 成功
→ 32 字节
```

✅ **完整 CSP 派生链路验证通过**

### B.4 新发现（值得记录）

#### 发现 1：keySuite 响应包含 3 个未使用字段

`spPublicKey` / `spPublicKeySign` / `sign` —— 参考项目的实现里没有用到。
推测是服务端的可验证凭证（SP = Service Provider）。
不影响当前 4 个功能，但说明还有未被逆向的机制。

#### 发现 2：`keySecret.aesKey` 未被使用

参考项目只用 `hmacKey` 派生 hac，但服务端同时下发了 `aesKey`。
说明存在另一条加密通道（可能是敏感数据的信封加密）。
当前 4 个功能不需要。

#### 发现 3：hac_key 有效期 4 个月 ★

```
validFrom   = 派生时刻
updateFrom  = +3 个月   （建议更新时刻）
validTo     = +4 个月   （失效时刻）
```

**对实现的影响**：hac_key 派生一次可用 4 个月，
不需要每次启动都派生。手表端应持久化缓存，
并在 `updateFrom` 之后择机重新派生。

---

## 四、C. 真车完整链路实测（2026-10-14 00:30-00:33）✅

### C.0 真车信息

```
VIN:         <VIN 已脱敏>
车牌:        鲁A*****（已脱敏）
车型:        理想L6 Max  (modelId=100502131647776385)
昵称:        <车主自定昵称>
角色:        authorized (vehicleType), vehicleRoleId=15
真机 device_id: <本地 device_id，运行时随机生成>
真实 key_id:    <本地 key_id>
```

> 注：`modelId=100502131647776385` 与参考项目
> `vehicle_configs/100502131647776385.json` 完全一致 → 配置表可直接复用。

### C.1 遇到的拦路错误：`login_required` ★★

**现象**：PAKE 登录成功、`main_bearer` 有效，但换任何 scope token 都返回：

```
302  location: https://account.lixiang.com/app-auth?error=login_required
```

**根因**（`li_api.py` 第 6 行早有记载，第一版实现漏了）：

> 裸 Bearer 换不了 scope token (login_required)，
> **必须带登录会话 cookie**

服务端 Set-Cookie 把 `sso_token` 的域设成 `id.lixiang.com`，
而 `/api/auth` 换 token 时校验会话 → 不带 cookie 永远 `login_required`。

**修复**（三处，已验证有效）：

1. `lx_login.py` 新增：
   - `export_session_cookies()` 导出登录态 cookie（`sso_token` 435 字符 JWT）
   - `import_session_cookies()` 装载（过期丢弃、幂等）
   - `sync_parent_domain_cookies()` 把 `sso_token`/`isapp`/`X-LX-Deviceid`/
     `authli_device_id` 同步到父域 `.lixiang.com`；**`login()` 成功后自动调用**
2. `lx_token.py`：`TokenManager.__init__` 新增 `cookies` 参数 + `load_cookies()`
3. `cred.json`：新增 `session_cookies`（10 条）+ 车辆信息字段

**⚠️ ArkTS 侧 `TokenManager.ets` / `PakeLogin.ets` 必须同步实现，否则手表端必然卡死。**

### C.2 另一发现：车辆列表接口也要签名头

```
不带签名 → {"code":100002,"msg":"缺少必要的请求参数:
            X-CHJ-Env,X-CHJ-Version,X-CHJ-Key,X-CHJ-Deviceid,
            X-CHJ-Timestamp,X-CHJ-Nonce,X-CHJ-Sign,Content-MD5"}
带签名   → 200 {"data":[{vin, modelName, ...}]}
```

`/saos-vehicle-api/v2-0/vehicles/basics` 需要完整 x-chj 头。
参考项目的 `list_vehicles` 走的是另一条无签名路径。

### C.3 VSS 实时状态（8 信号全命中）

```json
{
  "Vehicle.Body.DoorLockStatus.MainDoor":         0,
  "Vehicle.Body.WindowPosition.MainWindow":       0,
  "Vehicle.Body.WindowPosition.CopilotWindow":    0,
  "Vehicle.Body.WindowPosition.BackLeftWindow":   0,
  "Vehicle.Body.WindowPosition.BackRightWindow":  0,
  "Vehicle.Cabin.AC.FOffStatus":                  0,
  "Vehicle.Cabin.AC.SetTemp":                     22.0,
  "Vehicle.Cabin.AC.FrtACIncarTemp":              17.0
}
```

解析结果：`locked=True`（与用户所述"车是锁着的"一致）、
四窗全关、空调关闭、设定 22°C、车内 17°C。

### C.4 真车解锁 ✅

```
wakeup   → {"code":0,"success":true,"message":"success"}
cmd/send → {"requestId":"q2a0yjm5jAOa8tnG000"}
轮询     → pushState:1 已下发
         → pushState:5 执行成功  resultCode:"0"  failReason:"success"
耗时:      00:32:49.509 → 00:32:51.06  (约 1.5s)
```

**信号闭环**：`MainDoor` `0` → `1`，`locked` `True` → `False`（连续 3 次采样确认）。

### C.5 真车落锁（恢复原状）✅

```
cmd/send → {"requestId":"Jcu0yjm5GLya8tnG000"}
轮询     → pushState:1 → 5 执行成功
耗时:      00:33:11.419 → 00:33:11.956  (0.54s)
恢复:      locked=True  MainDoor=0  ✅
```

### C.6 用户约束

用户明确要求：**只尝试 lock/unlock，不要鸣笛 find 和开窗 windows**。
本轮**仅执行 lock + unlock**，`find`/`flash`/`whistle`/`windows`/`ac`
全部未触碰。

---

## 五、结论

**全部验证通过**：

- ✅ 签名算法（x-chj）100% 正确 —— 服务端实测接受
- ✅ 身份派生（CSP/RSA/AES-CTR）100% 正确
- ✅ 登录流程（PAKE 六步）正确
- ✅ **登录 cookie 传递链条** 正确（关键修复点）
- ✅ 三个 token（MESH/VAT/VSS）换取正确
- ✅ 车控通道（cmd/send + cmd-result 轮询）正确
- ✅ VSS 信号路径与 L6 Max 实车**完全匹配**
- ✅ **真车解锁成功**
- ✅ **真车落锁成功**

**剩余未验证**（因用户约束未执行，但参数已在离线测试中覆盖）：

- `find` / `flash` / `whistle`（寻车）
- `ac_on` / `ac_off`（空调，长命令 900s）

> **2026-10-16 变更**：按用户要求**删除「开关车窗」**（`remoteVehWdwControl`，
> 代码与 UI 均已移除），**新增「授权驾驶」**（`remoteVehAuth`，`cmdData={}`）。
> 上文关于 `windows_open` / `windows_close` 的验证项已不再适用。

**下一步**：把 cookie 传递机制补进 ArkTS 的 `PakeLogin.ets` + `TokenManager.ets`，
然后编译装机。
