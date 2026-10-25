"""理想汽车协议常量 —— 与手表端 ArkTS 的 Constants.ets 保持一一对应。

任何一处改动，两边必须同步。这是唯一的权威表。
"""

# ── 域名 ──────────────────────────────────────────────────────
BASE_ID = "https://id.lixiang.com"
BASE_ACCT = "https://account.lixiang.com"
API_APP = "https://api-app.lixiang.com"

# ── 登录 ──────────────────────────────────────────────────────
CLIENT_ID = "2AQClOaegaA7XecMSFx1p"
LOGIN_AUDIENCE = "5iIapSfVJlln0vU0OzUCH9"
LOGIN_SCOPE = "iam:client:type:app openid"
REDIRECT_URI = BASE_ACCT + "/app-auth"
SDK_VERSION = "0.0.0-snapshot-20240614055722"
APP_VERSION = "8.22.0"

DEFAULT_UA = (
    "Mozilla/5.0 (Phone; OpenHarmony 6.1) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/132.0.0.0 Safari/537.36  ArkWeb/6.1.0.117 Mobile m01/8.22.0"
)

SEED_MOD = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF61
B64_BCRYPT = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

# ── 业务签名 ──────────────────────────────────────────────────
SIGN_APP_VERSION = "8.25.4-10463"
KEY_SUITE_VER = "8.25.4-10463"

ENV = "prod"
DEFAULT_ACCEPT = "*/*"
DEFAULT_CONTENT_LANG = "zh-Hans-CN"
DEFAULT_CONTENT_TYPE = "application/json"
SIGN_SEP = "\n"
EMPTY_MD5 = "1B2M2Y8AsgTpgAmY7PhCfg=="

DEVICE_TYPE = "2"
MODEL_NAME = "IOS"
DEVICE_MODEL = "9.7-INCH IPAD"
SIGN_UA = f"m01/{SIGN_APP_VERSION} (iPad; iOS 16.7.12; Scale/2.00)"

# ── keySuite ──────────────────────────────────────────────────
EP_KEY_SUITE_DDES = "/ddes/v1-1/app/key-suite"
MAIN_DEVICE_KEY_ID = "020026d02bf87a0a153144000075c05e"

# 主 App 的内置 RSA 私钥（PKCS#8 DER，base64）
# ⚠️ 这不是用户凭据，是硬编码在官方 App 里的共享设备密钥
MAIN_RSA_PRIVATE_DER_B64 = (
    "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCMRBXH3xiTKCLv"
    "jxvSgnaGdDWN1QgS/OR6C4slAuYfVUuvEyUZUnQS7PPRr5K8/Vs8DFvMrL13huAA"
    "FrlioDeB9j7PMLUwtw5LZxx4FUBiTYMQgUWrxB19kdd1MbgJvACymTBuumFjBHiO"
    "HCRofDZ//VNrrSWezoqnWHNW4SINvbT2bO1qeXHp+UasgaKL6uRL/aufb4wsSiZi"
    "E7sRwQWlPWAMGncTPMjeiriNvfYRNbXhvE+qghucPmuSlg04cB7ZX7kSbwj32C9t"
    "llCEILAKK0RT3QKB+C86o4xYbU6dU098+fi04t9Tg6SIkuOwDOhHXhZKlFZNtI2S"
    "ZqMbTIJJAgMBAAECggEAGMwIlbcpHwrfcj54irSpw4dT2Gkq7kBrG/Bifv6ONEfe"
    "A2t9CYb8IkRlrlI9vM+Fi44bxIldTX44p4tc5sSwS3d/Dx3rSltyWX43GDuZkEdn"
    "vkk8Set30zUvQ/awNHhaHzjZyRmGEf0+WtE61oXvFJ1yW/zWQ8b72C3Y5ikS3h7C"
    "gp1y0XJE1GRgTWvguFftz/QVwDpJR6CwOXDoJNoB7tyJH9DwIF4Ta00VzB21DTd0"
    "n1Gc1sfz8iG5GC8amWfNsql1Q/wOr+o5sBnVrErj6otnHEiUGJEcYXV7icztTGK5"
    "2U3t0lzd4ALM/9sz9XsiEt6UgKIL4pW3xAN4NRoaCQKBgQDHbhORlFzsGCgALSGN"
    "WsCptDCHqim8g8PEGAMprCyJWH5B5xBWMoZslPbPIlx0MsnbS9C6wD/7bFqV2jhU"
    "UbHrHHEcQl/Mrzvppa15AReoEKOXfThg5pjGgG7lM4MH+snPLpI7qowPAN03aIFY"
    "InVGJ1vohKJCB//je1LADY7+0wKBgQC0DbgeCYap/2Vu7+HekRcAkot6kOncKpSd"
    "5oVf6G1Qk09FHRVxUjw4dknHXZqqPT6bBX98g0ZwvvHFrkk+kZPXrWU5N8qXc2lf"
    "fjWEyHKC1sQ5jOUNwwef0j+tvpoiA/py6mfB+72kPqkk0FfQNhHJrRjGQB9R0Rf/"
    "pn7H3Qjg8wKBgQCh6/sReW+U9ewMcJhMaAIEB9xbWkr219ksLv7qZ/PlNCeXJJ+8"
    "DNvd73kRJuoAIniIiF8aMhwA7LID96FCvO4DYh1of2+/BgxUIYPeuodVmuToi/Ap"
    "pTEoAoGHsTJTWUlf4YUz0r5TNDVo1n4mbBvh8PULrhz8Ffiq36eJbbjLpwKBgF2y"
    "JfW7j1A3j1lDi45+gjHSELMfZhMkNWJV62IVWY1smvukPtxRpvTa2Vnd4/ZjGIkj"
    "O0xYI/fX5YixQXxF1WGO4fX8inh1nogK7V7D0JM1n7czEp8utnD8wBZx8VNyLopO"
    "YOAZWH53/R0jLg8zk94XLaU9CQ9Sd+KZibAH3e7xAoGBAJ5EPf87Vbs5gC8DpVo0"
    "dOn1obATw1vEJ9Lii3uAn1gJGWpyhk4zX154GLTYvI/md8z8Cos2UlMtUjzBqWro"
    "Q3VPcCufCmA2/5zj3Of0vgy418F3nLbsG+0kOvZeWbV2g/zuofVHD1Yt/Bp1Kwxd"
    "2yBR7sljRuhZlV1CrwwG6CFb"
)

# ── token ─────────────────────────────────────────────────────
AUD_MESH = "1j0vgTqagJUHuT6nLmbTGx"
# ★★★ 十号坑（真机 Watch 6，2026-10-16）：scope 必须【合并 VSS】
#
#   服务端对同一 audience 只保留【最新】一条 token：先换 MESH、再换 VSS
#   （同 audience）→ 先前拿到的 MESH 立即失效
#   （实测 WWW-Authenticate: Bearer realm=1j0vgTqagJUHuT6nLmbTGx,error="invalid_token"）。
#   这会让车控恒 401（cmd/send 用 MESH 作 Authorization）。
#
#   修法与官方 subTokenData 的 httpLiMeshServiceV2 一致：一次换取 4 个 scope，
#   车控与 VSS 共用同一条 token。实测合并后 cmd-result/VSS/wakeup 全 200，
#   且连续调用互不顶掉。
SCOPE_MESH = ("remote-wakeup:wakeup veh-ctrl:cmd-send "
              "veh-ctrl:cmd-result-get vss:get-batch")
# VSS 与 MESH 同 audience → 不单独换取，TokenManager.vss() 直接复用 mesh()
AUD_VSS = "1j0vgTqagJUHuT6nLmbTGx"
SCOPE_VSS = "vss:get-batch"
AUD_VAT = "5Tc7yDrnMzALwc9Rytl9sp"

AUD_SAOS_VEHICLE = "7gbeHMwBPMZA5SU1b2awIo"
SCOPE_SAOS_VEHICLE = "login"

# ── 端点 ──────────────────────────────────────────────────────
EP_WAKEUP = "/iot-connect-manager-service/v2/wakeup"
EP_CMD_SEND = "/ssp-vehicle-control-service/ssp-vehicle-control/cmd/send"
EP_CMD_RESULT = "/ssp-vehicle-control-service/ssp-vehicle-control/cmd-result"
EP_VSS_BATCH = "/ssp-cloud-vss-service/mobile/vss/get-batch"
EP_SAOS_VEHICLES = (
    "/saos-vehicle-api/v2-0/vehicles/basics"
    "?types=owned,transferring,authorized,inviting&roleIds=1,10,11,13,15&vehicleInfo=true"
)
EP_AUTH = "/api/auth"

# ── 车控 ──────────────────────────────────────────────────────
CTRL_DOMAIN = "xcu"
CMD_EXPIRE = 30
LONG_CMD_EXPIRE = 900
CMD_EXPIRE_MS = 30_000
LONG_CMD_EXPIRE_MS = 900_000

LONG_RUNNING_CMD_KEYS = {"remoteVehACSmartControl", "rmCtrl"}

PUSH_STATE_SUCCESS = 5
PUSH_STATE_FAILED = 7
SUCCESS_RESULT_CODES = {0, "0", -15, "-15", -8, "-8"}

# ── 轮询（★ 只用于【短任务】：解闭锁 / 授权驾驶）─────────────
# 空调等长任务不适用：锁车状态整车休眠，远程唤醒 + 执行空调在服务端是
# jobExpire=900 的长任务，pushState 可能 1 分钟以上才进终态。
# 手表端空调走 poll=False（只等「下发被接受」），结果交给 VSS 回读 +
# OPTIMISTIC_TTL 乐观保护确认 —— 否则 UI 的 busy 态会锁死按钮面板。
CMD_POLL_TIMEOUT = 60.0
CMD_POLL_INTERVAL = 2.0
VSS_BATCH_SIZE = 50
# ★ 乐观更新有效期（秒）：车控下发后 VSS 信号（FOffStatus / SetTemp）可能
#   数十秒才刷新，窗口内以【本地乐观值】为准，避免被滞后旧值回冲
#   （否则表现为「刚点开空调，按钮又跳回『开空调』」）。
#   撤销条件：VSS 与乐观值一致（车端已确认）或本 TTL 到期。
#   对齐参考项目 climate.py 的 _optimistic_* + OPTIMISTIC_TTL。
OPTIMISTIC_TTL = 150.0

# ── 错误码 ────────────────────────────────────────────────────
ERR_JOB_CHANNEL = 2009
ERR_SERVICE_UNAVAILABLE = 100035
ERR_NO_PERMISSION = 100012
ERR_SIGN_INVALID = 100005

RESULT_CODE_HINTS = {
    "2009": "该命令走理想 App 的 LiNdn（JOB）通道，HTTP 接口不支持",
    "100035": "服务暂时不可用（该接口不属于本车型平台）",
    "100012": "没有接口访问权限",
    "100005": "签名校验失败",
    "-2": "车辆执行失败",
    "-3": "车辆执行失败",
}

# ── 四个目标功能的命令定义 ─────────────────────────────────────
# （用户需求：解闭车锁 / 授权驾驶 / 开关空调 / 寻车）
CMD_LOCK = "remoteVehLockControl"
CMD_AUTH = "remoteVehAuth"          # 授权驾驶，cmdData 恒为 {}
CMD_AC = "remoteVehACSmartControl"
CMD_SEARCH = "remoteVehSearch"

AC_TYPE_FRONT = "frtACSw"
AC_COUNTDOWN = "15"
AC_MIN_TEMP = 16
AC_MAX_TEMP = 28   # ★ L6 Max 的 temp.other.maxTemp = 28（不是通用的 30）
AC_DEFAULT_TEMP = 26

# VAT scope 需要逐条列出的命令名（注意名字已含 remoteVeh 前缀）
#
# ⚠️ 关于条数：三个来源给出了三个不同的数字
#     · sub_token_data.json 的 VAT      = 10 条（APK 原始定义）
#     · sub_token_data.json 的 VAT_1    = 12 条（+fTkC +rmCtrl）
#     · 参考项目 li_api.py 的常量        = 14 条（再 +cpCtrl +ssCtrl）
#   而 sub_token_data.json 明确警告：**【多请求 App 没有的 scope 会导致
#   服务端整批降级】**（实测 14 个 → 只给 8 个）。
#
#   因此本工具不照抄 14 条，而是【只请求真正要用的命令】。
#   4 个目标功能只涉及 4 个 scope —— 最小化请求最稳。
VAT_SCOPE_REQUIRED = (
    "remoteVehLockControl",     # 解闭车锁
    "remoteVehAuth",            # 授权驾驶（cmdData = {}）
    "remoteVehACSmartControl",  # 开关空调
    "remoteVehSearch",          # 寻车（闪灯/鸣笛同用）
)

# 完整集（要做更多功能时才用；默认不启用，避免整批降级）
VAT_SCOPE_EXTENDED = VAT_SCOPE_REQUIRED + (
    "remoteVehFrgControl",
    "remoteVehWdwControl",
    "remoteVehPlgControl",
    "remoteVehACFirstControl",
    "remoteADCtrl",
    "remoteADInit",
    "fTkC",
    "rmCtrl",
)


def vat_scope(vin: str, extended: bool = False) -> str:
    """VAT token 的 scope：每条命令都要单独列出并带 :<VIN>。

    extended=False（默认）只请求 4 个目标功能所需的 scope。
    """
    cmds = VAT_SCOPE_EXTENDED if extended else VAT_SCOPE_REQUIRED
    return " ".join(f"{c}:{vin}" for c in cmds)
