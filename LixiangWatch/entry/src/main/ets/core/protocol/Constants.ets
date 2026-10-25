/**
 * 理想汽车协议常量
 *
 * 来源：C3H3-AI/ha-lixiang（Home Assistant 集成）逆向结论，逐条对照 APK 实测值。
 * 本文件是手表端的唯一权威常量表 —— 任何硬编码字符串都应落在这里。
 *
 * ⚠️ 修改任何常量前，先回参考仓库核对对应文件：
 *    const.py / li_api.py / pake_login.py / key_suite.py / sub_token_data.json
 */

// ─────────────────────────────────────────────────────────────
//  基础域名
// ─────────────────────────────────────────────────────────────
export const BASE_ID: string = 'https://id.lixiang.com';
export const BASE_ACCT: string = 'https://account.lixiang.com';
export const API_APP: string = 'https://api-app.lixiang.com';

// ─────────────────────────────────────────────────────────────
//  OAuth / 登录
// ─────────────────────────────────────────────────────────────
/** 主 App（理想汽车）client_id */
export const CLIENT_ID: string = '2AQClOaegaA7XecMSFx1p';
/** 登录用 audience（注意与 VSS/MESH 的 audience 不同！） */
export const LOGIN_AUDIENCE: string = '5iIapSfVJlln0vU0OzUCH9';
export const LOGIN_SCOPE: string = 'iam:client:type:app openid';
export const REDIRECT_URI: string = BASE_ACCT + '/app-auth';

export const SDK_VERSION: string = '0.0.0-snapshot-20240614055722';
export const APP_VERSION: string = '8.22.0';

/** 登录页地址（第 2 步初始化页面会话用） */
export const LOGIN_PAGE: string = BASE_ACCT + '/login';
/** 手机浏览器辅助登录页（建立设备信任） */
export const APP_AUTH_PAGE: string = BASE_ACCT + '/app-auth';

// ── IDaaS 端点 ──
export const EP_API_AUTH: string = '/api/auth';
export const EP_API_DEVICES: string = '/api/devices';
export const EP_API_IDPS: string = '/api/idps';
export const EP_API_LOGIN: string = '/api/login';
export const EP_API_TOKEN: string = '/api/token';

/** 设备注册上报的屏幕信息（手表按手机尺寸上报，服务端不校验） */
export const DEVICE_OS: string = 'OpenHarmony';
export const DEVICE_OS_VERSION: string = '6.1';
export const DEVICE_SCREEN_H: number = 843;
export const DEVICE_SCREEN_W: number = 374;

/** 登录请求用的 UA（App 侧固定，非业务签名 UA） */
export const LOGIN_UA: string =
  'Mozilla/5.0 (Phone; OpenHarmony 6.1) AppleWebKit/537.36 (KHTML, like Gecko) '
  + 'Chrome/132.0.0.0 Safari/537.36  ArkWeb/6.1.0.117 Mobile m01/8.22.0';

/** PAKE createSeed 的模数（登录页 JS: FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF61） */
export const SEED_MOD: bigint = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF61');

/** bcrypt 自定义 base64 字母表（注意开头是 "./" 不是 "./" 的标准变体） */
export const B64_BCRYPT: string = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

// ─────────────────────────────────────────────────────────────
//  业务接口签名（x-chj）
// ─────────────────────────────────────────────────────────────
/** 业务接口签名用的 App 版本号（与登录的 APP_VERSION 不同！） */
export const SIGN_APP_VERSION: string = '8.25.4-10463';
/** keySuite 派生用的版本号 */
export const KEY_SUITE_VER: string = '8.25.4-10463';

export const ENV: string = 'prod';
export const DEFAULT_ACCEPT: string = '*/*';
export const DEFAULT_CONTENT_LANG: string = 'zh-Hans-CN';
export const DEFAULT_CONTENT_TYPE: string = 'application/json';
/** 签名分段分隔符 */
export const SIGN_SEP: string = '\n';
/** 空 body 的 Content-MD5（= base64(md5(""))） */
export const EMPTY_MD5: string = '1B2M2Y8AsgTpgAmY7PhCfg==';

/** 设备类型：2 = iOS。参考项目用 iPad 身份，服务端接受 */
export const DEVICE_TYPE: string = '2';
export const MODEL_NAME: string = 'IOS';
export const DEVICE_MODEL: string = '9.7-INCH IPAD';

export function defaultUserAgent(): string {
  return `m01/${SIGN_APP_VERSION} (iPad; iOS 16.7.12; Scale/2.00)`;
}

// ─────────────────────────────────────────────────────────────
//  签名身份派生（keySuite）
// ─────────────────────────────────────────────────────────────
export const EP_KEY_SUITE_DDES: string = '/ddes/v1-1/app/key-suite';
/** 主 App 的 device key id */
export const MAIN_DEVICE_KEY_ID: string = '020026d02bf87a0a153144000075c05e';

/**
 * 主 App 的 RSA 私钥（PKCS#8 DER，base64）。
 *
 * ⚠️ 这不是用户凭据 —— 它是硬编码在理想官方 App 里的"设备身份密钥"，
 *    所有安装了官方 App 的设备共用同一把。参考项目 v1.4.7 起才改为
 *    "现场派生"以此替代早期内置的成品签名凭据。
 *    这里保留原样，因为 keySuite 的 body 签名必须用它。
 */
export const MAIN_RSA_PRIVATE_DER_B64: string =
  'MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCMRBXH3xiTKCLv' +
  'jxvSgnaGdDWN1QgS/OR6C4slAuYfVUuvEyUZUnQS7PPRr5K8/Vs8DFvMrL13huAA' +
  'FrlioDeB9j7PMLUwtw5LZxx4FUBiTYMQgUWrxB19kdd1MbgJvACymTBuumFjBHiO' +
  'HCRofDZ//VNrrSWezoqnWHNW4SINvbT2bO1qeXHp+UasgaKL6uRL/aufb4wsSiZi' +
  'E7sRwQWlPWAMGncTPMjeiriNvfYRNbXhvE+qghucPmuSlg04cB7ZX7kSbwj32C9t' +
  'llCEILAKK0RT3QKB+C86o4xYbU6dU098+fi04t9Tg6SIkuOwDOhHXhZKlFZNtI2S' +
  'ZqMbTIJJAgMBAAECggEAGMwIlbcpHwrfcj54irSpw4dT2Gkq7kBrG/Bifv6ONEfe' +
  'A2t9CYb8IkRlrlI9vM+Fi44bxIldTX44p4tc5sSwS3d/Dx3rSltyWX43GDuZkEdn' +
  'vkk8Set30zUvQ/awNHhaHzjZyRmGEf0+WtE61oXvFJ1yW/zWQ8b72C3Y5ikS3h7C' +
  'gp1y0XJE1GRgTWvguFftz/QVwDpJR6CwOXDoJNoB7tyJH9DwIF4Ta00VzB21DTd0' +
  'n1Gc1sfz8iG5GC8amWfNsql1Q/wOr+o5sBnVrErj6otnHEiUGJEcYXV7icztTGK5' +
  '2U3t0lzd4ALM/9sz9XsiEt6UgKIL4pW3xAN4NRoaCQKBgQDHbhORlFzsGCgALSGN' +
  'WsCptDCHqim8g8PEGAMprCyJWH5B5xBWMoZslPbPIlx0MsnbS9C6wD/7bFqV2jhU' +
  'UbHrHHEcQl/Mrzvppa15AReoEKOXfThg5pjGgG7lM4MH+snPLpI7qowPAN03aIFY' +
  'InVGJ1vohKJCB//je1LADY7+0wKBgQC0DbgeCYap/2Vu7+HekRcAkot6kOncKpSd' +
  '5oVf6G1Qk09FHRVxUjw4dknHXZqqPT6bBX98g0ZwvvHFrkk+kZPXrWU5N8qXc2lf' +
  'fjWEyHKC1sQ5jOUNwwef0j+tvpoiA/py6mfB+72kPqkk0FfQNhHJrRjGQB9R0Rf/' +
  'pn7H3Qjg8wKBgQCh6/sReW+U9ewMcJhMaAIEB9xbWkr219ksLv7qZ/PlNCeXJJ+8' +
  'DNvd73kRJuoAIniIiF8aMhwA7LID96FCvO4DYh1of2+/BgxUIYPeuodVmuToi/Ap' +
  'pTEoAoGHsTJTWUlf4YUz0r5TNDVo1n4mbBvh8PULrhz8Ffiq36eJbbjLpwKBgF2y' +
  'JfW7j1A3j1lDi45+gjHSELMfZhMkNWJV62IVWY1smvukPtxRpvTa2Vnd4/ZjGIkj' +
  'O0xYI/fX5YixQXxF1WGO4fX8inh1nogK7V7D0JM1n7czEp8utnD8wBZx8VNyLopO' +
  'YOAZWH53/R0jLg8zk94XLaU9CQ9Sd+KZibAH3e7xAoGBAJ5EPf87Vbs5gC8DpVo0' +
  'dOn1obATw1vEJ9Lii3uAn1gJGWpyhk4zX154GLTYvI/md8z8Cos2UlMtUjzBqWro' +
  'Q3VPcCufCmA2/5zj3Of0vgy418F3nLbsG+0kOvZeWbV2g/zuofVHD1Yt/Bp1Kwxd' +
  '2yBR7sljRuhZlV1CrwwG6CFb';

// ─────────────────────────────────────────────────────────────
//  token audience / scope
// ─────────────────────────────────────────────────────────────
/**
 * MESH token：驱动车控通道权限（15 分钟）。
 *
 * ★★★ 十号坑（真机 Watch 6，2026-10-16）：scope 必须【合并 VSS】
 *
 *   服务端对同一 audience (1j0vgTqagJUHuT6nLmbTGx) 只保留【最新】一条 token：
 *   先换 MESH、再换 VSS（同 audience）→ 先前拿到的 MESH 立即失效
 *   （实测 WWW-Authenticate: error="invalid_token"）。
 *
 *   这直接导致车控 401：
 *     ensureTokens(): 换 MESH → 换 VAT → 换 VSS(顶掉 MESH) → cmd/send 401
 *
 *   修法（与官方 App 的 subTokenData 一致）：把 vss:get-batch 并入本 scope
 *   一次换取，车控与 VSS 共用同一条 token。
 *   官方 subTokenData 原文：
 *     {"type":"httpLiMeshServiceV2","audience":"1j0vgTqagJUHuT6nLmbTGx",
 *      "scope":["remote-wakeup:wakeup","veh-ctrl:cmd-result-get","veh-ctrl:cmd-send",
 *               "vss:get-batch","task-master"]}
 *
 *   实测（合并后）：cmd-result ✅200、VSS get-batch ✅200、wakeup ✅200 code:0，
 *   且连续互不顶掉。
 */
export const AUD_MESH: string = '1j0vgTqagJUHuT6nLmbTGx';
export const SCOPE_MESH: string =
  'remote-wakeup:wakeup veh-ctrl:cmd-send veh-ctrl:cmd-result-get vss:get-batch';
/**
 * VSS 与 MESH 同 audience，故不单独换取 —— 见上方十号坑。
 * 保留常量仅供文档/校验用；TokenManager.vss() 直接复用 MESH。
 */
export const AUD_VSS: string = '1j0vgTqagJUHuT6nLmbTGx';
export const SCOPE_VSS: string = 'vss:get-batch';
/** VAT token：具体车控命令的 scope 授权（约 20 小时） */
export const AUD_VAT: string = '5Tc7yDrnMzALwc9Rytl9sp';

/** L6 车辆列表接口的 audience */
export const AUD_SAOS_VEHICLE: string = '7gbeHMwBPMZA5SU1b2awIo';
export const SCOPE_SAOS_VEHICLE: string = 'login';

/**
 * VAT scope 需要逐条列出的命令名。
 *
 * ⚠️ 关于条数：参考项目里有三个不同来源给出三个数字
 *    · sub_token_data.json 的 VAT   = 10 条（APK 原始定义）
 *    · sub_token_data.json 的 VAT_1 = 12 条
 *    · li_api.py 的常量              = 14 条
 *  而 sub_token_data.json 明确警告：【多请求 App 没有的 scope 会导致
 *  服务端整批降级】（实测 14 个 → 只给 8 个）。
 *
 *  本工程只做 4 个功能 → 只请求所需的 4 个 scope，最小化最稳。
 */
export const VAT_SCOPE_REQUIRED: string[] = [
  'remoteVehLockControl',    // 解闭车锁
  'remoteVehAuth',           // 授权驾驶（cmdData = {}）
  'remoteVehACSmartControl', // 开关空调
  'remoteVehSearch'          // 寻车（闪灯/鸣笛同用）
];

/** 扩展集（要做更多功能时才用；默认不启用，避免整批降级） */
export const VAT_SCOPE_EXTENDED: string[] = VAT_SCOPE_REQUIRED.concat([
  'remoteVehFrgControl',
  'remoteVehWdwControl',
  'remoteVehPlgControl',
  'remoteVehACFirstControl',
  'remoteADCtrl',
  'remoteADInit',
  'fTkC',
  'rmCtrl'
]);

/** 生成 VAT scope 字符串（每条命令 + :VIN） */
export function vatScope(vin: string, extended: boolean = false): string {
  const cmds = extended ? VAT_SCOPE_EXTENDED : VAT_SCOPE_REQUIRED;
  return cmds.map((c: string) => `${c}:${vin}`).join(' ');
}

// ─────────────────────────────────────────────────────────────
//  端点
// ─────────────────────────────────────────────────────────────
export const EP_WAKEUP: string = '/iot-connect-manager-service/v2/wakeup';
export const EP_CMD_SEND: string = '/ssp-vehicle-control-service/ssp-vehicle-control/cmd/send';
export const EP_CMD_RESULT: string = '/ssp-vehicle-control-service/ssp-vehicle-control/cmd-result';
export const EP_VSS_BATCH: string = '/ssp-cloud-vss-service/mobile/vss/get-batch';
export const EP_SAOS_VEHICLES: string =
  '/saos-vehicle-api/v2-0/vehicles/basics?types=owned,transferring,authorized,inviting' +
  '&roleIds=1,10,11,13,15&vehicleInfo=true';
/** 授权换 token 的端点（PKCE，从 Location fragment 取 access_token） */
export const EP_AUTH: string = '/api/auth';

// ─────────────────────────────────────────────────────────────
//  车控
// ─────────────────────────────────────────────────────────────
/** cmd/send 的 domain，固定为 xcu */
export const CTRL_DOMAIN: string = 'xcu';
/** 短命令有效期（秒） */
export const CMD_EXPIRE: number = 30;
/** 长命令有效期（秒）—— 空调/座椅加热/后视镜加热必须用这个 */
export const LONG_CMD_EXPIRE: number = 900;
/** 上面两个的毫秒形式（用于 expireAt = now + N） */
export const CMD_EXPIRE_MS: number = CMD_EXPIRE * 1000;
export const LONG_CMD_EXPIRE_MS: number = LONG_CMD_EXPIRE * 1000;

// ── 四类命令的 cmdKey（真机实测值） ──
/** 解闭车锁 */
export const CMD_LOCK: string = 'remoteVehLockControl';
/** 授权驾驶（App 实现类 XHttpRemoteStartControl，cmdData 恒为空对象） */
export const CMD_AUTH: string = 'remoteVehAuth';
/** 开关空调 */
export const CMD_AC: string = 'remoteVehACSmartControl';
/** 寻车 / 闪灯 / 鸣笛（同一 cmdKey，靠 searchType 区分） */
export const CMD_SEARCH: string = 'remoteVehSearch';

// ── 空调字段 ──
/** acCtrlType：前排空调开关 */
export const AC_TYPE_FRONT: string = 'frtACSw';
/** acCountdownTimer：App 默认 15 分钟倒计时 */
export const AC_COUNTDOWN: string = '15';
/** ★ L6 Max 实测温度范围是 16-28（不是通用的 30） */
export const AC_MIN_TEMP: number = 16;
export const AC_MAX_TEMP: number = 28;
export const AC_DEFAULT_TEMP: number = 26;

/** 需要长有效期的命令（实测 jobExpire=30 会超时 ps=7 rc=空） */
export const LONG_RUNNING_CMD_KEYS: string[] = [
  'remoteVehACSmartControl', // 空调 / 座椅加热 / 方向盘加热 / 除霜
  'rmCtrl'                   // 后视镜加热（App TimeOut=660s）
];

/** pushState 终态 */
export const PUSH_STATE_SUCCESS: number = 5;
export const PUSH_STATE_FAILED: number = 7;

/** resultCode 中"视为成功"的集合（-15 = 倒计时完成，-8 = 同类特判） */
export const SUCCESS_RESULT_CODES: (number | string)[] = [0, '0', -15, '-15', -8, '-8'];

/**
 * 轮询参数 —— ★ 只用于【短任务】（解闭车锁 / 授权驾驶）。
 *
 * 空调等长任务不适用：锁车状态下车辆休眠，远程唤醒 + 执行空调在服务端
 * 是 jobExpire=900 的长任务，pushState 可能超过 1 分钟才进终态。
 * 若一并轮询，UI 的 busy 态会把整个按钮面板锁死 60 秒（真机实测的
 * 「关空调按钮一直转圈、点不动」）。
 * 手表端空调走 poll=false：只等「下发被接受」，结果交给 VSS 回读
 * + OPTIMISTIC_TTL_MS 乐观保护确认。见 Index.ets onAcTap()。
 */
export const CMD_POLL_TIMEOUT_MS: number = 60000;
export const CMD_POLL_INTERVAL_MS: number = 2000;

/** VSS 批量读取的每批上限（实测超过会被服务端拒） */
export const VSS_BATCH_SIZE: number = 50;

/**
 * ★ 乐观更新的有效期（毫秒）—— 空调这类长任务的状态保护窗口。
 *
 * 背景：车控下发后 VSS 信号（FOffStatus / SetTemp）可能延迟数十秒才刷新。
 * 这段时间内必须以【本地乐观值】为准，否则 refresh() 会用滞后旧值把用户
 * 刚点出来的状态冲掉 —— 表现为「刚点开空调，按钮又跳回『开空调』」。
 *
 * 撤销条件（满足任一即以 VSS 为准）：
 *   · 车端已确认：VSS 值与乐观值一致
 *   · 本 TTL 到期
 * 实现见 Index.ets 的 applyAcOptimistic()（对齐参考项目 climate.py 的
 * _optimistic_on / _optimistic_temp + OPTIMISTIC_TTL）。
 */
export const OPTIMISTIC_TTL_MS: number = 150000;

// ─────────────────────────────────────────────────────────────
//  错误码对照（真机实测）
// ─────────────────────────────────────────────────────────────
export const ERR_JOB_CHANNEL: number = 2009;       // 命令走 JOB 通道，HTTP 不可达
export const ERR_SERVICE_UNAVAILABLE: number = 100035; // X 系调 M 系端点
export const ERR_NO_PERMISSION: number = 100012;       // X 系调老平台 App API
export const ERR_SIGN_INVALID: number = 100005;        // 签名构造错误

export const RESULT_CODE_HINTS: Record<string, string> = {
  '2009': '该命令走理想 App 的 LiNdn（JOB）通道，HTTP 接口不支持',
  '100035': '服务暂时不可用（该接口不属于本车型平台）',
  '100012': '没有接口访问权限',
  '100005': '签名校验失败',
  '-2': '车辆执行失败',
  '-3': '车辆执行失败'
};

// ─────────────────────────────────────────────────────────────
//  本地存储键名
// ─────────────────────────────────────────────────────────────
export const STORE_NAME: string = 'lixiang_watch_store';
export const K_DEVICE_ID: string = 'device_id';
export const K_PHONE: string = 'phone';
export const K_MAIN_BEARER: string = 'main_bearer';
export const K_REFRESH_TOKEN: string = 'refresh_token';
export const K_MAIN_EXPIRES: string = 'main_bearer_expires';
export const K_HAC_KEY: string = 'hac_key';
export const K_KEY_ID: string = 'key_id';
export const K_VIN: string = 'vin';
export const K_VEHICLE_NAME: string = 'vehicle_name';
// ★★ 登录态 cookie（JSON 数组字符串）—— 换 scope token 必需，
//    没有它 /api/auth 恒返 error=login_required
export const K_SESSION_COOKIES: string = 'session_cookies';
