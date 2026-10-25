/**
 * PAKE 登录 —— 与 Python 的 lx_login.py 一一对应
 *
 * ═══════════════════════════════════════════════════════════════
 *  协议（理想自研 PAKE，非标准 SRP）
 * ═══════════════════════════════════════════════════════════════
 *
 *  1. seed = sha256(password) as int  mod 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF61
 *     → 32 hex
 *
 *  2. POST /api/idps {seed, strategy:PASSWORD, connection:LI_USER, user_tip}
 *     → t_login_use { option:"bcrypt$2a$10$", seeded:<32hex>, snonce:"HZ:<32hex>" }
 *
 *  3. salt    = "$2a$10$" + bcryptB64(16字节(seeded))     ← 22 字符
 *     ed_priv = sha256( bcrypt(password, salt) )          ← 32 字节种子
 *     msg     = sha256( bytes(snonce后缀) ‖ bytes(cnonce) )
 *     proof   = Ed25519.sign(msg, ed_priv).hex()          ← 128 hex
 *
 *  4. POST /api/login {proof:{cnonce,snonce,proof}}
 *     401(空体)          = 密码错误
 *     Location 含 SMS    = 风控，需手机浏览器建立设备信任
 *     成功               = Location 含 code=HZ.xxx
 *
 *  5. POST /api/token {grant_type:authorization_code, code, code_verifier}
 *     → access_token（主 Bearer）+ refresh_token
 *
 * ═══════════════════════════════════════════════════════════════
 *  ★★ 与 Python 版的唯一重大差异：cookie 必须手动管理
 * ═══════════════════════════════════════════════════════════════
 *
 *  ArkTS 的 @ohos.net.http **不维护 cookie jar**（每次 createHttp 都是新的），
 *  而理想服务端依赖 cookie：
 *    · 第 2 步 GET /login 会 Set-Cookie 一个页面会话
 *    · 第 5 步 /api/token 成功后会 Set-Cookie sso_token（435 字符 JWT）
 *    · 之后换 scope token 时必须回传 sso_token，否则恒 login_required
 *
 *  所以本模块自己实现：
 *    · CookieJar  —— 手动解析 Set-Cookie、跨请求携带
 *    · syncParentDomainCookies() —— 把 sso_token 同步到父域 .lixiang.com
 *      （对齐 App 的 util/e.smali:1143）
 *
 *  ⚠️ 手表端不做滑动验证，故首次登录必然 SMS 风控。
 *     标准流程：手表展示链接 → 用户手机浏览器打开完成验证 →
 *     服务器把 device_id 标记可信 → 手表再登录即通过。
 */

import { http } from '@kit.NetworkKit';
import { BusinessError } from '@kit.BasicServicesKit';
import {
  BASE_ID, BASE_ACCT, CLIENT_ID, LOGIN_AUDIENCE, LOGIN_SCOPE, REDIRECT_URI,
  SDK_VERSION, APP_VERSION, SEED_MOD, B64_BCRYPT, LOGIN_PAGE, APP_AUTH_PAGE,
  EP_API_AUTH, EP_API_DEVICES, EP_API_IDPS, EP_API_LOGIN, EP_API_TOKEN,
  DEVICE_OS, DEVICE_OS_VERSION, DEVICE_SCREEN_H, DEVICE_SCREEN_W, LOGIN_UA
} from './Constants';
import {
  utf8ToBytes, bytesToUtf8, bytesToHex, hexToBytes,
  bytesToBase64Url, concatBytes
} from '../crypto/Codec';
import { sha256, ed25519Sign, sha256Hex, randomBytes, uuid4Hex } from '../crypto/HarmonyCrypto';
import { SessionCookie, syncParentDomainCookies } from './TokenManager';
import { hilog } from '@kit.PerformanceAnalysisKit';

const DOMAIN: number = 0x0001;
const TAG: string = 'LixiangWatch';

// ─────────────────────────────────────────────────────────────
//  错误类型
// ─────────────────────────────────────────────────────────────

export class LoginError extends Error {
  step: string;
  status: number;
  detail: string;

  constructor(step: string, status: number = 0, detail: string = '') {
    super(status > 0 ? `[${step}] HTTP ${status} ${detail}` : `[${step}] ${detail}`);
    this.name = 'LoginError';
    this.step = step;
    this.status = status;
    this.detail = detail;
  }
}

/** 设备未受信任，需要短信验证 —— 应引导用户走手机浏览器辅助登录 */
export class NeedSmsCode extends LoginError {
  constructor(step: string, status: number, detail: string) {
    super(step, status, detail);
    this.name = 'NeedSmsCode';
  }
}

/** 账号/密码被拒 */
export class NeedPassword extends LoginError {
  constructor(step: string, status: number, detail: string) {
    super(step, status, detail);
    this.name = 'NeedPassword';
  }
}

// ─────────────────────────────────────────────────────────────
//  Cookie 容器（ArkTS 无内置 cookie jar，自己实现）
// ─────────────────────────────────────────────────────────────

/**
 * 极简 cookie jar。
 *
 * 只要域名匹配（精确或父域后缀）就回传，不做 path/expires 的严格校验
 * —— 理想服务端只用少量 cookie，这样足够且不易出错。
 */
export class CookieJar {
  private items: Array<SessionCookie> = [];

  set(name: string, value: string, domain: string, path: string = '/'): void {
    if (name.length === 0 || value.length === 0) {
      return;
    }
    // 同名同域覆盖（幂等）
    for (let i = 0; i < this.items.length; i++) {
      const c = this.items[i];
      if (c.name === name && c.domain === domain) {
        c.value = value;
        c.path = path;
        return;
      }
    }
    this.items.push({ name, value, domain, path, expires: 0 });
  }

  all(): Array<SessionCookie> {
    return this.items;
  }

  /** 生成请求头 Cookie 值（null 表示无需携带） */
  headerFor(host: string): string {
    const out: Array<string> = [];
    for (let i = 0; i < this.items.length; i++) {
      const c = this.items[i];
      const d = c.domain;
      let match = false;
      if (d.length === 0) {
        match = true;
      } else if (d.startsWith('.')) {
        // 父域 cookie：host 等于 d 去掉点，或以 d 结尾
        match = host === d.substring(1) || host.endsWith(d);
      } else {
        match = host === d;
      }
      if (match && c.value.length > 0) {
        out.push(`${c.name}=${c.value}`);
      }
    }
    return out.join('; ');
  }

  /** 解析响应里的 Set-Cookie（http 模块可能给数组、逗号拼接串或单个串） */
  absorb(setCookie: string | string[] | Object | undefined, host: string): void {
    if (setCookie === undefined || setCookie === null) {
      return;
    }
    const raw: Array<string> = [];
    if (Array.isArray(setCookie)) {
      const arr = setCookie as Array<string>;
      for (let i = 0; i < arr.length; i++) {
        raw.push(String(arr[i]));
      }
    } else if (typeof setCookie === 'string') {
      // ★ 若模块把多条 cookie 用 ", " 拼成一个字符串，必须再拆开。
      //   判定依据：逗号后紧跟 `name=`，且 name 不含空格 ——
      //   `Expires=Wed, 21 Oct 2026 07:28:00 GMT` 里的逗号后面是数字，
      //   不会命中，所以这个拆分不会误伤日期。
      const s = setCookie as string;
      const segs: Array<string> = s.split(/,\s*(?=[A-Za-z_][\w\-]*=)/);
      for (let i = 0; i < segs.length; i++) {
        raw.push(segs[i]);
      }
    } else {
      raw.push(String(setCookie));
    }
    for (let i = 0; i < raw.length; i++) {
      this.parseOne(raw[i], host);
    }
  }

  private parseOne(line: string, host: string): void {
    if (line.length === 0) {
      return;
    }
    const segs = line.split(';');
    if (segs.length === 0) {
      return;
    }
    const kv = segs[0];
    const eq = kv.indexOf('=');
    if (eq <= 0) {
      return;
    }
    const name = kv.substring(0, eq).trim();
    const value = kv.substring(eq + 1).trim();
    let domain = host;
    for (let i = 1; i < segs.length; i++) {
      const s = segs[i].trim();
      const low = s.toLowerCase();
      if (low.startsWith('domain=')) {
        domain = s.substring(7).trim();
      }
    }
    this.set(name, value, domain);
  }
}

// ─────────────────────────────────────────────────────────────
//  PAKE 原语
// ─────────────────────────────────────────────────────────────

/** createSeed：sha256(password) mod SEED_MOD，补齐 32 hex */
export function createSeed(password: string): string {
  const digestHex = sha256Hex(utf8ToBytes(password));
  let x = BigInt('0x' + digestHex) % SEED_MOD;
  let s = x.toString(16);
  while (s.length < 32) {
    s = '0' + s;
  }
  return s;
}

/** bcryptjs 的 encodeBase64（自定义字母表，无填充） */
export function bcryptB64(data: Uint8Array): string {
  const out: Array<string> = [];
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < data.length; i++) {
    acc = (acc << 8) | (data[i] & 0xFF);
    bits += 8;
    while (bits >= 6) {
      bits -= 6;
      out.push(B64_BCRYPT.charAt((acc >> bits) & 0x3F));
    }
  }
  if (bits > 0) {
    out.push(B64_BCRYPT.charAt((acc << (6 - bits)) & 0x3F));
  }
  return out.join('');
}

/** seeded(32hex) → 大整数 → 补齐 32hex → 16 字节 → bcrypt b64（22 字符） */
export function seededToSaltedStr(seededHex: string): string {
  let s = (BigInt('0x' + seededHex) % SEED_MOD).toString(16);
  while (s.length < 32) {
    s = '0' + s;
  }
  return bcryptB64(hexToBytes(s));
}

/** t_login_use 的结构 */
export interface TLoginUse {
  option?: string;
  kdf?: string;
  seeded?: string;
  salted?: string;
  snonce?: string;
}

/** 计算出的 proof 三件套 */
export interface ProofBundle {
  cnonce: string;
  snonce: string;
  proof: string;
}

/**
 * bcrypt 实现签名：由调用方注入（手表端用 core/crypto/HeavyCrypto.ets 的 bcryptAsync）。
 *
 * ★ 返回 Promise —— Watch 6 上纯 ArkTS bcrypt（cost=10）同步耗时约 6s，
 *   若在主线程直接跑会触发 THREAD_BLOCK_6S 看门狗把进程 SIG 9 杀掉，
 *   表现为「点登录 → 卡住 → 闪退」。故必须走 taskpool 工作线程。
 */
export type BcryptFn = (password: string, salt: string) => Promise<string>;

/**
 * 依服务器 t_login_use 计算 proof。
 *
 * @param bcryptFn bcrypt 实现。手表端传 `bcryptAsync`（core/crypto/HeavyCrypto.ets，
 *                 内部走 taskpool 工作线程）。底层实现已用 bcryptjs / Python bcrypt
 *                 双向对拍验证（含中文密码）。
 *                 注意 salt 必须是完整 29 字符（$2a$10$ + 22 字符体），
 *                 且 bcrypt 输出必须是标准 bcrypt 编码串（60 字符）。
 */
export async function createV2Proof(password: string, t: TLoginUse,
                                    bcryptFn: BcryptFn,
                                    cnonce?: string): Promise<ProofBundle> {
  const option = t.option ?? t.kdf ?? '';
  const snonce = t.snonce ?? '';
  if (option.length === 0 || snonce.length === 0) {
    throw new LoginError('proof', 0, 't_login_use 字段缺失');
  }

  let saltBody = '';
  const saltedHex = t.salted ?? '';
  if (saltedHex.length > 0) {
    // 只取非零字节，逐字节转字符
    const raw = hexToBytes(saltedHex);
    const chars: Array<string> = [];
    for (let i = 0; i < raw.length; i++) {
      if (raw[i] !== 0) {
        chars.push(String.fromCharCode(raw[i]));
      }
    }
    saltBody = chars.join('');
  } else {
    saltBody = seededToSaltedStr(t.seeded ?? '');
  }

  // option 形如 "bcrypt$2a$10$"，去掉前缀 "bcrypt" 留 "$2a$10$"
  const saltHead = option.startsWith('bcrypt') ? option.substring(6) : option;
  // ★ 秒级计算 → taskpool（await 期间主线程保持可响应，避免 THREAD_BLOCK_6S）
  const bcHash: string = await bcryptFn(password, saltHead + saltBody);
  const edPriv = sha256(utf8ToBytes(bcHash));

  const cn = (cnonce !== undefined && cnonce.length > 0) ? cnonce : bytesToHex(randomBytes(16));
  const snonceTail = snonce.split(':').pop() ?? '';
  const msg = sha256(concatBytes(hexToBytes(snonceTail), hexToBytes(cn)));
  const sig = ed25519Sign(edPriv, msg);
  return { cnonce: cn, snonce, proof: bytesToHex(sig) };
}

// ─────────────────────────────────────────────────────────────
//  登录客户端
// ─────────────────────────────────────────────────────────────

/** 登录成功后返回的凭据集合 */
export interface LoginResult {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  idToken: string;
  cookies: Array<SessionCookie>;
}

/** 单次 HTTP 调用结果 */
interface RawResp {
  code: number;
  body: string;
  location: string;
  json: Record<string, Object> | null;
}

/**
 * 手机号 + 密码登录，获取主 Bearer / refresh_token / 登录 cookie。
 *
 * ★ 手表端首次登录必然命中 SMS 风控（不做滑动验证），
 *   标准流程是先在手机浏览器建立 device_id 信任，再调 login()。
 */
export class LixiangLogin {
  readonly deviceId: string;
  private jar: CookieJar = new CookieJar();
  private bcryptFn: BcryptFn;
  private debug: boolean;
  /** 从 headersReceive 事件里成功吸收 Set-Cookie 的次数（真机排障用） */
  private cookieEvents: number = 0;

  constructor(bcryptFn: BcryptFn, deviceId?: string, debug: boolean = false) {
    this.bcryptFn = bcryptFn;
    this.deviceId = (deviceId !== undefined && deviceId.length > 0) ? deviceId : uuid4Hex();
    this.debug = debug;
    // 预置设备 cookie（与 Python 版一致）
    const doms = ['account.lixiang.com', 'id.lixiang.com'];
    for (let i = 0; i < doms.length; i++) {
      this.jar.set('X-LX-Deviceid', this.deviceId, doms[i]);
      this.jar.set('authli_device_id', this.deviceId, doms[i]);
    }
    this.jar.set('isapp', '1', 'account.lixiang.com');
  }

  /** 手机浏览器辅助登录链接（主链接 + 备用链接） */
  browserLoginUrls(): Array<string> {
    const base = APP_AUTH_PAGE + '?mode=h5'
      + `&client_id=${encodeURIComponent(CLIENT_ID)}`
      + `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}`
      + `&response_type=code`
      + `&scope=${encodeURIComponent(LOGIN_SCOPE)}`
      + `&audience=${encodeURIComponent(LOGIN_AUDIENCE)}`
      + `&device_id=${encodeURIComponent(this.deviceId)}`;
    const alt = APP_AUTH_PAGE + '?mode=h5'
      + `&client_id=${encodeURIComponent(CLIENT_ID)}`
      + `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}`
      + `&response_type=code`
      + `&device_id=${encodeURIComponent(this.deviceId)}`;
    return [base, alt];
  }

  getCookies(): Array<SessionCookie> {
    return this.jar.all();
  }

  /** 装载外部 cookie（持久化后复用会话） */
  importCookies(cookies: Array<SessionCookie>): void {
    for (let i = 0; i < cookies.length; i++) {
      const c = cookies[i];
      this.jar.set(c.name, c.value, c.domain, c.path);
    }
  }

  /** 从 headersReceive 事件对象里取 Set-Cookie 并吸收（七号坑的修复落点） */
  private absorbHeaderEvent(h: Object, host: string): void {
    if (h === undefined || h === null) {
      return;
    }
    const obj = h as Record<string, Object>;
    const keys: string[] = Object.keys(obj);
    for (let i = 0; i < keys.length; i++) {
      if (keys[i].toLowerCase() === 'set-cookie') {
        this.jar.absorb(obj[keys[i]], host);
        this.cookieEvents++;
        if (this.debug) {
          console.info(`[cookies] headersReceive 命中 set-cookie #${this.cookieEvents} @${host}`);
        }
        return;
      }
    }
  }

  /** 已吸收的 cookie 事件次数（供诊断显示） */
  cookieEventCount(): number {
    return this.cookieEvents;
  }

  /** 当前 jar 里的 cookie 名（供诊断显示） */
  cookieNames(): string {
    const items: Array<SessionCookie> = this.jar.all();
    const out: Array<string> = [];
    for (let i = 0; i < items.length; i++) {
      out.push(`${items[i].name}@${items[i].domain}`);
    }
    return out.join(',');
  }

  // ---------- 内部：HTTP ----------

  private idaasHeaders(): Record<string, string> {
    const ts: number = Date.now();
    return {
      'idaas-data': `model_name=OpenHarmony;device_model=;device_id=${this.deviceId};`
        + `app_version=${APP_VERSION};client_id=${CLIENT_ID};`
        + `sdk_version=${SDK_VERSION};timestamp=${ts}`,
      'idaas-data-x': 'source_url=registerAction=&pageUrl=&eventID=',
      'origin': BASE_ACCT,
      'referer': BASE_ACCT + '/',
      'User-Agent': LOGIN_UA,
      'x-requested-with': 'XMLHttpRequest'
    };
  }

  /**
   * idaasHeaders + 指定 content-type。
   *
   * ★ ArkTS 不支持对象展开（arkts-no-spread），只能手动逐键拷贝。
   */
  private idaasHeadersWith(contentType: string): Record<string, string> {
    const src: Record<string, string> = this.idaasHeaders();
    const out: Record<string, string> = {};
    const ks: string[] = Object.keys(src);
    for (let i = 0; i < ks.length; i++) {
      out[ks[i]] = src[ks[i]];
    }
    out['content-type'] = contentType;
    return out;
  }

  /**
   * 统一的 HTTP 调用。
   *
   * ★ ArkTS 下 body 只接受 string（表单串或 JSON 串）——
   *   对象字面量不允许隐式传参（arkts-no-untyped-obj-literals），
   *   所以调用方一律先 JSON.stringify / form() 再传。
   *
   * ★★ 二号坑（本会话根因）：@ohos.net.http 的 maxRedirects 默认 30，
   *   会自动跟随 3xx。而 /api/auth 第一步返回的是
   *   `300 {"location":"https://account.lixiang.com/login"}`，
   *   ArkTS 会把这个 POST 原样跟到 /login（一个只收 GET 的页面路由），
   *   nginx 直接回 405 Not Allowed。
   *   requests(默认不跟300) 没这问题 —— 这就是"Python 通、ArkTS 405"的根因。
   *   → redirect=false 时必须显式 maxRedirects: 0 关闭跟随。
   */
  private async call(url: string, method: http.RequestMethod, host: string,
                     headers: Record<string, string>,
                     body: string,
                     redirect: boolean = true): Promise<RawResp> {
    const hdrs: Record<string, string> = {};
    const ks: string[] = Object.keys(headers);
    for (let i = 0; i < ks.length; i++) {
      hdrs[ks[i]] = headers[ks[i]];
    }
    const ck: string = this.jar.headerFor(host);
    if (ck.length > 0) {
      hdrs['Cookie'] = ck;
    }

    const opts: http.HttpRequestOptions = {
      method: method,
      header: hdrs,
      extraData: body,
      connectTimeout: 20000,
      readTimeout: 20000,
      expectDataType: http.HttpDataType.STRING,
      // 0 = 禁止重定向（否则 300 会被跟随，POST /login → 405）
      maxRedirects: redirect ? 30 : 0
    };

    const httpReq = http.createHttp();

    // ★★★ 七号坑（真机 Watch 6 实测，2026-10-16）：cookie 必须在
    //   【响应头到达的瞬间】吸收，不能等 request() 返回。
    //
    //   根因链：
    //     · /api/auth 返回 `300 {"location":".../login"}`
    //       且带 `Set-Cookie: auth_session=...`（host-only，域 id.lixiang.com）
    //     · maxRedirects:0 遇 3xx 会抛 2300047（见下），此时 catch 里
    //       **拿不到 resp 对象** → 300 的 Set-Cookie 永久丢失
    //     · 紧跟其后的 /api/idps 校验会话 → 返回
    //       `412 {"error":"invalid_auth_session"}`
    //
    //   为什么 Python 侧从不复现：requests **不跟随 300**，正常收到响应并把
    //   Set-Cookie 存进 Session。已用对照实验证实——
    //   手工删掉 auth_session 后，Python 侧 /api/idps 必然 412。
    //
    //   修法：订阅 headersReceive。该事件在重定向判定【之前】触发，
    //   因此即便随后抛 2300047，cookie 也已经落袋。
    const self: LixiangLogin = this;
    // ★★ 2300047 路径下拿不到 resp 对象，但 /api/login 的【成功信号就是 302 的
    //    Location】(?code=HZ.xxx&state=...)。若只合成空响应，就会误报
    //    「响应无授权码」。所以把响应头整体缓存，异常时用来重建 RawResp。
    let lastHeader: Record<string, string> = {};
    try {
      httpReq.on('headersReceive', (h: Object) => {
        self.absorbHeaderEvent(h, host);
        lastHeader = PakeLoginHelper.flattenHeader(h);
      });
    } catch (e) {
      console.error('[cookies] headersReceive 订阅失败，300 响应的 Set-Cookie 可能丢失');
    }

    try {
      const resp = await httpReq.request(url, opts);
      // 吸收 Set-Cookie
      // ★★★ 五号坑：ArkTS 把 set-cookie 返回成 string[]（多条 cookie 一条一个元素）。
      //   早期实现走的是 headerValue()，而它对数组只取 arr[0] →
      //   一次响应里除第一条以外的 cookie 全丢（sso_token 常常不在第一条），
      //   结果就是"登录明明成功，换 scope token 却始终 login_required"。
      //   → 这里改取【原始值】，交给 CookieJar.absorb 自己兼容数组/字符串。
      const scRaw: Object | undefined = PakeLoginHelper.headerRaw(resp, 'set-cookie');
      if (scRaw !== undefined && scRaw !== null) {
        this.jar.absorb(scRaw, host);
      }

      const location: string = PakeLoginHelper.headerValue(resp, 'location');
      const text: string = String(resp.result ?? '');
      let json: Record<string, Object> | null = null;
      if (text.length > 0) {
        try {
          json = JSON.parse(text) as Record<string, Object>;
        } catch (e) {
          json = null;
        }
      }
      if (this.debug) {
        console.info(`[login] ${method} ${url} → ${resp.responseCode} loc=${location.substring(0, 80)}`);
      }
      return { code: resp.responseCode, body: text, location: location, json: json };
    } catch (e) {
      // ★★★ 三号坑：maxRedirects=0 时，服务端一返 3xx，http 模块立刻抛
      //   2300047（拿不到响应体）。而 /api/auth 第一步本身就是
      //   `300 {"location":".../login"}`，属于【正常业务码】不是错误。
      //   → 显式吞掉 2300047，合成一个 300 空响应交回调用方。
      const err = e as BusinessError;
      if (err.code === 2300047) {
        // ★ 先让 headersReceive 派发完再返回 —— 否则 finally 里的 destroy()
        //   可能把尚未派发的响应头事件取消掉，300 的 Set-Cookie 与 Location 就白丢了。
        await PakeLoginHelper.drain();
        const loc: string = lastHeader['location'] !== undefined ? lastHeader['location'] : '';
        console.error(`[3xx] 命中 2300047 → 合成 300，location=${loc.substring(0, 90)}`);
        return { code: 300, body: '', location: loc, json: null };
      }
      throw err as Error;
    } finally {
      httpReq.destroy();
    }
  }

  // ---------- 内部：表单编码 ----------

  private static form(pairs: Array<Array<string>>): string {
    const out: Array<string> = [];
    for (let i = 0; i < pairs.length; i++) {
      out.push(`${encodeURIComponent(pairs[i][0])}=${encodeURIComponent(pairs[i][1])}`);
    }
    return out.join('&');
  }

  // ---------- 主流程 ----------

  /**
   * 完整登录。
   *
   * @throws NeedPassword 密码错误
   * @throws NeedSmsCode  设备未受信任（应引导手机浏览器辅助登录）
   */
  async login(phone: string, password: string): Promise<LoginResult> {
    const tLogin0: number = Date.now();
    const phoneTip = phone.startsWith('+') ? phone : '+86' + phone;

    // ── 1. PKCE 授权请求 ──
    const verifier = bytesToBase64Url(randomBytes(32));
    const challenge = bytesToBase64Url(sha256(utf8ToBytes(verifier)));
    const state = bytesToBase64Url(randomBytes(16)).substring(0, 21);

    const form1: string = LixiangLogin.form([
      ['client_id', CLIENT_ID], ['device_id', this.deviceId],
      ['response_type', 'code'], ['redirect_uri', REDIRECT_URI],
      ['offline_access', 'true'], ['state', state],
      ['audience', LOGIN_AUDIENCE], ['scope', LOGIN_SCOPE],
      ['code_challenge', challenge], ['code_challenge_method', 'S256']
    ]);
    const r1: RawResp = await this.call(BASE_ID + EP_API_AUTH,
      http.RequestMethod.POST, 'id.lixiang.com',
      this.idaasHeadersWith('application/x-www-form-urlencoded'),
      form1, false);
    if (r1.code !== 200 && r1.code !== 300) {
      throw new LoginError('auth', r1.code, r1.body.substring(0, 200));
    }

    // ── 2. 打开登录页（初始化页面会话，拿 cookie） ──
    const pageHdrs: Record<string, string> = {
      'accept': 'text/html', 'referer': APP_AUTH_PAGE, 'User-Agent': LOGIN_UA
    };
    await this.call(
      `${LOGIN_PAGE}?client_id=${encodeURIComponent(CLIENT_ID)}`
      + `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}`,
      http.RequestMethod.GET, 'account.lixiang.com', pageHdrs, '');

    // ── 3. 设备注册 ──
    const body3: string = JSON.stringify({
      'client_id': CLIENT_ID, 'device_id': this.deviceId,
      'user_agent': LOGIN_UA, 'model': '', 'manufacturer': '',
      'os': DEVICE_OS, 'os_version': DEVICE_OS_VERSION,
      'screen_height': DEVICE_SCREEN_H, 'screen_width': DEVICE_SCREEN_W,
      'app_version': APP_VERSION
    } as Record<string, Object>);
    const r3: RawResp = await this.call(BASE_ID + EP_API_DEVICES,
      http.RequestMethod.POST, 'id.lixiang.com',
      this.idaasHeadersWith('application/json'), body3);
    if (r3.code !== 200) {
      throw new LoginError('devices', r3.code, r3.body.substring(0, 200));
    }

    // ── 4. PAKE 握手 ──
    const body4: string = JSON.stringify({
      'origin': BASE_ACCT, 'connection': 'LI_USER',
      'seed': createSeed(password), 'strategy': 'PASSWORD',
      'user_tip': phoneTip
    } as Record<string, Object>);
    const r4: RawResp = await this.call(BASE_ID + EP_API_IDPS,
      http.RequestMethod.POST, 'id.lixiang.com',
      this.idaasHeadersWith('application/json'), body4);
    if (r4.code !== 200) {
      // ★ 七号坑的诊断落点：412 + invalid_auth_session =
      //   第 1 步 /api/auth(300) 的 auth_session 没被吸收。
      console.error(`[idps] HTTP ${r4.code} cookie事件=${this.cookieEvents} jar=[${this.cookieNames()}]`);
      const hint: string = r4.body.indexOf('invalid_auth_session') >= 0
        ? ' ← auth_session 丢失(/api/auth 的 300 响应头未被吸收)'
        : '';
      throw new LoginError('idps', r4.code, r4.body.substring(0, 160) + hint);
    }
    const tUseObj: Object | undefined = (r4.json ?? {})['t_login_use'];
    if (tUseObj === undefined || tUseObj === null) {
      throw new LoginError('idps', 0, `响应无 t_login_use: ${r4.body.substring(0, 200)}`);
    }
    const tUse: TLoginUse = tUseObj as TLoginUse;

    // ── 5. proof → 授权码 ──
    // ★ 第 1~4 步均为网络 await，主线程不阻塞；第 5 步是唯一的重计算点。
    hilog.info(DOMAIN, TAG, '[耗时] 网络握手(step1-4) %{public}d ms', Date.now() - tLogin0);
    const tProof0: number = Date.now();
    const proof: ProofBundle = await createV2Proof(password, tUse, this.bcryptFn);
    hilog.info(DOMAIN, TAG, '[耗时] proof(bcrypt+ed25519) %{public}d ms', Date.now() - tProof0);
    const body5: string = JSON.stringify({
      'client_id': CLIENT_ID, 'connection': 'LI_USER',
      'user_tip': phoneTip, 'proof': proof
    } as Record<string, Object>);
    const r5: RawResp = await this.call(BASE_ID + EP_API_LOGIN,
      http.RequestMethod.POST, 'id.lixiang.com',
      this.idaasHeadersWith('application/json'), body5, false);

    if (r5.code === 401) {
      throw new NeedPassword('login', 401, '密码错误或账号不存在');
    }
    if (r5.code !== 200 && r5.code !== 300 && r5.code !== 302) {
      throw new LoginError('login', r5.code, r5.body.substring(0, 200));
    }

    const location = r5.location;
    if (location.indexOf('require=SMS_CODE') >= 0) {
      throw new NeedSmsCode('login', r5.code,
        '密码正确但风控要求短信验证（需先用手机浏览器建立设备信任）');
    }

    let code: string = PakeLoginHelper.queryParam(location, 'code');
    if (code.length === 0 && r5.json !== null) {
      const c: Object = r5.json['code'];
      if (c !== undefined && c !== null) {
        code = String(c);
      }
    }
    if (code.length === 0) {
      throw new LoginError('login', r5.code, `响应无授权码: ${location.substring(0, 200)}`);
    }

    // ── 6. 换 token ──
    const form6: string = LixiangLogin.form([
      ['client_id', CLIENT_ID], ['grant_type', 'authorization_code'],
      ['code', code], ['code_verifier', verifier]
    ]);
    const r6: RawResp = await this.call(BASE_ID + EP_API_TOKEN,
      http.RequestMethod.POST, 'id.lixiang.com',
      this.idaasHeadersWith('application/x-www-form-urlencoded'), form6);
    if (r6.code !== 200) {
      throw new LoginError('token', r6.code, r6.body.substring(0, 200));
    }

    // ★★ 关键：登录成功后把 sso_token 同步到父域 .lixiang.com
    //    换 scope token 时必须带它，否则永远 login_required
    syncParentDomainCookies(this.deviceId, this.jar.all());

    const j: Record<string, Object> = r6.json ?? {};
    return {
      accessToken: String(j['access_token'] ?? ''),
      refreshToken: String(j['refresh_token'] ?? ''),
      expiresIn: Number(j['expires_in'] ?? 0),
      idToken: String(j['id_token'] ?? ''),
      cookies: this.jar.all()
    };
  }

  /** 用 refresh_token 换新的 access_token（免密码，但不续 cookie） */
  async refresh(refreshToken: string): Promise<LoginResult> {
    const form: string = LixiangLogin.form([
      ['client_id', CLIENT_ID],
      ['grant_type', 'refresh_token'],
      ['refresh_token', refreshToken]
    ]);
    const r: RawResp = await this.call(BASE_ID + EP_API_TOKEN,
      http.RequestMethod.POST, 'id.lixiang.com',
      this.idaasHeadersWith('application/x-www-form-urlencoded'), form);
    if (r.code !== 200) {
      throw new LoginError('refresh', r.code, r.body.substring(0, 200));
    }
    const j: Record<string, Object> = r.json ?? {};
    return {
      accessToken: String(j['access_token'] ?? ''),
      refreshToken: String(j['refresh_token'] ?? refreshToken),
      expiresIn: Number(j['expires_in'] ?? 0),
      idToken: String(j['id_token'] ?? ''),
      cookies: this.jar.all()
    };
  }
}

// ─────────────────────────────────────────────────────────────
//  工具
// ─────────────────────────────────────────────────────────────

class PakeLoginHelper {
  /** 按小写名取响应头 —— 返回【原始值】（可能是 string，也可能是 string[]） */
  static headerRaw(resp: http.HttpResponse, name: string): Object | undefined {
    const h = resp.header;
    if (h === undefined || h === null) {
      return undefined;
    }
    const obj = h as Record<string, Object>;
    const keys = Object.keys(obj);
    const lower = name.toLowerCase();
    for (let i = 0; i < keys.length; i++) {
      if (keys[i].toLowerCase() === lower) {
        return obj[keys[i]];
      }
    }
    return undefined;
  }

  /** 把 headersReceive 的事件对象拍平成 Record<string,string>（多值取第一条） */
  static flattenHeader(h: Object): Record<string, string> {
    const out: Record<string, string> = {};
    if (h === undefined || h === null) {
      return out;
    }
    const obj = h as Record<string, Object>;
    const keys: string[] = Object.keys(obj);
    for (let i = 0; i < keys.length; i++) {
      const v: Object = obj[keys[i]];
      if (Array.isArray(v)) {
        const arr = v as Array<string>;
        if (arr.length > 0) {
          out[keys[i].toLowerCase()] = String(arr[0]);
        }
      } else {
        out[keys[i].toLowerCase()] = String(v);
      }
    }
    return out;
  }

  /** 让出一次宏任务 —— 保证已排队的 headersReceive 事件先派发完再接着跑 */
  static drain(): Promise<void> {
    return new Promise<void>((resolve) => {
      setTimeout(() => {
        resolve();
      }, 0);
    });
  }

  /** 按小写名取响应头（数组只取第一条，用于 Location 这类单值头） */
  static headerValue(resp: http.HttpResponse, name: string): string {
    const h = resp.header;
    if (h === undefined || h === null) {
      return '';
    }
    const obj = h as Record<string, Object>;
    const keys = Object.keys(obj);
    const lower = name.toLowerCase();
    for (let i = 0; i < keys.length; i++) {
      if (keys[i].toLowerCase() === lower) {
        const v = obj[keys[i]];
        if (Array.isArray(v)) {
          const arr = v as Array<string>;
          return arr.length > 0 ? String(arr[0]) : '';
        }
        return String(v ?? '');
      }
    }
    return '';
  }

  /** 从 URL query 取参数 */
  static queryParam(url: string, name: string): string {
    const qi = url.indexOf('?');
    if (qi < 0) {
      return '';
    }
    let q = url.substring(qi + 1);
    const hi = q.indexOf('#');
    if (hi >= 0) {
      q = q.substring(0, hi);
    }
    const parts = q.split('&');
    for (let i = 0; i < parts.length; i++) {
      const eq = parts[i].indexOf('=');
      if (eq < 0) {
        continue;
      }
      if (parts[i].substring(0, eq) === name) {
        return decodeURIComponent(parts[i].substring(eq + 1));
      }
    }
    return '';
  }
}
