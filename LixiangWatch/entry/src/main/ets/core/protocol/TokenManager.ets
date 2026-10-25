/**
 * token 换取链 —— 与 Python 的 lx_token.py 一一对应
 *
 * ═══════════════════════════════════════════════════════════════
 *  三条 token
 * ═══════════════════════════════════════════════════════════════
 *
 *  MESH (aud 1j0vgTqagJUHuT6nLmbTGx, ~15min)
 *    scope: remote-wakeup:wakeup veh-ctrl:cmd-send veh-ctrl:cmd-result-get vss:get-batch
 *    用途: cmd/send、cmd-result、wakeup 的 Authorization 【以及 VSS 读信号】
 *    ★★★ 十号坑：vss:get-batch 必须并入本 scope（同 audience 只保留最新 token），
 *        否则后换的 VSS 会顶掉 MESH → 车控恒 401。故 vss() 直接复用 mesh()。
 *
 *  VAT (aud 5Tc7yDrnMzALwc9Rytl9sp, ~20h)
 *    scope: remoteVehLockControl:<VIN> ...  ← 逐条列
 *    用途: cmd/send 的 body.token
 *
 *  （VSS 不再单独换取 —— 见上）
 *
 * ═══════════════════════════════════════════════════════════════
 *  换取方式
 * ═══════════════════════════════════════════════════════════════
 *
 *  POST https://id.lixiang.com/api/auth
 *    Authorization: Bearer <主 Bearer>
 *    Cookie: sso_token=...; isapp=1; ...        ← ★★ 必须有！
 *    body(form): prompt=none, redirect_uri, scope, response_type=token,
 *                device_id, client_id, audience
 *  → 302，Location 的 fragment 里有 access_token
 *
 *  ★★ 头号坑：裸 Bearer 换不了 scope token
 *
 *    服务端 Set-Cookie 把 sso_token 的域设成 id.lixiang.com，
 *    而 /api/auth 换 token 时【校验登录会话】→ 不带 cookie 恒返回
 *      302 https://account.lixiang.com/app-auth?error=login_required
 *    （即便 main_bearer 完全有效！）
 *    参考项目 li_api.py 第 6 行原文：
 *      "裸 Bearer 换不了 scope token (login_required), 必须带登录会话 cookie"
 *    → 所以登录后必须导出 cookie 并在此处携带。
 *
 *  ⚠️ 多请求 App 没有的 scope 会让服务端【整批降级】→ 所以按需最小化
 */

import { http } from '@kit.NetworkKit';
import { BusinessError } from '@kit.BasicServicesKit';
import { Signer } from './Signer';
import {
  BASE_ID, EP_AUTH, CLIENT_ID, REDIRECT_URI,
  AUD_MESH, SCOPE_MESH, AUD_VAT,
  AUD_SAOS_VEHICLE, SCOPE_SAOS_VEHICLE, vatScope
} from './Constants';

/** MESH token 有效期（秒）—— 服务端实际给 ~15 分钟 */
const MESH_TTL_SEC: number = 780;
/** VAT token 有效期（秒）—— 服务端实际给 ~20 小时 */
const VAT_TTL_SEC: number = 19 * 3600;

export class TokenError extends Error {
  constructor(msg: string) {
    super(msg);
    this.name = 'TokenError';
  }
}

/** 一条登录态 cookie（可持久化） */
export interface SessionCookie {
  name: string;
  value: string;
  domain: string;
  path: string;
  expires: number;
}

/** cookie 列表 → 请求头 Cookie 字符串 */
export function cookiesToHeader(cookies: Array<SessionCookie>): string {
  const out: Array<string> = [];
  for (let i = 0; i < cookies.length; i++) {
    const c = cookies[i];
    if (c.value.length === 0) {
      continue;
    }
    out.push(`${c.name}=${c.value}`);
  }
  return out.join('; ');
}

/** 把 cookie 同步到父域 .lixiang.com（对齐 App 的 util/e.smali:1143） */
export function syncParentDomainCookies(deviceId: string,
                                        cookies: Array<SessionCookie>): boolean {
  let sso = '';
  for (let i = 0; i < cookies.length; i++) {
    if (cookies[i].name === 'sso_token' && cookies[i].value.length > 0) {
      sso = cookies[i].value;
      break;
    }
  }
  if (sso.length === 0) {
    return false;
  }
  const add = (name: string, value: string): void => {
    cookies.push({ name, value, domain: '.lixiang.com', path: '/', expires: 0 });
  };
  add('sso_token', sso);
  add('isapp', '1');
  add('X-LX-Deviceid', deviceId);
  add('authli_device_id', deviceId);
  return true;
}

class CachedToken {
  value: string;
  expiresAt: number;

  constructor(value: string, ttlSec: number) {
    this.value = value;
    // 统一用秒为单位，与 Python 版一致
    this.expiresAt = Date.now() / 1000 + ttlSec;
  }

  valid(skewSec: number = 30): boolean {
    return this.value.length > 0 && (Date.now() / 1000) < (this.expiresAt - skewSec);
  }
}

export class TokenManager {
  private mainBearer: string;
  private deviceId: string;
  private vin: string;
  /** ★ 字段名带下划线：ArkTS 里字段与方法不能同名（否则 Duplicate identifier） */
  private _meshTok: CachedToken | null = null;
  private _vatTok: CachedToken | null = null;

  /**
   * ★★★ P0 修复（2026-10-20）：换取进程内去重（in-flight dedupe）。
   *
   * 问题：refresh() 与车控的 run() 都会 await ensureTokens()。若恰好 MESH
   *   过期，两个调用会【并发】各发一次 /api/auth 换 token。而服务端对同一
   *   audience 只保留最新一条 —— 先返回的那次拿到的 token 立刻被第二次
   *   顶掉，谁先用谁 401。这是「十号坑」（同 audience 互顶）的并发变种，
   *   偶发、且现有日志很难抓。
   *
   * 修法：同一时刻只允许一次换取，后续调用直接复用同一个 Promise。
   */
  private _meshPending: Promise<string> | null = null;
  private _vatPending: Promise<string> | null = null;

  /**
   * 失效代际。invalidateAll() 时自增，用于让「已经在飞的换取」在返回时
   * 不把过期结果写回缓存（否则重新登录后可能被旧 token 覆盖）。
   */
  private _gen: number = 0;

  /** ★ 登录态 cookie —— 换 scope token 必须携带 */
  private cookies: Array<SessionCookie> = [];

  constructor(mainBearer: string, deviceId: string, vin: string,
              cookies?: Array<SessionCookie>) {
    this.mainBearer = mainBearer;
    this.deviceId = deviceId;
    this.vin = vin;
    if (cookies !== undefined && cookies !== null) {
      this.setCookies(cookies);
    }
  }

  /** ★★ 装载登录态 cookie（含 sso_token）。换 token 前必须调用。 */
  setCookies(cookies: Array<SessionCookie>): void {
    this.cookies = cookies ?? [];
  }

  getCookies(): Array<SessionCookie> {
    return this.cookies;
  }

  hasSession(): boolean {
    return this.cookiesToHeader().length > 0;
  }

  private cookiesToHeader(): string {
    return cookiesToHeader(this.cookies);
  }

  setMainBearer(t: string): void {
    this.mainBearer = t;
    this.invalidateAll();
  }

  setVin(vin: string): void {
    this.vin = vin;
    // 换 VIN 后旧 VAT 作废；代际自增可让「已在飞的换取」不写回旧缓存
    this._gen = this._gen + 1;
    this._vatTok = null;
    this._vatPending = null;
  }

  // ---------- 底层换取 ----------

  private async exchange(scope: string, audience: string, ttlSec: number): Promise<string> {
    const form = [
      'prompt=none',
      `redirect_uri=${encodeURIComponent(REDIRECT_URI)}`,
      `scope=${encodeURIComponent(scope)}`,
      'response_type=token',
      `device_id=${encodeURIComponent(this.deviceId)}`,
      `client_id=${encodeURIComponent(CLIENT_ID)}`,
      `audience=${encodeURIComponent(audience)}`
    ].join('&');

    const ck = this.cookiesToHeader();
    const httpReq = http.createHttp();

    // ★★★ 八号坑（真机 Watch 6，2026-10-16）：与 PakeLogin 的七号坑同源。
    //   maxRedirects:0 遇 302 会抛 2300047，**此时拿不到 resp 对象**，
    //   而换 token 的成败信号恰恰就在 302 的 Location 上
    //   （?access_token=xxx 或 ?error=login_required）。
    //   不订阅 headersReceive 的话，成功与失败都会退化成「拿不到 token」。
    let lastHeader: Record<string, string> = {};
    try {
      httpReq.on('headersReceive', (h: Object) => {
        lastHeader = TokenManager.flattenHeader(h);
      });
    } catch (e) {
      console.error('[token] headersReceive 订阅失败，302 的 Location 可能取不到');
    }

    let loc: string = '';
    let raw: string = '';
    let code: number = 0;
    try {
      const resp = await httpReq.request(BASE_ID + EP_AUTH, {
        method: http.RequestMethod.POST,
        header: {
          'Authorization': 'Bearer ' + this.mainBearer,
          'Content-Type': 'application/x-www-form-urlencoded',
          // ★★ 决定性的一行：不带 cookie 必然 login_required
          'Cookie': ck
        },
        extraData: form,
        connectTimeout: 20000,
        readTimeout: 20000,
        // ★★ 必须禁止跟随重定向：换 token 的成败信号就在 302 的
        //    Location（...?access_token=xxx 或 ...?error=login_required）上，
        //    @ohos.net.http 默认 maxRedirects=30 会把 302 跟掉，
        //    Location 取不到 → 成功和失败都变成"拿不到 token"。
        maxRedirects: 0
      });
      loc = TokenManager.headerOf(resp, 'location');
      raw = String(resp.result ?? '');
      code = resp.responseCode;
    } catch (e) {
      const err = e as BusinessError;
      if (err.code === 2300047) {
        // 302 属于【正常路径】。等响应头事件派发完，再从缓存取 Location。
        await TokenManager.drain();
        loc = lastHeader['location'] !== undefined ? lastHeader['location'] : '';
        code = 302;
      } else {
        throw err as Error;
      }
    } finally {
      httpReq.destroy();
    }
    return this.resolveToken(loc, raw, code, audience, scope);
  }

  /** 从 Location（或降级到 body）解析 access_token；失败抛可读的 TokenError */
  private resolveToken(loc: string, raw: string, code: number,
                       audience: string, scope: string): string {
    const tok = TokenManager.extractToken(loc);
    if (tok.length > 0) {
      return tok;
    }
    // ★ 显式识别会话失效，给出可操作的错误
    if (loc.indexOf('login_required') >= 0) {
      throw new TokenError(
        '会话失效 (login_required)：登录 cookie 缺失或已过期，需重新登录');
    }
    if (loc.indexOf('access_denied') >= 0) {
      throw new TokenError(
        `scope 被拒 (access_denied): ${scope.substring(0, 80)}`);
    }
    // 有时直接在 body 里
    if (raw.length > 0) {
      try {
        const j = JSON.parse(raw) as Record<string, Object>;
        const at = j['access_token'];
        if (at !== undefined && at !== null) {
          return String(at);
        }
      } catch (e) {
        // 非 JSON，忽略
      }
    }
    throw new TokenError(
      `换取 token 失败 (aud=${audience.substring(0, 12)}): HTTP ${code}, `
      + `location=${loc.substring(0, 150)}`);
  }

  /** 把 headersReceive 的事件对象拍平成 Record<string,string>（多值取第一条） */
  private static flattenHeader(h: Object): Record<string, string> {
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

  /** 让出一次宏任务 —— 保证已排队的 headersReceive 事件先派发完 */
  private static drain(): Promise<void> {
    return new Promise<void>((resolve) => {
      setTimeout(() => {
        resolve();
      }, 0);
    });
  }

  /** 从 HttpResponse 里按小写名取头（ArkTS 的 header 是 object） */
  private static headerOf(resp: http.HttpResponse, name: string): string {
    const h = resp.header;
    if (h === undefined || h === null) {
      return '';
    }
    const obj = h as Record<string, string>;
    const keys = Object.keys(obj);
    const lower = name.toLowerCase();
    for (let i = 0; i < keys.length; i++) {
      if (keys[i].toLowerCase() === lower) {
        return String(obj[keys[i]] ?? '');
      }
    }
    return '';
  }

  /** 从 Location 的 fragment（或 query）取 access_token */
  static extractToken(location: string): string {
    if (location.length === 0) {
      return '';
    }
    let frag = '';
    const hi = location.indexOf('#');
    if (hi >= 0) {
      frag = location.substring(hi + 1);
    } else {
      const qi = location.indexOf('?');
      if (qi >= 0) {
        frag = location.substring(qi + 1);
      }
    }
    if (frag.length === 0) {
      return '';
    }
    const parts = frag.split('&');
    for (let i = 0; i < parts.length; i++) {
      const eq = parts[i].indexOf('=');
      if (eq < 0) {
        continue;
      }
      const k = parts[i].substring(0, eq);
      if (k === 'access_token' || k === 'token') {
        return decodeURIComponent(parts[i].substring(eq + 1));
      }
    }
    return '';
  }

  // ---------- 三个 token ----------

  /**
   * MESH token：车控 Authorization。
   *
   * ★★★ 十号坑：scope 里已含 vss:get-batch —— 服务端对同一 audience 只保留
   *   最新一条 token，若另外单独换 VSS 会把这条顶掉（车控恒 401）。
   *
   * ★ P0：并发调用只发一次请求（见 _meshPending 注释）。
   */
  async mesh(force: boolean = false): Promise<string> {
    if (!force && this._meshTok !== null && this._meshTok.valid()) {
      return this._meshTok.value;
    }
    if (this._meshPending !== null) {
      // 已有一次在换取 → 复用，避免并发换取导致同 audience 互顶
      return await this._meshPending;
    }
    const p: Promise<string> = this.meshFresh();
    this._meshPending = p;
    try {
      return await p;
    } finally {
      this._meshPending = null;
    }
  }

  private async meshFresh(): Promise<string> {
    const gen: number = this._gen;
    const t: string = await this.exchange(SCOPE_MESH, AUD_MESH, MESH_TTL_SEC);
    // 换取期间发生过 invalidateAll（例如重新登录）→ 不写回旧结果
    if (gen === this._gen) {
      this._meshTok = new CachedToken(t, MESH_TTL_SEC);
    }
    return t;
  }

  async vat(force: boolean = false): Promise<string> {
    if (!force && this._vatTok !== null && this._vatTok.valid()) {
      return this._vatTok.value;
    }
    if (this.vin.length === 0) {
      throw new TokenError('换取 VAT token 需要 vin');
    }
    if (this._vatPending !== null) {
      return await this._vatPending;
    }
    const p: Promise<string> = this.vatFresh();
    this._vatPending = p;
    try {
      return await p;
    } finally {
      this._vatPending = null;
    }
  }

  private async vatFresh(): Promise<string> {
    const gen: number = this._gen;
    const vin: string = this.vin;
    const t: string = await this.exchange(vatScope(vin), AUD_VAT, VAT_TTL_SEC);
    if (gen === this._gen) {
      this._vatTok = new CachedToken(t, VAT_TTL_SEC);
    }
    return t;
  }

  /**
   * VSS token（读实时信号）。
   *
   * ★★★ 十号坑：与 MESH 同 audience，服务端只认最后换取的那一条 ——
   *   单独换会顶掉车控用的 MESH。所以这里【直接复用 mesh()】，
   *   因为 SCOPE_MESH 已包含 vss:get-batch。
   */
  async vss(force: boolean = false): Promise<string> {
    return await this.mesh(force);
  }

  invalidateAll(): void {
    // 代际自增：让「已在飞的换取」返回后不写回旧 token
    this._gen = this._gen + 1;
    this._meshTok = null;
    this._vatTok = null;
    this._meshPending = null;
    this._vatPending = null;
  }

  // ---------- 车辆列表 ----------

  /**
   * 拉取车辆列表。
   *
   * ★ 需要 x-chj 签名头 —— 不带会返回
   *   {"code":100002,"msg":"缺少必要的请求参数: X-CHJ-Env,..."}
   */
  async listVehicles(signer: Signer): Promise<Array<Record<string, Object>>> {
    const tok = await this.exchange(SCOPE_SAOS_VEHICLE, AUD_SAOS_VEHICLE, 780);
    const path = '/saos-vehicle-api/v2-0/vehicles/basics'
      + '?types=owned,transferring,authorized,inviting&roleIds=1,10,11,13,15&vehicleInfo=true';
    const hdrs = signer.buildHeaders('GET', '', tok, '');
    hdrs['Accept'] = '*/*';
    const httpReq = http.createHttp();
    try {
      const resp = await httpReq.request('https://api-app.lixiang.com' + path, {
        method: http.RequestMethod.GET,
        header: hdrs,
        connectTimeout: 20000,
        readTimeout: 20000,
        maxRedirects: 0
      });
      if (resp.responseCode !== 200) {
        throw new TokenError(`拉取车辆列表失败 HTTP ${resp.responseCode}`);
      }
      const j = JSON.parse(String(resp.result)) as Record<string, Object>;
      const code = j['code'];
      if (code !== undefined && Number(code) !== 0) {
        throw new TokenError(`拉取车辆列表失败 code=${code} msg=${j['msg']}`);
      }
      const data = (j['data'] ?? j) as Record<string, Object>;
      if (Array.isArray(data)) {
        return data as Array<Record<string, Object>>;
      }
      const keys = ['vehicles', 'list', 'items'];
      for (let i = 0; i < keys.length; i++) {
        const v = data[keys[i]];
        if (Array.isArray(v)) {
          return v as Array<Record<string, Object>>;
        }
      }
      return [];
    } finally {
      httpReq.destroy();
    }
  }
}
