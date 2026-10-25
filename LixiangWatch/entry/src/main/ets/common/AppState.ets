/**
 * 应用状态与凭据管理
 *
 * 职责：装载凭据 → 装配 Signer / TokenManager / VehicleControl / VssReader
 *
 * 存储：使用 @ohos.data.preferences（应用私有，随应用卸载清除）。
 * ⚠️ 生产环境建议再叠一层 HUKS 加密（见 README 的"安全加固"章节）。
 */

import { preferences } from '@kit.ArkData';
import { common } from '@kit.AbilityKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { Signer } from '../core/protocol/Signer';
import {
  TokenManager, SessionCookie, syncParentDomainCookies
} from '../core/protocol/TokenManager';
import { LixiangLogin, LoginResult } from '../core/protocol/PakeLogin';
import { VehicleControl } from '../core/control/VehicleControl';
import { VssReader } from '../core/control/VssReader';
import { bcryptAsync } from '../core/crypto/HeavyCrypto';
import {
  STORE_NAME, K_DEVICE_ID, K_PHONE, K_MAIN_BEARER, K_REFRESH_TOKEN,
  K_MAIN_EXPIRES, K_HAC_KEY, K_KEY_ID, K_VIN, K_VEHICLE_NAME, K_SESSION_COOKIES
} from '../core/protocol/Constants';

const DOMAIN: number = 0x0001;
const TAG: string = 'LixiangWatch';

/** 主 bearer 到期前多久开始静默续期（毫秒） */
const REFRESH_AHEAD_MS: number = 120000;
/** 两次静默续期尝试的最小间隔（毫秒）—— 防止失败时被反复触发 */
const SILENT_RETRY_COOLDOWN_MS: number = 60000;

export interface Credentials {
  deviceId: string;
  phone: string;
  mainBearer: string;
  refreshToken: string;
  /** 主 bearer 的绝对到期时间（毫秒）；0 = 未知 */
  mainExpiresAt: number;
  hacKey: string;
  keyId: string;
  vin: string;
  vehicleName: string;
  /** ★★ 登录态 cookie（含 sso_token）——换 scope token 必需 */
  sessionCookies: Array<SessionCookie>;
}

export class AppState {
  private static _inst: AppState | null = null;
  private store: preferences.Preferences | null = null;
  private cred: Credentials | null = null;
  private _tokenMgr: TokenManager | null = null;
  private _signer: Signer | null = null;
  private _vc: VehicleControl | null = null;
  private _vss: VssReader | null = null;
  /** 正在进行的静默续期（去重，避免并发刷新 bearer） */
  private refreshing: Promise<boolean> | null = null;
  /** 上次静默续期尝试的时间戳 */
  private lastSilentAttempt: number = 0;
  /**
   * ★ 复审补充：登录态代际号。
   *
   * clear()（重新登录）会让在飞的静默续期失去意义 —— 续期用的是【旧】
   * 凭据，完成后若照常 buildClients()，会把刚清掉的旧会话又装回去，
   * 表现为「点了重新登录，界面却自己恢复了 / 或仍用旧 bearer」。
   * 续期开始前快照本值，落地前比对，不一致就整体丢弃。
   */
  private epoch: number = 0;

  static get(): AppState {
    if (AppState._inst === null) {
      AppState._inst = new AppState();
    }
    return AppState._inst;
  }

  // ---------- 持久化 ----------

  private async openStore(ctx: common.UIAbilityContext): Promise<preferences.Preferences> {
    if (this.store === null) {
      this.store = await preferences.getPreferences(ctx, STORE_NAME);
    }
    return this.store;
  }

  /**
   * 装载凭据并装配客户端。返回是否具备完整凭据。
   *
   * ★ P2-2：改用 getSync 批量读取。
   *   以前是 9 次串行的 `await s.get(...)` —— 每次都是一个异步 IPC 往返，
   *   冷启动白白多等好几轮。preferences 在 getPreferences 时已把数据读进
   *   内存缓存，getSync 只是读缓存，不产生 IPC。
   */
  async load(ctx?: common.UIAbilityContext): Promise<boolean> {
    if (ctx !== undefined) {
      await this.openStore(ctx);
    }
    if (this.store === null) {
      return false;
    }
    const s = this.store;
    const rd = (k: string): string => {
      try {
        const v = s.getSync(k, '');
        return v === undefined || v === null ? '' : String(v);
      } catch (e) {
        return '';
      }
    };
    // ★ 统一按字符串存取：preferences 的 getSync(key, defValue) 若遇到
    //   存储类型与 defValue 类型不一致，部分版本会抛类型错误。
    const expRaw: string = rd(K_MAIN_EXPIRES);
    const expNum: number = expRaw.length > 0 ? Number(expRaw) : 0;
    const c: Credentials = {
      deviceId: rd(K_DEVICE_ID),
      phone: rd(K_PHONE),
      mainBearer: rd(K_MAIN_BEARER),
      refreshToken: rd(K_REFRESH_TOKEN),
      mainExpiresAt: isNaN(expNum) ? 0 : expNum,
      hacKey: rd(K_HAC_KEY),
      keyId: rd(K_KEY_ID),
      vin: rd(K_VIN),
      vehicleName: rd(K_VEHICLE_NAME),
      sessionCookies: AppState.parseCookies(rd(K_SESSION_COOKIES))
    };
    this.cred = c;

    if (c.deviceId.length === 0 || c.mainBearer.length === 0) {
      return false;
    }
    if (c.hacKey.length === 0 || c.keyId.length === 0 || c.vin.length === 0) {
      // 登录了但还没派生身份 / 没选车
      hilog.warn(DOMAIN, TAG, '凭据不完整：缺 hac/keyId/vin');
      return false;
    }
    if (c.sessionCookies.length === 0) {
      // ★★ 没有 cookie 就换不到任何 scope token —— 必须重新登录
      hilog.error(DOMAIN, TAG, '凭据不完整：缺登录 cookie（会 login_required）');
      return false;
    }

    try {
      this.buildClients(c);
    } catch (e) {
      // ★ P1：hac_key 损坏（被截断/含非法字符）以前会静默产出 NaN 字节，
      //   最终表现为「签名错误」，极难定位。现在这里直接判定凭据不可用。
      const err = e as Error;
      hilog.error(DOMAIN, TAG, '装配客户端失败（凭据损坏，需重新登录）: %{public}s',
        err.message);
      return false;
    }
    return true;
  }

  private buildClients(c: Credentials): void {
    // 释放旧句柄，避免重新登录后句柄泄漏
    if (this._vc !== null) {
      this._vc.close();
    }
    const signer = new Signer({
      hacKey: hexToBytes(c.hacKey),
      keyId: c.keyId,
      deviceId: c.deviceId,
      // ★ X-CHJ-TOKEN 必须是【主 bearer】。早期传空串：
      //   @ohos.net.http 对空值头大概率直接【跳过不发】→ 网关判缺头 → 401。
      appToken: c.mainBearer
    });
    this._signer = signer;
    // ★★ 传入 cookie —— 否则换 token 一律 login_required
    this._tokenMgr = new TokenManager(c.mainBearer, c.deviceId, c.vin, c.sessionCookies);
    this._vss = new VssReader(signer, c.vin, '');
    this._vc = new VehicleControl(signer, c.vin, '', '');
  }

  /**
   * ★ 换齐车控所需的两把 token 并注入客户端。
   *
   * 车控需要 **双 token**：
   *   Authorization: Bearer <MESH>（aud=1j0vgTqagJUHuT6nLmbTGx）
   *   body.token      = <VAT>（aud=5Tc7yDrnMzALwc9Rytl9sp）
   *
   * 两者都需带登录 cookie 才能换取（否则 login_required）。
   *
   * ★★★ P3 修复：失败时先尝试 refresh_token 静默续期，再重试一次。
   *   以前 token 过期只能重新登录 —— 而手表上重新登录要手输密码 +
   *   23.6 秒 bcrypt。静默续期只是一次 HTTP，体验天差地别。
   */
  async ensureTokens(): Promise<void> {
    // 主动续期：主 bearer 临近到期就先换掉，避免「第一次车控必然失败」
    if (this.shouldProactiveRefresh()) {
      await this.silentRefresh();
    }
    try {
      await this.loadTokens();
    } catch (e) {
      const err = e as Error;
      if (AppState.isAuthRelated(err.message)) {
        hilog.warn(DOMAIN, TAG,
          '换 token 失败(%{public}s)，尝试 refresh_token 静默续期', err.message);
        const ok: boolean = await this.silentRefresh();
        if (ok) {
          await this.loadTokens();
          return;
        }
      }
      throw err;
    }
  }

  private async loadTokens(): Promise<void> {
    const tm = this._tokenMgr;
    const vc = this._vc;
    const vss = this._vss;
    if (tm === null || vc === null || vss === null) {
      throw new Error('凭据未就绪，请先登录');
    }
    if (!tm.hasSession()) {
      throw new Error('登录会话已失效（无 cookie），请重新登录');
    }
    // ★★★ 十号坑（真机 2026-10-16）：MESH 与 VSS 是【同一 audience】，
    //   服务端只保留最后换取的那一条 token。以前这里先换 MESH、再换 VSS，
    //   结果 VSS 把 MESH 顶掉 → cmd/send 恒 401（invalid_token）。
    //   现在 SCOPE_MESH 已并入 vss:get-batch，两者共用同一条 token，
    //   所以这里【绝不能再单独换 VSS】。
    const meshTok: string = await tm.mesh();
    const vatTok: string = await tm.vat();
    vc.setTokens(meshTok, vatTok);
    vss.setToken(meshTok);
    // ★ 真机排障：token 长度能一眼区分「没换到（0）」和「换到了但服务端不认」
    hilog.info(DOMAIN, TAG,
      '[token] MESH+VSS 共用 len=%{public}d VAT len=%{public}d',
      meshTok.length, vatTok.length);
  }

  // ---------- 静默续期 ----------

  /** 主 bearer 是否已到该续期的时候 */
  private shouldProactiveRefresh(): boolean {
    const c = this.cred;
    if (c === null || c.refreshToken.length === 0 || c.mainExpiresAt <= 0) {
      return false;
    }
    if (Date.now() < c.mainExpiresAt - REFRESH_AHEAD_MS) {
      return false;
    }
    // 冷却：失败后别每轮 refresh 都重试
    return Date.now() - this.lastSilentAttempt >= SILENT_RETRY_COOLDOWN_MS;
  }

  /** 错误信息是否属于「登录态问题」（值得用 refresh_token 再试一次） */
  private static isAuthRelated(msg: string): boolean {
    return msg.indexOf('login_required') >= 0
      || msg.indexOf('会话失效') >= 0
      || msg.indexOf('HTTP 401') >= 0
      || msg.indexOf('401 未授权') >= 0
      || msg.indexOf('invalid_token') >= 0;
  }

  /**
   * 用 refresh_token 静默续期（去重：并发调用共享同一次请求）。
   *
   * @returns true = 已换到新 bearer 并重建了客户端；false = 失败（调用方应提示重登）
   */
  async silentRefresh(): Promise<boolean> {
    if (this.refreshing !== null) {
      return await this.refreshing;
    }
    const p: Promise<boolean> = this.doSilentRefresh();
    this.refreshing = p;
    try {
      return await p;
    } finally {
      this.refreshing = null;
    }
  }

  private async doSilentRefresh(): Promise<boolean> {
    const c = this.cred;
    if (c === null || c.refreshToken.length === 0) {
      return false;
    }
    const ep: number = this.epoch;
    this.lastSilentAttempt = Date.now();
    try {
      const login: LixiangLogin = new LixiangLogin(bcryptAsync, c.deviceId);
      // 带上已有 cookie：续期后服务端可能同时下发新的 sso_token
      login.importCookies(c.sessionCookies);
      const r: LoginResult = await login.refresh(c.refreshToken);
      if (ep !== this.epoch) {
        // 期间用户执行了「重新登录」→ 本次续期结果作废，绝不能再写回
        hilog.warn(DOMAIN, TAG, '[续期] 期间登录态已变更，丢弃本次续期结果');
        return false;
      }
      if (r.accessToken.length === 0) {
        hilog.warn(DOMAIN, TAG, '[续期] 响应无 access_token');
        return false;
      }
      const cookies: Array<SessionCookie> = r.cookies;
      // ★ 一号坑：新 cookie 必须同步到父域，否则后续换 scope token 仍然 login_required
      syncParentDomainCookies(c.deviceId, cookies);
      const next: Credentials = {
        deviceId: c.deviceId,
        phone: c.phone,
        mainBearer: r.accessToken,
        refreshToken: r.refreshToken.length > 0 ? r.refreshToken : c.refreshToken,
        mainExpiresAt: r.expiresIn > 0 ? Date.now() + r.expiresIn * 1000 : 0,
        hacKey: c.hacKey,
        keyId: c.keyId,
        vin: c.vin,
        vehicleName: c.vehicleName,
        sessionCookies: cookies
      };
      this.cred = next;
      // ★ 复审修正顺序：先重建客户端，再落盘。
      //   反过来的话，saveCredentials 一旦抛错就走 catch 返回 false，
      //   而 cred 已被替换、客户端却还是旧的 bearer —— 内存与磁盘不一致。
      this.buildClients(next);
      try {
        await this.saveCredentials(next);
      } catch (e) {
        // 落盘失败不影响本次会话，下次启动会重新登录
        const se = e as Error;
        hilog.warn(DOMAIN, TAG, '[续期] 凭据落盘失败（不影响本次会话）: %{public}s',
          se.message);
      }
      hilog.info(DOMAIN, TAG,
        '[续期] 主 bearer 已刷新，len=%{public}d cookie=%{public}d 条',
        r.accessToken.length, cookies.length);
      return true;
    } catch (e) {
      const err = e as Error;
      hilog.warn(DOMAIN, TAG, '[续期] 失败: %{public}s', err.message);
      return false;
    }
  }

  // ---------- cookie 序列化 ----------

  private static parseCookies(raw: string): Array<SessionCookie> {
    if (raw.length === 0) {
      return [];
    }
    try {
      const arr = JSON.parse(raw) as Array<Record<string, Object>>;
      const out: Array<SessionCookie> = [];
      for (let i = 0; i < arr.length; i++) {
        const o = arr[i];
        out.push({
          name: String(o['name'] ?? ''),
          value: String(o['value'] ?? ''),
          domain: String(o['domain'] ?? ''),
          path: String(o['path'] ?? '/'),
          expires: Number(o['expires'] ?? 0)
        });
      }
      return out;
    } catch (e) {
      hilog.warn(DOMAIN, TAG, '解析 cookie 失败，忽略');
      return [];
    }
  }

  // ---------- 访问器 ----------

  get credentials(): Credentials | null {
    return this.cred;
  }

  signer(): Signer {
    if (this._signer === null) {
      throw new Error('凭据未就绪，请先登录');
    }
    return this._signer;
  }

  vehicleControl(): VehicleControl {
    if (this._vc === null) {
      throw new Error('凭据未就绪，请先登录');
    }
    return this._vc;
  }

  vssReader(): VssReader {
    if (this._vss === null) {
      throw new Error('凭据未就绪，请先登录');
    }
    return this._vss;
  }

  tokenManager(): TokenManager {
    if (this._tokenMgr === null) {
      throw new Error('凭据未就绪，请先登录');
    }
    return this._tokenMgr;
  }

  // ---------- 写入 ----------

  async saveCredentials(c: Credentials): Promise<void> {
    if (this.store === null) {
      throw new Error('存储未初始化');
    }
    const s = this.store;
    const map: Array<[string, string]> = [
      [K_DEVICE_ID, c.deviceId], [K_PHONE, c.phone],
      [K_MAIN_BEARER, c.mainBearer], [K_REFRESH_TOKEN, c.refreshToken],
      [K_HAC_KEY, c.hacKey], [K_KEY_ID, c.keyId],
      [K_VIN, c.vin], [K_VEHICLE_NAME, c.vehicleName]
    ];
    for (let i = 0; i < map.length; i++) {
      const k: string = map[i][0];
      const v: string = map[i][1];
      if (v.length > 0) {
        await s.put(k, v);
      }
    }
    // 到期时间单独存（数字 → 字符串）；0 表示未知，直接抹掉旧值避免误判
    await s.put(K_MAIN_EXPIRES, String(c.mainExpiresAt > 0 ? c.mainExpiresAt : 0));
    await s.put(K_SESSION_COOKIES, JSON.stringify(c.sessionCookies));
    await s.flush();
  }

  /**
   * 清空登录态。
   *
   * ★ device_id 必须【保留】：它代表「这台设备」，而不是「登录态」。
   *   Watch 6 实测：沿用同一 device_id 可免短信风控；一旦清掉，
   *   服务端视为全新设备，下次登录大概率被 SMS 风控拦下，
   *   而手表端没有便捷的浏览器辅助登录通道 —— 会直接把用户卡死。
   */
  async clear(): Promise<void> {
    if (this.store === null) {
      return;
    }
    // ★ 复审补充：磁盘操作单独 try —— store 抛异常时【内存态仍必须清掉】，
    //   否则「重新登录」会看到旧凭据还在内存里，startup 又把它装配回来。
    try {
      const keepDev: string = String(this.store.getSync(K_DEVICE_ID, '') ?? '');
      await this.store.clear();
      if (keepDev.length > 0) {
        await this.store.put(K_DEVICE_ID, keepDev);
      }
      await this.store.flush();
    } catch (e) {
      const se = e as Error;
      hilog.error(DOMAIN, TAG, '清空存储失败（内存态仍会清理）: %{public}s', se.message);
    }
    // 释放 http 句柄，避免重新登录后旧客户端继续持资源
    if (this._vc !== null) {
      this._vc.close();
    }
    // ★ 代际自增：让「正在飞的静默续期」完成后不再把旧会话装回来
    this.epoch = this.epoch + 1;
    this.cred = null;
    this._vc = null;
    this._vss = null;
    this._tokenMgr = null;
    this._signer = null;
    this.lastSilentAttempt = 0;
  }
}

/**
 * hex → 字节数组（严格校验）。
 *
 * ★ P1 修复：以前不校验，`parseInt('zz', 16)` 得 NaN，写入 Uint8Array 后
 *   变成 0，最终表现为「签名错误 / 登录失败」，而根因（存储里的 hac_key
 *   损坏或被截断）完全看不出来。现在直接抛，由 load() 转成「需重新登录」。
 */
function hexToBytes(hex: string): Uint8Array {
  const s = hex.replace(/[\s\r\n]/g, '');
  if (s.length === 0 || (s.length & 1) !== 0) {
    throw new Error(`hex 长度非法：${s.length}（应为非零偶数）`);
  }
  const out = new Uint8Array(s.length >> 1);
  for (let i = 0; i < out.length; i++) {
    const hi = hexVal(s.charAt(i * 2));
    const lo = hexVal(s.charAt(i * 2 + 1));
    if (hi < 0 || lo < 0) {
      throw new Error(`hex 含非法字符：位置 ${i * 2}`);
    }
    out[i] = (hi << 4) | lo;
  }
  return out;
}

/** 单个 hex 字符 → 0..15；非法返回 -1 */
function hexVal(ch: string): number {
  const c = ch.charCodeAt(0);
  if (c >= 48 && c <= 57) {
    return c - 48;                // 0-9
  }
  if (c >= 97 && c <= 102) {
    return c - 87;                // a-f
  }
  if (c >= 65 && c <= 70) {
    return c - 55;                // A-F
  }
  return -1;
}
