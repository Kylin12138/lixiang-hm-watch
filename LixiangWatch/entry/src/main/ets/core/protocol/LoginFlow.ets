/**
 * 登录编排器 —— 把「PAKE 登录 → keySuite 派生 → 拉车辆 → 落库」串起来。
 *
 * 与 Python 侧 verify_tool/lx_main.py 的 `login` / `derive` 子命令一一对应。
 *
 * ★ 关键顺序（不能颠倒）：
 *   1. PAKE 六步登录        → main_bearer + sessionCookies（含 sso_token）
 *   2. syncParentDomainCookies → 把 sso_token 注入 .lixiang.com 父域
 *   3. keySuite 派生        → hac_key + keyId（有效期 4 个月，应缓存）
 *   4. 拉车辆列表（需签名头）→ vin
 *   5. 写入 preferences
 *
 * 缺任何一步，后续换 scope token 都会 login_required。
 */

import { hilog } from '@kit.PerformanceAnalysisKit';
import { LixiangLogin, LoginResult, LoginError, NeedSmsCode, NeedPassword }
  from './PakeLogin';
import { bcryptAsync } from '../crypto/HeavyCrypto';
import { deriveIdentity, DerivedIdentity, IdentityDeriveError } from './KeySuite';
import { TokenManager, SessionCookie, syncParentDomainCookies } from './TokenManager';
import { Signer } from './Signer';
import { AppState, Credentials } from '../../common/AppState';

const DOMAIN: number = 0x0001;
const TAG: string = 'LixiangWatch';

/** 登录阶段（供 UI 显示进度） */
export enum LoginPhase {
  Pake = 'PAKE 登录',
  Derive = '派生设备身份',
  Vehicles = '拉取车辆列表',
  Save = '保存凭据',
  Done = '完成'
}

/** 登录进度回调 */
export type ProgressFn = (phase: LoginPhase, detail: string) => void;

/** 登录结果 */
export interface LoginOutcome {
  phone: string;
  deviceId: string;
  mainBearer: string;
  refreshToken: string;
  hacKeyHex: string;
  keyId: string;
  vin: string;
  vehicleName: string;
  cookieCount: number;
}

/** 车辆摘要（供 UI 选车） */
export interface VehicleBrief {
  vin: string;
  name: string;
  plateNo: string;
  model: string;
  modelId: string;
  vehicleType: string;
}

/**
 * 一次完整的登录流程。
 *
 * @param ctx        UIAbilityContext（用于写 preferences）
 * @param phone      手机号
 * @param password   密码明文
 * @param deviceId   设备 id；不传则沿用已存的，或新建
 * @param onProgress 进度回调（可选）
 */
export async function loginAndPrepare(
  ctx: object,
  phone: string,
  password: string,
  deviceId?: string,
  onProgress?: ProgressFn
): Promise<LoginOutcome> {

  const prog = (p: LoginPhase, d: string): void => {
    hilog.info(DOMAIN, TAG, '[登录] %{public}s: %{public}s', p, d);
    if (onProgress !== undefined) {
      onProgress(p, d);
    }
  };

  // ── 0. 复用/新建 device id ──
  const app: AppState = AppState.get();
  const prev: Credentials | null = app.credentials;
  let dev: string = (deviceId ?? '').trim();
  if (dev.length === 0 && prev !== null && prev.deviceId.length > 0) {
    dev = prev.deviceId;
  }

  // ── 1. PAKE 登录 ──
  prog(LoginPhase.Pake, '正在登录…（设备端密码学计算约需 20~30 秒）');
  // ★ bcryptAsync：内部走 taskpool 工作线程（纯 ArkTS bcrypt 在 Watch 6 上约 6s，
  //   摊在主线程会触发 THREAD_BLOCK_6S 被 SIG 9 强杀）
  const login: LixiangLogin = new LixiangLogin(bcryptAsync, dev);
  let res: LoginResult;
  try {
    res = await login.login(phone, password);
  } catch (e) {
    const err = e as Error;
    if (err instanceof NeedSmsCode) {
      throw new LoginError('sms', 0,
        '该设备需要短信验证：请在手机 App 上登录一次以提高设备信任度后重试');
    }
    if (err instanceof NeedPassword) {
      throw new LoginError('password', 0, '账号密码错误，请检查后重试');
    }
    if (err instanceof LoginError) {
      throw err;                     // 已是本模块错误，原样上抛
    }
    throw new LoginError('pake', 0, `登录失败: ${err.message}`);
  }
  const cookies: Array<SessionCookie> = login.getCookies();
  prog(LoginPhase.Pake,
    `登录成功，cookie ${cookies.length} 条，token ${res.accessToken.substring(0, 16)}…`);

  // ── 2. 注入父域 cookie（★★ 换 scope token 的硬前提）──
  if (dev.length === 0) {
    dev = login.deviceId;
  }
  const injected: boolean = syncParentDomainCookies(dev, cookies);
  if (!injected) {
    throw new LoginError('cookie', 0,
      '登录成功但未拿到 sso_token，无法换取业务 token。请重试登录。');
  }

  // ── 3. keySuite 派生 ──
  prog(LoginPhase.Derive, '正在派生设备身份（hac_key）…');
  const tDerive0: number = Date.now();
  let id: DerivedIdentity;
  try {
    id = await deriveIdentity(dev, res.accessToken);
  } catch (e) {
    const de = e as Error;
    throw new LoginError('derive', 0,
      `设备身份派生失败: ${de instanceof Error ? de.message : '未知错误'}`);
  }
  const remainDays: number = Math.floor((id.validTo - Date.now()) / 86400000);
  prog(LoginPhase.Derive,
    `hac_key 派生成功（keyId=${id.keyId}，剩余约 ${remainDays} 天，耗时 ${Date.now() - tDerive0}ms）`);

  // ── 4. 拉车辆列表（★ 必须带签名头）──
  prog(LoginPhase.Vehicles, '正在拉取车辆列表…');
  const tVeh0: number = Date.now();
  const signer: Signer = new Signer({
    hacKey: hexToBytes(id.hacKeyHex),
    keyId: id.keyId,
    deviceId: dev,
    // ★ 与 AppState.buildClients 保持一致：X-CHJ-TOKEN 用主 bearer，不能用空串
    appToken: res.accessToken
  });
  const tm: TokenManager = new TokenManager(res.accessToken, dev, '', cookies);
  let vehicles: Array<Record<string, Object>> = [];
  try {
    vehicles = await tm.listVehicles(signer);
  } catch (e) {
    const te = e as Error;
    throw new LoginError('vehicles', 0,
      `车辆列表拉取失败: ${te instanceof Error ? te.message : '未知错误'}`);
  }
  if (vehicles.length === 0) {
    throw new LoginError('vehicles', 0,
      '账号下没有可用车辆。请确认车辆已绑定到该账号。');
  }

  const v: VehicleBrief = toBrief(vehicles[0]);
  prog(LoginPhase.Vehicles,
    `找到 ${vehicles.length} 辆车，使用「${v.name}」（耗时 ${Date.now() - tVeh0}ms）`);

  // ── 5. 落库 ──
  prog(LoginPhase.Save, '正在保存凭据…');
  const cred: Credentials = {
    deviceId: dev,
    phone: phone,
    mainBearer: res.accessToken,
    refreshToken: res.refreshToken,
    // ★ 记录绝对到期时间：ensureTokens() 据此提前静默续期，
    //   避免「bearer 过期 → 第一次车控失败 → 只能重新走 23.6s PAKE」
    mainExpiresAt: res.expiresIn > 0 ? Date.now() + res.expiresIn * 1000 : 0,
    hacKey: id.hacKeyHex,
    keyId: id.keyId,
    vin: v.vin,
    vehicleName: v.name,
    sessionCookies: cookies
  };
  await app.saveCredentials(cred);
  // 重新装配客户端
  await app.load();

  prog(LoginPhase.Done, '登录完成');

  return {
    phone: phone,
    deviceId: dev,
    mainBearer: res.accessToken,
    refreshToken: res.refreshToken,
    hacKeyHex: id.hacKeyHex,
    keyId: id.keyId,
    vin: v.vin,
    vehicleName: v.name,
    cookieCount: cookies.length
  };
}

/** 把服务端车辆对象转成 UI 友好的摘要 */
export function toBrief(o: Record<string, Object>): VehicleBrief {
  const g = (k: string): string => {
    const v: Object = o[k];
    return v === undefined || v === null ? '' : String(v);
  };
  const model: Object = o['vehicleModel'];
  const modelStr: string = model === undefined || model === null
    ? '' : String(model);
  const name: string = g('vehicleName').length > 0 ? g('vehicleName') : g('nickname');
  return {
    vin: g('vin'),
    name: name,
    plateNo: g('plateNo'),
    model: modelStr,
    modelId: g('modelId'),
    vehicleType: g('vehicleType')
  };
}

/** hex → 字节（严格校验，同 AppState 的版本：损坏时立即报错而非静默产出 0） */
function hexToBytes(hex: string): Uint8Array {
  const s: string = hex.replace(/[\s\r\n]/g, '');
  if (s.length === 0 || (s.length & 1) !== 0) {
    throw new Error(`hex 长度非法：${s.length}（应为非零偶数）`);
  }
  const out: Uint8Array = new Uint8Array(s.length >> 1);
  for (let i = 0; i < out.length; i++) {
    const hi: number = hexVal(s.charAt(i * 2));
    const lo: number = hexVal(s.charAt(i * 2 + 1));
    if (hi < 0 || lo < 0) {
      throw new Error(`hex 含非法字符：位置 ${i * 2}`);
    }
    out[i] = (hi << 4) | lo;
  }
  return out;
}

/** 单个 hex 字符 → 0..15；非法返回 -1 */
function hexVal(ch: string): number {
  const c: number = ch.charCodeAt(0);
  if (c >= 48 && c <= 57) {
    return c - 48;
  }
  if (c >= 97 && c <= 102) {
    return c - 87;
  }
  if (c >= 65 && c <= 70) {
    return c - 55;
  }
  return -1;
}

