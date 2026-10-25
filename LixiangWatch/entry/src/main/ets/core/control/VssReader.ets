/**
 * VSS 实时信号读取 —— 与 Python 的 lx_vss.py 一一对应
 *
 * 端点：POST /ssp-cloud-vss-service/mobile/vss/get-batch
 * body：{"vin":"...","paths":[...]}
 * header：Bearer <VSS token>（scope vss:get-batch）
 * 返回：{"items":[{"path":"...","dp":{"value":...,"tsFormat":...}}]}
 */

import { http } from '@kit.NetworkKit';
import { BusinessError } from '@kit.BasicServicesKit';
import { Signer } from '../protocol/Signer';
import { API_APP, EP_VSS_BATCH, VSS_BATCH_SIZE } from '../protocol/Constants';

// ── 功能相关的信号路径 ──
export const SIG_LOCK: string = 'Vehicle.Body.DoorLockStatus.MainDoor';
export const SIG_AC_ON: string = 'Vehicle.Cabin.AC.FOffStatus';
export const SIG_AC_SET_TEMP: string = 'Vehicle.Cabin.AC.SetTemp';
export const SIG_AC_INSIDE_TEMP: string = 'Vehicle.Cabin.AC.FrtACIncarTemp';

export const DEFAULT_PATHS: string[] = [
  SIG_LOCK,
  SIG_AC_ON, SIG_AC_SET_TEMP, SIG_AC_INSIDE_TEMP
];

/** 需要读取状态的功能 */
export interface VehicleState {
  locked: boolean | null;
  acOn: boolean | null;
  acSetTemp: number | null;
  insideTemp: number | null;
}

interface VssItem {
  path?: string;
  dp?: VssDp;
}

interface VssDp {
  value?: Object;
  tsFormat?: string;
}

interface VssResponse {
  items?: VssItem[];
}

/**
 * 失败类型 —— 只有【业务性 HTTP 错误】才值得二分重试。
 *
 * ★ P1 修复：以前不分类型，一律二分降级。网络整段不通或 token 失效时，
 *   4 条路径会放大成最多 7 次 × 20s 超时，而这段时间 refresh() 的
 *   syncing 守卫会把后续刷新全部跳过 → 界面“僵”几分钟。
 */
const FAIL_NONE: number = 0;
/** 网络/超时/302：二分毫无意义，且会成倍放大等待 */
const FAIL_NETWORK: number = 1;
/** 401/403：鉴权问题，重试无意义 */
const FAIL_AUTH: number = 2;
/** 其它 4xx/5xx：可能是某条坏路径拖垮整批 → 二分有意义 */
const FAIL_HTTP: number = 3;

/** 二分降级最大深度（4 条路径下最多 2 层） */
const MAX_BISECT_DEPTH: number = 3;

/** 单次 getChunk 的结果：数据 + 失败类型 */
interface ChunkResult {
  map: Map<string, Object>;
  fail: number;
}

export class VssReader {
  private signer: Signer;
  private vin: string;
  private token: string;

  constructor(signer: Signer, vin: string, token: string) {
    this.signer = signer;
    this.vin = vin;
    this.token = token;
  }

  setToken(token: string): void {
    this.token = token;
  }

  /** 读取一批信号 → Map<path, value> */
  async getBatch(paths: string[]): Promise<Map<string, Object>> {
    const out = new Map<string, Object>();
    // ★ P2-4：整批（含二分重试）共用同一个 http 句柄，避免每次 createHttp
    const h: http.HttpRequest = http.createHttp();
    try {
      for (let i = 0; i < paths.length; i += VSS_BATCH_SIZE) {
        const chunk = paths.slice(i, i + VSS_BATCH_SIZE);
        const r: ChunkResult = await this.getChunk(h, chunk, 0);
        if (r.fail === FAIL_AUTH) {
          // 鉴权失效：后续批次也必然失败，立刻放弃，别刷请求
          break;
        }
        if (r.fail === FAIL_NETWORK) {
          // 网络整段不通：继续发只会叠加超时
          break;
        }
        r.map.forEach((v: Object, k: string) => {
          out.set(k, v);
        });
      }
    } finally {
      h.destroy();
    }
    return out;
  }

  /** 单批读取，失败时按【错误类型】决定是否二分降级 */
  private async getChunk(h: http.HttpRequest, paths: string[],
                         depth: number): Promise<ChunkResult> {
    const out = new Map<string, Object>();
    if (paths.length === 0) {
      return { map: out, fail: FAIL_NONE };
    }
    const body = JSON.stringify({ 'vin': this.vin, 'paths': paths });
    const headers = this.signer.buildHeaders('POST', body, this.token, this.vin);
    let fail: number = FAIL_NONE;
    try {
      const resp = await h.request(API_APP + EP_VSS_BATCH, {
        method: http.RequestMethod.POST,
        header: headers,
        extraData: body,
        connectTimeout: 20000,
        readTimeout: 20000,
        maxRedirects: 0
      });
      if (resp.responseCode === 200) {
        const j: VssResponse = JSON.parse(String(resp.result)) as VssResponse;
        const items: VssItem[] = j.items ?? [];
        for (let i = 0; i < items.length; i++) {
          const it: VssItem = items[i];
          const p: string = it.path ?? '';
          if (p.length === 0) {
            continue;
          }
          // ★ 只写入实际有值的信号；缺值路径不落 Map，
          //   交由 asInt/asFloat/isLocked 的 undefined 分支返回 null
          const dp: VssDp = it.dp ?? {};
          const val: Object | undefined = dp.value;
          if (val !== undefined && val !== null) {
            out.set(p, val);
          }
        }
        return { map: out, fail: FAIL_NONE };
      }
      if (resp.responseCode === 401 || resp.responseCode === 403) {
        fail = FAIL_AUTH;
        console.error(`[vss] HTTP ${resp.responseCode}：token 失效，不重试`);
      } else {
        fail = FAIL_HTTP;
      }
    } catch (e) {
      // ★★ 九号坑同源：maxRedirects:0 遇 3xx 抛 2300047。
      //   这属于【鉴权/重定向】问题，二分重试没有意义 —— 以前会因此
      //   把一次失败放大成 7 次请求。
      const err = e as BusinessError;
      if (err.code === 2300047) {
        console.error('[vss] 302 重定向：token 可能已过期或未登录');
        fail = FAIL_AUTH;
      } else {
        console.error(`[vss] 请求异常，不二分: ${err.message}`);
        fail = FAIL_NETWORK;
      }
    }

    // 只有业务性 HTTP 错误才二分（定位单条坏路径）
    if (fail === FAIL_HTTP && depth < MAX_BISECT_DEPTH && paths.length > 1) {
      const mid = Math.floor(paths.length / 2);
      const a = await this.getChunk(h, paths.slice(0, mid), depth + 1);
      const b = await this.getChunk(h, paths.slice(mid), depth + 1);
      a.map.forEach((v: Object, k: string) => {
        b.map.set(k, v);
      });
      const subFail: number = a.fail === FAIL_AUTH || b.fail === FAIL_AUTH
        ? FAIL_AUTH
        : (a.fail === FAIL_NETWORK || b.fail === FAIL_NETWORK ? FAIL_NETWORK : FAIL_NONE);
      return { map: b.map, fail: subFail };
    }
    return { map: out, fail: fail };
  }

  // ── 语义化读取 ──

  async readState(): Promise<VehicleState> {
    const raw = await this.getBatch(DEFAULT_PATHS);
    return {
      locked: VssReader.isLocked(raw.get(SIG_LOCK)),
      acOn: VssReader.isAcOn(raw.get(SIG_AC_ON)),
      acSetTemp: VssReader.asFloat(raw.get(SIG_AC_SET_TEMP)),
      insideTemp: VssReader.asFloat(raw.get(SIG_AC_INSIDE_TEMP))
    };
  }

  /** DoorLockStatus.MainDoor: 0 = 落锁，非 0 = 解锁 */
  static isLocked(v: Object | undefined): boolean | null {
    if (v === undefined || v === null) {
      return null;
    }
    const n = parseFloat(String(v));
    if (!isNaN(n)) {
      return n === 0;
    }
    const s = String(v).trim().toUpperCase();
    if (s === 'LOCKED' || s === 'LOCK' || s === '1') {
      return true;
    }
    if (s === 'UNLOCKED' || s === 'UNLOCK' || s === '0') {
      return false;
    }
    return null;
  }

  /**
   * FOffStatus: 1 = 开，0 = 关（官方信号，不是风速）。
   *
   * ★ P1 修复：以前「未知值」默认返回 true（当作空调已开）。
   *   FOffStatus 若下发新枚举（如 2/3/文本），会被误判成「已开」，
   *   UI 直接显示「关空调」，用户点一下反而把空调关了。
   *   现在未知值返回 null，UI 走「—」分支，不猜测。
   */
  static isAcOn(v: Object | undefined): boolean | null {
    if (v === undefined || v === null) {
      return null;
    }
    const n = parseFloat(String(v));
    if (!isNaN(n)) {
      if (n === 1) {
        return true;
      }
      if (n === 0) {
        return false;
      }
      return null;
    }
    const s = String(v).trim().toUpperCase();
    if (s === 'ON' || s === 'TRUE' || s === 'OPEN' || s === 'RUNNING') {
      return true;
    }
    if (s === 'OFF' || s === 'FALSE' || s === 'NONE' || s === 'CLOSED' || s === '') {
      return false;
    }
    return null;
  }

  static asInt(v: Object | undefined): number | null {
    if (v === undefined || v === null) {
      return null;
    }
    const n = parseFloat(String(v));
    return isNaN(n) ? null : Math.trunc(n);
  }

  static asFloat(v: Object | undefined): number | null {
    if (v === undefined || v === null) {
      return null;
    }
    const n = parseFloat(String(v));
    return isNaN(n) ? null : n;
  }
}
