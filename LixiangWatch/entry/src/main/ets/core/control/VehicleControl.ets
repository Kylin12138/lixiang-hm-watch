/**
 * 车控通道 —— 与 Python 的 lx_vehicle.py 一一对应
 *
 * ═══════════════════════════════════════════════════════════════
 *  完整流程
 * ═══════════════════════════════════════════════════════════════
 *
 *  ① POST /iot-connect-manager-service/v2/wakeup      ← 唤醒（可失败）
 *     body: {"source":"0x3B","bizId":"0"}  header: Bearer MESH
 *
 *  ② POST /ssp-vehicle-control-service/ssp-vehicle-control/cmd/send
 *     body: {vin, cmdKey, cmdData, domain:"xcu",
 *            jobExpire, expire, expireAt, token:<VAT>}
 *     → requestId
 *
 *  ③ GET .../cmd-result/{requestId}  每 2s 轮询到 pushState ∈ {5,7}
 *
 * ═══════════════════════════════════════════════════════════════
 *  ★ 实战要点（都是踩过的坑）
 * ═══════════════════════════════════════════════════════════════
 *
 *  · jobExpire：短命令 30 / 长命令（空调）必须 900，否则超时 ps=7 rc=空
 *  · body.token 必须是 VAT（不是 MESH，不是 "0"，不是空）
 *  · Authorization 必须是 MESH
 *  · pushState=7 但 resultCode ∈ {0,-8,-15} → 实际成功（倒计时到期）
 *  · 超时未到终态（pushState=1）→ 不报错！命令可能已生效
 *  · acCtrlTemp 必须是 Number，其余三个空调字段必须是 String
 *  · L6 Max 温度范围 16-28
 */

import { http } from '@kit.NetworkKit';
import { BusinessError } from '@kit.BasicServicesKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { Signer } from '../protocol/Signer';
import {
  API_APP, EP_WAKEUP, EP_CMD_SEND, EP_CMD_RESULT, CTRL_DOMAIN,
  CMD_EXPIRE, LONG_CMD_EXPIRE, CMD_EXPIRE_MS, LONG_CMD_EXPIRE_MS,
  LONG_RUNNING_CMD_KEYS, PUSH_STATE_SUCCESS, PUSH_STATE_FAILED,
  CMD_POLL_TIMEOUT_MS, CMD_POLL_INTERVAL_MS,
  ERR_JOB_CHANNEL, RESULT_CODE_HINTS,
  CMD_LOCK, CMD_AUTH, CMD_AC, CMD_SEARCH,
  AC_TYPE_FRONT, AC_COUNTDOWN, AC_MIN_TEMP, AC_MAX_TEMP, AC_DEFAULT_TEMP
} from '../protocol/Constants';

const DOMAIN: number = 0x0001;
const TAG: string = 'LixiangWatch';

export class LiCommandError extends Error {
  requestId: string;
  resultCode: string | number | undefined;
  pushState: number | undefined;

  constructor(message: string, requestId: string = '',
              resultCode?: string | number, pushState?: number) {
    super(message);
    this.name = 'LiCommandError';
    this.requestId = requestId;
    this.resultCode = resultCode;
    this.pushState = pushState;
  }
}

export interface CommandResult {
  ok: boolean;
  requestId: string;
  cmdKey: string;
  pushState?: number;
  resultCode?: string | number;
  resultMsg?: string;
  timeout?: boolean;
}

export class VehicleControl {
  private signer: Signer;
  private vin: string;
  private meshToken: string;
  private vatToken: string;
  private debug: boolean;

  /**
   * ★ P2-4：复用 http 句柄。
   *
   * 以前每次 signedCall 都 http.createHttp() + destroy()，60 秒轮询 = 30 个对象，
   * 每个都带 native 侧资源。现在整个车控实例共用一个句柄，
   * 并用 inUse 串行化（同一 HttpRequest 不支持并发 request）。
   */
  private h: http.HttpRequest | null = null;
  private inUse: boolean = false;

  constructor(signer: Signer, vin: string, meshToken: string,
              vatToken: string, debug: boolean = false) {
    this.signer = signer;
    this.vin = vin;
    this.meshToken = meshToken;
    this.vatToken = vatToken;
    this.debug = debug;
  }

  setTokens(mesh: string, vat: string): void {
    this.meshToken = mesh;
    this.vatToken = vat;
  }

  /** 释放底层 http 句柄（应用退出/重新登录时调用） */
  close(): void {
    this.dropHandle();
  }

  // ---------- 底层 ----------

  /**
   * 把服务端可能返回的 number / string 统一成 number。
   * ★ P1：pushState 之前用 `=== 5` 严格比较，若服务端返回 "5" 就会一直
   *   等满超时再报「车辆未及时回报」—— 明明成功了。
   */
  private static numOf(v: Object | undefined | null): number | null {
    if (v === undefined || v === null) {
      return null;
    }
    const n = Number(v);
    return isNaN(n) ? null : n;
  }

  /** resultCode 是否属于「视为成功」集合（-15 = 倒计时完成，-8 = 同类特判） */
  private static isSuccessCode(v: string | number | undefined): boolean {
    if (v === undefined || v === null) {
      return false;
    }
    const n = Number(v);
    if (isNaN(n)) {
      return false;
    }
    return n === 0 || n === -15 || n === -8;
  }

  private async acquire(): Promise<void> {
    while (this.inUse) {
      await this.sleep(15);
    }
    this.inUse = true;
  }

  private release(): void {
    this.inUse = false;
  }

  private handle(): http.HttpRequest {
    if (this.h === null) {
      this.h = http.createHttp();
    }
    return this.h;
  }

  private dropHandle(): void {
    if (this.h !== null) {
      try {
        this.h.destroy();
      } catch (e) {
        // 已销毁/未初始化，忽略
      }
      this.h = null;
    }
  }

  private async signedCall(method: string, path: string, body: string,
                           bearer: string): Promise<Record<string, Object>> {
    const headers = this.signer.buildHeaders(method, body, bearer, this.vin);
    await this.acquire();
    try {
      const resp = await this.handle().request(API_APP + path, {
        method: method === 'GET' ? http.RequestMethod.GET : http.RequestMethod.POST,
        header: headers,
        extraData: body.length > 0 ? body : undefined,
        connectTimeout: 20000,
        readTimeout: 20000,
        // ★ 禁止跟随重定向：401/token 过期时会返回 302 到登录页，
        //   跟随了就拿不到 401，只剩一坨 HTML，无法定位。
        maxRedirects: 0
      });
      const raw = String(resp.result);
      if (resp.responseCode === 401) {
        // ★ 真机 401 诊断。已排除的项（PC 侧同代码 + 真实服务端全 200）：
        //   token 交换失败 / device_id 信任度 / 签名算法 / appToken 取值。
        const hk: string = Object.keys(headers).join('|');
        hilog.error(DOMAIN, TAG,
          '[ctrl401] %{public}s meshLen=%{public}d vatLen=%{public}d bodyLen=%{public}d '
          + 'tokenHdrLen=%{public}d md5=%{public}s headers=[%{public}s] resp=%{public}s',
          path, this.meshToken.length, this.vatToken.length, body.length,
          String(headers['X-CHJ-TOKEN'] ?? '').length,
          String(headers['Content-MD5'] ?? ''), hk, raw.substring(0, 120));
        throw new LiCommandError(`401 未授权（token 可能过期）: ${raw.substring(0, 200)}`);
      }
      if (resp.responseCode !== 200) {
        throw new LiCommandError(`HTTP ${resp.responseCode}: ${raw.substring(0, 300)}`);
      }
      return JSON.parse(raw) as Record<string, Object>;
    } catch (e) {
      // ★ 异常后句柄状态未知（可能已半关闭）→ 丢弃重建，避免后续请求连环失败
      this.dropHandle();
      const err = e as BusinessError;
      // ★★ 九号坑：maxRedirects:0 遇 302 会抛 2300047（拿不到 resp 对象），
      //   而业务接口在 token 过期 / 未登录时【正是返回 302 跳登录页】。
      if (err.code === 2300047) {
        throw new LiCommandError(
          '请求被重定向(302)：token 可能已过期或未登录，请重新登录');
      }
      throw err as Error;
    } finally {
      this.release();
    }
  }

  // ---------- ① 唤醒 ----------

  /** 远程唤醒。失败不阻断主流程（车可能已在线）。 */
  async wakeup(): Promise<void> {
    const body = '{"source":"0x3B","bizId":"0"}';
    await this.signedCall('POST', EP_WAKEUP, body, this.meshToken);
  }

  // ---------- ② 下发 ----------

  async sendCommandRaw(cmdKey: string,
                       cmdData?: Record<string, Object>): Promise<Record<string, Object>> {
    const isLong: boolean = LONG_RUNNING_CMD_KEYS.indexOf(cmdKey) >= 0;
    const je: number = isLong ? LONG_CMD_EXPIRE : CMD_EXPIRE;
    const jeMs: number = isLong ? LONG_CMD_EXPIRE_MS : CMD_EXPIRE_MS;
    const nowMs: number = new Date().getTime();
    const body: string = JSON.stringify({
      'vin': this.vin,
      'cmdKey': cmdKey,
      'cmdData': cmdData ?? {},
      'domain': CTRL_DOMAIN,
      'jobExpire': je,
      'expire': je,
      'expireAt': nowMs + jeMs,
      'token': this.vatToken
    });
    return this.signedCall('POST', EP_CMD_SEND, body, this.meshToken);
  }

  // ---------- ③ 轮询 ----------

  private async getCommandResult(requestId: string): Promise<Record<string, Object>> {
    return this.signedCall('GET', `${EP_CMD_RESULT}/${requestId}`, '', this.meshToken);
  }

  private sleep(ms: number): Promise<void> {
    return new Promise<void>((resolve) => {
      setTimeout(() => resolve(), ms);
    });
  }

  // ---------- 完整流程 ----------

  async sendCommand(cmdKey: string, cmdData?: Record<string, Object>,
                    wake: boolean = true, poll: boolean = true,
                    timeoutMs: number = CMD_POLL_TIMEOUT_MS,
                    pollIntervalMs: number = CMD_POLL_INTERVAL_MS): Promise<CommandResult> {
    if (wake) {
      try {
        await this.wakeup();
      } catch (e) {
        // 唤醒失败不阻断
      }
    }

    const resp = await this.sendCommandRaw(cmdKey, cmdData);
    const requestId: string = String(resp['requestId'] ?? '');
    const rc = resp['resultCode'];

    // ★ P1：resultCode 可能是 "0"（字符串）→ 必须按数值比较
    const rcNum: number | null = VehicleControl.numOf(rc);
    if (rcNum !== null && rcNum !== 0) {
      throw new LiCommandError(
        `命令下发被拒 (${cmdKey}): resultCode=${rc}`,
        requestId, rc as string | number);
    }
    if (requestId.length === 0) {
      throw new LiCommandError(
        `命令下发无 requestId (${cmdKey}): ${JSON.stringify(resp).substring(0, 200)}`);
    }

    if (!poll) {
      return { ok: true, requestId: requestId, cmdKey: cmdKey };
    }

    // 轮询到终态
    const tPoll: number = new Date().getTime();
    const deadline: number = tPoll + timeoutMs;
    let last: Record<string, Object> = {};
    let psN: number | null = null;
    while (new Date().getTime() < deadline) {
      try {
        last = await this.getCommandResult(requestId);
      } catch (e) {
        await this.sleep(pollIntervalMs);
        continue;
      }
      // ★ P1：pushState 可能是 "5"（字符串），严格 === 会一直等到超时
      psN = VehicleControl.numOf(last['pushState']);
      if (psN === PUSH_STATE_SUCCESS || psN === PUSH_STATE_FAILED) {
        break;
      }
      await this.sleep(pollIntervalMs);
    }

    const ps: number | undefined = psN === null ? undefined : psN;
    const rcFinal = last['resultCode'] as string | number | undefined;

    // ★ 成功路径此前完全无日志，出了「按钮转圈」这类问题无从定位，补上。
    hilog.info(DOMAIN, TAG,
      '[cmd] %{public}s 轮询结束 pushState=%{public}s 耗时=%{public}dms',
      cmdKey, ps === undefined ? 'None' : String(ps),
      new Date().getTime() - tPoll);

    const base: CommandResult = {
      ok: false, requestId: requestId, cmdKey: cmdKey,
      pushState: ps, resultCode: rcFinal,
      resultMsg: String(last['resultMsg'] ?? last['msg'] ?? '')
    };

    if (ps === PUSH_STATE_SUCCESS) {
      base.ok = true;
      return base;
    }
    if (ps === PUSH_STATE_FAILED) {
      // pushState=7 但 rc 属于成功集合（倒计时完成）→ 仍算成功
      if (VehicleControl.isSuccessCode(rcFinal)) {
        base.ok = true;
        return base;
      }
      let rcInt = -1;
      if (rcFinal !== undefined) {
        rcInt = parseInt(String(rcFinal), 10);
      }
      const hint = RESULT_CODE_HINTS[String(rcFinal)] ?? '';
      let msg = base.resultMsg !== undefined && base.resultMsg.length > 0
        ? base.resultMsg : hint;
      const fail = String(last['failReason'] ?? '').trim();
      if (fail.length > 0 && msg.indexOf(fail) < 0) {
        msg = msg.length > 0 ? `${msg}（${fail}）` : fail;
      }
      const extra = rcInt === ERR_JOB_CHANNEL ? ` [JOB 通道：${hint}]` : '';
      throw new LiCommandError(
        `命令执行失败 (${cmdKey}): pushState=${ps} resultCode=${rcFinal} msg=${msg}${extra}`,
        requestId, rcFinal, ps);
    }

    // 超时未终态：命令可能已生效，不报错
    base.ok = true;
    base.timeout = true;
    return base;
  }

  // ═══════════════════════════════════════════════════════════
  //  四个目标功能
  // ═══════════════════════════════════════════════════════════

  /** 落锁（lockSw=0） */
  async lock(poll: boolean = true, wake: boolean = true): Promise<CommandResult> {
    return this.sendCommand(CMD_LOCK, { 'lockSw': '0' }, wake, poll);
  }

  /** 解锁（lockSw=1） */
  async unlock(poll: boolean = true, wake: boolean = true): Promise<CommandResult> {
    return this.sendCommand(CMD_LOCK, { 'lockSw': '1' }, wake, poll);
  }

  /**
   * 授权驾驶。
   *
   * ★ cmdData 必须是**空对象** `{}`（参考项目实测；App 实现类
   *   `XHttpRemoteStartControl`，cmdKey 却是 `remoteVehAuth`）。
   * ★ 需要等结果：这是一次真实授权，不能 fire-and-forget。
   * ★ L6（X 系）读不到 `remoteStartStatus`（该信号仅 M 系平台有），
   *   所以没有可回读的状态 —— UI 上做成一次性动作按钮，不做开关态。
   */
  async authDrive(poll: boolean = true, wake: boolean = true): Promise<CommandResult> {
    return this.sendCommand(CMD_AUTH, {}, wake, poll);
  }

  /**
   * 开空调。
   *
   * ★ acCtrlTemp 必须是 Number，其余三个字段必须是 String
   * ★ L6 Max 温度范围 16-28
   * ★ poll 默认 true（脚本/离线验证用）。**手表端传 false**：
   *   空调是 jobExpire=900 的长任务，锁车时需远程唤醒整车，等终态会把
   *   UI 锁死一分钟。见 Index.ets onAcTap()。
   */
  async acOn(temp: number = AC_DEFAULT_TEMP, poll: boolean = true,
             wake: boolean = true): Promise<CommandResult> {
    let t = temp;
    if (t < AC_MIN_TEMP) {
      t = AC_MIN_TEMP;
    }
    if (t > AC_MAX_TEMP) {
      t = AC_MAX_TEMP;
    }
    const data: Record<string, Object> = {
      'acCtrlValue': 'ON',
      'acCtrlType': AC_TYPE_FRONT,
      'acCountdownTimer': AC_COUNTDOWN,
      'acCtrlTemp': t                      // Number，不是字符串
    };
    return this.sendCommand(CMD_AC, data, wake, poll);
  }

  /** 关空调（不带 acCtrlTemp）。poll 语义同 acOn：手表端传 false。 */
  async acOff(poll: boolean = true, wake: boolean = true): Promise<CommandResult> {
    const data: Record<string, Object> = {
      'acCtrlValue': 'OFF',
      'acCtrlType': AC_TYPE_FRONT,
      'acCountdownTimer': AC_COUNTDOWN
    };
    return this.sendCommand(CMD_AC, data, wake, poll);
  }

  /** 寻车（不等结果，App 也是 fire-and-forget） */
  async findCar(wake: boolean = true): Promise<CommandResult> {
    return this.sendCommand(CMD_SEARCH, { 'searchType': '0' }, wake, false);
  }

  /** 闪灯（searchType 是整数 1） */
  async flashLight(wake: boolean = true): Promise<CommandResult> {
    return this.sendCommand(CMD_SEARCH, { 'searchType': 1 }, wake, false);
  }

  /** 鸣笛（searchType 是整数 2） */
  async whistle(wake: boolean = true): Promise<CommandResult> {
    return this.sendCommand(CMD_SEARCH, { 'searchType': 2 }, wake, false);
  }
}
