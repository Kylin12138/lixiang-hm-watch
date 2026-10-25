/**
 * 手表端主界面 —— 四个功能：解闭车锁 / 授权驾驶 / 开关空调 / 寻车
 *
 * 设计约束：
 *  · 圆形表盘（Watch6 是圆形），内容必须避开四角
 *  · 触摸目标 ≥ 44vp（手指粗，且运动场景下容易点偏）
 *  · 单手可操作：主要操作放在拇指自然触及的下半屏
 *  · 深色底（OLED 省电，且手表默认深色）
 *  · 每个操作给明确的即时反馈（加载/成功/失败），车控有 1-10s 延迟
 */

import { VehicleControl, LiCommandError, CommandResult } from '../core/control/VehicleControl';
import { VssReader } from '../core/control/VssReader';
import { AC_MIN_TEMP, AC_MAX_TEMP, AC_DEFAULT_TEMP, OPTIMISTIC_TTL_MS } from '../core/protocol/Constants';
import { AppState } from '../common/AppState';
import { loginAndPrepare, LoginPhase } from '../core/protocol/LoginFlow';
import { capsFromJson, CryptoCapabilities } from '../core/crypto/HarmonyCrypto';
import { probeCapabilitiesAsync, taskpoolSelftest } from '../core/crypto/HeavyCrypto';
import { window } from '@kit.ArkUI';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { common } from '@kit.AbilityKit';

const DOMAIN: number = 0x0001;
const TAG: string = 'LixiangWatch';

/** 从表盘切回应用时，状态超过这个时长就重新拉一次（毫秒） */
const PAGE_SHOW_STALE_MS: number = 45000;
/** 前台周期刷新间隔（毫秒）—— 兜住「熄屏再亮屏」这条 onPageShow 不触发的路径 */
const FOREGROUND_POLL_MS: number = 60000;
/** 调温防抖窗口（毫秒）—— 连点 5 次只下发 1 条指令 */
const TEMP_DEBOUNCE_MS: number = 800;

/** run() 的可选行为 */
interface RunOptions {
  /** 长任务（空调）：需要更长的状态收敛窗口 */
  longRun?: boolean;
  /** 失败回调（用于撤销乐观状态） */
  onFail?: () => void;
}


@Entry
@Component
struct Index {
  @State locked: boolean | null = null;
  @State acOn: boolean | null = null;
  @State insideTemp: number | null = null;
  @State setTemp: number = AC_DEFAULT_TEMP;
  /** 授权驾驶的二次确认：true = 已武装，再点一次才下发 */
  @State authArmed: boolean = false;
  @State busy: string = '';          // 正在执行的操作 key
  @State syncing: boolean = false;
  @State toast: string = '';
  @State ready: boolean = false;
  @State statusMsg: string = '正在初始化…';

  // ── 登录界面状态 ──
  @State needLogin: boolean = false;
  @State phoneInput: string = '';
  @State pwdInput: string = '';
  @State loginBusy: boolean = false;
  @State loginMsg: string = '';
  /** loginMsg 是否为失败态 —— 决定用警示色还是灰字 */
  @State loginFailed: boolean = false;
  @State loginElapsed: number = 0;
  @State caps: CryptoCapabilities | null = null;

  private vc: VehicleControl | null = null;
  private vss: VssReader | null = null;

  /**
   * ★ 空调乐观状态（不参与渲染，只作为「以谁为准」的判据）。
   *
   * 空调下发后 VSS 可能数十秒才刷新，这段时间内不能让 refresh()
   * 用滞后旧值覆盖用户刚点出来的状态。详见 applyAcOptimistic()。
   */
  private acOptOn: boolean | null = null;
  private acOptTemp: number | null = null;
  private acOptUntil: number = 0;

  private toastTimer: number = -1;
  private loginTimer: number = -1;
  private authTimer: number = -1;
  /** 车控后分段刷新的「链」定时器（单链，新的取代旧的） */
  private refreshTimer: number = -1;
  /** 前台周期刷新定时器 */
  private pollTimer: number = -1;
  /** 调温防抖定时器 */
  private tempTimer: number = -1;
  /** 上次成功/尝试刷新的时间（onPageShow 用来判 stale） */
  private lastRefreshAt: number = 0;
  /** 页面已销毁 → 禁止再发请求/定时器回调写 @State */
  private destroyed: boolean = false;
  /** 当前是否持有「屏幕常亮」 */
  private screenOn: boolean = false;
  /** 上一次报错文案 + 时间（用于去重，避免轮询反复弹同一个错误） */
  private lastErrText: string = '';
  private lastErrAt: number = 0;

  /** 退出登录的二次确认弹窗 */
  private logoutDlg: CustomDialogController = new CustomDialogController({
    builder: LogoutDialog({
      onConfirm: () => { this.doLogout(); }
    }),
    // autoCancel 让「点空白处」等价于取消，符合手表小屏的操作习惯
    autoCancel: true,
    alignment: DialogAlignment.Center,
    // ★ 页面是纯黑底 + 白字，系统默认弹窗是白底，不设 true 会切成浅色底却仍用浅色字
    customStyle: true
  });

  aboutToAppear(): void {
    this.destroyed = false;
    hilog.info(DOMAIN, TAG, '[页面] aboutToAppear');
    this.startPolling();
    this.bootstrap();
  }

  /**
   * 前台周期刷新。
   *
   * ★ 为什么需要：手表最典型的「离开/回来」是熄屏与抬腕，这条路径
   *   上 onPageShow 不会被调用（页面一直没离开过），实测熄屏 50s 后
   *   亮屏没有任何刷新。而应用被冻结时 JS 定时器也停摆，所以 60s
   *   一次的轮询在后台几乎不耗电，亮屏后立刻补一次。
   */
  private startPolling(): void {
    if (this.pollTimer >= 0) {
      return;
    }
    this.pollTimer = setInterval(() => {
      // ★★ 自愈：熄屏会触发 aboutToDisappear（页面其实没销毁），而亮屏不再
      //   触发 onPageShow —— 若指望外部复位 destroyed，页面会永久冻结。
      //   这里让轮询自己当「我还活着」的探针：定时器还在跑 = 页面还在。
      if (this.destroyed) {
        this.destroyed = false;
        hilog.info(DOMAIN, TAG, '[轮询] 自愈 destroyed（熄屏返回后未收到 onPageShow）');
      }
      if (!this.ready || this.needLogin) {
        return;
      }
      if (this.busy.length > 0 || this.syncing || this.loginBusy) {
        return;                     // 正在执行命令/已有一轮在拉，别叠加
      }
      hilog.info(DOMAIN, TAG, '[轮询] 前台周期刷新');
      this.refresh();
    }, FOREGROUND_POLL_MS);
  }

  /**
   * ★ P0-5：页面重新可见时补一次刷新。
   *
   * ★★ 真机教训（2026-10-20）：手表熄屏会触发 aboutToDisappear，而页面
   *   本身并没有销毁（亮屏后画面还在）。如果只在那里置 destroyed=true 就
   *   再也不复位，会出现「界面永远不刷新、busy 永远不复位」的假死。
   *   所以这里必须把 destroyed 复位并重新拉起轮询（onPageShow 只在
   *   页面真实存在时触发，是「我还活着」的可靠信号）。
   */
  onPageShow(): void {
    this.destroyed = false;
    hilog.info(DOMAIN, TAG, '[页面] onPageShow ready=%{public}s', String(this.ready));
    this.startPolling();
    if (!this.ready || this.needLogin) {
      return;
    }
    if (this.busy.length > 0 || this.syncing) {
      return;
    }
    if (Date.now() - this.lastRefreshAt < PAGE_SHOW_STALE_MS) {
      return;                       // 刚刷过，别一进一出就打接口
    }
    this.refresh();
  }

  aboutToDisappear(): void {
    // ★ P0-4：销毁后必须停掉所有定时器 —— 否则定时回调继续发网络请求、
    //   继续写 @State（组件已销毁），既浪费电也可能报错。
    // ★★ 但【轮询定时器必须留下】：手表熄屏就会走到这里，页面并未销毁；
    //   若连 pollTimer 一起清掉，亮屏后又没有 onPageShow 去重新拉起，
    //   这条页面就永远刷不动了（状态冻结，且再也不会自愈）。
    //   留着它只多一个 60s 的空转检查，应用被冻结时 JS 定时器本身也停摆。
    hilog.info(DOMAIN, TAG, '[页面] aboutToDisappear（清定时器，保留轮询）');
    this.destroyed = true;
    this.clearTimers();
  }

  private clearTimers(): void {
    if (this.toastTimer >= 0) {
      clearTimeout(this.toastTimer);
      this.toastTimer = -1;
    }
    if (this.authTimer >= 0) {
      clearTimeout(this.authTimer);
      this.authTimer = -1;
    }
    if (this.loginTimer >= 0) {
      clearInterval(this.loginTimer);
      this.loginTimer = -1;
    }
    if (this.refreshTimer >= 0) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = -1;
    }
    if (this.tempTimer >= 0) {
      clearTimeout(this.tempTimer);
      this.tempTimer = -1;
    }
    // pollTimer 故意不清 —— 见 aboutToDisappear 的说明
  }

  /** 初始化：装配客户端 → 拉一次状态；能力探测并行在后台跑 */
  async bootstrap(): Promise<void> {
    // ★ P2-1：能力探测含 2 次纯 Ed25519 + 1 次 RSA2048 生成，是秒级同步计算。
    //   以前直接在 bootstrap 里同步跑，首屏被它拖住。现在丢到工作线程，
    //   不阻塞首屏（login 页的探测小字晚一两秒出现即可）。
    this.probeCaps();

    try {
      const ctx = this.getUIContext().getHostContext() as common.UIAbilityContext;
      const ok = await AppState.get().load(ctx);
      if (!ok) {
        this.needLogin = true;
        this.ready = false;
        this.statusMsg = '';
        return;
      }
      this.vc = AppState.get().vehicleControl();
      this.vss = AppState.get().vssReader();
      this.ready = true;
      this.needLogin = false;
      this.statusMsg = '';
      await this.refresh();
    } catch (e) {
      const err = e as Error;
      hilog.error(DOMAIN, TAG, 'bootstrap 失败: %{public}s', err.message);
      this.statusMsg = this.friendlyError(err.message);
      this.ready = false;
    }
  }

  /**
   * 重新取客户端引用。
   *
   * ★ 静默续期（AppState.silentRefresh）会重建 Signer / TokenManager /
   *   VehicleControl / VssReader，本页持有的旧引用就失效了（旧 token、
   *   旧 http 句柄）。凡是可能触发续期的地方，之后都要调本方法。
   */
  private syncClients(): void {
    try {
      this.vc = AppState.get().vehicleControl();
      this.vss = AppState.get().vssReader();
    } catch (e) {
      // 凭据已被清空（重新登录中），保持原值即可
      const err = e as Error;
      hilog.warn(DOMAIN, TAG, '同步客户端引用失败: %{public}s', err.message);
    }
  }

  /** 后台能力探测（不 await，失败只记日志） */
  private async probeCaps(): Promise<void> {
    if (this.caps !== null) {
      return;
    }
    try {
      const json: string = await probeCapabilitiesAsync();
      const c: CryptoCapabilities = capsFromJson(json);
      this.caps = c;
      hilog.info(DOMAIN, TAG, '能力探测: %{public}s', c.summary());
      // ★ bcryptAsync 在 taskpool 不可用时【直接失败】（绝不回退主线程，
      //   否则 23.6s 同步必被 SIG 9 强杀）。这里提前自检一次并留痕，
      //   免得用户点登录才看到「工作线程不可用」而不知道原因。
      const tp: string = await taskpoolSelftest();
      hilog.info(DOMAIN, TAG, '工作线程自检: %{public}s', tp);
    } catch (e) {
      hilog.warn(DOMAIN, TAG, '能力探测失败: %{public}s', String(e));
    }
  }

  /**
   * ★ P2-5：按需开关屏幕常亮。
   *
   * 以前 EntryAbility 里无条件常开 —— 手表 OLED 长期亮屏既费电又烧屏。
   * 真正需要常亮的只有登录那 20~30 秒（bcrypt 计算期间用户必须看得见进度，
   * 否则会以为卡死而强退）。
   */
  private setScreenOn(on: boolean): void {
    if (this.screenOn === on) {
      return;
    }
    this.screenOn = on;
    try {
      const ctx = this.getUIContext().getHostContext() as common.UIAbilityContext;
      window.getLastWindow(ctx).then((w: window.Window) => {
        w.setWindowKeepScreenOn(on);
      }).catch((e: Error) => {
        hilog.warn(DOMAIN, TAG, 'setWindowKeepScreenOn 失败: %{public}s', e.message);
      });
    } catch (e) {
      const err = e as Error;
      hilog.warn(DOMAIN, TAG, '取窗口失败: %{public}s', err.message);
    }
  }

  /** 执行登录（PAKE → 派生 → 拉车 → 落库） */
  async doLogin(): Promise<void> {
    const phone = this.phoneInput.trim();
    if (phone.length !== 11) {
      this.loginMsg = '请输入 11 位手机号';
      this.loginFailed = true;
      return;
    }
    if (this.pwdInput.length === 0) {
      this.loginMsg = '请输入密码';
      this.loginFailed = true;
      return;
    }
    this.loginBusy = true;
    this.loginMsg = '';            // 进度文案由回调填，避免与「正在连接…」重复
    this.loginFailed = false;
    // ★ 登录期间保持屏幕常亮：bcrypt 要算 20~30 秒，熄屏会让用户以为卡死而强退
    this.setScreenOn(true);
    // ★ Watch 6 实测：PAKE 的 bcrypt（cost=10）单步耗时约 23.6s（PC 仅 56ms）。
    //   它已挪到 taskpool 工作线程，主线程不会卡死，但界面会静默 20+ 秒。
    //   若不显示计时，用户会以为卡死而强退 —— 故暴露已用秒数。
    this.loginElapsed = 0;
    this.loginTimer = setInterval(() => {
      this.loginElapsed = this.loginElapsed + 1;
    }, 1000);
    try {
      const ctx = this.getUIContext().getHostContext() as common.UIAbilityContext;
      const out = await loginAndPrepare(ctx, phone, this.pwdInput, undefined,
        (phase: LoginPhase, detail: string) => {
          // ★ 阶段名与 detail 都是技术话（`PAKE 登录`、`派生设备身份（hac_key）`），
          //   只在日志留痕，界面显示用户能懂的进度。
          hilog.info(DOMAIN, TAG, '[登录] %{public}s: %{public}s', phase, detail);
          this.loginMsg = this.loginPhaseText(phase);
        });
      this.pwdInput = '';
      this.loginMsg = `登录成功：${out.vehicleName}`;
      this.loginFailed = false;
      this.needLogin = false;
      this.ready = true;
      this.vc = AppState.get().vehicleControl();
      this.vss = AppState.get().vssReader();
      await this.refresh();
    } catch (e) {
      const err = e as Error;
      hilog.error(DOMAIN, TAG, '登录失败: %{public}s', err.message);
      // ★ 原始报错里有 `[idps] HTTP 412 {...}` 这类服务端原文，普通用户看不懂。
      //   完整原文进 hilog（排障用），界面只给结论。
      this.loginMsg = `登录失败：${this.friendlyError(err.message)}`;
      this.loginFailed = true;
    } finally {
      if (this.loginTimer >= 0) {
        clearInterval(this.loginTimer);
        this.loginTimer = -1;
      }
      this.loginBusy = false;
      this.setScreenOn(false);
    }
  }

  /** 拉取车辆状态 */
  async refresh(): Promise<void> {
    if (this.vss === null || this.syncing || this.destroyed) {
      return;                       // 已有一次在跑 → 跳过，避免并发打架
    }
    this.syncing = true;
    this.lastRefreshAt = Date.now();
    try {
      // 换齐 token（内部有缓存，不会每次都请求）
      await AppState.get().ensureTokens();
      // ★ ensureTokens 可能触发 refresh_token 静默续期（会重建客户端）
      //   → 之后必须重新取引用，否则拿旧 token / 旧句柄去读 VSS
      this.syncClients();
      const st = await this.vss.readState();
      if (this.destroyed) {
        return;                     // 拉取期间页面已销毁 → 不写 @State
      }
      this.locked = st.locked;
      this.insideTemp = st.insideTemp;
      // ★ 空调不能直接覆盖：VSS 滞后会把刚下发的意图冲掉，见下方说明
      this.applyAcOptimistic(st.acOn, st.acSetTemp);
    } catch (e) {
      const err = e as Error;
      hilog.warn(DOMAIN, TAG, 'refresh 失败: %{public}s', err.message);
      if (!this.destroyed) {
        // ★ 离线时 60s 轮询会反复失败 —— 同一错误 5 分钟内只提示一次
        this.toastError(`状态读取失败: ${this.friendlyError(err.message)}`);
      }
    } finally {
      this.syncing = false;
    }
  }

  /**
   * ★ 空调状态的乐观保护。
   *
   * 为什么需要：
   *   空调是**长任务** —— 锁车时整车休眠，下发后要远程唤醒 + 启动空调，
   *   服务端 jobExpire 给到 900s，VSS 信号（FOffStatus / SetTemp）几十秒
   *   内不会更新。若不保护，refresh() 会用**旧值**把用户刚点出来的状态
   *   冲回去，表现为「刚点开空调，按钮又跳回『开空调』」，
   *   用户会以为没生效而重复点，反而把空调关掉。
   *
   * 策略（对齐参考项目 climate.py 的 _optimistic_* + OPTIMISTIC_TTL）：
   *   · TTL 内 且 VSS 与乐观值不一致 → 保留乐观值（VSS 还没跟上）
   *   · VSS 与乐观值一致（车端已确认）→ 撤销乐观态，改以 VSS 为准
   *   · TTL 到期 → 无条件撤销乐观态，改以 VSS 为准
   */
  private applyAcOptimistic(vssOn: boolean | null, vssTemp: number | null): void {
    const fresh: boolean = Date.now() < this.acOptUntil;

    if (!fresh) {
      // 保护期已过：VSS 是唯一真相
      this.acOptOn = null;
      this.acOptTemp = null;
      this.acOn = vssOn;
      if (vssTemp !== null && vssTemp !== undefined) {
        this.setTemp = vssTemp;
      }
      return;
    }

    // 开关
    if (this.acOptOn === null) {
      this.acOn = vssOn;
    } else if (vssOn !== null && vssOn === this.acOptOn) {
      this.acOptOn = null;              // 车端已确认 → 交还给 VSS
      this.acOn = vssOn;
    } else {
      this.acOn = this.acOptOn;         // VSS 还没跟上 → 保持乐观值
    }

    // 设定温度
    if (this.acOptTemp === null) {
      if (vssTemp !== null && vssTemp !== undefined) {
        this.setTemp = vssTemp;
      }
    } else if (vssTemp !== null && vssTemp !== undefined
               && Math.abs(vssTemp - this.acOptTemp) < 0.1) {
      this.acOptTemp = null;            // 车端已确认
      this.setTemp = vssTemp;
    } else {
      this.setTemp = this.acOptTemp;    // VSS 还没跟上 → 保持乐观值
    }
  }

  /**
   * 车控之后分段刷新。
   *
   * VSS 不是实时的：短任务几秒内更新，空调这类长任务可能数十秒。
   * 只拉一次会拿到旧值（虽然有乐观保护兜着），所以按递增间隔多拉几次，
   * 让状态尽快收敛到车端真实值。串行执行，不并发。
   *
   * ★ P0-4：定时器句柄必须保存 —— 以前 `setTimeout` 的返回值直接丢弃，
   *   页面销毁后这条链还在跑（继续换 token、发 VSS、写已销毁组件的 @State）。
   * ★ P2-3：短任务只拉 2 轮（1.2s / 5s）。以前一律 4 轮到 50 秒，
   *   每轮都要换 token + 打 VSS，纯属浪费；空调才需要长窗口。
   */
  private scheduleRefresh(round: number, longRun: boolean): void {
    const delays: number[] = longRun ? [1200, 5000, 15000, 30000] : [1200, 5000];
    if (round === 0 && this.refreshTimer >= 0) {
      // 新的一次车控 → 取代旧链，避免多条链叠加刷接口
      clearTimeout(this.refreshTimer);
      this.refreshTimer = -1;
    }
    if (this.destroyed || round >= delays.length) {
      this.refreshTimer = -1;
      return;
    }
    this.refreshTimer = setTimeout(() => {
      this.refreshTimer = -1;
      if (this.destroyed) {
        return;
      }
      this.refresh().then((): void => {
        if (!this.destroyed) {
          this.scheduleRefresh(round + 1, longRun);
        }
      });
    }, delays[round]);
  }

  /** 统一的命令执行包装：busy 标记 + 错误提示 + 失败回滚 + 完成后刷新 */
  async run(key: string, label: string, fn: () => Promise<CommandResult>,
            opts?: RunOptions): Promise<void> {
    if (this.busy.length > 0) {
      return;                       // 防重复点击
    }
    this.disarmAuth();              // 任何车控动作都解除「授权驾驶」待确认态
    this.busy = key;
    this.showToast(`正在${label}…`);
    try {
      await AppState.get().ensureTokens();
      // ★ 同上：ensureTokens 可能静默续期并重建客户端，之后的 fn 必须用新引用
      this.syncClients();
      const r = await fn();
      if (this.destroyed) {
        return;
      }
      if (r.timeout === true) {
        this.showToast(`${label}指令已发出，车辆暂未反馈`);
      } else {
        this.showToast(`${label}成功`);
      }
    } catch (e) {
      const err = e as Error;
      hilog.error(DOMAIN, TAG, '%{public}s 失败: %{public}s', label, err.message);
      if (this.destroyed) {
        return;
      }
      // ★★★ P0-1：下发失败必须撤销乐观状态。
      //   以前 catch 只弹 toast，acOpt* 仍挂着 150s TTL → 界面显示
      //   「关空调」（=空调已开），而车其实没开。用户再点一次才是真的开。
      if (opts !== undefined && opts.onFail !== undefined) {
        opts.onFail();
      }
      this.showToast(`${label}失败：${this.friendlyCommandError(err)}`);
      if (this.isAuthError(err)) {
        // 登录态问题 → 后台用 refresh_token 静默续期，用户重试即可，无需重登
        this.trySilentRefresh();
      }
    } finally {
      // ★ busy 必须无条件复位：它一旦卡住，四个按钮就永久不可点。
      //   destroyed 只在 aboutToDisappear 置真、在 onPageShow 复位，
      //   把「关键状态复位」押在它身上是危险的。
      this.busy = '';
      if (!this.destroyed) {
        // 车控后 VSS 可能延迟数十秒才刷新 —— 分段多拉几次，让它尽快收敛
        const longRun: boolean = opts !== undefined && opts.longRun === true;
        this.scheduleRefresh(0, longRun);
      }
    }
  }

  /** 后台静默续期（不阻塞 UI） */
  private async trySilentRefresh(): Promise<void> {
    try {
      const ok: boolean = await AppState.get().silentRefresh();
      if (ok && !this.destroyed) {
        // 续期会重建客户端 → 重新取引用，否则下一次点击还用旧 token
        this.syncClients();
        this.showToast('登录已自动刷新，请再试一次');
      }
    } catch (e) {
      const err = e as Error;
      hilog.warn(DOMAIN, TAG, '静默续期失败: %{public}s', err.message);
    }
  }

  /** 错误是否属于「登录态问题」 */
  private isAuthError(err: Error): boolean {
    const m: string = err.message;
    return m.indexOf('login_required') >= 0
      || m.indexOf('会话失效') >= 0
      || m.indexOf('HTTP 401') >= 0
      || m.indexOf('401 未授权') >= 0
      || m.indexOf('重定向(302)') >= 0
      || m.indexOf('invalid_token') >= 0;
  }

  /**
   * 登录阶段 → 用户能懂的说法。
   *
   * LoginFlow 给出的 detail 是给排障看的（`派生设备身份（hac_key）`、
   * `设备端密码学计算约需 20~30 秒`），普通用户看到只会困惑。
   * 完整 detail 仍写 hilog，随时可查。
   */
  private loginPhaseText(phase: LoginPhase): string {
    switch (phase) {
      case LoginPhase.Pake:
        return '正在验证账号…';
      case LoginPhase.Derive:
        return '正在绑定本设备…';
      case LoginPhase.Vehicles:
        return '正在读取车辆信息…';
      case LoginPhase.Save:
        return '正在保存登录状态…';
      case LoginPhase.Done:
        return '登录完成';
      default:
        return '正在登录…';
    }
  }

  /**
   * 把技术错误码翻译成人话。
   *
   * ★★ P1 修复：以前用 `indexOf('401')` / `indexOf('2009')` 做【裸数字子串匹配】。
   *   requestId、时间戳、甚至 `resultCode=1401` 里都可能带这些数字，
   *   于是普通失败会被翻译成「登录已过期」—— 排障时它会撒谎。
   *   现在只认带语义的完整片段。
   *
   * ★ 兜底不再回吐原文：调用处的结果会直接显示给用户，
   *   `[idps] HTTP 412 {...}` 这类服务端原文对用户没有意义。原文一律进日志。
   */
  friendlyError(msg: string): string {
    if (msg.indexOf('login_required') >= 0 || msg.indexOf('会话失效') >= 0
        || msg.indexOf('HTTP 401') >= 0 || msg.indexOf('401 未授权') >= 0
        || msg.indexOf('invalid_token') >= 0) {
      return '登录已过期，请重新登录';
    }
    if (msg.indexOf('重定向(302)') >= 0) {
      return '登录状态异常，请重试或重新登录';
    }
    if (msg.indexOf('签名校验失败') >= 0) {
      return '签名校验失败';
    }
    if (msg.indexOf('JOB 通道') >= 0 || msg.indexOf('该命令走理想 App') >= 0) {
      return '该功能当前不支持';
    }
    if (msg.indexOf('网络') >= 0 || msg.indexOf('timeout') >= 0
        || msg.indexOf('超时') >= 0 || msg.indexOf('2300028') >= 0) {
      return '网络超时，请重试';
    }
    // 服务端有时会给一句中文 msg，它本身就是给人看的，优先用它
    const idx = msg.lastIndexOf('msg=');
    if (idx >= 0) {
      const tail: string = msg.substring(idx + 4);
      if (tail.length > 0) {
        return tail.length > 40 ? `${tail.substring(0, 40)}…` : tail;
      }
    }
    return '请稍后重试';
  }

  /**
   * 命令错误的友好文案 —— 优先用 LiCommandError 里的【结构化字段】，
   * 而不是去猜字符串（见 friendlyError 的注释）。
   */
  friendlyCommandError(err: Error): string {
    if (err instanceof LiCommandError) {
      const rc = err.resultCode;
      const n: number = rc === undefined || rc === null ? NaN : Number(rc);
      if (!isNaN(n)) {
        if (n === 2009 || n === 100035 || n === 100012) {
          return '该功能当前不支持';
        }
        if (n === 100005) {
          return '签名校验失败';
        }
        if (n === -2 || n === -3) {
          return '车辆执行失败，请重试';
        }
      }
    }
    return this.friendlyError(err.message);
  }

  showToast(text: string): void {
    this.toast = text;
    if (this.toastTimer >= 0) {
      clearTimeout(this.toastTimer);
    }
    this.toastTimer = setTimeout(() => {
      this.toast = '';
      this.toastTimer = -1;
    }, 2500);
  }

  /**
   * 同一错误在 5 分钟内只提示一次。
   *
   * ★ 复审补充：前台轮询每 60s 拉一次状态，离线时会连续失败 ——
   *   若每次都弹 toast，界面就变成「每分钱跳一次红字」，且没有任何新信息。
   */
  private toastError(text: string): void {
    const now: number = Date.now();
    if (text === this.lastErrText && now - this.lastErrAt < 300000) {
      return;
    }
    this.lastErrText = text;
    this.lastErrAt = now;
    this.showToast(text);
  }

  // ---------- 四个功能 ----------

  onLockTap(): void {
    if (this.vc === null) {
      return;
    }
    const isLocked = this.locked === true;
    const prev: boolean | null = this.locked;
    const fn = (): Promise<CommandResult> =>
      isLocked ? this.vc!.unlock() : this.vc!.lock();
    this.locked = !isLocked;              // 乐观更新
    this.run('lock', isLocked ? '解锁' : '落锁', fn, {
      // ★ P0-1 同类：下发失败要撤销乐观状态，否则界面显示的状态与车相反
      onFail: () => {
        this.locked = prev;
      }
    });
  }

  /**
   * 授权驾驶 —— 安全敏感操作，做二次确认。
   *
   * 第一次点：武装（按钮变「再点确认」高亮），3 秒内不点自动解除。
   * 第二次点：真正下发 remoteVehAuth。
   *
   * 误触防护：任何其他车控动作开始时会 disarmAuth()，避免「点过别的按钮后
   * 再点这个以为是第一次」而直接授权的场景。
   */
  onAuthTap(): void {
    if (this.vc === null) {
      return;
    }
    if (!this.authArmed) {
      this.authArmed = true;
      this.showToast('再点一次确认「授权驾驶」');
      if (this.authTimer >= 0) {
        clearTimeout(this.authTimer);
      }
      this.authTimer = setTimeout(() => {
        this.authArmed = false;
        this.authTimer = -1;
      }, 3000);
      return;
    }
    this.disarmAuth();
    this.run('auth', '授权驾驶', () => this.vc!.authDrive());
  }

  /** 解除授权驾驶的待确认状态 */
  private disarmAuth(): void {
    if (this.authTimer >= 0) {
      clearTimeout(this.authTimer);
      this.authTimer = -1;
    }
    if (this.authArmed) {
      this.authArmed = false;
    }
  }

  /**
   * 开关空调。
   *
   * ★★ 为什么不等执行结果（poll=false）：
   *   锁车状态下整车休眠，空调在服务端是 jobExpire=900 的长任务，下发后
   *   要远程唤醒车辆才能执行，cmd-result 可能 1 分钟以上才进 pushState 终态。
   *   早期这里走默认轮询（上限 60s），真机表现为：空调确实开了，但
   *   busy='ac' 会让【四个按钮全部变灰不可点】长达一分钟 —— 用户看到的
   *   就是「关空调按钮一直转圈、点不动」。
   *
   *   现在只等「下发被服务端接受」（HTTP 200 且拿到 requestId），执行结果
   *   改由 VSS 回读 + applyAcOptimistic() 的 TTL 乐观保护确认。
   *   下发阶段的失败（401 / resultCode≠0）仍照常抛出并提示。
   */
  onAcTap(): void {
    if (this.vc === null) {
      return;
    }
    const isOn = this.acOn === true;
    const next: boolean = !isOn;
    const fn = (): Promise<CommandResult> =>
      isOn ? this.vc!.acOff(false) : this.vc!.acOn(this.setTemp, false);

    // 保存旧值用于失败回滚
    const prevOn: boolean | null = this.acOn;
    const prevOptOn: boolean | null = this.acOptOn;
    const prevOptUntil: number = this.acOptUntil;

    // 乐观更新：立即反映用户意图，并在 TTL 内不被滞后的 VSS 值冲掉
    this.acOptOn = next;
    this.acOptUntil = Date.now() + OPTIMISTIC_TTL_MS;
    this.acOn = next;

    this.run('ac', isOn ? '关空调' : '开空调', fn, {
      longRun: true,
      // ★★ P0-1：下发失败（401 / resultCode≠0 / 无 requestId）必须撤销乐观状态。
      //   否则 150s 内界面会一直显示「关空调」，而车根本没开 —— 与现实相反。
      onFail: () => {
        this.acOn = prevOn;
        this.acOptOn = prevOptOn;
        this.acOptUntil = prevOptUntil;
      }
    });
  }

  /**
   * 调温。
   *
   * ★★ 新发现的 bug（2026-10-20）：以前这里只改本地 setTemp，
   *   【从不给车下发指令】—— 界面温度变了，车里的温度纹丝不动。
   *   本方法在 acOn === true 时才可见，所以只要调温就必须真的发 acOn(新温度)。
   *   连点用 800ms 防抖合并成一条，避免 5 次点击发 5 条长任务。
   */
  onAcTempChange(delta: number): void {
    // ★ 复查补漏（2026-10-20）：± 按钮此前没有 busy 守卫。若在别的指令
    //   执行中调温，本地温度会先变、下发却要等防抖重试，重试用尽就静默丢弃
    //   —— 界面显示一个新温度，车里没变，且乐观态会把它锁住 150s。
    if (this.busy.length > 0) {
      this.showToast('正在执行其他操作，请稍候');
      return;
    }
    let t = this.setTemp + delta;
    if (t < AC_MIN_TEMP) {
      t = AC_MIN_TEMP;
    }
    if (t > AC_MAX_TEMP) {
      t = AC_MAX_TEMP;
    }
    if (t === this.setTemp) {
      return;
    }
    this.setTemp = t;
    // 调温同样要保护，否则 refresh() 会立刻用旧设定值冲掉刚调好的温度
    this.acOptTemp = t;
    this.acOptUntil = Date.now() + OPTIMISTIC_TTL_MS;
    this.scheduleTempApply(0);
  }

  /** 调温防抖下发（attempt 用于「忙时稍后重试」计数，最多 3 次） */
  private scheduleTempApply(attempt: number): void {
    if (this.tempTimer >= 0) {
      clearTimeout(this.tempTimer);
    }
    this.tempTimer = setTimeout(() => {
      this.tempTimer = -1;
      if (this.destroyed || this.vc === null) {
        return;
      }
      if (this.acOn !== true) {
        return;                     // 期间被关掉了，不再下发
      }
      if (this.busy.length > 0) {
        if (attempt < 3) {
          this.scheduleTempApply(attempt + 1);
          return;
        }
        // ★ 复查补漏：重试用尽 = 这条调温【从未下发】。必须撤销乐观温度，
        //   否则界面会显示一个车里不存在的温度，且 150s 内刷不回来。
        this.acOptTemp = null;
        this.acOptUntil = 0;
        this.showToast('调温未下发（正在执行其他操作），请重试');
        return;
      }
      const target: number = this.setTemp;
      const prevOptTemp: number | null = this.acOptTemp;
      this.run('ac', `调到 ${target}℃`, () => this.vc!.acOn(target, false), {
        onFail: () => {
          this.acOptTemp = prevOptTemp;
        }
      });
    }, TEMP_DEBOUNCE_MS);
  }

  onFindTap(): void {
    if (this.vc === null) {
      return;
    }
    this.run('find', '寻车', () => this.vc!.findCar());
  }

  // ---------- UI ----------

  build() {
    Stack({ alignContent: Alignment.Center }) {
      // 背景
      Column()
        .width('100%')
        .height('100%')
        .backgroundColor($r('app.color.lx_bg'))

      if (this.needLogin) {
        this.buildLogin()
      } else if (!this.ready) {
        this.buildNotReady()
      } else {
        this.buildMain()
      }

      // 顶部 toast
      if (this.toast.length > 0) {
        Text(this.toast)
          .fontSize(13)
          .fontColor($r('app.color.lx_text'))
          .backgroundColor('#CC333336')
          .borderRadius(14)
          .padding({ left: 12, right: 12, top: 7, bottom: 7 })
          .maxLines(2)
          .textOverflow({ overflow: TextOverflow.Ellipsis })
          .constraintSize({ maxWidth: '86%' })
          .position({ x: '50%', y: 44 })
          .translate({ x: '-50%' })
          .zIndex(10)
      }
    }
    .width('100%')
    .height('100%')
  }

  @Builder
  buildLogin() {
    Column({ space: 6 }) {
      Text('理想车控')
        .fontSize(16)
        .fontWeight(FontWeight.Medium)
        .fontColor($r('app.color.lx_text'))

      // 交代「用什么登录」—— 普通用户看到两个输入框，需要知道自己该填什么
      Text('使用理想汽车账号登录')
        .fontSize(10)
        .fontColor($r('app.color.lx_text_dim'))
        .margin({ bottom: 4 })

      // ★ 只在「这台设备根本没法登录」时提示一句用户能懂的话。
      //   原先是 `⚠ ED25519 硬件与软件通道均不可用` —— 算法名对用户毫无意义，
      //   而且这么长的技术串在 466x466 上会挤爆版面。
      if (this.caps !== null && !this.caps.ed25519) {
        Text('此设备暂不支持安全登录，请更新系统后重试')
          .fontSize(10)
          .fontColor($r('app.color.lx_warn'))
          .textAlign(TextAlign.Center)
          .maxLines(2)
          .padding({ left: 24, right: 24 })
      }

      TextInput({ placeholder: '手机号', text: this.phoneInput })
        .type(InputType.PhoneNumber)
        .maxLength(11)
        .fontSize(13)
        .height(36)
        .width('78%')
        .backgroundColor($r('app.color.lx_card'))
        .fontColor($r('app.color.lx_text'))
        .placeholderColor($r('app.color.lx_text_dim'))
        .onChange((v: string) => { this.phoneInput = v; })

      TextInput({ placeholder: '密码', text: this.pwdInput })
        .type(InputType.Password)
        .maxLength(64)
        .fontSize(13)
        .height(36)
        .width('78%')
        .backgroundColor($r('app.color.lx_card'))
        .fontColor($r('app.color.lx_text'))
        .placeholderColor($r('app.color.lx_text_dim'))
        .onChange((v: string) => { this.pwdInput = v; })

      Button(this.loginBusy ? '登录中…' : '登录')
        .fontSize(13)
        .height(34)
        .width('78%')
        .backgroundColor($r('app.color.lx_primary'))
        .fontColor('#FFFFFF')
        .enabled(!this.loginBusy)
        .onClick(() => { this.doLogin(); })

      // ★ 登录耗时提示 —— bcrypt 在 Watch 6 上约 23.6s，界面必须自证「还在跑」
      if (this.loginBusy) {
        Text(this.loginElapsed >= 3
          ? `已等待 ${this.loginElapsed} 秒 · 首次登录约需 20~30 秒，请保持亮屏`
          : '正在连接…')
          .fontSize(9)
          .fontColor($r('app.color.lx_primary'))
          .textAlign(TextAlign.Center)
          .width('100%')
      }

      if (this.loginMsg.length > 0) {
        // 文案已统一为短句（最长约 15 字），不再需要滚动小窗
        Text(this.loginMsg)
          .fontSize(10)
          .fontColor(this.loginFailed ? $r('app.color.lx_warn') : $r('app.color.lx_text_dim'))
          .textAlign(TextAlign.Center)
          .maxLines(3)
          .textOverflow({ overflow: TextOverflow.Ellipsis })
          .padding({ left: 20, right: 20 })
          .width('100%')
      }
    }
    .width('100%')
    .height('100%')
    .justifyContent(FlexAlign.Center)
  }

  @Builder
  buildNotReady() {
    Column({ space: 10 }) {
      Text('理想车控')
        .fontSize(18)
        .fontWeight(FontWeight.Medium)
        .fontColor($r('app.color.lx_text'))
      Text(this.statusMsg)
        .fontSize(12)
        .fontColor($r('app.color.lx_text_dim'))
        .textAlign(TextAlign.Center)
        .padding({ left: 24, right: 24 })
      Button('重试')
        .fontSize(14)
        .height(36)
        .backgroundColor($r('app.color.lx_card'))
        .fontColor($r('app.color.lx_text'))
        .onClick(() => {
          this.statusMsg = '正在初始化…';
          this.bootstrap();
        })
      Button('重新登录')
        .fontSize(12)
        .height(30)
        .backgroundColor($r('app.color.lx_card'))
        .fontColor($r('app.color.lx_text_dim'))
        .onClick(() => {
          this.doRelogin();
        })
    }
    .width('100%')
    .justifyContent(FlexAlign.Center)
  }

  /** 有指令在飞时不允许退出（否则清凭据会让在飞请求撞 401/空引用） */
  private canLogout(): boolean {
    return this.busy.length === 0 && !this.loginBusy;
  }

  /**
   * 退出登录 —— 弹窗「确认」后调用。
   *
   * 实际动作与 doRelogin() 完全一致（清凭据 → 回登录页），
   * 单独包一层只为在「有指令在飞」时给一句反馈：
   * doRelogin() 遇到 busy 会静默 return，用户点了确认却毫无反应，会以为按钮坏了。
   */
  private doLogout(): void {
    if (!this.canLogout()) {
      this.showToast('正在执行操作，请稍后再退出');
      return;
    }
    hilog.info(DOMAIN, TAG, '[退出] 用户确认退出登录');
    this.doRelogin();
  }

  /**
   * 清空登录态并回到登录页。
   *
   * ★ P0-6：clear() 是 async，以前调用处没 await —— 它和随后的登录写库
   *   存在竞态：用户点完「重新登录」立刻输入密码登录，clear() 可能后完成，
   *   把刚写入的新凭据又抹掉（表现为「登录成功但仍提示未登录」）。
   */
  async doRelogin(): Promise<void> {
    if (this.busy.length > 0 || this.loginBusy) {
      return;
    }
    // 停掉刷新链与调温防抖，避免清凭据后还有请求在飞
    if (this.refreshTimer >= 0) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = -1;
    }
    if (this.tempTimer >= 0) {
      clearTimeout(this.tempTimer);
      this.tempTimer = -1;
    }
    try {
      await AppState.get().clear();
    } catch (e) {
      const err = e as Error;
      hilog.warn(DOMAIN, TAG, '清空凭据失败: %{public}s', err.message);
    }
    this.vc = null;
    this.vss = null;
    this.locked = null;
    this.acOn = null;
    this.insideTemp = null;
    this.acOptOn = null;
    this.acOptTemp = null;
    this.acOptUntil = 0;
    this.needLogin = true;
    this.ready = false;
    this.loginMsg = '';
    this.loginFailed = false;
  }

  @Builder
  buildMain() {
    // 布局：上半区（可滚动）+ 底部固定的「退出登录」。
    //
    // ★ 真机 2026-10-25：上一版外层用 SpaceBetween，但纵向预算超了 14vp
    //   （内容 183 + 上下留白 64 = 247 > 表盘 233vp），SpaceBetween 算出负的
    //   剩余空间后各元素只能顺序紧排 → 退出登录压在「开空调/寻车」的下边缘上。
    //   只挪按钮没用：往下 4vp 就会被圆屏切角。
    //
    //   改为「上半区 layoutWeight(1) + 底部固定按钮」：
    //   - 正常状态内容 312px 装进 314px 的可视区，按钮与宫格间距约 34px；
    //   - 空调开启后调温条不再新增行（移到顶部行），高度不变，不顶按钮；
    //   - 上半区仍保留 Scroll 兜底：万一以后内容变长，是滚动而不是重叠。
    Column() {
      Scroll() {
        Column() {
          // ── 顶部行（固定 28vp 高）──
          // ★ 真机 2026-10-25：解锁后空调会自动开启，所以「空调开」是常态。
          //   实测纵向预算：4 张 64vp 卡（272）+ 调温行（84）+ 退出登录（56）
          //   + 上下留白 = 514px，而表盘只有 466px —— 调温行必然被挤出屏幕。
          //   因此调温条与状态条【共用这一行】：空调开着就显示调温，关着就显示状态。
          //   行高两条分支一致，切换时整页不跳动；锁定状态仍由宫格里
          //   「解锁 / 落锁」的文案体现，圆点颜色也保留。
          Row({ space: 6 }) {
            if (this.acOn === true) {
              Circle()
                .width(6)
                .height(6)
                .fill(this.locked === true
                  ? $r('app.color.lx_success')
                  : (this.locked === false
                    ? $r('app.color.lx_warn')
                    : $r('app.color.lx_text_dim')))

              Row({ space: 8 }) {
                this.tempBtn('-', -1)

                Text(`${this.setTemp}℃`)
                  .fontSize(15)
                  .fontWeight(FontWeight.Medium)
                  .fontColor($r('app.color.lx_primary'))
                  .width(40)
                  .textAlign(TextAlign.Center)

                this.tempBtn('+', 1)
              }
            } else {
              Row({ space: 3 }) {
                Circle()
                  .width(6)
                  .height(6)
                  .fill(this.locked === true
                    ? $r('app.color.lx_success')
                    : (this.locked === false
                      ? $r('app.color.lx_warn')
                      : $r('app.color.lx_text_dim')))
                Text(this.locked === true ? '已锁' : (this.locked === false ? '已解锁' : '—'))
                  .fontSize(11)
                  .fontColor($r('app.color.lx_text_dim'))
              }

              Text('·')
                .fontSize(11)
                .fontColor($r('app.color.lx_text_dim'))

              Text(this.insideTemp !== null ? `车内 ${this.insideTemp}℃` : '车内 —')
                .fontSize(11)
                .fontColor($r('app.color.lx_text_dim'))

              if (this.syncing) {
                LoadingProgress()
                  .width(12)
                  .height(12)
                  .color($r('app.color.lx_text_dim'))
              }
            }
          }
          .height(28)
          .justifyContent(FlexAlign.Center)
          .margin({ bottom: 8 })

          // ── 2×2 功能宫格 ──
          Column({ space: 8 }) {
            Row({ space: 8 }) {
              this.funcCard('lock', () => this.onLockTap())

              this.funcCard('auth', () => this.onAuthTap())
            }

            Row({ space: 8 }) {
              this.funcCard('ac', () => this.onAcTap())

              this.funcCard('find', () => this.onFindTap())
            }
          }
          .padding({ left: 12, right: 12 })
        }
        .width('100%')
        .alignItems(HorizontalAlign.Center)
      }
      .width('100%')
      .layoutWeight(1)
      .align(Alignment.Top)
      .scrollBar(BarState.Off)
      .edgeEffect(EdgeEffect.None)

      // ── 退出登录 ──
      // 样式：透明底 + 细描边，视觉权重低于宫格，不像「第五个功能」。
      // 尺寸：圆形表盘底部可用宽度收窄，按钮做窄（92vp）并居中。
      // 位置：作为固定底栏，不参与上半区滚动，永远不会被宫格压住。
      Button('退出登录')
        .fontSize(11)
        .height(28)
        .width(92)
        .backgroundColor(Color.Transparent)
        .fontColor($r('app.color.lx_text_dim'))
        .borderWidth(1)
        .borderColor('#3A3A3C')
        .borderRadius(14)
        .opacity(this.canLogout() ? 1.0 : 0.4)
        // 与宫格留出明确间距。宫格底边在 y≈344px，按钮顶边 378px，
        // 实际间距约 34px；按钮底边 434px，该高度圆屏弦长约 118vp，
        // 92vp 的按钮不会被圆角切到。
        .margin({ top: 16 })
        .onClick(() => {
          if (this.canLogout()) {
            this.logoutDlg.open();
          }
        })
    }
    .width('100%')
    .height('100%')
    .alignItems(HorizontalAlign.Center)
    .padding({ top: 16, bottom: 16 })
  }

  /**
   * ★★★ 十一号坑（真机 2026-10-16）：ArkUI 的 @Builder 对【基本类型参数】
   *   是「传值快照」—— 父组件状态变了不会重渲染。
   *
   *   症状：车辆已锁（顶部显示「已锁」）时，按钮仍显示「落锁」，
   *   但 onLockTap() 读的是最新状态 → 点下去实际执行的是 **解锁**。
   *   文案与行为相反，是个危险的功能误导。
   *
   *   修法：@Builder 只收 key，label/icon/active 一律在【内部实时计算】
   *   （@Builder 内部读 this.xxx 是响应式的）。
   */
  private cardLabel(key: string): string {
    if (key === 'lock') {
      return this.locked === true ? '解锁' : '落锁';
    }
    if (key === 'auth') {
      return this.authArmed ? '再点确认' : '授权驾驶';
    }
    if (key === 'ac') {
      return this.acOn === true ? '关空调' : '开空调';
    }
    return '寻车';
  }

  private cardIcon(key: string): string {
    if (key === 'lock') {
      return this.locked === true ? '🔓' : '🔒';
    }
    if (key === 'auth') {
      return '🔑';
    }
    if (key === 'ac') {
      return '❄';
    }
    return '🔔';
  }

  private cardActive(key: string): boolean {
    if (key === 'lock') {
      return this.locked === true;
    }
    if (key === 'auth') {
      return this.authArmed;      // 仅表示「待确认」，不代表已授权
    }
    if (key === 'ac') {
      return this.acOn === true;
    }
    return false;
  }

  /**
   * 调温按钮是否可用 —— 在 @Builder 内部实时调用。
   * ★ 十二号坑：不要把 busy/setTemp 当参数传进 @Builder（传值快照，不刷新）。
   */
  private tempBtnEnabled(delta: number): boolean {
    if (this.busy.length > 0) {
      return false;
    }
    return delta < 0 ? this.setTemp > AC_MIN_TEMP : this.setTemp < AC_MAX_TEMP;
  }

  /**
   * 圆形调温按钮。
   *
   * ★ 真机 2026-10-20：原来用 `Button('−')` 画 32x32 圆钮，手表上渲染成
   *   【空白圆圈】—— 字形没出来，用户根本找不到调温入口。改用 Text 做按钮
   *   （文字组件渲染最稳），并用 ASCII 的 -/+ 避开字体缺 U+2212 的问题。
   */
  @Builder
  tempBtn(label: string, delta: number) {
    Text(label)
      .fontSize(16)
      .fontWeight(FontWeight.Medium)
      .fontColor(this.tempBtnEnabled(delta)
        ? $r('app.color.lx_text') : $r('app.color.lx_text_dim'))
      .width(26)
      .height(26)
      .textAlign(TextAlign.Center)
      .backgroundColor($r('app.color.lx_card'))
      .borderRadius(13)
      .opacity(this.tempBtnEnabled(delta) ? 1.0 : 0.45)
      .onClick(() => {
        if (this.tempBtnEnabled(delta)) {
          this.onAcTempChange(delta);
        }
      })
  }

  @Builder
  funcCard(key: string, onTap: () => void) {
    Column({ space: 4 }) {
      if (this.busy === key) {
        LoadingProgress()
          .width(20)
          .height(20)
          .color($r('app.color.lx_primary'))
      } else {
        Text(this.cardIcon(key))
          .fontSize(20)
      }
      Text(this.cardLabel(key))
        .fontSize(12)
        .fontColor($r('app.color.lx_text'))
        .maxLines(1)
    }
    .width(72)
    // 56vp：调温条移入顶部行后腾出了空间，但仍需给底部按钮留出明确的间距。
    // 64vp 时空调开启态总高 514px > 表盘 466px，必然挤压按钮。
    .height(56)
    .justifyContent(FlexAlign.Center)
    .backgroundColor(this.cardActive(key) ? '#330FA98D' : $r('app.color.lx_card'))
    .borderRadius(14)
    .borderWidth(this.cardActive(key) ? 1 : 0)
    .borderColor($r('app.color.lx_primary'))
    .opacity(this.busy.length > 0 && this.busy !== key ? 0.5 : 1.0)
    .onClick(() => {
      if (this.busy.length === 0) {
        onTap();
      }
    })
  }
}

/**
 * 退出登录的二次确认弹窗。
 *
 * 为什么用 @CustomDialog 而不是 AlertDialog.show()：
 * 车控页是纯黑底 + 白字，系统 AlertDialog 走浅色底，会与页面风格割裂，
 * 按钮也无法对齐 lx_primary。这里配合 customStyle: true 由自己完全接管
 * 底色、圆角、字号，保证与主界面同一套视觉语言。
 *
 * 「取消」走 controller.close()，「确认」先 close 再回调 ——
 * 顺序不能反：先回调会触发清凭据 + 切页面，弹窗若还没关，会盖在登录页上。
 */
@CustomDialog
struct LogoutDialog {
  controller?: CustomDialogController;
  onConfirm: () => void = () => {};

  build() {
    Column({ space: 10 }) {
      Text('退出登录')
        .fontSize(15)
        .fontWeight(FontWeight.Medium)
        .fontColor($r('app.color.lx_text'))

      // 把后果说清楚（要重新输账号密码），用户才能判断该不该点确认。
      // 文案刻意压到 12 字：上一版 18 字在 200vp 宽度里折在「使/用」中间，很难看。
      Text('退出后需重新输入账号密码')
        .fontSize(10)
        .fontColor($r('app.color.lx_text_dim'))
        .textAlign(TextAlign.Center)
        .maxLines(2)

      Row({ space: 10 }) {
        Button('取消')
          .fontSize(13)
          .height(32)
          .width(78)
          .backgroundColor($r('app.color.lx_card_pressed'))
          .fontColor($r('app.color.lx_text'))
          .onClick(() => {
            if (this.controller !== undefined) {
              this.controller.close();
            }
          })

        Button('确认')
          .fontSize(13)
          .height(32)
          .width(78)
          .backgroundColor($r('app.color.lx_primary'))
          .fontColor('#FFFFFF')
          .onClick(() => {
            if (this.controller !== undefined) {
              this.controller.close();
            }
            this.onConfirm();
          })
      }
      .margin({ top: 4 })
    }
    // 宽度 200vp：圆形表盘弹窗顶边（y≈110）处可用宽度只有约 390px，
    // 再宽四角就会被圆屏切掉。按钮宽 =（200 - 左右 padding 28 - 间距 10）/ 2 = 81，
    // 取 78 留一点余量，避免贴边。
    .width(200)
    .padding({ left: 14, right: 14, top: 16, bottom: 14 })
    .borderRadius(20)
    .backgroundColor($r('app.color.lx_card'))
    .alignItems(HorizontalAlign.Center)
  }
}
