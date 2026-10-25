/**
 * 重计算卸载（taskpool）—— 把秒级同步计算移出 UI 主线程。
 *
 * ★★★ 十号坑（Watch 6 真机实证）：
 *   纯 ArkTS bcrypt 是【秒级同步计算】（PC 实测 cost=10 约 56ms；
 *   Watch 6 实测约 5s，倍率 ~90x）。直接在主线程跑会触发
 *   HarmonyOS 主线程看门狗：
 *
 *     12:27:35.522 AppMS: faultData: com.kylin.lixianghmwatch,pid:15569
 *                  will exit because THREAD_BLOCK_6S
 *     12:27:35.529 resource_schedule_service: [PID 15569 KILLED][SIG 9]
 *
 *   表象为「点登录 → 卡在"正在登录…" → 数秒后闪退」。
 *   注意这不是 JS 异常/JS crash，是【系统强杀】，所以
 *   应用内 try/catch 抓不到，只能从 hilog 的 AppMS/KILLED 看到。
 *
 * 修法：把 bcrypt 丢到 taskpool 工作线程执行。
 *   工作线程不受主线程 THREAD_BLOCK 看门狗约束，UI 全程可响应。
 *
 * 注意：@Concurrent 函数必须是【顶层函数】且不能捕获任何外部变量；
 *   其内部可以调用 import 进来的模块函数（bcryptHash 即此类）。
 */
import { taskpool } from '@kit.ArkTS';
import { bcryptHash } from './Bcrypt';
import { probeCapabilities } from './HarmonyCrypto';

/** 在 taskpool 线程执行的 bcrypt（顶层 + 无外部捕获） */
@Concurrent
function bcryptTask(password: string, salt: string): string {
  return bcryptHash(password, salt);
}

/**
 * 在 taskpool 线程执行的能力探测（顶层 + 无外部捕获）。
 *
 * ★ 只能返回【可序列化】的值 —— CryptoCapabilities 是类实例，
 *   taskpool 跨线程传不回来，故序列化成 JSON 字符串，
 *   由主线程用 capsFromJson() 还原。
 */
@Concurrent
function probeCapsTask(): string {
  const c = probeCapabilities();
  return JSON.stringify({
    'sha256': c.sha256, 'md5': c.md5, 'hmacSha256': c.hmacSha256,
    'rsa': c.rsa, 'aesCtr': c.aesCtr, 'ed25519': c.ed25519,
    'random': c.random, 'mockEnv': c.mockEnv,
    'pureFallback': c.pureFallback, 'pureSelftestOk': c.pureSelftestOk,
    'ed25519Hw': c.ed25519Hw, 'detail': c.detail
  });
}

/** 标准 bcrypt 输出长度（$2a$10$ + 53 字符体） */
const BCRYPT_LEN: number = 60;

/**
 * 异步 bcrypt。
 *
 * ★★★ P0 修复（2026-10-20）：taskpool 失败时【绝不能】回退主线程同步实现。
 *
 *   回退等于必然闪退：bcrypt cost=10 在 Watch 6 上同步耗时约 23.6s，
 *   直接触发主线程看门狗 → `AppMS: will exit because THREAD_BLOCK_6S`
 *   → `[PID x KILLED][SIG 9]`。系统强杀，应用内 try/catch 抓不到。
 *
 *   以前那行 `return bcryptHash(...)` 把「一次可恢复的并发失败」
 *   变成了「进程必死」，且死因完全不可见。现在改成抛可读错误：
 *   登录会失败并显示原因，但进程活着，用户可以重试。
 *
 * @throws Error 工作线程不可用或返回结果不合法
 */
export async function bcryptAsync(password: string, salt: string): Promise<string> {
  let out: Object;
  try {
    const task: taskpool.Task = new taskpool.Task(bcryptTask, password, salt);
    out = await taskpool.execute(task);
  } catch (e) {
    const err = e as Error;
    // ★ 不回退主线程 —— 见上方注释
    throw new Error(
      `密码学工作线程不可用，已中止（若在主线程计算会因阻塞 20+ 秒被系统强杀）：${err.message}`);
  }
  const s: string = out as string;
  if (s === undefined || s === null || s.length !== BCRYPT_LEN) {
    throw new Error(
      `密码学工作线程返回的 bcrypt 结果长度异常(${s === undefined || s === null ? 'null' : s.length})，`
      + `期望 ${BCRYPT_LEN}`);
  }
  return s;
}

/**
 * 异步能力探测（P2-1）。
 *
 * probeCapabilities() 内含 2 次纯 Ed25519 签名 + 1 次 RSA2048 密钥生成，
 * 在手表上是秒级同步计算，摊在主线程属十号坑同类风险（启动即卡顿）。
 * 这里挪到 taskpool；失败时退回主线程同步探测 —— 那只是 1~2 秒，
 * 不构成看门狗风险（与 bcrypt 的 23.6s 完全不是一个量级）。
 */
export async function probeCapabilitiesAsync(): Promise<string> {
  try {
    const task: taskpool.Task = new taskpool.Task(probeCapsTask);
    const out: Object = await taskpool.execute(task);
    const s: string = out as string;
    if (s !== undefined && s !== null && s.length > 2) {
      return s;
    }
    console.error('[heavy] 能力探测返回空，回退主线程');
  } catch (e) {
    const err = e as Error;
    console.error(`[heavy] taskpool 能力探测失败，回退主线程: ${err.message}`);
  }
  return capsToJson();
}

/** 兜底：主线程同步探测后序列化成同样的 JSON 形状 */
function capsToJson(): string {
  const c = probeCapabilities();
  return JSON.stringify({
    'sha256': c.sha256, 'md5': c.md5, 'hmacSha256': c.hmacSha256,
    'rsa': c.rsa, 'aesCtr': c.aesCtr, 'ed25519': c.ed25519,
    'random': c.random, 'mockEnv': c.mockEnv,
    'pureFallback': c.pureFallback, 'pureSelftestOk': c.pureSelftestOk,
    'ed25519Hw': c.ed25519Hw, 'detail': c.detail
  });
}

/**
 * taskpool 可用性自检 —— 跑一次极小的任务，确认工作线程能起来。
 * 供登录页诊断小字用。
 */
export async function taskpoolSelftest(): Promise<string> {
  try {
    const t0: number = Date.now();
    const task: taskpool.Task = new taskpool.Task(bcryptTask,
      'x', '$2a$04$abcdefghijklmnopqrstuu');   // cost=4，极快
    const out: Object = await taskpool.execute(task);
    const s: string = out as string;
    return s.length === BCRYPT_LEN ? `OK ${Date.now() - t0}ms` : `长度异常 ${s.length}`;
  } catch (e) {
    const err = e as Error;
    return `不可用: ${err.message}`;
  }
}
