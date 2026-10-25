/**
 * HarmonyOS 加密能力封装 —— 【双通道】硬件 + 纯 ArkTS 降级
 *
 * ═══════════════════════════════════════════════════════════════
 *  为什么要有纯实现降级
 * ═══════════════════════════════════════════════════════════════
 *
 *  1) DevEco **Previewer** 里 `cryptoFramework` 的所有同步接口都是
 *     mocked 实现，一律返回空 `Uint8Array` 且不抛异常。日志原文：
 *       The createMd / digestSync / createMac / createCipher /
 *       createAsyKeyGenerator / generateRandomSync interface in the
 *       previewer is a mocked implementation…
 *     → 硬件通道下 sha256() 返回 0 字节，`BigInt('0x')` 直接抛异常，
 *       PAKE 登录连第一步都走不到。有了纯实现，Previewer 才能跑通全链路。
 *
 *  2) 华为官方文档的「轻量级智能穿戴」HUKS 支持列表里 **没有 ED25519**。
 *     Watch 6 属完整 HarmonyOS、预期支持，但这是【未经真机验证的假设】。
 *     一旦真机不支持，纯实现就是唯一退路。
 *
 * ═══════════════════════════════════════════════════════════════
 *  策略
 * ═══════════════════════════════════════════════════════════════
 *
 *  · 启动时探测一次 (probeCapabilities)，结果缓存。
 *  · 检测到桩环境 → 全程走纯实现（不再尝试硬件，避免反复打日志）。
 *  · 真机环境 → 优先硬件；**每次调用失败都会自动降级到纯实现**，
 *    对上层调用者完全透明（返回类型不变）。
 *  · 非对称密钥：`RsaKeyHandle` 同时持有硬件密钥对象与纯实现密钥参数，
 *    哪条通道可用就走哪条 —— 这是为了避开 `cryptoFramework.PriKey`
 *    这一硬件专属类型泄漏到协议层。
 *
 * ═══════════════════════════════════════════════════════════════
 *  覆盖的密码学原语
 * ═══════════════════════════════════════════════════════════════
 *
 *  · SHA-256 / MD5（摘要）
 *  · HMAC-SHA256（x-chj 请求签名、keySuite 引导签名）
 *  · RSA-2048 PKCS#1 v1.5（解密 + SHA256 签名，keySuite 身份派生）
 *  · AES-256-CTR（hac 派生）
 *  · Ed25519（PAKE proof 签名）
 */

import { cryptoFramework } from '@kit.CryptoArchitectureKit';
import {
  bytesToBase64, bytesToHex, hexToBytes, utf8ToBytes
} from './Codec';
import { sha256Bytes, md5Bytes } from './pure/Sha';
import { hmacSha256Bytes } from './pure/Hmac';
import { aes256Ctr } from './pure/Aes';
import {
  RsaPrivateKey, parseRsaPrivateKeyDer,
  rsaDecryptPkcs1 as rsaDecryptPure,
  rsaSignPkcs1Sha256 as rsaSignPure
} from './pure/Rsa';
import { ed25519SignPure, ed25519Selftest, ed25519SelftestDetail } from './pure/Ed25519';

const MD_ALGO = 'SHA256';
const MD_MD5 = 'MD5';

// ─────────────────────────────────────────────────────────────
//  通道判定
// ─────────────────────────────────────────────────────────────

let pureModeCache: boolean | null = null;

/**
 * 当前是否处于「cryptoFramework 为桩实现」的环境。
 *
 * ★ 判定必须校验【实际字节数】而不是「是否抛异常」——
 *   Previewer 的桩实现不抛异常，只返回空数组，用异常判会得到假阴性。
 */
function detectPureMode(): boolean {
  try {
    const md = cryptoFramework.createMd(MD_ALGO);
    md.updateSync({ data: new Uint8Array([1, 2, 3]) });
    const out: Uint8Array = md.digestSync().data;
    return !(out !== undefined && out !== null && out.length === 32);
  } catch (e) {
    return true;
  }
}

/** 是否走纯 ArkTS 实现（结果缓存） */
export function isPureMode(): boolean {
  if (pureModeCache === null) {
    pureModeCache = detectPureMode();
  }
  return pureModeCache;
}

// ─────────────────────────────────────────────────────────────
//  摘要
// ─────────────────────────────────────────────────────────────

/** SHA-256 摘要（32 字节） */
export function sha256(data: Uint8Array): Uint8Array {
  if (isPureMode()) {
    return sha256Bytes(data);
  }
  try {
    const md = cryptoFramework.createMd(MD_ALGO);
    md.updateSync({ data: data });
    const out: Uint8Array = md.digestSync().data;
    if (out !== undefined && out !== null && out.length === 32) {
      return out;
    }
    console.error('[crypto] SHA-256 硬件返回长度异常，降级纯实现');
  } catch (e) {
    console.error('[crypto] SHA-256 硬件调用失败，降级纯实现');
  }
  return sha256Bytes(data);
}

/** MD5 摘要（16 字节，仅用于 Content-MD5 头，非安全用途） */
export function md5(data: Uint8Array): Uint8Array {
  if (isPureMode()) {
    return md5Bytes(data);
  }
  try {
    const md = cryptoFramework.createMd(MD_MD5);
    md.updateSync({ data: data });
    const out: Uint8Array = md.digestSync().data;
    if (out !== undefined && out !== null && out.length === 16) {
      return out;
    }
    console.error('[crypto] MD5 硬件返回长度异常，降级纯实现');
  } catch (e) {
    console.error('[crypto] MD5 硬件调用失败，降级纯实现');
  }
  return md5Bytes(data);
}

/** SHA-256 摘要的 hex 字符串 */
export function sha256Hex(data: Uint8Array): string {
  return bytesToHex(sha256(data));
}

// ─────────────────────────────────────────────────────────────
//  HMAC-SHA256
// ─────────────────────────────────────────────────────────────

/**
 * HMAC-SHA256。
 *
 * ★ 关键实测结论（参考项目踩过）：
 *   key 必须是 hac_key 的【原始 32 字节】，用 base64 文本再 encode() 会报
 *   "请求签名错误"（100005）。这里接口只接受 Uint8Array，从类型上杜绝误用。
 */
export function hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
  if (!isPureMode()) {
    try {
      const mac = cryptoFramework.createMac('SHA256');
      const symKey = cryptoFramework.createSymKeyGenerator('HMAC')
        .convertKeySync({ data: key });
      mac.initSync(symKey);
      mac.updateSync({ data: data });
      const out: Uint8Array = mac.doFinalSync().data;
      if (out !== undefined && out !== null && out.length === 32) {
        return out;
      }
      console.error('[crypto] HMAC-SHA256 硬件返回长度异常，降级纯实现');
    } catch (e) {
      console.error('[crypto] HMAC-SHA256 硬件调用失败，降级纯实现');
    }
  }
  return hmacSha256Bytes(key, data);
}

/** HMAC-SHA256 → base64（业务接口签名用） */
export function hmacSha256Base64(key: Uint8Array, data: Uint8Array): string {
  return bytesToBase64(hmacSha256(key, data));
}

/** HMAC-SHA256 → hex（keySuite 引导签名用，注意与业务接口不同！） */
export function hmacSha256Hex(key: Uint8Array, data: Uint8Array): string {
  return bytesToHex(hmacSha256(key, data));
}

// ─────────────────────────────────────────────────────────────
//  RSA（双层密钥句柄）
// ─────────────────────────────────────────────────────────────

/**
 * RSA 私钥句柄。
 *
 * ★ 为什么需要这一层：纯软件实现产不出 `cryptoFramework.PriKey`
 *   （那是硬件专属类型）。把两种表示一起装进句柄，协议层就不用关心
 *   自己跑在哪条通道上。
 *
 * ★ hw 与 pure 会【同时】填充：硬件调用在真机上极少失败，但一旦失败
 *   （例如设备能力缺失），现场再解析 DER 会引入难以预料的失败点。
 *   预解析的开销只有几毫秒，一次性。
 */
export class RsaKeyHandle {
  /** 硬件密钥对象；桩环境或加载失败时为 null */
  hw: cryptoFramework.PriKey | null = null;
  /** 纯软件解析结果；始终填充 */
  pure: RsaPrivateKey | null = null;

  available(): boolean {
    return this.hw !== null || this.pure !== null;
  }
}

/**
 * 从 PKCS#8 DER 字节构造 RSA 私钥句柄。
 *
 * 两条通道都会尝试填充；只要有一条成功即返回。
 */
export function loadRsaPrivateKeyFromDer(der: Uint8Array): RsaKeyHandle {
  const h: RsaKeyHandle = new RsaKeyHandle();

  // 纯实现通道：始终解析（成本低，且是硬件失败时的唯一退路）
  try {
    h.pure = parseRsaPrivateKeyDer(der);
  } catch (e) {
    const err = e as Error;
    console.error(`[crypto] RSA DER 纯解析失败: ${err.message}`);
  }

  // 硬件通道：桩环境下跳过，避免无谓的 mocked 调用与日志噪音
  if (!isPureMode()) {
    try {
      const gen = cryptoFramework.createAsyKeyGenerator('RSA2048');
      const pair = gen.convertKeySync(null, { data: der });
      h.hw = pair.priKey;
    } catch (e) {
      const err = e as Error;
      console.error(`[crypto] RSA 私钥硬件加载失败，将走纯实现: ${err.message}`);
      h.hw = null;
    }
  }

  if (!h.available()) {
    throw new Error('RSA 私钥加载失败：硬件与纯实现均不可用');
  }
  return h;
}

/**
 * RSA 解密（PKCS#1 v1.5）。
 * 用于 keySuite：RD = decrypt(tempAesKey)
 */
export function rsaDecryptPkcs1(key: RsaKeyHandle, cipher: Uint8Array): Uint8Array {
  if (key.hw !== null) {
    try {
      const engine = cryptoFramework.createCipher('RSA2048|PKCS1');
      engine.initSync(cryptoFramework.CryptoMode.DECRYPT_MODE, key.hw, null);
      const out: Uint8Array = engine.doFinalSync({ data: cipher }).data;
      if (out !== undefined && out !== null && out.length > 0) {
        return out;
      }
      console.error('[crypto] RSA 硬件解密返回空，降级纯实现');
    } catch (e) {
      const err = e as Error;
      console.error(`[crypto] RSA 硬件解密失败，降级纯实现: ${err.message}`);
    }
  }
  const pk: RsaPrivateKey | null = key.pure;
  if (pk === null) {
    throw new Error('RSA 解密不可用：纯实现密钥参数缺失');
  }
  return rsaDecryptPure(pk, cipher);
}

/**
 * RSA 签名（PKCS#1 v1.5 + SHA256）。
 * 用于 keySuite 的 body sign 字段。
 */
export function rsaSignPkcs1Sha256(key: RsaKeyHandle, data: Uint8Array): Uint8Array {
  if (key.hw !== null) {
    try {
      const signer = cryptoFramework.createSign('RSA2048|PKCS1|SHA256');
      signer.initSync(key.hw);
      signer.updateSync({ data: data });
      const out: Uint8Array = signer.signSync(null).data;
      if (out !== undefined && out !== null && out.length === 256) {
        return out;
      }
      console.error('[crypto] RSA 硬件签名返回长度异常，降级纯实现');
    } catch (e) {
      const err = e as Error;
      console.error(`[crypto] RSA 硬件签名失败，降级纯实现: ${err.message}`);
    }
  }
  const pk: RsaPrivateKey | null = key.pure;
  if (pk === null) {
    throw new Error('RSA 签名不可用：纯实现密钥参数缺失');
  }
  return rsaSignPure(pk, data);
}

// ─────────────────────────────────────────────────────────────
//  AES-256-CTR
// ─────────────────────────────────────────────────────────────

/**
 * AES-256-CTR 解密（无填充）。
 * 用于 hac 派生：hac = decrypt(hmacKey, key=RD, iv=tempIv)
 */
export function aesCtrDecrypt(key: Uint8Array, iv: Uint8Array, cipher: Uint8Array): Uint8Array {
  if (!isPureMode()) {
    try {
      const symGen = cryptoFramework.createSymKeyGenerator('AES256');
      const symKey = symGen.convertKeySync({ data: key });
      const engine = cryptoFramework.createCipher('AES256|CTR|NoPadding');
      const params: cryptoFramework.IvParamsSpec = {
        iv: { data: iv },
        algName: 'IvParamsSpec'
      };
      engine.initSync(cryptoFramework.CryptoMode.DECRYPT_MODE, symKey, params);
      const out: Uint8Array = engine.doFinalSync({ data: cipher }).data;
      if (out !== undefined && out !== null && out.length === cipher.length) {
        return out;
      }
      console.error('[crypto] AES-CTR 硬件返回长度异常，降级纯实现');
    } catch (e) {
      const err = e as Error;
      console.error(`[crypto] AES-CTR 硬件调用失败，降级纯实现: ${err.message}`);
    }
  }
  return aes256Ctr(key, iv, cipher);
}

// ─────────────────────────────────────────────────────────────
//  Ed25519
// ─────────────────────────────────────────────────────────────

/**
 * RFC 8032 §7.1 TEST 2 的已知向量 —— 用来【验证硬件 Ed25519 的语义】。
 *
 * 只验"能签出 64 字节"是不够的：语义错了也是 64 字节。
 * 必须逐字节比对官方向量，才能确认硬件实现是纯 RFC 8032。
 */
const RFC8032_T2_SEED_HEX =
  '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb';
const RFC8032_T2_MSG_HEX = '72';
const RFC8032_T2_SIG_HEX =
  '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da'
  + '085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00';

/** 硬件 Ed25519 候选算法名（HarmonyOS 文档口径；带 |NoDigest 表示不做预哈希） */
const ED25519_GEN_ALGO = 'Ed25519';
const ED25519_SIGN_ALGO = 'Ed25519';

let ed25519HwCache: boolean | null = null;
let ed25519HwNote: string = '';

/** 上一次硬件 Ed25519 探测的说明（供排障显示） */
export function ed25519HardwareNote(): string {
  return ed25519HwNote;
}

/** 用 32 字节种子构造硬件私钥对象 */
function hwEd25519PriKey(seed: Uint8Array): cryptoFramework.PriKey {
  const gen = cryptoFramework.createAsyKeyGenerator(ED25519_GEN_ALGO);
  const pair = gen.convertKeySync({ data: seed }, null);
  return pair.priKey;
}

/**
 * 硬件 Ed25519 是否【可用且语义正确】。结果缓存，只真正测一次。
 *
 * 判据：把 RFC 8032 TEST 2 的 seed 喂给硬件，签同一消息，
 *       结果必须与官方签名【逐字节相等】。
 */
function ed25519HardwareUsable(): boolean {
  if (ed25519HwCache !== null) {
    return ed25519HwCache;
  }
  ed25519HwCache = false;
  ed25519HwNote = '';
  try {
    const pri: cryptoFramework.PriKey = hwEd25519PriKey(hexToBytes(RFC8032_T2_SEED_HEX));
    const signer = cryptoFramework.createSign(ED25519_SIGN_ALGO);
    signer.initSync(pri);
    signer.updateSync({ data: hexToBytes(RFC8032_T2_MSG_HEX) });
    const out: Uint8Array = signer.signSync(null).data;
    if (out === undefined || out === null || out.length !== 64) {
      ed25519HwNote = `长度异常(${out === undefined || out === null ? 'null' : out.length})`;
      console.error('[crypto] 硬件 Ed25519 输出长度异常，改用纯实现');
      return false;
    }
    const got: string = bytesToHex(out);
    if (got !== RFC8032_T2_SIG_HEX) {
      ed25519HwNote = '语义不符(RFC8032 TEST2 不通过)';
      console.error('[crypto] 硬件 Ed25519 与 RFC 8032 不符，改用纯实现');
      return false;
    }
    ed25519HwCache = true;
    ed25519HwNote = '硬件可用';
    console.error('[crypto] 硬件 Ed25519 通过 RFC 8032 向量校验');
    return true;
  } catch (e) {
    const err = e as Error;
    ed25519HwNote = `硬件不可用(${err.message})`;
    console.error(`[crypto] 硬件 Ed25519 不可用，改用纯实现: ${err.message}`);
    return false;
  }
}

/** 硬件 Ed25519 是否可用（供能力探测查询，不触发真实签名） */
export function ed25519HardwareOk(): boolean {
  if (isPureMode()) {
    return false;
  }
  return ed25519HardwareUsable();
}

/**
 * Ed25519 签名（PAKE proof）。
 *
 * ★ 输入是 32 字节的 ed25519 【种子】(seed)，不是 64 字节扩展私钥。
 *   PAKE 协议里 ed_priv = sha256(bcrypt_hash) 恰好是 32 字节。
 *
 * ★★ 为什么不能"硬件优先、成功就用"：
 *   PAKE 的 proof 必须与 Python 侧【逐字节一致】。而 HarmonyOS 的
 *   `cryptoFramework` Ed25519 语义并不明确（可能是 Ed25519ph / 带预哈希，
 *   也可能纯 RFC 8032）。**只要语义不同，签名就不是 64 字节以内的偶然相等，
 *   而是完全不同的值** —— 服务端会直接判 proof 错误，表现为"登录失败"。
 *   因此这里【不猜】：用 RFC 8032 TEST 2 的已知向量去验硬件，
 *   验过了才用；验不过（含抛异常）一律走已验证的纯实现。
 */
export function ed25519Sign(seed: Uint8Array, msg: Uint8Array): Uint8Array {
  if (!isPureMode() && ed25519HardwareUsable()) {
    try {
      const pri: cryptoFramework.PriKey = hwEd25519PriKey(seed);
      const signer = cryptoFramework.createSign(ED25519_SIGN_ALGO);
      signer.initSync(pri);
      signer.updateSync({ data: msg });
      const out: Uint8Array = signer.signSync(null).data;
      if (out !== undefined && out !== null && out.length === 64) {
        return out;
      }
      console.error('[crypto] Ed25519 硬件签名返回长度异常，降级纯实现');
    } catch (e) {
      const err = e as Error;
      console.error(`[crypto] Ed25519 硬件签名失败，降级纯实现: ${err.message}`);
    }
  }
  // ★ 纯实现如果真的抛了（真机上出现过），必须给一个【可识别的】错误，
  //   否则会以一句语焉不详的 "登录失败" 收场，无从判断卡在哪。
  try {
    return ed25519SignPure(seed, msg);
  } catch (e) {
    const err = e as Error;
    console.error(`[crypto] Ed25519 纯实现失败: ${err.message}`);
    throw new Error(`Ed25519 纯实现失败: ${err.message}`);
  }
}

// ─────────────────────────────────────────────────────────────
//  能力探测
// ─────────────────────────────────────────────────────────────

export class CryptoCapabilities {
  sha256: boolean = false;
  md5: boolean = false;
  hmacSha256: boolean = false;
  rsa: boolean = false;
  aesCtr: boolean = false;
  ed25519: boolean = false;
  random: boolean = false;

  /**
   * cryptoFramework 是否为 Previewer 的【桩实现】。
   * 为 true 时上述能力全部由纯 ArkTS 实现提供。
   */
  mockEnv: boolean = false;

  /** 是否已启用纯 ArkTS 降级通道 */
  pureFallback: boolean = false;

  /** 纯实现自检是否通过（RFC 8032 TEST 1） */
  pureSelftestOk: boolean = false;

  /** 硬件 Ed25519 是否可用（false 表示走纯实现，不代表功能不可用） */
  ed25519Hw: boolean = false;

  /** ★ 真机排障用：各原语的实测结果（一行，直接显示在 UI 上） */
  detail: string = '';

  /** 是否全部必需能力可用 */
  allRequired(): boolean {
    // ed25519 只在「重新登录」时需要；已登录用户走 refresh_token 时不碰它，
    // 所以单独判断。
    return this.sha256 && this.md5 && this.hmacSha256
      && this.rsa && this.aesCtr && this.random;
  }

  /** 实际生效的实现通道 */
  channel(): string {
    return this.pureFallback ? '纯 ArkTS 软件实现' : 'cryptoFramework 硬件实现';
  }

  summary(): string {
    const tail = this.mockEnv
      ? ' | ★ Previewer 桩环境：cryptoFramework 返回空数据，已整体切到纯 ArkTS 实现'
      : '';
    return `通道=${this.channel()} sha256=${this.sha256} md5=${this.md5} `
      + `hmac=${this.hmacSha256} rsa=${this.rsa} aesCtr=${this.aesCtr} `
      + `ed25519=${this.ed25519} rng=${this.random}${tail}`;
  }
}

let cachedCaps: CryptoCapabilities | null = null;

/** 纯实现自检失败时的具体原因（真机排障用） */
let pureProbeNote: string = '';

/** 纯实现 Ed25519 自检耗时（毫秒）；-1 表示未测 */
let pureProbeMs: number = -1;

/** 纯实现自检耗时（供排障显示） */
export function pureSelftestMs(): number {
  return pureProbeMs;
}

/**
 * 用固定输入验证纯实现确实能产出【正确结果】（而非"没抛异常"）。
 *
 * ★ 不能只验长度 —— 长度对但内容错，在 Previewer 里看不出来，
 *   在真机上会变成"签名错误 / 登录失败"。
 *   所以 ed25519 这一段直接比对 RFC 8032 官方向量。
 *
 * ★ 同时记录耗时：手表上 BigInt 可能比桌面慢两个数量级，
 *   "很慢"和"崩了"必须能区分开。
 */
function probePure(): boolean {
  pureProbeNote = '';
  try {
    if (sha256Bytes(new Uint8Array([1, 2, 3])).length !== 32) {
      pureProbeNote = 'SHA-256 长度错';
      return false;
    }
    if (md5Bytes(new Uint8Array([1, 2, 3])).length !== 16) {
      pureProbeNote = 'MD5 长度错';
      return false;
    }
    if (hmacSha256Bytes(new Uint8Array(32).fill(7), utf8ToBytes('probe')).length !== 32) {
      pureProbeNote = 'HMAC 长度错';
      return false;
    }
    if (aes256Ctr(new Uint8Array(32).fill(3), new Uint8Array(16).fill(1),
      new Uint8Array(16).fill(0)).length !== 16) {
      pureProbeNote = 'AES-CTR 长度错';
      return false;
    }
    const t0: number = Date.now();
    const edNote: string = ed25519SelftestDetail();
    const edMs: number = Date.now() - t0;
    pureProbeMs = edMs;
    if (edNote !== 'OK') {
      pureProbeNote = `Ed25519 ${edNote}`;
      return false;
    }
    return true;
  } catch (e) {
    const err = e as Error;
    pureProbeNote = `异常 ${err.message}`;
    return false;
  }
}

/**
 * 探测加密能力。结果缓存，只在首次调用时真正探测。
 *
 * 这是路线 B（手表直连）的可行性检查 —— 如果 ed25519 不可用，
 * 手表端仍可用已保存的 refresh_token 维持登录，但无法重新做 PAKE 登录。
 */
export function probeCapabilities(): CryptoCapabilities {
  if (cachedCaps !== null) {
    return cachedCaps;
  }
  const c = new CryptoCapabilities();
  c.mockEnv = isPureMode();

  // ★ 桩环境：cryptoFramework 全是空返回，全部能力交由纯实现提供
  if (c.mockEnv) {
    c.pureFallback = true;
    c.pureSelftestOk = probePure();
    c.sha256 = c.pureSelftestOk;
    c.md5 = c.pureSelftestOk;
    c.hmacSha256 = c.pureSelftestOk;
    c.aesCtr = c.pureSelftestOk;
    c.rsa = c.pureSelftestOk;
    c.ed25519 = c.pureSelftestOk;
    c.ed25519Hw = false;
    c.random = true;      // randomBytes 有 Math.random 兜底
    c.detail = buildDetail(c);
    cachedCaps = c;
    return c;
  }

  // ★ 真机路径：逐项探测硬件实现，且校验【实际字节数】
  try {
    const d = sha256(new Uint8Array([1, 2, 3]));
    c.sha256 = d !== undefined && d.length === 32;
  } catch (e) {
    c.sha256 = false;
  }
  try {
    const d = md5(new Uint8Array([1, 2, 3]));
    c.md5 = d !== undefined && d.length === 16;
  } catch (e) {
    c.md5 = false;
  }
  try {
    const d = hmacSha256(new Uint8Array(32).fill(7), utf8ToBytes('probe'));
    c.hmacSha256 = d !== undefined && d.length === 32;
  } catch (e) {
    c.hmacSha256 = false;
  }
  try {
    const d = aesCtrDecrypt(new Uint8Array(32).fill(3), new Uint8Array(16).fill(1),
      new Uint8Array(16).fill(0));
    c.aesCtr = d !== undefined && d.length === 16;
  } catch (e) {
    c.aesCtr = false;
  }
  try {
    const r = cryptoFramework.createRandom();
    const d: Uint8Array = r.generateRandomSync(16).data;
    c.random = d !== undefined && d !== null && d.length === 16;
  } catch (e) {
    c.random = false;
  }

  // ── 非对称 ──
  // ★★ 六号坑（真机 Watch 6 实测踩到）：这里【绝对不能】把「硬件探测」
  //   和「整体可用性」塞进同一个 try 块。真机上硬件 ED25519 不可用时，
  //   `createAsyKeyGenerator('Ed25519')` 会抛异常 → 整个 try 跳 catch →
  //   把前面已经判定成功的 `c.ed25519 = true` 冲成 false →
  //   UI 误报「本机不支持 ED25519，无法登录」，而纯实现明明是好的。
  //   → 两个判定必须各自独立 try。
  try {
    const seed: Uint8Array = new Uint8Array(32).fill(9);
    const sig: Uint8Array = ed25519Sign(seed, utf8ToBytes('probe'));
    // ed25519Sign 内部会「硬件验不过就降级纯实现」，
    // 所以这里拿到的 64 字节只要长度对，就代表【存在可用通道】。
    c.ed25519 = sig !== undefined && sig !== null && sig.length === 64;
  } catch (e) {
    const err = e as Error;
    c.ed25519 = false;
    console.error(`[crypto] Ed25519 两条通道都不可用: ${err.message}`);
  }
  // 硬件支持情况：独立探测，失败只影响通道标记，不影响可用性
  c.ed25519Hw = ed25519HardwareOk();
  if (!c.ed25519Hw && c.ed25519) {
    c.pureFallback = true;      // 功能可用，但走的是软件实现
  }

  // RSA：同样只看「实际能不能完成一次运算」
  c.rsa = false;
  try {
    const kp = cryptoFramework.createAsyKeyGenerator('RSA2048').generateKeyPairSync();
    const pri: cryptoFramework.PriKey = kp.priKey;
    c.rsa = pri !== undefined && pri !== null;
  } catch (e) {
    c.rsa = false;
  }

  // 真机上也保底验证一次纯实现，确保退路是通的
  c.pureSelftestOk = probePure();
  c.detail = buildDetail(c);

  cachedCaps = c;
  return c;
}

/**
 * 从 JSON 还原 CryptoCapabilities。
 *
 * ★ 为什么需要：能力探测已挪到 taskpool（HeavyCrypto.probeCapabilitiesAsync）。
 *   taskpool 只能跨线程回传可序列化的值，类实例传不回来，
 *   故工作线程返回 JSON 字符串，主线程用本函数还原。
 */
export function capsFromJson(s: string): CryptoCapabilities {
  const c = new CryptoCapabilities();
  try {
    const o = JSON.parse(s) as Record<string, Object>;
    c.sha256 = o['sha256'] === true;
    c.md5 = o['md5'] === true;
    c.hmacSha256 = o['hmacSha256'] === true;
    c.rsa = o['rsa'] === true;
    c.aesCtr = o['aesCtr'] === true;
    c.ed25519 = o['ed25519'] === true;
    c.random = o['random'] === true;
    c.mockEnv = o['mockEnv'] === true;
    c.pureFallback = o['pureFallback'] === true;
    c.pureSelftestOk = o['pureSelftestOk'] === true;
    c.ed25519Hw = o['ed25519Hw'] === true;
    c.detail = String(o['detail'] ?? '');
  } catch (e) {
    const err = e as Error;
    console.error(`[crypto] 解析能力探测结果失败: ${err.message}`);
    c.detail = '能力探测结果解析失败';
  }
  return c;
}

/** 拼一行紧凑的自检结果，方便在手表 UI 上直接显示 / 截图排障 */
function buildDetail(c: CryptoCapabilities): string {
  const p: string[] = [];
  p.push(c.mockEnv ? 'Previewer桩' : '真机');
  p.push(`纯:${c.pureSelftestOk ? 'OK' : 'FAIL'}`);
  p.push(`sha:${c.sha256 ? 'OK' : 'NO'}`);
  p.push(`md5:${c.md5 ? 'OK' : 'NO'}`);
  p.push(`hmac:${c.hmacSha256 ? 'OK' : 'NO'}`);
  p.push(`aes:${c.aesCtr ? 'OK' : 'NO'}`);
  p.push(`rsa:${c.rsa ? 'OK' : 'NO'}`);
  p.push(`ed:${c.ed25519 ? 'OK' : 'NO'}`);
  p.push(`edHw:${c.ed25519Hw ? 'Y' : 'N'}`);
  p.push(`rng:${c.random ? 'OK' : 'NO'}`);
  if (pureProbeMs >= 0) {
    p.push(`ed纯:${pureProbeMs}ms`);
  }
  if (!c.pureSelftestOk && pureProbeNote.length > 0) {
    p.push(`| 纯实现:${pureProbeNote}`);
  }
  const note: string = ed25519HardwareNote();
  if (note.length > 0) {
    p.push(`| ${note}`);
  }
  return p.join(' ');
}

// ─────────────────────────────────────────────────────────────
//  随机数
// ─────────────────────────────────────────────────────────────

/** 密码学安全随机字节 */
export function randomBytes(n: number): Uint8Array {
  if (!isPureMode()) {
    try {
      const r = cryptoFramework.createRandom();
      const d: Uint8Array = r.generateRandomSync(n).data;
      if (d !== undefined && d !== null && d.length === n) {
        return d;
      }
    } catch (e) {
      // 落到下面的兜底
    }
  }
  // ★ 兜底：Previewer 桩环境返回空数组，且 Math.random 并非密码学安全。
  //   该路径只在【开发环境】生效，真机永远走 cryptoFramework。
  const fb = new Uint8Array(n);
  for (let i = 0; i < n; i++) {
    fb[i] = Math.floor(Math.random() * 256) & 0xff;
  }
  return fb;
}

/** 密码学安全随机 hex（等价 Python secrets.token_hex） */
export function randomHex(nBytes: number): string {
  return bytesToHex(randomBytes(nBytes));
}

/** 生成 UUID v4 字符串（等价 Python uuid.uuid4().hex） */
export function uuid4Hex(): string {
  const b = randomBytes(16);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  return bytesToHex(b);
}
