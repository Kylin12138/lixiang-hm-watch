/**
 * 纯 ArkTS Ed25519（RFC 8032）—— 仅签名
 *
 * ★★ 双重价值
 *
 *   1) Previewer 桩环境：cryptoFramework 的 createAsyKeyGenerator('Ed25519')
 *      是 mocked 实现，拿不到真私钥、签不出真签名 → PAKE 登录必炸。
 *      本文件让 Previewer 也能跑通完整登录链路。
 *
 *   2) 真机兜底：华为官方文档的「轻量级智能穿戴」HUKS 支持列表里
 *      **没有 ED25519**。Watch 6 属完整 HarmonyOS，预期支持，
 *      但这是【未经真机验证的假设】。一旦真机不支持，本实现就是唯一退路。
 *
 * 实现要点
 *   · 曲线：twisted Edwards  -x² + y² = 1 + d·x²·y²   over GF(2^255-19)
 *   · 坐标：扩展坐标 (X:Y:Z:T)，全程只需 1 次域求逆（仿射坐标会慢两个数量级）
 *   · 域运算全部用 BigInt，所有结果归一化到 [0, p)
 *
 * ⚠️ 安全性说明：标量乘使用朴素的倍点-加点，**不是常数时间**实现。
 *    对「手表控制自己车辆」这一威胁模型，时序侧信道的实际风险极低；
 *    若日后要强化，应换成固定窗口 + 摆动 (wNAF) 且分支无关的写法。
 */

import { sha512Bytes } from './Sha';

// ─────────────────────────────────────────────────────────────
//  常量
// ─────────────────────────────────────────────────────────────

const BIG0: bigint = BigInt(0);
const BIG1: bigint = BigInt(1);
const BIG2: bigint = BigInt(2);
const BIG8: bigint = BigInt(8);
const BIG254: bigint = BigInt(254);
const BIG255: bigint = BigInt(255);
const BIGFF: bigint = BigInt(0xff);

/** 域特征 p = 2^255 - 19 */
const P: bigint = BigInt('0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED');

/** 群的阶 L = 2^252 + 27742317777372353535851937790883648493 */
const L: bigint = BigInt('0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED');

// ─────────────────────────────────────────────────────────────
//  域运算
// ─────────────────────────────────────────────────────────────

/** 归一化到 [0, p) */
function fmod(x: bigint): bigint {
  const r: bigint = x % P;
  return r < BIG0 ? r + P : r;
}

/** 模幂（平方-乘法） */
function fpow(b: bigint, e: bigint): bigint {
  let r: bigint = BIG1;
  let x: bigint = fmod(b);
  let n: bigint = e;
  while (n > BIG0) {
    if ((n & BIG1) === BIG1) {
      r = fmod(r * x);
    }
    x = fmod(x * x);
    n >>= BIG1;
  }
  return r;
}

/** 域求逆（费马小定理：a^(p-2)） */
function finv(a: bigint): bigint {
  return fpow(a, P - BIG2);
}

/** 字节串 → 小端整数 */
function bytesToNumLE(b: Uint8Array): bigint {
  let r: bigint = BIG0;
  for (let i: number = b.length - 1; i >= 0; i--) {
    r = (r << BIG8) | BigInt(b[i]);
  }
  return r;
}

/** 整数 → 32 字节小端 */
function numToBytes32LE(v: bigint): Uint8Array {
  const out: Uint8Array = new Uint8Array(32);
  let x: bigint = v;
  for (let i: number = 0; i < 32; i++) {
    out[i] = Number(x & BIGFF);
    x >>= BIG8;
  }
  return out;
}

// ─────────────────────────────────────────────────────────────
//  曲线点（扩展坐标 X:Y:Z:T，满足 T = X·Y/Z）
// ─────────────────────────────────────────────────────────────

class Pt {
  X: bigint = BIG0;
  Y: bigint = BIG1;
  Z: bigint = BIG1;
  T: bigint = BIG0;
}

/** 单位元 (0 : 1 : 1 : 0) */
function ptIdentity(): Pt {
  return new Pt();
}

/**
 * 点加（add-2008-hwcd-3，a = -1）。
 * 统一公式，对单位元同样成立。
 */
function ptAdd(a: Pt, b: Pt): Pt {
  const A: bigint = fmod((a.Y - a.X) * (b.Y - b.X));
  const B: bigint = fmod((a.Y + a.X) * (b.Y + b.X));
  const C: bigint = fmod(a.T * d2() * b.T);
  const Dd: bigint = fmod(a.Z * BIG2 * b.Z);
  const E: bigint = fmod(B - A);
  const F: bigint = fmod(Dd - C);
  const G: bigint = fmod(Dd + C);
  const H: bigint = fmod(B + A);

  const r: Pt = new Pt();
  r.X = fmod(E * F);
  r.Y = fmod(G * H);
  r.T = fmod(E * H);
  r.Z = fmod(F * G);
  return r;
}

/** 倍点（dbl-2008-hwcd，a = -1） */
function ptDbl(a: Pt): Pt {
  const A: bigint = fmod(a.X * a.X);
  const B: bigint = fmod(a.Y * a.Y);
  const C: bigint = fmod(BIG2 * a.Z * a.Z);
  const Dd: bigint = fmod(-A);
  const E: bigint = fmod((a.X + a.Y) * (a.X + a.Y) - A - B);
  const G: bigint = fmod(Dd + B);
  const F: bigint = fmod(G - C);
  const H: bigint = fmod(Dd - B);

  const r: Pt = new Pt();
  r.X = fmod(E * F);
  r.Y = fmod(G * H);
  r.T = fmod(E * H);
  r.Z = fmod(F * G);
  return r;
}

/** 标量乘（朴素倍点-加点，从左到右） */
function ptScalarMul(a: Pt, k: bigint): Pt {
  let r: Pt = ptIdentity();
  let q: Pt = a;
  let n: bigint = k;
  while (n > BIG0) {
    if ((n & BIG1) === BIG1) {
      r = ptAdd(r, q);
    }
    q = ptDbl(q);
    n >>= BIG1;
  }
  return r;
}

/** 点编码：y 小端 32 字节，最高位填 x 的奇偶 */
function ptEncode(p: Pt): Uint8Array {
  const zi: bigint = finv(p.Z);
  const x: bigint = fmod(p.X * zi);
  const y: bigint = fmod(p.Y * zi);
  const out: Uint8Array = numToBytes32LE(y);
  out[31] = (out[31] & 0x7f) | (Number(x & BIG1) << 7);
  return out;
}

// ─────────────────────────────────────────────────────────────
//  基点与曲线常数（惰性初始化，避免顶层立即执行）
// ─────────────────────────────────────────────────────────────

/** 2·d mod p，点加公式里要用 */
let D2_CACHE: bigint | null = null;
function d2(): bigint {
  if (D2_CACHE === null) {
    // d = -121665 · 121666⁻¹ mod p
    const num: bigint = fmod(-BigInt(121665));
    const den: bigint = finv(BigInt(121666));
    D2_CACHE = fmod(BIG2 * fmod(num * den));
  }
  return D2_CACHE;
}

let BASE_CACHE: Pt | null = null;
function basePoint(): Pt {
  if (BASE_CACHE === null) {
    const bx: bigint = BigInt('15112221349535400772501151409588531511454012693041857206046113283949847762202');
    const by: bigint = BigInt('46316835694926478169428394003475163141307993866256225615783033603165251855960');
    const b: Pt = new Pt();
    b.X = fmod(bx);
    b.Y = fmod(by);
    b.Z = BIG1;
    b.T = fmod(bx * by);
    BASE_CACHE = b;
  }
  return BASE_CACHE;
}

// ─────────────────────────────────────────────────────────────
//  Ed25519 签名
// ─────────────────────────────────────────────────────────────

/** 把 64 字节摘要按小端解释后对 L 取模，得到标量 */
function scReduce(h: Uint8Array): bigint {
  return bytesToNumLE(h) % L;
}

/**
 * SHA-512 输出的前 32 字节 → clamp 后的标量 a。
 *
 * RFC 8032 clamp：
 *   · 清最低 3 位（保证是 8 的倍数，落在主子群里）
 *   · 清最高位（bit 255）
 *   · 置 bit 254
 * 掩码 `2^255 - 8` 恰好同时完成「清 bit0~2」与「清 bit255」。
 */
function clampScalar(h: Uint8Array): bigint {
  let a: bigint = bytesToNumLE(h.subarray(0, 32));
  a = a & ((BIG1 << BIG255) - BIG8);
  a = a | (BIG1 << BIG254);
  return a;
}

/** 由 32 字节种子推出 32 字节公钥（用于测试与自检） */
export function ed25519PublicKey(seed: Uint8Array): Uint8Array {
  if (seed.length !== 32) {
    throw new Error(`Ed25519 种子必须是 32 字节，实际 ${seed.length}`);
  }
  return ptEncode(ptScalarMul(basePoint(), clampScalar(sha512Bytes(seed))));
}

/**
 * Ed25519 签名。
 *
 * ★ 输入 seed 是 32 字节【种子】，不是 64 字节扩展私钥 ——
 *   与 PAKE 协议一致：ed_priv = sha256(bcrypt_hash) 恰为 32 字节。
 *
 * @param seed 32 字节种子
 * @param msg  待签名消息
 * @returns    64 字节签名（R || S）
 */
export function ed25519SignPure(seed: Uint8Array, msg: Uint8Array): Uint8Array {
  if (seed.length !== 32) {
    throw new Error(`Ed25519 种子必须是 32 字节，实际 ${seed.length}`);
  }
  // SHA-512(seed) 只算一次：前 32 字节派生标量，后 32 字节做确定性 nonce 前缀
  const h: Uint8Array = sha512Bytes(seed);
  const a: bigint = clampScalar(h);
  const prefix: Uint8Array = h.subarray(32, 64);
  const A: Uint8Array = ptEncode(ptScalarMul(basePoint(), a));

  // r = SHA512(prefix || M) mod L      ← prefix 是 32 字节，紧跟消息
  const rInput: Uint8Array = new Uint8Array(32 + msg.length);
  rInput.set(prefix, 0);
  rInput.set(msg, 32);
  const r: bigint = scReduce(sha512Bytes(rInput));

  // R = r·B
  const R: Uint8Array = ptEncode(ptScalarMul(basePoint(), r));

  // k = SHA512(R || A || M) mod L      ← 三段各 32 / 32 / len，共 64 + len
  const kInput: Uint8Array = new Uint8Array(64 + msg.length);
  kInput.set(R, 0);
  kInput.set(A, 32);
  kInput.set(msg, 64);
  const k: bigint = scReduce(sha512Bytes(kInput));

  // S = (r + k·a) mod L
  const S: bigint = (r + k * a) % L;

  const sig: Uint8Array = new Uint8Array(64);
  sig.set(R, 0);
  sig.set(numToBytes32LE(S), 32);
  return sig;
}

/** 自检：用 RFC 8032 TEST 1 向量 */
export function ed25519Selftest(): boolean {
  try {
    const seed: Uint8Array = new Uint8Array([
      0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
      0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
    ]);
    const sig: Uint8Array = ed25519SignPure(seed, new Uint8Array(0));
    const want: string = 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f'
      + 'b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b';
    let got: string = '';
    for (let i: number = 0; i < sig.length; i++) {
      got += sig[i].toString(16).padStart(2, '0');
    }
    return got === want;
  } catch (e) {
    return false;
  }
}

/**
 * 自检的【详细】版本 —— 真机排障用。
 *
 * 手表端取日志麻烦，所以这里把"到底哪一步错了"直接变成可显示字符串：
 *   成功 → "OK"
 *   不匹配 → "TEST1 不符 得=… 期=…"
 *   抛异常 → "异常: xxx"
 */
export function ed25519SelftestDetail(): string {
  let seedHex: string = '';
  try {
    const seed: Uint8Array = new Uint8Array([
      0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
      0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
    ]);
    // ① 公钥派生（不涉及签名，先隔离曲线运算）
    const pk: Uint8Array = ed25519PublicKey(seed);
    for (let i: number = 0; i < pk.length; i++) {
      seedHex += pk[i].toString(16).padStart(2, '0');
    }
    const wantPk: string = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';
    if (seedHex !== wantPk) {
      return `公钥派生不符 得=${seedHex.substring(0, 16)}… 期=${wantPk.substring(0, 16)}…`;
    }
    // ② 签名
    const sig: Uint8Array = ed25519SignPure(seed, new Uint8Array(0));
    let got: string = '';
    for (let i: number = 0; i < sig.length; i++) {
      got += sig[i].toString(16).padStart(2, '0');
    }
    const want: string = 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f'
      + 'b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b';
    if (got !== want) {
      return `TEST1 签名不符 len=${sig.length} 得=${got.substring(0, 16)}…`;
    }
    return 'OK';
  } catch (e) {
    const err = e as Error;
    return `异常: ${err.message}`;
  }
}
