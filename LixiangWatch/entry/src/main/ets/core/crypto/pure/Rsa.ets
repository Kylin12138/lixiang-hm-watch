/**
 * 纯 ArkTS RSA-2048（PKCS#1 v1.5）—— 解密 + SHA256 签名
 *
 * 用途：keySuite 身份派生
 *   · `RD = RSA-PKCS1v15.decrypt(tempAesKey, priv)`
 *   · `sign = base64(RSA-PKCS1v15-SHA256(priv, "requestId:deviceId:..."))`
 *
 * 同属「Previewer 桩环境降级」套件。
 *
 * 实现要点：
 *   · 私钥直接解析 PKCS#8 DER（内含 PKCS#1 RSAPrivateKey），不预抽 n/d 常量，
 *     避免密钥材料在代码里出现第二份副本。
 *   · 模幂默认走 CRT（p/q/dp/dq/qinv），速度约为直接 d 次方的 3~4 倍；
 *     CRT 参数缺失时自动退回直算。
 */

import { sha256Bytes } from './Sha';

// ─────────────────────────────────────────────────────────────
//  RSA 私钥结构
// ─────────────────────────────────────────────────────────────

/** 解析结果：模数 / 私钥指数 / CRT 参数 */
export class RsaPrivateKey {
  n: bigint = BigInt(0);
  e: bigint = BigInt(0);
  d: bigint = BigInt(0);
  p: bigint = BigInt(0);
  q: bigint = BigInt(0);
  dp: bigint = BigInt(0);
  dq: bigint = BigInt(0);
  qinv: bigint = BigInt(0);
  /** 模数字节长度（RSA-2048 → 256） */
  modulusBytes: number = 0;
  /** CRT 参数是否齐全 */
  hasCrt: boolean = false;
}

// ─────────────────────────────────────────────────────────────
//  极简 DER 解析
// ─────────────────────────────────────────────────────────────

class DerTlv {
  tag: number = 0;
  /** 内容起始下标 */
  start: number = 0;
  /** 内容结束下标（不含） */
  end: number = 0;
  /** 下一个 TLV 的起始下标 */
  next: number = 0;
}

class DerInt {
  value: bigint = BigInt(0);
  next: number = 0;
}

/** 读一个 TLV 头部 + 定位内容 */
function derRead(buf: Uint8Array, pos: number): DerTlv {
  const tlv: DerTlv = new DerTlv();
  tlv.tag = buf[pos];
  let len: number = buf[pos + 1];
  let off: number = pos + 2;
  if ((len & 0x80) !== 0) {
    const n: number = len & 0x7f;
    len = 0;
    for (let i: number = 0; i < n; i++) {
      len = (len << 8) | buf[off + i];
    }
    off += n;
  }
  tlv.start = off;
  tlv.end = off + len;
  tlv.next = off + len;
  return tlv;
}

/** 读一个 DER INTEGER，去掉符号补的 0x00 */
function derReadInt(buf: Uint8Array, pos: number): DerInt {
  const t = derRead(buf, pos);
  if (t.tag !== 0x02) {
    throw new Error(`DER 期望 INTEGER(0x02)，实际 0x${t.tag.toString(16)}`);
  }
  let i: number = t.start;
  // DER 有符号整数：正数若最高位为 1 会补一个前导 0x00
  while (i < t.end - 1 && buf[i] === 0x00) {
    i++;
  }
  let v: bigint = BigInt(0);
  for (; i < t.end; i++) {
    v = (v << BigInt(8)) | BigInt(buf[i]);
  }
  const r: DerInt = new DerInt();
  r.value = v;
  r.next = t.next;
  return r;
}

/** 计算正 BigInt 的字节长度 */
function bitLen(v: bigint): number {
  let n: number = 0;
  let x: bigint = v;
  while (x > BigInt(0)) {
    n++;
    x >>= BigInt(1);
  }
  return n;
}

/**
 * 解析 PKCS#8 DER 私钥。
 *
 * PrivateKeyInfo ::= SEQUENCE {
 *   version    INTEGER,
 *   algorithm  AlgorithmIdentifier,
 *   key        OCTET STRING  ← 内含 RSAPrivateKey
 * }
 */
export function parseRsaPrivateKeyDer(der: Uint8Array): RsaPrivateKey {
  const outer: DerTlv = derRead(der, 0);
  if (outer.tag !== 0x30) {
    throw new Error('PKCS#8 结构异常：外层不是 SEQUENCE');
  }
  let pos: number = outer.start;

  // version
  pos = derReadInt(der, pos).next;
  // AlgorithmIdentifier
  const alg: DerTlv = derRead(der, pos);
  pos = alg.next;
  // privateKey OCTET STRING
  const oct: DerTlv = derRead(der, pos);
  if (oct.tag !== 0x04) {
    throw new Error('PKCS#8 结构异常：未找到 privateKey OCTET STRING');
  }

  const inner: Uint8Array = der.subarray(oct.start, oct.end);
  const seq: DerTlv = derRead(inner, 0);
  if (seq.tag !== 0x30) {
    throw new Error('RSAPrivateKey 结构异常：不是 SEQUENCE');
  }
  // ★ 注意：位置变量命名为 pos，不要叫 q —— RSA 里已经有一个素数叫 q，
  //   同名会写出 `q = primeQ` 这种自毁式赋值（已踩过一次）。
  let p: number = seq.start;

  const key: RsaPrivateKey = new RsaPrivateKey();
  p = derReadInt(inner, p).next;            // version
  const nInt: DerInt = derReadInt(inner, p);
  key.n = nInt.value;                       // modulus
  p = nInt.next;
  const eInt: DerInt = derReadInt(inner, p);
  key.e = eInt.value;                       // publicExponent
  p = eInt.next;
  const dInt: DerInt = derReadInt(inner, p);
  key.d = dInt.value;                       // privateExponent
  p = dInt.next;

  // 剩余为 p/q/dp/dq/qinv，若齐全则启用 CRT
  const pi: DerInt = derReadInt(inner, p);
  key.p = pi.value;
  const qi: DerInt = derReadInt(inner, pi.next);
  key.q = qi.value;
  const dpi: DerInt = derReadInt(inner, qi.next);
  key.dp = dpi.value;
  const dqi: DerInt = derReadInt(inner, dpi.next);   // ← 上一版误写成 dqi.next
  key.dq = dqi.value;
  const qinvi: DerInt = derReadInt(inner, dqi.next);
  key.qinv = qinvi.value;

  key.hasCrt = key.p > BigInt(1) && key.q > BigInt(1)
    && key.dp > BigInt(0) && key.dq > BigInt(0) && key.qinv > BigInt(0);

  key.modulusBytes = Math.floor((bitLen(key.n) + 7) / 8);
  if (key.modulusBytes <= 0) {
    throw new Error('RSA 模数解析失败（长度为 0）');
  }
  if (key.d <= BigInt(0)) {
    throw new Error('RSA 私钥指数解析失败');
  }
  return key;
}

// ─────────────────────────────────────────────────────────────
//  大整数工具
// ─────────────────────────────────────────────────────────────

/** 模幂，平方-乘法 */
function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  if (mod === BigInt(1)) {
    return BigInt(0);
  }
  let result: bigint = BigInt(1);
  let b: bigint = base % mod;
  let e: bigint = exp;
  const one: bigint = BigInt(1);
  while (e > BigInt(0)) {
    if ((e & one) === one) {
      result = (result * b) % mod;
    }
    b = (b * b) % mod;
    e >>= one;
  }
  return result;
}

/** 八位组串 → 整数（大端） */
function os2ip(b: Uint8Array): bigint {
  let v: bigint = BigInt(0);
  for (let i: number = 0; i < b.length; i++) {
    v = (v << BigInt(8)) | BigInt(b[i]);
  }
  return v;
}

/** 整数 → 定长八位组串（大端） */
function i2osp(v: bigint, len: number): Uint8Array {
  const out: Uint8Array = new Uint8Array(len);
  let x: bigint = v;
  for (let i: number = len - 1; i >= 0; i--) {
    out[i] = Number(x & BigInt(0xff));
    x >>= BigInt(8);
  }
  return out;
}

/** 私钥运算：c^d mod n（优先走 CRT） */
function privateOp(key: RsaPrivateKey, c: bigint): bigint {
  if (!key.hasCrt) {
    return modPow(c, key.d, key.n);
  }
  // CRT: m1 = c^dp mod p, m2 = c^dq mod q, h = qinv·(m1-m2) mod p
  const m1: bigint = modPow(c % key.p, key.dp, key.p);
  const m2: bigint = modPow(c % key.q, key.dq, key.q);
  let h: bigint = (m1 - m2) % key.p;
  if (h < BigInt(0)) {
    h += key.p;
  }
  h = (key.qinv * h) % key.p;
  return m2 + h * key.q;
}

// ─────────────────────────────────────────────────────────────
//  PKCS#1 v1.5
// ─────────────────────────────────────────────────────────────

/** SHA-256 的 DigestInfo 前缀（RFC 8017 附录 A.2.4） */
const SHA256_DIGEST_INFO: number[] = [
  0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
  0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
];

/**
 * RSA 私钥解密 + PKCS#1 v1.5 去填充。
 * EM = 0x00 || 0x02 || PS(非零) || 0x00 || M
 */
export function rsaDecryptPkcs1(key: RsaPrivateKey, cipher: Uint8Array): Uint8Array {
  const k: number = key.modulusBytes;
  if (cipher.length !== k) {
    throw new Error(`RSA 密文长度应为 ${k} 字节，实际 ${cipher.length}`);
  }
  const em: Uint8Array = i2osp(privateOp(key, os2ip(cipher)), k);

  if (em[0] !== 0x00 || em[1] !== 0x02) {
    throw new Error('PKCS#1 v1.5 解密失败：块类型不是 0x02');
  }
  let i: number = 2;
  while (i < k && em[i] !== 0x00) {
    i++;
  }
  if (i >= k) {
    throw new Error('PKCS#1 v1.5 解密失败：未找到分隔符 0x00');
  }
  if (i < 10) {
    throw new Error('PKCS#1 v1.5 解密失败：填充串过短');
  }
  return new Uint8Array(em.subarray(i + 1, k));
}

/**
 * RSA 私钥签名（RSASSA-PKCS1-v1_5 + SHA-256）。
 * EM = 0x00 || 0x01 || PS(0xFF) || 0x00 || DigestInfo
 */
export function rsaSignPkcs1Sha256(key: RsaPrivateKey, data: Uint8Array): Uint8Array {
  const k: number = key.modulusBytes;
  const tLen: number = SHA256_DIGEST_INFO.length + 32;
  if (k < tLen + 11) {
    throw new Error(`RSA 模数过小（${k} 字节），无法容纳 PKCS#1 v1.5 签名块`);
  }
  const em: Uint8Array = new Uint8Array(k);
  em[0] = 0x00;
  em[1] = 0x01;
  const psEnd: number = k - tLen - 1;
  for (let i: number = 2; i < psEnd; i++) {
    em[i] = 0xff;
  }
  em[psEnd] = 0x00;
  for (let i: number = 0; i < SHA256_DIGEST_INFO.length; i++) {
    em[psEnd + 1 + i] = SHA256_DIGEST_INFO[i];
  }
  const digest: Uint8Array = sha256Bytes(data);
  for (let i: number = 0; i < 32; i++) {
    em[psEnd + 1 + SHA256_DIGEST_INFO.length + i] = digest[i];
  }
  return i2osp(privateOp(key, os2ip(em)), k);
}
