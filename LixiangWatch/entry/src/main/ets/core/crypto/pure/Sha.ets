/**
 * 纯 ArkTS 摘要原语 —— SHA-256 / SHA-512 / MD5
 *
 * ★★ 为什么需要这份实现
 *
 *   DevEco **Previewer** 里 `@ohos.security.cryptoFramework` 的
 *   【所有同步接口】都是 mocked 实现，一律返回空 `Uint8Array`，
 *   且【不抛异常】。日志原文：
 *
 *     The createMd / updateSync / digestSync interface in the previewer
 *     is a mocked implementation and may behave differently than on a real device.
 *
 *   后果：Previewer 里 sha256() 返回长度为 0 的数组 →
 *         `BigInt('0x' + '')` 抛 `Cannot convert string to a BigInt` →
 *         登录链路在第 0 步就炸。
 *
 *   本文件提供一份【不依赖任何系统能力】的纯软件实现，
 *   由 HarmonyCrypto 在检测到桩环境时自动接管（真机仍走硬件实现）。
 *
 * 设计约束（ArkTS 严格模式）：
 *   · 无 `any` / `unknown`，所有变量显式标注类型
 *   · 不使用对象展开、`delete`、`Partial` / `Record`
 *   · 所有 32 位运算显式 `| 0` / `>>> 0` 归一
 */

// ═══════════════════════════════════════════════════════════════
//  SHA-256
// ═══════════════════════════════════════════════════════════════

/** SHA-256 轮常量（前 64 个质数立方根小数部分前 32 位） */
const K256: number[] = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

function rotr32(x: number, n: number): number {
  return ((x >>> n) | (x << (32 - n))) >>> 0;
}

/** SHA-256 摘要，返回 32 字节 */
export function sha256Bytes(msg: Uint8Array): Uint8Array {
  const h: Int32Array = new Int32Array(8);
  h[0] = 0x6a09e667 | 0;
  h[1] = 0xbb67ae85 | 0;
  h[2] = 0x3c6ef372 | 0;
  h[3] = 0xa54ff53a | 0;
  h[4] = 0x510e527f | 0;
  h[5] = 0x9b05688c | 0;
  h[6] = 0x1f83d9ab | 0;
  h[7] = 0x5be0cd19 | 0;

  const bitLen: number = msg.length * 8;
  const padded: number = Math.ceil((msg.length + 9) / 64) * 64;
  const buf: Uint8Array = new Uint8Array(padded);
  buf.set(msg, 0);
  buf[msg.length] = 0x80;

  // 长度域：64 位大端，写在最后 8 字节
  const hi: number = Math.floor(bitLen / 4294967296);
  const lo: number = bitLen % 4294967296;
  buf[padded - 8] = (hi >>> 24) & 0xff;
  buf[padded - 7] = (hi >>> 16) & 0xff;
  buf[padded - 6] = (hi >>> 8) & 0xff;
  buf[padded - 5] = hi & 0xff;
  buf[padded - 4] = (lo >>> 24) & 0xff;
  buf[padded - 3] = (lo >>> 16) & 0xff;
  buf[padded - 2] = (lo >>> 8) & 0xff;
  buf[padded - 1] = lo & 0xff;

  const w: Int32Array = new Int32Array(64);
  for (let off: number = 0; off < padded; off += 64) {
    for (let i: number = 0; i < 16; i++) {
      const j: number = off + i * 4;
      w[i] = ((buf[j] << 24) | (buf[j + 1] << 16) | (buf[j + 2] << 8) | buf[j + 3]) | 0;
    }
    for (let i: number = 16; i < 64; i++) {
      const x: number = w[i - 15];
      const y: number = w[i - 2];
      const s0: number = (rotr32(x, 7) ^ rotr32(x, 18) ^ (x >>> 3)) >>> 0;
      const s1: number = (rotr32(y, 17) ^ rotr32(y, 19) ^ (y >>> 10)) >>> 0;
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
    }

    let a: number = h[0];
    let b: number = h[1];
    let c: number = h[2];
    let d: number = h[3];
    let e: number = h[4];
    let f: number = h[5];
    let g: number = h[6];
    let hh: number = h[7];

    for (let i: number = 0; i < 64; i++) {
      const s1: number = (rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)) >>> 0;
      const ch: number = ((e & f) ^ (~e & g)) >>> 0;
      const t1: number = (hh + s1 + ch + K256[i] + w[i]) | 0;
      const s0: number = (rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)) >>> 0;
      const maj: number = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const t2: number = (s0 + maj) | 0;

      hh = g;
      g = f;
      f = e;
      e = (d + t1) | 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) | 0;
    }

    h[0] = (h[0] + a) | 0;
    h[1] = (h[1] + b) | 0;
    h[2] = (h[2] + c) | 0;
    h[3] = (h[3] + d) | 0;
    h[4] = (h[4] + e) | 0;
    h[5] = (h[5] + f) | 0;
    h[6] = (h[6] + g) | 0;
    h[7] = (h[7] + hh) | 0;
  }

  const out: Uint8Array = new Uint8Array(32);
  for (let i: number = 0; i < 8; i++) {
    const v: number = h[i] >>> 0;
    out[i * 4] = (v >>> 24) & 0xff;
    out[i * 4 + 1] = (v >>> 16) & 0xff;
    out[i * 4 + 2] = (v >>> 8) & 0xff;
    out[i * 4 + 3] = v & 0xff;
  }
  return out;
}

// ═══════════════════════════════════════════════════════════════
//  SHA-512（Ed25519 需要）
// ═══════════════════════════════════════════════════════════════

const MASK64: bigint = BigInt('0xFFFFFFFFFFFFFFFF');

/** 80 个 64 位轮常量，hex 形式（前 80 个质数立方根小数部分前 64 位） */
const K512_HEX: string[] = [
  '428a2f98d728ae22', '7137449123ef65cd', 'b5c0fbcfec4d3b2f', 'e9b5dba58189dbbc',
  '3956c25bf348b538', '59f111f1b605d019', '923f82a4af194f9b', 'ab1c5ed5da6d8118',
  'd807aa98a3030242', '12835b0145706fbe', '243185be4ee4b28c', '550c7dc3d5ffb4e2',
  '72be5d74f27b896f', '80deb1fe3b1696b1', '9bdc06a725c71235', 'c19bf174cf692694',
  'e49b69c19ef14ad2', 'efbe4786384f25e3', '0fc19dc68b8cd5b5', '240ca1cc77ac9c65',
  '2de92c6f592b0275', '4a7484aa6ea6e483', '5cb0a9dcbd41fbd4', '76f988da831153b5',
  '983e5152ee66dfab', 'a831c66d2db43210', 'b00327c898fb213f', 'bf597fc7beef0ee4',
  'c6e00bf33da88fc2', 'd5a79147930aa725', '06ca6351e003826f', '142929670a0e6e70',
  '27b70a8546d22ffc', '2e1b21385c26c926', '4d2c6dfc5ac42aed', '53380d139d95b3df',
  '650a73548baf63de', '766a0abb3c77b2a8', '81c2c92e47edaee6', '92722c851482353b',
  'a2bfe8a14cf10364', 'a81a664bbc423001', 'c24b8b70d0f89791', 'c76c51a30654be30',
  'd192e819d6ef5218', 'd69906245565a910', 'f40e35855771202a', '106aa07032bbd1b8',
  '19a4c116b8d2d0c8', '1e376c085141ab53', '2748774cdf8eeb99', '34b0bcb5e19b48a8',
  '391c0cb3c5c95a63', '4ed8aa4ae3418acb', '5b9cca4f7763e373', '682e6ff3d6b2b8a3',
  '748f82ee5defb2fc', '78a5636f43172f60', '84c87814a1f0ab72', '8cc702081a6439ec',
  '90befffa23631e28', 'a4506cebde82bde9', 'bef9a3f7b2c67915', 'c67178f2e372532b',
  'ca273eceea26619c', 'd186b8c721c0c207', 'eada7dd6cde0eb1e', 'f57d4f7fee6ed178',
  '06f067aa72176fba', '0a637dc5a2c898a6', '113f9804bef90dae', '1b710b35131c471b',
  '28db77f523047d84', '32caab7b40c72493', '3c9ebe0a15c9bebc', '431d67c49c100d4c',
  '4cc5d4becb3e42b6', '597f299cfc657e2a', '5fcb6fab3ad6faec', '6c44198c4a475817'
];

const H512_HEX: string[] = [
  '6a09e667f3bcc908', 'bb67ae8584caa73b', '3c6ef372fe94f82b', 'a54ff53a5f1d36f1',
  '510e527fade682d1', '9b05688c2b3e6c1f', '1f83d9abfb41bd6b', '5be0cd19137e2179'
];

let k512Cache: bigint[] | null = null;
let h512Cache: bigint[] | null = null;

function k512(): bigint[] {
  if (k512Cache === null) {
    const arr: bigint[] = [];
    for (let i: number = 0; i < K512_HEX.length; i++) {
      arr.push(BigInt('0x' + K512_HEX[i]));
    }
    k512Cache = arr;
  }
  return k512Cache;
}

function h512(): bigint[] {
  if (h512Cache === null) {
    const arr: bigint[] = [];
    for (let i: number = 0; i < H512_HEX.length; i++) {
      arr.push(BigInt('0x' + H512_HEX[i]));
    }
    h512Cache = arr;
  }
  return h512Cache;
}

function rotr64(x: bigint, n: number): bigint {
  const nb: bigint = BigInt(n);
  return ((x >> nb) | (x << (BigInt(64) - nb))) & MASK64;
}

/** SHA-512 摘要，返回 64 字节 */
export function sha512Bytes(msg: Uint8Array): Uint8Array {
  const h: bigint[] = h512().slice();
  const K: bigint[] = k512();

  // 长度域是 128 位；本工程输入远小于 2^64 bit，高 64 位恒为 0
  const bitLen: number = msg.length * 8;
  const padded: number = Math.ceil((msg.length + 17) / 128) * 128;
  const buf: Uint8Array = new Uint8Array(padded);
  buf.set(msg, 0);
  buf[msg.length] = 0x80;

  const hi: number = Math.floor(bitLen / 4294967296);
  const lo: number = bitLen % 4294967296;
  buf[padded - 8] = (hi >>> 24) & 0xff;
  buf[padded - 7] = (hi >>> 16) & 0xff;
  buf[padded - 6] = (hi >>> 8) & 0xff;
  buf[padded - 5] = hi & 0xff;
  buf[padded - 4] = (lo >>> 24) & 0xff;
  buf[padded - 3] = (lo >>> 16) & 0xff;
  buf[padded - 2] = (lo >>> 8) & 0xff;
  buf[padded - 1] = lo & 0xff;

  const w: bigint[] = [];
  for (let i: number = 0; i < 80; i++) {
    w.push(BigInt(0));
  }

  for (let off: number = 0; off < padded; off += 128) {
    for (let i: number = 0; i < 16; i++) {
      const j: number = off + i * 8;
      let v: bigint = BigInt(0);
      for (let k: number = 0; k < 8; k++) {
        v = (v << BigInt(8)) | BigInt(buf[j + k]);
      }
      w[i] = v;
    }
    for (let i: number = 16; i < 80; i++) {
      const x: bigint = w[i - 15];
      const y: bigint = w[i - 2];
      const s0: bigint = rotr64(x, 1) ^ rotr64(x, 8) ^ (x >> BigInt(7));
      const s1: bigint = rotr64(y, 19) ^ rotr64(y, 61) ^ (y >> BigInt(6));
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & MASK64;
    }

    let a: bigint = h[0];
    let b: bigint = h[1];
    let c: bigint = h[2];
    let d: bigint = h[3];
    let e: bigint = h[4];
    let f: bigint = h[5];
    let g: bigint = h[6];
    let hh: bigint = h[7];

    for (let i: number = 0; i < 80; i++) {
      const s1: bigint = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
      const ch: bigint = (e & f) ^ ((~e & MASK64) & g);
      const t1: bigint = (hh + s1 + ch + K[i] + w[i]) & MASK64;
      const s0: bigint = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
      const maj: bigint = (a & b) ^ (a & c) ^ (b & c);
      const t2: bigint = (s0 + maj) & MASK64;

      hh = g;
      g = f;
      f = e;
      e = (d + t1) & MASK64;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) & MASK64;
    }

    h[0] = (h[0] + a) & MASK64;
    h[1] = (h[1] + b) & MASK64;
    h[2] = (h[2] + c) & MASK64;
    h[3] = (h[3] + d) & MASK64;
    h[4] = (h[4] + e) & MASK64;
    h[5] = (h[5] + f) & MASK64;
    h[6] = (h[6] + g) & MASK64;
    h[7] = (h[7] + hh) & MASK64;
  }

  const out: Uint8Array = new Uint8Array(64);
  for (let i: number = 0; i < 8; i++) {
    const v: bigint = h[i];
    for (let k: number = 0; k < 8; k++) {
      out[i * 8 + k] = Number((v >> BigInt((7 - k) * 8)) & BigInt(0xff));
    }
  }
  return out;
}

// ═══════════════════════════════════════════════════════════════
//  MD5（仅用于 Content-MD5 请求头，非安全用途）
// ═══════════════════════════════════════════════════════════════

/** MD5 轮常量：K[i] = floor(2^32 * |sin(i+1)|)，运行时计算避免抄错 */
let md5KCache: Int32Array | null = null;

function md5K(): Int32Array {
  if (md5KCache === null) {
    const arr: Int32Array = new Int32Array(64);
    for (let i: number = 0; i < 64; i++) {
      arr[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) | 0;
    }
    md5KCache = arr;
  }
  return md5KCache;
}

const MD5_S: number[] = [
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
];

function rotl32(x: number, n: number): number {
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}

/** MD5 摘要，返回 16 字节 */
export function md5Bytes(msg: Uint8Array): Uint8Array {
  const K: Int32Array = md5K();

  let a0: number = 0x67452301 | 0;
  let b0: number = 0xefcdab89 | 0;
  let c0: number = 0x98badcfe | 0;
  let d0: number = 0x10325476 | 0;

  const bitLen: number = msg.length * 8;
  const padded: number = Math.ceil((msg.length + 9) / 64) * 64;
  const buf: Uint8Array = new Uint8Array(padded);
  buf.set(msg, 0);
  buf[msg.length] = 0x80;

  // MD5 长度域是 【小端】 64 位
  const hi: number = Math.floor(bitLen / 4294967296);
  const lo: number = bitLen % 4294967296;
  buf[padded - 8] = lo & 0xff;
  buf[padded - 7] = (lo >>> 8) & 0xff;
  buf[padded - 6] = (lo >>> 16) & 0xff;
  buf[padded - 5] = (lo >>> 24) & 0xff;
  buf[padded - 4] = hi & 0xff;
  buf[padded - 3] = (hi >>> 8) & 0xff;
  buf[padded - 2] = (hi >>> 16) & 0xff;
  buf[padded - 1] = (hi >>> 24) & 0xff;

  const m: Int32Array = new Int32Array(16);
  for (let off: number = 0; off < padded; off += 64) {
    for (let i: number = 0; i < 16; i++) {
      const j: number = off + i * 4;
      m[i] = (buf[j] | (buf[j + 1] << 8) | (buf[j + 2] << 16) | (buf[j + 3] << 24)) | 0;
    }

    let a: number = a0;
    let b: number = b0;
    let c: number = c0;
    let d: number = d0;

    for (let i: number = 0; i < 64; i++) {
      let f: number = 0;
      let g: number = 0;
      if (i < 16) {
        f = ((b & c) | (~b & d)) | 0;
        g = i;
      } else if (i < 32) {
        f = ((d & b) | (~d & c)) | 0;
        g = (5 * i + 1) % 16;
      } else if (i < 48) {
        f = (b ^ c ^ d) | 0;
        g = (3 * i + 5) % 16;
      } else {
        f = (c ^ (b | ~d)) | 0;
        g = (7 * i) % 16;
      }
      const sum: number = (a + f + K[i] + m[g]) | 0;
      const tmp: number = d;
      d = c;
      c = b;
      b = (b + rotl32(sum, MD5_S[i])) | 0;
      a = tmp;
    }

    a0 = (a0 + a) | 0;
    b0 = (b0 + b) | 0;
    c0 = (c0 + c) | 0;
    d0 = (d0 + d) | 0;
  }

  const out: Uint8Array = new Uint8Array(16);
  const vals: Int32Array = new Int32Array(4);
  vals[0] = a0;
  vals[1] = b0;
  vals[2] = c0;
  vals[3] = d0;
  for (let i: number = 0; i < 4; i++) {
    const v: number = vals[i] >>> 0;
    out[i * 4] = v & 0xff;
    out[i * 4 + 1] = (v >>> 8) & 0xff;
    out[i * 4 + 2] = (v >>> 16) & 0xff;
    out[i * 4 + 3] = (v >>> 24) & 0xff;
  }
  return out;
}
