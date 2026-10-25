/**
 * 纯 ArkTS AES-256-CTR
 *
 * 用途：keySuite 身份派生 —— `hac = AES-256-CTR(key=RD, iv=tempIv).decrypt(hmacKey)`
 * 同属「Previewer 桩环境降级」套件。
 *
 * 实现要点：
 *   · S-box 运行期按 GF(2^8) 逆元 + 仿射变换【计算得出】，
 *     不手抄 256 字节常量表 —— 抄错是这类实现最常见的翻车点。
 *   · AES-256：Nk=8，Nr=14，密钥扩展出 60 个 32 位字（240 字节）。
 *   · CTR 模式加解密同构（都是与密钥流异或），计数器按【大端】整块自增，
 *     与 OpenSSL / cryptoFramework 一致。
 */

// ═══════════════════════════════════════════════════════════════
//  GF(2^8) 运算
// ═══════════════════════════════════════════════════════════════

/** GF(2^8) 乘 2（x·{02}） */
function xtime(a: number): number {
  const x: number = (a << 1) & 0xff;
  return (a & 0x80) !== 0 ? (x ^ 0x1b) : x;
}

/** GF(2^8) 一般乘法 */
function gmul(a: number, b: number): number {
  let p: number = 0;
  let x: number = a & 0xff;
  let y: number = b & 0xff;
  for (let i: number = 0; i < 8; i++) {
    if ((y & 1) !== 0) {
      p ^= x;
    }
    const hi: number = x & 0x80;
    x = (x << 1) & 0xff;
    if (hi !== 0) {
      x ^= 0x1b;
    }
    y >>= 1;
  }
  return p & 0xff;
}

/** GF(2^8) 乘法逆元（0 的逆元定义为 0） */
function ginv(a: number): number {
  if (a === 0) {
    return 0;
  }
  // a^254 = a^-1（费马小定理，GF(2^8) 乘法群阶 255）
  let r: number = 1;
  let base: number = a & 0xff;
  let e: number = 254;
  while (e > 0) {
    if ((e & 1) !== 0) {
      r = gmul(r, base);
    }
    base = gmul(base, base);
    e >>= 1;
  }
  return r;
}

function rotl8(v: number, n: number): number {
  return ((v << n) | (v >>> (8 - n))) & 0xff;
}

let sboxCache: Uint8Array | null = null;

/** S-box：s = inv ^ rotl(inv,1..4) ^ 0x63 */
function sbox(): Uint8Array {
  if (sboxCache === null) {
    const s: Uint8Array = new Uint8Array(256);
    for (let i: number = 0; i < 256; i++) {
      const inv: number = ginv(i);
      s[i] = (inv ^ rotl8(inv, 1) ^ rotl8(inv, 2) ^ rotl8(inv, 3) ^ rotl8(inv, 4) ^ 0x63) & 0xff;
    }
    sboxCache = s;
  }
  return sboxCache;
}

// ═══════════════════════════════════════════════════════════════
//  密钥扩展（AES-256）
// ═══════════════════════════════════════════════════════════════

let roundKeyCache: Uint8Array | null = null;
let roundKeyCacheKey: string = '';

/** 展开 32 字节主密钥为 240 字节轮密钥（15 组 × 16 字节） */
function expandKey256(key: Uint8Array): Uint8Array {
  if (key.length !== 32) {
    throw new Error(`AES-256 主密钥必须是 32 字节，实际 ${key.length}`);
  }
  const S: Uint8Array = sbox();
  const w: Uint8Array = new Uint8Array(240);
  w.set(key, 0);

  let rcon: number = 1;
  for (let i: number = 8; i < 60; i++) {
    let t0: number = w[(i - 1) * 4];
    let t1: number = w[(i - 1) * 4 + 1];
    let t2: number = w[(i - 1) * 4 + 2];
    let t3: number = w[(i - 1) * 4 + 3];

    if (i % 8 === 0) {
      // RotWord → SubWord → 异或 Rcon
      const tmp: number = t0;
      t0 = S[t1] ^ rcon;
      t1 = S[t2];
      t2 = S[t3];
      t3 = S[tmp];
      rcon = xtime(rcon);
    } else if (i % 8 === 4) {
      // AES-256 特有：中间位置多一次 SubWord
      t0 = S[t0];
      t1 = S[t1];
      t2 = S[t2];
      t3 = S[t3];
    }

    w[i * 4] = w[(i - 8) * 4] ^ t0;
    w[i * 4 + 1] = w[(i - 8) * 4 + 1] ^ t1;
    w[i * 4 + 2] = w[(i - 8) * 4 + 2] ^ t2;
    w[i * 4 + 3] = w[(i - 8) * 4 + 3] ^ t3;
  }
  return w;
}

/** 带缓存的密钥扩展（CTR 每次调用都扩展一次，缓存避免重复开销） */
function roundKeys(key: Uint8Array): Uint8Array {
  let tag: string = '';
  for (let i: number = 0; i < key.length; i++) {
    tag += key[i].toString(16);
  }
  if (roundKeyCache === null || roundKeyCacheKey !== tag) {
    roundKeyCache = expandKey256(key);
    roundKeyCacheKey = tag;
  }
  return roundKeyCache;
}

// ═══════════════════════════════════════════════════════════════
//  分组加密
// ═══════════════════════════════════════════════════════════════

/** 加密单个 16 字节分组（state 按列优先，index = r + 4c） */
function encryptBlock(w: Uint8Array, input: Uint8Array): Uint8Array {
  const S: Uint8Array = sbox();
  const s: Uint8Array = new Uint8Array(16);
  for (let i: number = 0; i < 16; i++) {
    s[i] = input[i] ^ w[i];
  }

  const t: Uint8Array = new Uint8Array(16);
  for (let round: number = 1; round <= 14; round++) {
    // SubBytes
    for (let i: number = 0; i < 16; i++) {
      s[i] = S[s[i]];
    }
    // ShiftRows：第 r 行左移 r 位
    for (let r: number = 0; r < 4; r++) {
      for (let c: number = 0; c < 4; c++) {
        t[r + 4 * c] = s[r + 4 * ((c + r) % 4)];
      }
    }
    for (let i: number = 0; i < 16; i++) {
      s[i] = t[i];
    }
    // MixColumns（最后一轮不做）
    if (round !== 14) {
      for (let c: number = 0; c < 4; c++) {
        const a0: number = s[4 * c];
        const a1: number = s[4 * c + 1];
        const a2: number = s[4 * c + 2];
        const a3: number = s[4 * c + 3];
        s[4 * c] = (gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3) & 0xff;
        s[4 * c + 1] = (a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3) & 0xff;
        s[4 * c + 2] = (a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3)) & 0xff;
        s[4 * c + 3] = (gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2)) & 0xff;
      }
    }
    // AddRoundKey
    const rk: number = round * 16;
    for (let i: number = 0; i < 16; i++) {
      s[i] = s[i] ^ w[rk + i];
    }
  }
  return s;
}

// ═══════════════════════════════════════════════════════════════
//  CTR 模式（加解密同构）
// ═══════════════════════════════════════════════════════════════

/**
 * AES-256-CTR。加解密用同一个函数 —— CTR 本质是与密钥流异或。
 *
 * @param key    32 字节主密钥
 * @param iv     16 字节初始计数器
 * @param data   待处理数据（任意长度，无需填充）
 */
export function aes256Ctr(key: Uint8Array, iv: Uint8Array, data: Uint8Array): Uint8Array {
  if (key.length !== 32) {
    throw new Error(`AES-256 密钥必须是 32 字节，实际 ${key.length}`);
  }
  if (iv.length < 16) {
    throw new Error(`AES-CTR 初始向量至少 16 字节，实际 ${iv.length}`);
  }
  const w: Uint8Array = roundKeys(key);
  const out: Uint8Array = new Uint8Array(data.length);
  const counter: Uint8Array = new Uint8Array(16);
  counter.set(iv.subarray(0, 16), 0);

  for (let off: number = 0; off < data.length; off += 16) {
    const ks: Uint8Array = encryptBlock(w, counter);
    const n: number = Math.min(16, data.length - off);
    for (let i: number = 0; i < n; i++) {
      out[off + i] = data[off + i] ^ ks[i];
    }
    // 计数器整块大端自增
    for (let i: number = 15; i >= 0; i--) {
      counter[i] = (counter[i] + 1) & 0xff;
      if (counter[i] !== 0) {
        break;
      }
    }
  }
  return out;
}
