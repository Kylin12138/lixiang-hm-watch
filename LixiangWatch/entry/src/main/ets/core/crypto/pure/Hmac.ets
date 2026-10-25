/**
 * 纯 ArkTS HMAC 原语 —— HMAC-SHA256 / HMAC-SHA512 / HKDF
 *
 * 与 Sha.ets 同属「Previewer 桩环境降级」套件。真机仍走
 * cryptoFramework 的硬件实现，本文件只在检测到桩实现时接管。
 *
 * 用途：
 *   · Signer.ets 的 x-chj 请求签名（业务接口鉴权三件套之一）
 *   · KeySuite.ets 的引导签名
 *   · Ed25519 的 HKDF（Ed25519 内部用不到 HKDF，但派生流程可能用到）
 */

import { sha256Bytes, sha512Bytes } from './Sha';

const BLOCK_256: number = 64;
const BLOCK_512: number = 128;

/**
 * HMAC 通用内核。
 *
 * ★ 刻意【不使用函数类型作形参】—— 直接按 is512 分支调用具体摘要函数，
 *   避免 ArkTS 对函数类型参数的限制，也让抽取验证脚本更容易处理。
 */
function hmacCore(is512: boolean, key: Uint8Array, data: Uint8Array): Uint8Array {
  const blockSize: number = is512 ? 128 : 64;
  const digestLen: number = is512 ? 64 : 32;

  // 1) key 过长先摘要，过短补 0 到 blockSize
  let k: Uint8Array = key;
  if (k.length > blockSize) {
    k = is512 ? sha512Bytes(k) : sha256Bytes(k);
  }
  const kp: Uint8Array = new Uint8Array(blockSize);
  kp.set(k, 0);

  // 2) ipad / opad
  const inner: Uint8Array = new Uint8Array(blockSize + data.length);
  const outer: Uint8Array = new Uint8Array(blockSize + digestLen);
  for (let i: number = 0; i < blockSize; i++) {
    inner[i] = kp[i] ^ 0x36;
    outer[i] = kp[i] ^ 0x5c;
  }
  inner.set(data, blockSize);

  // 3) H(opad || H(ipad || m))
  const innerHash: Uint8Array = is512 ? sha512Bytes(inner) : sha256Bytes(inner);
  outer.set(innerHash, blockSize);
  return is512 ? sha512Bytes(outer) : sha256Bytes(outer);
}

/** HMAC-SHA256，返回 32 字节 */
export function hmacSha256Bytes(key: Uint8Array, data: Uint8Array): Uint8Array {
  return hmacCore(false, key, data);
}

/** HMAC-SHA512，返回 64 字节 */
export function hmacSha512Bytes(key: Uint8Array, data: Uint8Array): Uint8Array {
  return hmacCore(true, key, data);
}

/**
 * HKDF-Extract + HKDF-Expand（RFC 5869），SHA-256 版。
 *
 * 用途：从共享密钥派生定长密钥材料（keySuite 派生链等处）。
 */
export function hkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  outLen: number
): Uint8Array {
  // Extract；RFC 5869：salt 为空时用 digestLen 个 0 字节
  const realSalt: Uint8Array = salt.length === 0 ? new Uint8Array(32) : salt;
  const prk: Uint8Array = hmacSha256Bytes(realSalt, ikm);

  // Expand
  const out: Uint8Array = new Uint8Array(outLen);
  let t: Uint8Array = new Uint8Array(0);
  let pos: number = 0;
  let counter: number = 1;
  while (pos < outLen) {
    const chunk: Uint8Array = new Uint8Array(t.length + info.length + 1);
    chunk.set(t, 0);
    chunk.set(info, t.length);
    chunk[t.length + info.length] = counter & 0xff;
    t = hmacSha256Bytes(prk, chunk);
    const take: number = Math.min(t.length, outLen - pos);
    out.set(t.subarray(0, take), pos);
    pos += take;
    counter++;
  }
  return out;
}
