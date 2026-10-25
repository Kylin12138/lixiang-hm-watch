/**
 * 编码工具：base64 / hex / UTF-8 字节互转
 *
 * 背景：ArkTS 的 util.Base64Helper 只在 API 11+ 且部分设备形态受限，
 * 这里自己实现一份纯计算版本，保证手表端可用、行为可预测。
 * 性能上这些数据量都很小（最大也就 2KB 的 RSA 密钥），无需优化。
 */

const B64_CHARS: string = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const B64_LOOKUP: Int16Array = (() => {
  const t = new Int16Array(256).fill(-1);
  for (let i = 0; i < B64_CHARS.length; i++) {
    t[B64_CHARS.charCodeAt(i)] = i;
  }
  return t;
})();

/** UTF-8 编码成字节数组 */
export function utf8ToBytes(s: string): Uint8Array {
  const out: number[] = [];
  for (let i = 0; i < s.length; i++) {
    let c = s.charCodeAt(i);
    if (c < 0x80) {
      out.push(c);
    } else if (c < 0x800) {
      out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
    } else if (c >= 0xd800 && c <= 0xdbff) {
      // 代理对：合成完整码点
      const c2 = s.charCodeAt(++i);
      const cp = 0x10000 + ((c - 0xd800) << 10) + (c2 - 0xdc00);
      out.push(
        0xf0 | (cp >> 18),
        0x80 | ((cp >> 12) & 0x3f),
        0x80 | ((cp >> 6) & 0x3f),
        0x80 | (cp & 0x3f)
      );
    } else {
      out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
    }
  }
  return new Uint8Array(out);
}

/** 字节数组按 UTF-8 解码成字符串 */
export function bytesToUtf8(b: Uint8Array): string {
  let s = '';
  let i = 0;
  while (i < b.length) {
    const c = b[i];
    if (c < 0x80) {
      s += String.fromCharCode(c);
      i += 1;
    } else if ((c & 0xe0) === 0xc0) {
      s += String.fromCharCode(((c & 0x1f) << 6) | (b[i + 1] & 0x3f));
      i += 2;
    } else if ((c & 0xf0) === 0xe0) {
      s += String.fromCharCode(((c & 0x0f) << 12) | ((b[i + 1] & 0x3f) << 6) | (b[i + 2] & 0x3f));
      i += 3;
    } else {
      const cp =
        ((c & 0x07) << 18) |
        ((b[i + 1] & 0x3f) << 12) |
        ((b[i + 2] & 0x3f) << 6) |
        (b[i + 3] & 0x3f);
      const v = cp - 0x10000;
      s += String.fromCharCode(0xd800 + (v >> 10), 0xdc00 + (v & 0x3ff));
      i += 4;
    }
  }
  return s;
}

/** 标准 base64 编码（带 = 填充） */
export function bytesToBase64(b: Uint8Array): string {
  let out = '';
  let i = 0;
  for (; i + 2 < b.length; i += 3) {
    const n = (b[i] << 16) | (b[i + 1] << 8) | b[i + 2];
    out += B64_CHARS[(n >> 18) & 63] + B64_CHARS[(n >> 12) & 63]
      + B64_CHARS[(n >> 6) & 63] + B64_CHARS[n & 63];
  }
  const rem = b.length - i;
  if (rem === 1) {
    const n = b[i] << 16;
    out += B64_CHARS[(n >> 18) & 63] + B64_CHARS[(n >> 12) & 63] + '==';
  } else if (rem === 2) {
    const n = (b[i] << 16) | (b[i + 1] << 8);
    out += B64_CHARS[(n >> 18) & 63] + B64_CHARS[(n >> 12) & 63]
      + B64_CHARS[(n >> 6) & 63] + '=';
  }
  return out;
}

/**
 * base64 解码，容错补齐 `=` 填充。
 *
 * ★ 参考项目 _b64decode 就是容错的 —— 服务端下发的 base64 有时不带填充，
 *   严格解码会抛异常。这里必须同样容错。
 */
export function base64ToBytes(s: string): Uint8Array {
  let str = s.replace(/[\s\r\n]/g, '');
  const pad = str.length % 4;
  if (pad === 2) {
    str += '==';
  } else if (pad === 3) {
    str += '=';
  } else if (pad === 1) {
    // 非法长度，截掉最后一位容错处理
    str = str.slice(0, -1);
  }
  const out: number[] = [];
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);
    if (ch === 0x3d) {
      break; // '='
    }
    const v = ch < 256 ? B64_LOOKUP[ch] : -1;
    if (v < 0) {
      continue; // 跳过非法字符（空白等）
    }
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}

/** base64url 编码（无填充），用于 PKCE */
export function bytesToBase64Url(b: Uint8Array): string {
  return bytesToBase64(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** 字节数组转小写 hex */
export function bytesToHex(b: Uint8Array): string {
  let s = '';
  for (let i = 0; i < b.length; i++) {
    s += b[i].toString(16).padStart(2, '0');
  }
  return s;
}

/** hex 转字节数组（忽略空白） */
export function hexToBytes(hex: string): Uint8Array {
  const s = hex.replace(/[\s\r\n]/g, '');
  const out = new Uint8Array(s.length >> 1);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(s.substr(i * 2, 2), 16);
  }
  return out;
}

/** 两个字节数组拼接 */
export function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/** 字节数组比较（等价判断） */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}
