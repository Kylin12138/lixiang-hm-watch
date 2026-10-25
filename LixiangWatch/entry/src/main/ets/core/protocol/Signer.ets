/**
 * x-chj 请求签名器
 *
 * ═══════════════════════════════════════════════════════════════
 *  算法（来源：ha-lixiang/signer.py，真机实测通过）
 * ═══════════════════════════════════════════════════════════════
 *
 *   stringToSign = [env, appVersion, keyId, deviceId, METHOD,
 *                   accept, contentLang, contentMD5, contentType,
 *                   timestamp, nonce] 用 "\n" 拼接
 *                 + 末尾再补一个 "\n"
 *
 *   sign = base64( HMAC-SHA256( hac_key原始字节, stringToSign ) )
 *
 * ═══════════════════════════════════════════════════════════════
 *  ★ 三个必须记住的坑（每一个都真实踩过）
 * ═══════════════════════════════════════════════════════════════
 *
 *  1. HMAC key 必须是 hac_key 的【原始 32 字节】。
 *     如果把 hac_key 当字符串 encode() 再当 key 用 → 服务端返回
 *     "请求签名错误"（code 100005）。这一点已在接口签名上用
 *     Uint8Array 强制约束。
 *
 *  2. 11 段拼完【必须再补一个 "\n"】。漏掉就是一个完全不同的签名。
 *
 *  3. header 名大小写敏感，且必须与签名段一一对应：
 *       Content-MD5（不是 Content-Md5）
 *       Content-Language / Content-Type / Accept 都要带上。
 *
 * ⚠️ 还有一个容易搞混的地方：
 *     keySuite 请求的 X-CHJ-Sign 用的是【hexdigest】，
 *     业务接口用的是【base64】—— 两者不同，不要套用。
 *     keySuite 见 KeySuite.ets。
 */

import { hmacSha256Base64, md5, randomHex } from '../crypto/HarmonyCrypto';
import { bytesToBase64, utf8ToBytes } from '../crypto/Codec';
import {
  ENV, SIGN_APP_VERSION, DEFAULT_ACCEPT, DEFAULT_CONTENT_LANG,
  DEFAULT_CONTENT_TYPE, EMPTY_MD5, DEVICE_TYPE, MODEL_NAME
} from './Constants';

export interface SignResult {
  sign: string;
  timestamp: string;
  nonce: string;
  contentMd5: string;
}

export interface DeviceIdentity {
  /** hac_key 的原始 32 字节 */
  hacKey: Uint8Array;
  /** 服务端下发的 keyId（keySuite 响应里的 keyId） */
  keyId: string;
  /** 设备 id（deviceId / xdev） */
  deviceId: string;
  /** app token（登录拿到的 EVA token，放 X-CHJ-TOKEN 头） */
  appToken: string;
}

/**
 * 计算 body 的 Content-MD5。
 *
 * 空 body 时返回硬编码常量 EMPTY_MD5（= base64(md5(""))），
 * 与实际计算等价，但省一次调用 —— 参考项目也是这么做的。
 */
export function contentMd5(body: string): string {
  if (!body || body.length === 0) {
    return EMPTY_MD5;
  }
  return bytesToBase64(md5(utf8ToBytes(body)));
}

/**
 * 构造 stringToSign（11 段 + 末尾 \n）。
 * 单独抽出来是为了方便写测试用例逐段核对。
 */
export function buildStringToSign(
  keyId: string,
  deviceId: string,
  method: string,
  md5B64: string,
  timestamp: string,
  nonce: string,
  appVersion: string = SIGN_APP_VERSION
): string {
  const parts: string[] = [
    ENV,
    appVersion,
    keyId,
    deviceId,
    method.toUpperCase(),
    DEFAULT_ACCEPT,
    DEFAULT_CONTENT_LANG,
    md5B64,
    DEFAULT_CONTENT_TYPE,
    timestamp,
    nonce
  ];
  return parts.join('\n') + '\n';
}

export class Signer {
  private identity: DeviceIdentity;

  constructor(identity: DeviceIdentity) {
    this.identity = identity;
  }

  get deviceId(): string {
    return this.identity.deviceId;
  }

  get keyId(): string {
    return this.identity.keyId;
  }

  /**
   * 生成签名。
   *
   * @param method HTTP 方法
   * @param body   请求体字符串（GET 传空字符串）
   */
  signRequest(method: string, body: string, timestamp?: string, nonce?: string): SignResult {
    const ts = timestamp !== undefined && timestamp.length > 0
      ? timestamp
      : `${new Date().getTime()}`;
    const nc = nonce !== undefined && nonce.length > 0 ? nonce : this.newNonce();
    const m = contentMd5(body);

    const sts = buildStringToSign(
      this.identity.keyId, this.identity.deviceId, method, m, ts, nc);
    const data = utf8ToBytes(sts);
    const sign = hmacSha256Base64(this.identity.hacKey, data);

    return { sign: sign, timestamp: ts, nonce: nc, contentMd5: m };
  }

  /**
   * 构造完整的业务请求头。
   *
   * @param method   HTTP 方法
   * @param body     请求体
   * @param bearer   MESH / VSS token（放 Authorization）
   * @param vin      车架号（放 X-CHJ-VIN），无车上下文时传空
   */
  buildHeaders(method: string, body: string, bearer: string, vin: string): Record<string, string> {
    const r = this.signRequest(method, body);
    const h: Record<string, string> = {
      'X-CHJ-Env': ENV,
      'X-CHJ-APP-Version': SIGN_APP_VERSION,
      'X-CHJ-Key': this.identity.keyId,
      'X-CHJ-Deviceid': this.identity.deviceId,
      'X-CHJ-Timestamp': r.timestamp,
      'X-CHJ-Nonce': r.nonce,
      'X-CHJ-Sign': r.sign,
      'Content-MD5': r.contentMd5,
      'Content-Type': DEFAULT_CONTENT_TYPE,
      'Content-Language': DEFAULT_CONTENT_LANG,
      'Accept': DEFAULT_ACCEPT,
      'X-CHJ-Version': SIGN_APP_VERSION,
      'X-CHJ-DeviceType': DEVICE_TYPE,
      'X-CHJ-ModelName': MODEL_NAME,
      'X-CHJ-Tag': '1',
      'X-CHJ-TOKEN': this.identity.appToken,
      'Authorization': `Bearer ${bearer}`,
      'User-Agent': `m01/${SIGN_APP_VERSION} (iPad; iOS 16.7.12; Scale/2.00)`
    };
    if (vin && vin.length > 0) {
      h['X-CHJ-VIN'] = vin;
    }
    return h;
  }

  /** 生成随机 nonce（32 hex 字符） */
  private newNonce(): string {
    return randomHex(16);
  }
}
