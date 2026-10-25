/**
 * keySuite 签名身份派生 —— 与 Python 的 lx_keysuite.py 一一对应
 *
 * ═══════════════════════════════════════════════════════════════
 *  流程
 * ═══════════════════════════════════════════════════════════════
 *
 *   POST {API_APP}/ddes/v1-1/app/key-suite
 *   body: {deviceId, deviceKeyId, nonce, requestId, sign, timestamp}
 *     sign = base64( RSA-PKCS1v15-SHA256( priv,
 *                  "requestId:deviceId:deviceKeyId:nonce:timestamp" ) )
 *
 *   响应:
 *     data.tempAesKey   (base64)
 *     data.tempIv       (base64)
 *     data.keySuite.keySecret.hmacKey (base64)
 *     data.keySuite.keyId
 *
 *   派生:
 *     RD  = RSA-PKCS1v15.decrypt(tempAesKey, priv)           ← 32 字节
 *     hac = AES-256-CTR(key=RD, iv=tempIv).decrypt(hmacKey)  ← 32 字节
 *     → (hacKey, keyId)
 *
 * ═══════════════════════════════════════════════════════════════
 *  ★★ 与业务接口的两处差异（必须记住）
 * ═══════════════════════════════════════════════════════════════
 *
 *   1. X-CHJ-Sign 用 **hexdigest**（业务接口用 base64）
 *   2. 签名文本第 3 段是 **bootHacHex[:32]**（不是 keyId）
 *      第 11 段是 **nonce.upper() + timestamp**（不是单纯 nonce）
 */

import { http } from '@kit.NetworkKit';
import { BusinessError } from '@kit.BasicServicesKit';
import {
  API_APP, EP_KEY_SUITE_DDES, MAIN_DEVICE_KEY_ID, MAIN_RSA_PRIVATE_DER_B64,
  KEY_SUITE_VER
} from './Constants';
import {
  base64ToBytes, bytesToBase64, bytesToHex, utf8ToBytes
} from '../crypto/Codec';
import {
  hmacSha256Hex, loadRsaPrivateKeyFromDer, md5, randomHex,
  rsaDecryptPkcs1, rsaSignPkcs1Sha256, aesCtrDecrypt, uuid4Hex,
  RsaKeyHandle
} from '../crypto/HarmonyCrypto';

export class IdentityDeriveError extends Error {
  constructor(msg: string) {
    super(msg);
    this.name = 'IdentityDeriveError';
  }
}

export interface DerivedIdentity {
  /** hac_key 的 hex 字符串（64 字符 = 32 字节） */
  hacKeyHex: string;
  /** 服务端下发的 keyId */
  keyId: string;
  /**
   * 有效期（毫秒时间戳）。
   *
   * ★ 2026-10-14 实测发现（参考项目未记录）：
   *     validFrom  = 派生时刻
   *     updateFrom = +3 个月（建议更新时刻）
   *     validTo    = +4 个月（失效时刻）
   *   → hac_key 派生一次可用 4 个月，应持久化缓存并在
   *     updateFrom 之后择机重新派生，而不是每次启动都派生。
   */
  validFrom: number;
  validTo: number;
  updateFrom: number;
}

/** 解析有效期字段 */
export function parseValidity(j: KeySuiteResponse): number[] {
  const ks: KeySuiteInner = (j.data ?? {}).keySuite ?? {};
  return [ks.validFrom ?? 0, ks.validTo ?? 0, ks.updateFrom ?? 0];
}

/** body 的 RSA 签名原文 */
export function buildDataToSign(requestId: string, xdev: string,
                                kid: string, nonce: string,
                                ts: string): string {
  return [requestId, xdev, kid, nonce, ts].join(':');
}

/** keySuite 请求：headers 与 body 分离（ArkTS 不支持 delete，必须显式分开） */
export class KeySuiteRequest {
  headers: Record<string, string>;
  body: string;

  constructor(headers: Record<string, string>, body: string) {
    this.headers = headers;
    this.body = body;
  }
}

/**
 * 组装 keySuite 请求（headers + body），不发网络。
 * 单独抽出来便于写测试。
 */
export function buildKeySuiteRequest(
  xdev: string, kid: string, priv: RsaKeyHandle,
  bearer: string, requestId: string, nonce: string, ts: string,
  bootHacHex: string, ver: string = KEY_SUITE_VER
): KeySuiteRequest {
  const dataToSign: string = buildDataToSign(requestId, xdev, kid, nonce, ts);
  const signBytes: Uint8Array = rsaSignPkcs1Sha256(priv, utf8ToBytes(dataToSign));
  const signB64: string = bytesToBase64(signBytes);

  // body 按 Gson 字母序：deviceId, deviceKeyId, nonce, requestId, sign, timestamp
  const body: string = `{"deviceId":"${xdev}","deviceKeyId":"${kid}","nonce":"${nonce}",`
    + `"requestId":"${requestId}","sign":"${signB64}","timestamp":"${ts}"}`;

  const md5b: string = bytesToBase64(md5(utf8ToBytes(body)));

  // ★ 第 3 段是 bootHacHex[:32]，第 11 段是 nonce.upper() + ts
  const dtsx: string = [
    'prod', ver, bootHacHex.substring(0, 32), xdev, 'POST', '*/*',
    'zh-Hans-CN', md5b, 'application/json', ts, nonce.toUpperCase() + ts
  ].join('\n');
  const xsign: string = hmacSha256Hex(hexToBytesLocal(bootHacHex), utf8ToBytes(dtsx + '\n'));

  const headers: Record<string, string> = {
    'Authorization': 'Bearer ' + bearer,
    'Content-Type': 'application/json',
    'Content-MD5': md5b,
    'Accept': '*/*',
    'Content-Language': 'zh-Hans-CN',
    'X-CHJ-Timestamp': ts,
    'X-CHJ-Nonce': nonce.toUpperCase(),
    'X-CHJ-Sign': xsign,                    // ★ hexdigest
    'X-CHJ-Deviceid': xdev,
    'X-CHJ-Key': bootHacHex.substring(0, 32),
    'X-CHJ-APP-Version': ver,
    'X-CHJ-Env': 'prod',
    'X-CHJ-Version': ver
  };
  return new KeySuiteRequest(headers, body);
}

/** 本地 hex→bytes（避免与 Codec 的循环依赖） */
function hexToBytesLocal(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length >> 1);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
}

/**
 * 响应 → 32 字节 hac_key。
 *
 * RD  = RSA-PKCS1v15 解密 tempAesKey
 * hac = AES-256-CTR(key=RD, iv=tempIv).decrypt(hmacKey)
 */
export function formatDk(tempAesKeyB64: string, tempIvB64: string,
                         hmacKeyB64: string,
                         priv: RsaKeyHandle): Uint8Array {
  const ta = base64ToBytes(tempAesKeyB64);
  const ti = base64ToBytes(tempIvB64);
  const hk = base64ToBytes(hmacKeyB64);
  const rd = rsaDecryptPkcs1(priv, ta);
  const hac = aesCtrDecrypt(rd, ti, hk);
  if (hac.length !== 32) {
    throw new IdentityDeriveError(`formatDK 派生长度异常: ${hac.length} 字节`);
  }
  return hac;
}

/** 解析 keySuite 响应 */
interface KeySuiteResponse {
  code?: number;
  msg?: string;
  message?: string;
  data?: KeySuiteData;
}

interface KeySuiteData {
  tempAesKey?: string;
  tempIv?: string;
  keySuite?: KeySuiteInner;
}

interface KeySuiteInner {
  keyId?: string;
  keySecret?: KeySecret;
  validFrom?: number;
  validTo?: number;
  updateFrom?: number;
}

interface KeySecret {
  hmacKey?: string;
}

/**
 * 现场派生签名身份。
 *
 * ★ 2026-10-14 实测确认：该端点【不校验 bearer】——
 *   任意无效 bearer 只要 x-chj 签名与 body 的 RSA 签名正确，
 *   服务端即返回 code=0 并下发完整密钥材料。
 *   因此策略是：**永不重派生，除非缓存过期**。
 *   每次冷启动都重新派生是浪费的（hac_key 有效期 4 个月）。
 *
 * @param xdev    设备 id（deviceId）
 * @param bearer  主 Bearer 或 app token（实测可传任意值）
 * @param keyId   设备 key id，默认主 App 的
 */
export async function deriveIdentity(xdev: string, bearer: string,
                                     keyId: string = MAIN_DEVICE_KEY_ID
): Promise<DerivedIdentity> {
  const priv: RsaKeyHandle = loadRsaPrivateKeyFromDer(
    base64ToBytes(MAIN_RSA_PRIVATE_DER_B64));
  const ts: string = `${new Date().getTime()}`;
  const requestId: string = uuid4Hex();
  const nonce: string = uuid4Hex();
  const bootHacHex: string = randomHex(32);   // 引导签名：随机值即通过

  const req: KeySuiteRequest = buildKeySuiteRequest(
    xdev, keyId, priv, bearer, requestId, nonce, ts, bootHacHex);
  const body: string = req.body;
  const headers: Record<string, string> = req.headers;

  const httpReq = http.createHttp();
  try {
    const resp = await httpReq.request(API_APP + EP_KEY_SUITE_DDES, {
      method: http.RequestMethod.POST,
      header: headers,
      extraData: body,
      connectTimeout: 20000,
      readTimeout: 20000,
      maxRedirects: 0
    });
    if (resp.responseCode !== 200) {
      throw new IdentityDeriveError(
        `keySuite HTTP ${resp.responseCode}: ${String(resp.result).substring(0, 200)}`);
    }
    const raw = String(resp.result);
    let j: KeySuiteResponse;
    try {
      j = JSON.parse(raw) as KeySuiteResponse;
    } catch (e) {
      throw new IdentityDeriveError(`keySuite 响应非 JSON: ${raw.substring(0, 200)}`);
    }
    if (j.code !== 0) {
      throw new IdentityDeriveError(
        `keySuite code=${j.code} msg=${j.msg ?? j.message ?? ''}`);
    }
    const dd: KeySuiteData = j.data ?? {};
    const ks: KeySuiteInner = dd.keySuite ?? {};
    const sec: KeySecret = ks.keySecret ?? {};
    if (!dd.tempAesKey) {
      throw new IdentityDeriveError('keySuite 响应缺少字段: tempAesKey');
    }
    if (!dd.tempIv) {
      throw new IdentityDeriveError('keySuite 响应缺少字段: tempIv');
    }
    if (!sec.hmacKey) {
      throw new IdentityDeriveError('keySuite 响应缺少字段: hmacKey');
    }

    const hac = formatDk(dd.tempAesKey, dd.tempIv, sec.hmacKey, priv);
    return {
      hacKeyHex: bytesToHex(hac),
      keyId: ks.keyId ?? keyId,
      validFrom: ks.validFrom ?? 0,
      validTo: ks.validTo ?? 0,
      updateFrom: ks.updateFrom ?? 0
    };
  } catch (e) {
    const err = e as BusinessError;
    // ★★ 九号坑同源：maxRedirects:0 遇 3xx 抛 2300047（拿不到 resp）。
    //   这里以前没 catch，会直接把 "2300047" 抛给 UI。
    if (err.code === 2300047) {
      throw new IdentityDeriveError(
        'keySuite 请求被重定向(302)：登录会话可能已失效，请重新登录');
    }
    throw err as Error;
  } finally {
    httpReq.destroy();
  }
}
