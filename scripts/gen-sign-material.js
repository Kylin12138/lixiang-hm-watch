/**
 * 生成 hvigor 认可的「签名密码密文 + material 材料」。
 *
 * 背景：
 *   hvigor 的 SignHap 任务会【无条件】对 build-profile.json5 里的
 *   storePassword / keyPassword 调 DecipherUtil.decryptPwd() 解密
 *   （见 hvigor-ohos-plugin/src/tasks/sign/command-builder-impl/common-sign-command-builder.js）。
 *   所以这两个字段【必须是密文】，明文会直接报：
 *     00303116 Configuration Error
 *     The length of the storePassword or keyPassword field ... is less than 32
 *   （因为解密前先校验 length >= 32 且为偶数）
 *
 * 逆向出的算法（见 hvigor-ohos-plugin/src/utils/decipher-util.js）：
 *   密文格式: [4B big-endian: ivLen][ivLen 字节 IV][GCM 密文][16B authTag]
 *   key      = pbkdf2Sync(xorKey.toString(), salt, 10000, 16, 'sha256')
 *   xorKey   = fd[0] ^ fd[1] ^ fd[2] ^ component    // 全部 16 字节
 *   component = 固定常量（下面的 COMPONENT）
 *   salt     = material/ac/ 目录下所有文件的字节拼接
 *   material 目录 = <storeFile 所在目录>/material/{fd,ac,ce}/
 *     - fd/  : 若干文件，内容各 16 字节，按文件名排序
 *     - ac/  : 若干文件，内容即 salt
 *     - ce/  : 若干文件，内容即「被加密的工作材料」(workMaterial)
 *   解密时: workMaterial 用 xorKey 解出真正的 AES key（再解密码）
 *
 * 用法:
 *   node scripts/gen-sign-material.js <signatureDir> <storePassword> <keyPassword>
 * 例:
 *   node scripts/gen-sign-material.js LixiangWatch/signature 123456 123456
 */
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// decipher-util.js 里的固定常量
const COMPONENT = Buffer.from([
  49, 243, 9, 115, 214, 175, 91, 184, 211, 190, 177, 88, 101, 131, 192, 119
]);

function xorAll(bufs) {
  let acc = Buffer.from(bufs[0]);
  for (let i = 1; i < bufs.length; i++) {
    const b = bufs[i];
    if (b.length !== acc.length) {
      throw new Error(`xor 长度不一致: ${acc.length} vs ${b.length}`);
    }
    for (let j = 0; j < b.length; j++) {
      acc[j] = acc[j] ^ b[j];
    }
  }
  return acc;
}

/**
 * ★★★ 关键：hvigor 侧 getRootKey 走的是
 *     pbkdf2Sync(xorComponents(...).toString(), salt, 1e4, 16, 'sha256')
 *   而 xorComponents 返回的是 **Int8Array**（不是 Buffer）。
 *   Int8Array.prototype.toString() 等价于 join(',')，
 *   且元素是【有符号】的 —— 形如 "49,-13,9,115,..."。
 *   用 Buffer.toString()（utf8）会丢字节、得到完全不同的 key → AES-GCM 认证失败
 *   （00303242 unable to authenticate data）。
 */
function int8ArrayToString(buf) {
  const arr = [];
  for (let i = 0; i < buf.length; i++) {
    // Buffer 是无符号 0-255，Int8Array 要转成 -128..127
    const v = buf[i] > 127 ? buf[i] - 256 : buf[i];
    arr.push(v);
  }
  return arr.join(',');
}

/**
 * 加密：必须与 hvigor 的 decrypt 严格互逆。
 *
 * ★★★ 布局（反直觉，务必对照 decipher-util.js 的 decrypt）：
 *     [4B big-endian: ivLen][cipher][iv][authTag(16B)]
 *
 *   hvigor 解密时:
 *     ivLen   = 读前 4 字节
 *     cipher  = r[4 : len-ivLen-16]
 *     iv      = r[len-ivLen-16 : len-16]
 *     tag     = 末 16 字节
 */
function encryptPwd(key, plaintext, log) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-128-gcm', key, iv);
  const enc = Buffer.concat([c.update(Buffer.from(plaintext, 'utf8')), c.final()]);
  const tag = c.getAuthTag();
  const head = Buffer.alloc(4);
  head.writeUInt32BE(iv.length, 0);
  const out = Buffer.concat([head, enc, iv, tag]); // ← cipher 在前，iv 在后
  if (log) {
    log(`  明文 "${plaintext}" (${plaintext.length}B) → 密文 ${out.length}B, hex 长度 ${out.toString('hex').length}`);
  }
  return out;
}

/**
 * 写「单文件目录」：目录下恰好 1 个文件。
 * readDirBytes(dir) 会 readdirSync 取第 1 个并 readFileSync。
 */
function writeOneFileDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
  return path.join(dir, 'd');
}


function main() {
  const [sigDir, storePwd, keyPwd] = process.argv.slice(2);
  if (!sigDir || !storePwd || !keyPwd) {
    console.error('用法: node gen-sign-material.js <signatureDir> <storePassword> <keyPassword>');
    process.exit(1);
  }

  const matDir = path.resolve(sigDir, 'material');
  const log = (m) => console.log(m);
  log(`material 目录: ${matDir}`);

  // ---- 1. 造 fd/ : 3 个 16 字节文件 ----
  const fdParts = [crypto.randomBytes(16), crypto.randomBytes(16), crypto.randomBytes(16)];
  const xorKey = xorAll([...fdParts, COMPONENT]); // 16 字节

  // ---- 2. 造 ac/ : salt ----
  const salt = crypto.randomBytes(32);
  const rootKey = crypto.pbkdf2Sync(
    int8ArrayToString(xorKey), salt, 10000, 16, 'sha256');

  // hvigor 侧: key = decrypt(rootKey, workMaterial) —— 即 workMaterial 加密后
  // 得到【真正用来解密码的 AES key】。我们让它直接等于一个随机 16 字节 key。
  const realKey = crypto.randomBytes(16);
  // 用 rootKey 加密 realKey 作为 workMaterial（布局同上：cipher 在前、iv 在后）
  const encryptRaw = (k, pt) => {
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-128-gcm', k, iv);
    const enc = Buffer.concat([c.update(pt), c.final()]);
    const head = Buffer.alloc(4);
    head.writeUInt32BE(iv.length, 0);
    return Buffer.concat([head, enc, iv, c.getAuthTag()]);
  };
  const workMaterial = encryptRaw(rootKey, realKey);

  // ---- 3. 写材料 ----
  // 结构约束（严格按 decipher-util.js 的读法反推）：
  //   readFd(materialDir,'fd'):  readdirSync('fd') 的结果【每个条目】
  //                             再交给 readDirBytes() → 该条目必须是目录
  //   readSalt('ac')          :  直接 readDirBytes('ac') → ac 下放【文件】
  //   readWorkMaterial('ce')  :  直接 readDirBytes('ce') → ce 下放【文件】
  //   readDirBytes(dir)       :  readdirSync(dir) 必须【恰好 1 项】，读其内容
  const fdDir = path.join(matDir, 'fd');
  for (let i = 0; i < fdParts.length; i++) {
    const sub = path.join(fdDir, `k${i + 1}`);   // fd/k1 是目录
    fs.mkdirSync(sub, { recursive: true });
    fs.writeFileSync(path.join(sub, 'd'), fdParts[i]);  // 里面恰好 1 个文件
  }
  fs.writeFileSync(writeOneFileDir(path.join(matDir, 'ac')), salt);
  fs.writeFileSync(writeOneFileDir(path.join(matDir, 'ce')), workMaterial);

  // ---- 4. 用 realKey 加密两个密码，输出密文 ----
  log('生成密文：');
  const encStore = encryptPwd(realKey, storePwd, log);
  const encKey = encryptPwd(realKey, keyPwd, log);

  const out = {
    storePassword: encStore.toString('hex'),
    keyPassword: encKey.toString('hex')
  };
  const outFile = path.resolve(sigDir, 'passwords.json');
  fs.writeFileSync(outFile, JSON.stringify(out, null, 2), 'utf8');
  log('');
  log(`✅ 已写出 ${outFile}`);
  log(`   storePassword = ${out.storePassword}`);
  log(`   keyPassword   = ${out.keyPassword}`);
  log('');
  log('把上面两个值填进 build-profile.json5 的 material.storePassword / keyPassword');
}

main();
