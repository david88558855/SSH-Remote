/**
 * password.xlsx 密码表支持。
 *
 * 格式与 Remote-SSH 仓库的 remote.mjs readPasswords 完全一致：
 * 第 1 列主机名、第 2 列密码，扫描全部 sheet，两边的密码表可以直接互拷。
 *
 * 解析优先级（显式配置 > 文件，不做自动探测）：
 *   1. 环境变量 SSH_REMOTE_PASSWORD —— 设了就用它
 *   2. 密码表 password.xlsx（路径由 SSH_REMOTE_PASSWORD_FILE 指定，
 *      缺省为程序目录下的 password.xlsx）—— 按主机名查
 *
 * 失败语义（快速失败，不静默回退）：
 *   - 显式指定的 SSH_REMOTE_PASSWORD_FILE 不存在 → 调用方（server.js）启动即报错
 *   - 密码表文件存在但解析损坏 → 抛错，绝不带着空密码去撞服务端
 *   - 缺省路径下没有 password.xlsx → 视为没配密码表，返回 null 交给上层报错指路
 */

import fs from 'node:fs';
import XLSX from 'xlsx';

/** 读整个 xlsx → { 主机名: 密码 }。文件不存在或损坏时抛错。 */
export function readPasswords(filePath) {
  // SheetJS 对解析不了的文件会静默按纯文本处理（一个垃圾行也不报错），
  // 这不符合「损坏就报错」的语义。xlsx 本质是 zip，先验 PK 签名再交给它：
  // 不是真 xlsx（比如拿 Word 文档改名、写了一半的文件）在这里就拦下。
  if (/\.xlsx$/i.test(filePath)) {
    const fd = fs.openSync(filePath, 'r');
    try {
      const sig = Buffer.alloc(4);
      fs.readSync(fd, sig, 0, 4, 0);
      if (sig.toString('latin1') !== 'PK\u0003\u0004') {
        throw new Error('不是有效的 xlsx 文件（缺少 ZIP 签名，可能是损坏或改名的其他文件）');
      }
    } finally {
      fs.closeSync(fd);
    }
  }
  const wb = XLSX.readFile(filePath);
  const map = {};
  for (const name of wb.SheetNames) {
    // header:1 → 二维数组，自己按位置取列，不做表头推断：
    // 表头行取出来也只是 map 里多一条永远查不到的假主机，无害。
    const rows = XLSX.utils.sheet_to_json(wb.Sheets[name], { header: 1 });
    for (const row of rows) {
      if (row && row.length >= 2) {
        const h = String(row[0]).trim();
        const p = String(row[1]).trim();
        if (h && p) map[h] = p;
      }
    }
  }
  return map;
}

/**
 * password 模式的密码解析。
 * 返回 { password, source }：source 为 'SSH_REMOTE_PASSWORD' 或密码表文件路径，
 * 都没拿到则 password 为 null，由调用方报错指路。
 */
export function resolvePassword({ host, envPassword, passwordFile }) {
  if (envPassword) {
    return { password: envPassword, source: 'SSH_REMOTE_PASSWORD' };
  }
  if (!fs.existsSync(passwordFile)) {
    return { password: null, source: null };
  }
  let map;
  try {
    map = readPasswords(passwordFile);
  } catch (e) {
    throw new Error(`密码表解析失败 ${passwordFile}：${e.message}。请确认是合法的 xlsx 文件`);
  }
  const pw = map[host];
  return pw ? { password: pw, source: passwordFile } : { password: null, source: null };
}
