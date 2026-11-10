/**
 * 认证方式自测：不需要真实远端机。
 *
 * 本脚本用 ssh2 自己的 Server 起一个 mock sshd（支持密码/公钥/空认证三种验证），
 * 逐项验证 RemoteSession 的认证逻辑：
 *
 *   1. password 模式（正确密码连上、错误密码被拒、缺密码/空串密码快速失败）
 *   2. key 模式（私钥连上、文件缺失时报指引）
 *   3. none 模式（服务端允许空认证则连上、被拒时指路）
 *   4. authMode 非法值/缺省 → 构造时直接拒绝
 *
 * 认证方式三选一必填：password | key | none（环境变量 SSH_REMOTE_AUTH）。
 *
 * 跑法：node auth-selftest.js（退出码非 0 即有失败）
 */

import crypto from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import ssh2pkg from 'ssh2';
import { RemoteSession } from './ssh-session.js';

const { Server: SshServer, utils } = ssh2pkg;

const PASSWORD = 'selftest-pass-1';
let passed = 0;
let failed = 0;

function check(name, ok, extra = '') {
  if (ok) {
    passed++;
    console.log(`  ✓ ${name}`);
  } else {
    failed++;
    console.error(`  ✗ ${name}${extra ? ` —— ${extra}` : ''}`);
  }
}

// ── 密钥材料（ssh2 keygen 生成，OpenSSH PEM 格式） ──────────────────
function makeKeypair() {
  const pair = utils.generateKeyPairSync('ed25519');
  const parsed = utils.parseKey(pair.private);
  return {
    privPem: pair.private,
    pubPem: pair.public,
    pubBlob: parsed.getPublicSSH(),
    parsed,
    privKeyObj: crypto.createPrivateKey(parsed.getPrivatePEM()),
  };
}

const hostKey = makeKeypair();
const userKey = makeKeypair();
const userPubBlob = userKey.pubBlob;

// ── mock sshd ───────────────────────────────────────────────────────
// opts.acceptNone: 服务端接受 none 认证（模拟允许空认证的机器）
// opts.echoCommand: exec 时把收到的命令串原样回显（用于验证命令包装逻辑）
function startMockSshd(opts = {}) {
  return new Promise((resolve) => {
    const srv = new SshServer({ hostKeys: [{ key: hostKey.privPem }] });
    srv.on('error', (e) => console.error('[mock-sshd] error:', e));
    // ssh2 的标准用法：authentication / session / exec 全挂在连接对象上
    // （不注册 connection 监听器的话，握手完成即自动断开）
    srv.on('connection', (client) => {
      // 注意：ssh2 v1.17 的 auth ctx 字段是 method（不是老文档里的 type）
      client.on('authentication', (ctx) => {
        if (ctx.method === 'none' && opts.acceptNone) {
          ctx.accept();
          return;
        }
        if (ctx.method === 'password') {
          if (ctx.password === PASSWORD) ctx.accept();
          else ctx.reject();
          return;
        }
        if (ctx.method === 'publickey') {
          if (ctx.key && Buffer.compare(ctx.key.data, userPubBlob) === 0) {
            ctx.accept();
          } else {
            ctx.reject();
          }
          return;
        }
        ctx.reject();
      });
      client.on('ready', () => {
        client.on('session', (accept) => {
          const session = accept();
          session.on('exec', (accept2, reject2, info) => {
            const stream = accept2();
            stream.stdout.write(opts.echoCommand ? info.command : 'mock-ssh-ok');
            stream.exit(0);
            stream.end();
            stream.close();
          });
        });
      });
    });
    srv.listen(0, '127.0.0.1');
    srv.on('listening', () => resolve(srv));
  });
}

// ── 测试 ────────────────────────────────────────────────────────────
const port = await new Promise((res) => {
  startMockSshd().then((srv) => res(srv.address().port));
});
// none 探测专用服务器（模拟允许空认证的机器）
const nonePort = await new Promise((res) => {
  startMockSshd({ acceptNone: true }).then((srv) => res(srv.address().port));
});

const base = {
  host: '127.0.0.1',
  port,
  username: 'selftest',
  readyTimeout: 10000,
};

console.log(`mock sshd=127.0.0.1:${port}  mock sshd(none)=127.0.0.1:${nonePort}`);

// 1. password 模式
{
  const s = new RemoteSession({ ...base, authMode: 'password', password: PASSWORD });
  try {
    await s.ensure();
    const r = await s.exec('echo hi');
    check('password 模式：正确密码连上并执行', r.stdout === 'mock-ssh-ok', `stdout=${JSON.stringify(r.stdout)}`);
    check('password 模式：authMethod 记录正确', s.authMethod === 'password', `got ${s.authMethod}`);
  } catch (e) {
    check('password 模式：正确密码连上并执行', false, e.message);
  }
  s.close();
}
{
  const s = new RemoteSession({ ...base, authMode: 'password', password: 'wrong' });
  try {
    await s.ensure();
    check('password 模式：错误密码被拒', false, '竟然连上了');
  } catch (e) {
    check('password 模式：错误密码被拒', /All configured authentication methods failed/.test(e.message) && /PasswordAuthentication/.test(e.message), e.message);
  }
  s.close();
}
{
  const s = new RemoteSession({ ...base, authMode: 'password' });
  try {
    await s.ensure();
    check('password 模式：缺密码时报指引', false, '竟然连上了');
  } catch (e) {
    check('password 模式：缺密码时报指引', /SSH_REMOTE_PASSWORD/.test(e.message), e.message);
  }
  s.close();
}
{
  // 空字符串密码视同未配置：快速失败给指引，不会拿空密码去撞
  const s = new RemoteSession({ ...base, authMode: 'password', password: '' });
  try {
    await s.ensure();
    check('password 模式：空串密码快速失败', false, '竟然连上了');
  } catch (e) {
    check('password 模式：空串密码快速失败', /没有密码/.test(e.message) && /SSH_REMOTE_PASSWORD/.test(e.message), e.message);
  }
  s.close();
}

// 2. key 模式
{
  const keyFile = path.join(os.tmpdir(), `ssh-remote-selftest-key-${process.pid}`);
  fs.writeFileSync(keyFile, userKey.privPem, { mode: 0o600 });
  const s = new RemoteSession({ ...base, authMode: 'key', keyPath: keyFile });
  try {
    await s.ensure();
    check('key 模式：私钥连上', s.authMethod === 'key', `got ${s.authMethod}`);
  } catch (e) {
    check('key 模式：私钥连上', false, e.message);
  }
  fs.unlinkSync(keyFile);
  s.close();
}
{
  const s = new RemoteSession({ ...base, authMode: 'key', keyPath: '/nonexistent/key' });
  try {
    await s.ensure();
    check('key 模式：私钥缺失时报指引', false, '竟然连上了');
  } catch (e) {
    check('key 模式：私钥缺失时报指引', /SSH_REMOTE_KEY/.test(e.message) || /SSH_REMOTE_AUTH=password/.test(e.message), e.message);
  }
  s.close();
}

// 3. none 模式（空认证）
{
  const s = new RemoteSession({ host: '127.0.0.1', port: nonePort, username: 'selftest', authMode: 'none', readyTimeout: 10000 });
  try {
    await s.ensure();
    const r = await s.exec('echo hi');
    check('none 模式：服务端接受空认证则连上', r.stdout === 'mock-ssh-ok' && s.authMethod === 'none', `stdout=${JSON.stringify(r.stdout)} auth=${s.authMethod}`);
  } catch (e) {
    check('none 模式：服务端接受空认证则连上', false, e.message);
  }
  s.close();
}
{
  const s = new RemoteSession({ ...base, authMode: 'none', readyTimeout: 10000 });
  try {
    await s.ensure();
    check('none 模式：被拒时报错指路', false, '竟然连上了');
  } catch (e) {
    check('none 模式：被拒时报错指路', /空认证/.test(e.message), e.message);
  }
  s.close();
}

// 4. authMode 校验：非法值/缺省一律构造时拒绝
{
  for (const bad of ['agent', 'auto', '', undefined]) {
    let threw = '';
    try {
      new RemoteSession({ ...base, authMode: bad });
    } catch (e) {
      threw = e.message;
    }
    check(`authMode=${bad === undefined ? '(未传)' : JSON.stringify(bad)}：构造时拒绝`, /三选一/.test(threw) && /SSH_REMOTE_AUTH/.test(threw), threw || '没抛错');
  }
}

// 5. password.xlsx 密码表：解析、查找、优先级、快速失败
{
  const XLSX = (await import('xlsx')).default;
  const fs = await import('node:fs');
  const os = await import('node:os');
  const path = await import('node:path');
  const { readPasswords, resolvePassword } = await import('./password-file.js');

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-remote-pw-'));
  const mk = (file, sheets) => {
    const wb = XLSX.utils.book_new();
    for (const [name, rows] of Object.entries(sheets)) {
      XLSX.utils.book_append_sheet(wb, XLSX.utils.aoa_to_sheet(rows), name);
    }
    XLSX.writeFile(wb, file);
  };
  const ok = path.join(dir, 'ok.xlsx');
  mk(ok, { Sheet1: [['主机名', '密码'], ['host-a', 'pw-a'], ['', '跳过'], ['host-b', 'pw-b']], Sheet2: [['host-c', 'pw-c']] });

  const m1 = readPasswords(ok);
  check('密码表：多 sheet 全扫、空行跳过', m1['host-a'] === 'pw-a' && m1['host-b'] === 'pw-b' && m1['host-c'] === 'pw-c' && m1['主机名'] === '密码', JSON.stringify(m1));

  check('密码表：文件不存在直接抛错', (() => { try { readPasswords(path.join(dir, 'nope.xlsx')); return false; } catch { return true; } })(), '没抛错');

  const r1 = resolvePassword({ host: 'host-b', envPassword: null, passwordFile: ok });
  check('密码表：按主机名查到密码', r1.password === 'pw-b' && r1.source === ok, JSON.stringify(r1));

  const r2 = resolvePassword({ host: 'host-x', envPassword: null, passwordFile: ok });
  check('密码表：主机不在表里 → null', r2.password === null && r2.source === null, JSON.stringify(r2));

  const r3 = resolvePassword({ host: 'host-x', envPassword: 'env-pw', passwordFile: ok });
  check('密码表：env 显式密码优先于表', r3.password === 'env-pw' && r3.source === 'SSH_REMOTE_PASSWORD', JSON.stringify(r3));

  const r4 = resolvePassword({ host: 'host-a', envPassword: null, passwordFile: path.join(dir, '缺.xlsx') });
  check('密码表：缺省文件不存在 → null 交给上层指路', r4.password === null && r4.source === null, JSON.stringify(r4));

  const bad = path.join(dir, 'bad.xlsx');
  fs.writeFileSync(bad, Buffer.from('这不是一个 xlsx 文件'));
  let threw = '';
  try { resolvePassword({ host: 'host-a', envPassword: null, passwordFile: bad }); } catch (e) { threw = e.message; }
  check('密码表：损坏文件抛错不静默', /解析失败/.test(threw), threw || '没抛错');

  fs.rmSync(dir, { recursive: true, force: true });
}

// 6. login shell 包装：buildRemoteCommand 组装 + 端到端（mock sshd 回显实际命令串）
{
  const { buildRemoteCommand } = await import('./ssh-session.js');
  const echoPort = await new Promise((res) => {
    startMockSshd({ acceptNone: true, echoCommand: true }).then((srv) => res(srv.address().port));
  });
  const s = new RemoteSession({ host: '127.0.0.1', port: echoPort, username: 'selftest', authMode: 'none', readyTimeout: 10000 });

  try {
    await s.ensure();

    // 单元：组装形状
    check('loginShell：默认关闭时不包装', buildRemoteCommand('echo hi') === 'echo hi', buildRemoteCommand('echo hi'));
    check('loginShell：只有 cwd 时仅前置 cd', buildRemoteCommand('echo hi', { cwd: '/w' }) === `cd '/w' && echo hi`, buildRemoteCommand('echo hi', { cwd: '/w' }));
    check('loginShell：开启时套 bash -lc', buildRemoteCommand('echo hi', { loginShell: true }) === `bash -lc 'echo hi'`, buildRemoteCommand('echo hi', { loginShell: true }));
    const { shellQuote } = await import('./ssh-session.js');
    check('loginShell：开启 + cwd 时 cd 在登录 shell 内', buildRemoteCommand('echo hi', { cwd: '/w', loginShell: true }) === `bash -lc ${shellQuote(`cd ${shellQuote('/w')} && echo hi`)}`, buildRemoteCommand('echo hi', { cwd: '/w', loginShell: true }));

    // 端到端：mock 收到的就是组装结果（验证 exec 选项真的传到了 conn.exec）
    const r1 = await s.exec('echo hi', { loginShell: true, cwd: '/w' });
    check('loginShell：端到端——sshd 收到 bash -lc 包装串', r1.stdout === buildRemoteCommand('echo hi', { loginShell: true, cwd: '/w' }), `got ${JSON.stringify(r1.stdout)}`);

    const r2 = await s.exec('echo hi');
    check('loginShell：端到端——不传选项则原样透传', r2.stdout === 'echo hi', `got ${JSON.stringify(r2.stdout)}`);

    // 引号安全：命令里带单引号不破坏包装（mock 回显 == 组装结果即未串行）
    const tricky = `echo 'it''s'`;
    const r3 = await s.exec(tricky, { loginShell: true });
    check('loginShell：命令含单引号仍完整包装', r3.stdout === buildRemoteCommand(tricky, { loginShell: true }), `got ${JSON.stringify(r3.stdout)}`);
  } catch (e) {
    check('loginShell：端到端验证', false, e.message);
  }
  s.close();
}

console.log(`\n结果：${passed} 通过 / ${failed} 失败`);
process.exit(failed === 0 ? 0 : 1);
