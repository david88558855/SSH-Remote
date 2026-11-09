/**
 * 认证方式自测：不需要真实远端机。
 *
 * 本脚本用 ssh2 自己的 Server 起一个 mock sshd（支持密码/公钥两种认证），
 * 再手写一个最小 OpenSSH-agent 协议的 unix socket 服务（identities + sign），
 * 然后逐项验证 RemoteSession 的四种认证路径：
 *
 *   1. password 模式（正确密码连上、错误密码被拒）
 *   2. key 模式
 *   3. agent 模式（免密：凭据由 agent 持有，本地不落私钥路径也能连）
 *   4. auto 模式（无任何凭据 → 报配置指引；有密码+私钥 → 全带上由服务端挑）
 *
 * 跑法：node auth-selftest.js（退出码非 0 即有失败）
 */

import crypto from 'node:crypto';
import net from 'node:net';
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
function startMockSshd() {
  return new Promise((resolve) => {
    const srv = new SshServer({ hostKeys: [{ key: hostKey.privPem }] });
    srv.on('error', (e) => console.error('[mock-sshd] error:', e));
    // ssh2 的标准用法：authentication / session / exec 全挂在连接对象上
    // （不注册 connection 监听器的话，握手完成即自动断开）
    srv.on('connection', (client) => {
      // 注意：ssh2 v1.17 的 auth ctx 字段是 method（不是老文档里的 type）
      client.on('authentication', (ctx) => {
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
          session.on('exec', (accept2) => {
            const stream = accept2();
            stream.stdout.write('mock-ssh-ok');
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

// ── 最小 OpenSSH-agent（SSH_AGENTC_REQUEST_IDENTITIES / SIGN_REQUEST） ──
const AGENT_FAILURE = 5;
const AGENT_IDENTITIES_ANSWER = 12;
const AGENT_SIGN_RESPONSE = 14;
const AGENTC_REQUEST_IDENTITIES = 11;
const AGENTC_SIGN_REQUEST = 13;

function startMockAgent() {
  return new Promise((resolve, reject) => {
    const sockPath = path.join(os.tmpdir(), `ssh-remote-selftest-agent-${process.pid}.sock`);
    try { fs.unlinkSync(sockPath); } catch { /* 不存在就算了 */ }

    const srv = net.createServer((sock) => {
      let buf = Buffer.alloc(0);
      sock.on('data', (d) => {
        buf = Buffer.concat([buf, d]);
        while (buf.length >= 4) {
          const len = buf.readUInt32BE(0);
          if (buf.length < 4 + len) break;
          const msg = buf.subarray(4, 4 + len);
          buf = buf.subarray(4 + len);
          handleMessage(msg, sock);
        }
      });
    });

    function handleMessage(msg, sock) {
      const type = msg[0];
      if (type === AGENTC_REQUEST_IDENTITIES) {
        // 响应结构：[12][uint32 nkeys][string keyblob][string comment]×n
        // comment 不能省——客户端按成对 string 解析，缺了会解析失败
        const comment = Buffer.from('selftest');
        const keyStr = Buffer.alloc(4 + userPubBlob.length);
        keyStr.writeUInt32BE(userPubBlob.length, 0);
        userPubBlob.copy(keyStr, 4);
        const comStr = Buffer.alloc(4 + comment.length);
        comStr.writeUInt32BE(comment.length, 0);
        comment.copy(comStr, 4);
        const body = Buffer.alloc(1 + 4);
        body[0] = AGENT_IDENTITIES_ANSWER;
        body.writeUInt32BE(1, 1);
        const reply = Buffer.concat([body, keyStr, comStr]);
        const out = Buffer.alloc(4 + reply.length);
        out.writeUInt32BE(reply.length, 0);
        reply.copy(out, 4);
        sock.write(out);
        return;
      }
      if (type === AGENTC_SIGN_REQUEST) {
        // msg: [13][4+n key blob][4+m data][4 flags]
        const klen = msg.readUInt32BE(1);
        const dlen = msg.readUInt32BE(5 + klen);
        const data = msg.subarray(9 + klen, 9 + klen + dlen);
        // ed25519：直接 crypto.sign，sig blob = string "ssh-ed25519" + string sig
        const sig = crypto.sign(null, data, userKey.privKeyObj);
        const algo = Buffer.from('ssh-ed25519');
        const s1 = Buffer.alloc(4 + algo.length); s1.writeUInt32BE(algo.length, 0); algo.copy(s1, 4);
        const s2 = Buffer.alloc(4 + sig.length); s2.writeUInt32BE(sig.length, 0); sig.copy(s2, 4);
        const sigBlob = Buffer.concat([s1, s2]);
        const body = Buffer.alloc(1 + 4 + sigBlob.length);
        body[0] = AGENT_SIGN_RESPONSE;
        body.writeUInt32BE(sigBlob.length, 1);
        sigBlob.copy(body, 5);
        const out = Buffer.alloc(4 + body.length);
        out.writeUInt32BE(body.length, 0);
        body.copy(out, 4);
        sock.write(out);
        return;
      }
      const body = Buffer.from([AGENT_FAILURE]);
      const out = Buffer.alloc(4 + 1);
      out.writeUInt32BE(1, 0);
      body.copy(out, 4);
      sock.write(out);
    }

    srv.on('error', reject);
    srv.listen(sockPath, () => resolve({ srv, sockPath }));
  });
}

// ── 测试 ────────────────────────────────────────────────────────────
const port = await new Promise((res) => {
  startMockSshd().then((srv) => res(srv.address().port));
});
const { srv: agentSrv, sockPath: agentSock } = await startMockAgent();

const base = {
  host: '127.0.0.1',
  port,
  username: 'selftest',
  readyTimeout: 10000,
};

console.log(`mock sshd=127.0.0.1:${port}  agent=${agentSock}`);

// 1. password 模式
{
  const s = new RemoteSession({ ...base, authMode: 'password', password: PASSWORD, agent: null });
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
  const s = new RemoteSession({ ...base, authMode: 'password', password: 'wrong', agent: null });
  try {
    await s.ensure();
    check('password 模式：错误密码被拒', false, '竟然连上了');
  } catch (e) {
    check('password 模式：错误密码被拒', /authentication/i.test(e.message), e.message);
  }
  s.close();
}
{
  const s = new RemoteSession({ ...base, authMode: 'password', agent: null });
  try {
    await s.ensure();
    check('password 模式：缺密码时给出配置指引', false, '竟然连上了');
  } catch (e) {
    check('password 模式：缺密码时给出配置指引', /SSH_REMOTE_PASSWORD/.test(e.message), e.message);
  }
  s.close();
}

// 2. key 模式
{
  const keyFile = path.join(os.tmpdir(), `ssh-remote-selftest-key-${process.pid}`);
  fs.writeFileSync(keyFile, userKey.privPem, { mode: 0o600 });
  const s = new RemoteSession({ ...base, authMode: 'key', keyPath: keyFile, agent: null });
  try {
    await s.ensure();
    check('key 模式：私钥连上', s.authMethod === 'key', `got ${s.authMethod}`);
  } catch (e) {
    check('key 模式：私钥连上', false, e.message);
  }
  s.close();
}
{
  const s = new RemoteSession({ ...base, authMode: 'key', keyPath: '/nonexistent/key', agent: null });
  try {
    await s.ensure();
    check('key 模式：私钥缺失时报错带指引', false, '竟然连上了');
  } catch (e) {
    check('key 模式：私钥缺失时报错带指引', /读私钥失败/.test(e.message) && /SSH_REMOTE_AUTH=password/.test(e.message), e.message);
  }
  s.close();
}

// 3. agent 模式（免密）
{
  const s = new RemoteSession({ ...base, authMode: 'agent', agent: agentSock, keyPath: '/nonexistent/key' });
  try {
    await s.ensure();
    check('agent 模式：免密连上（凭据由 agent 持有）', s.authMethod === 'agent', `got ${s.authMethod}`);
  } catch (e) {
    check('agent 模式：免密连上（凭据由 agent 持有）', false, e.message);
  }
  s.close();
}
{
  const s = new RemoteSession({ ...base, authMode: 'agent', agent: null, keyPath: '/nonexistent/key' });
  try {
    await s.ensure();
    check('agent 模式：无 agent 时报错带指引', false, '竟然连上了');
  } catch (e) {
    check('agent 模式：无 agent 时报错带指引', /SSH_AUTH_SOCK/.test(e.message), e.message);
  }
  s.close();
}

// 4. auto 模式
{
  const s = new RemoteSession({ ...base, authMode: 'auto', keyPath: '/nonexistent/key', agent: null });
  try {
    await s.ensure();
    check('auto 模式：零凭据时报配置指引', false, '竟然连上了');
  } catch (e) {
    check('auto 模式：零凭据时报配置指引', /SSH_REMOTE_PASSWORD/.test(e.message) && /ssh-agent/.test(e.message), e.message);
  }
  s.close();
}
{
  // auto + 只有密码：key 读不到不算错，走密码
  const s = new RemoteSession({ ...base, authMode: 'auto', password: PASSWORD, keyPath: '/nonexistent/key', agent: null });
  try {
    await s.ensure();
    check('auto 模式：只有密码时走密码', s.authMethod === 'password', `got ${s.authMethod}`);
  } catch (e) {
    check('auto 模式：只有密码时走密码', false, e.message);
  }
  s.close();
}
{
  // auto + 密码和私钥都有：全带上，服务端公钥先过
  const keyFile = path.join(os.tmpdir(), `ssh-remote-selftest-key2-${process.pid}`);
  fs.writeFileSync(keyFile, userKey.privPem, { mode: 0o600 });
  const s = new RemoteSession({ ...base, authMode: 'auto', password: PASSWORD, keyPath: keyFile, agent: null });
  try {
    await s.ensure();
    check('auto 模式：密码+私钥都带上', s.authMethod === 'key+password', `got ${s.authMethod}`);
  } catch (e) {
    check('auto 模式：密码+私钥都带上', false, e.message);
  }
  s.close();
}
{
  // auto + 错误密码 + 无 key：auth 全被拒的报错要带指引
  const s = new RemoteSession({ ...base, authMode: 'auto', password: 'wrong', keyPath: '/nonexistent/key', agent: null });
  try {
    await s.ensure();
    check('auto 模式：凭据全被拒时带指引', false, '竟然连上了');
  } catch (e) {
    check('auto 模式：凭据全被拒时带指引', /当前方式/.test(e.message) && /SSH_AUTH_SOCK|ssh-copy-id/.test(e.message), e.message);
  }
  s.close();
}

agentSrv.close();
console.log(`\n结果：${passed} 通过 / ${failed} 失败`);
process.exit(failed === 0 ? 0 : 1);
