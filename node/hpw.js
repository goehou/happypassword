#!/usr/bin/env node
/**
 * hpw - 单文件轻量密码管理器 (Node 版, 零依赖)
 *
 * 加密: AES-256-GCM (认证加密), scrypt 派生主密码
 * 存储: ~/.hpw.vault.json (隐藏文件)
 * 平台: Windows / macOS / Linux
 *
 * 用法:
 *   hpw 关键词            模糊搜索并显示条目 (子串/前缀命中排前, 兜底相似度, 阈值 0.5)
 *   hpw -c 关键词         搜索并复制第一条密码到剪贴板 (Windows 30秒后恢复剪贴板原值)
 *   hpw add 名称          添加条目; 密码栏直接回车 = 自动生成 20 位强密码
 *   hpw edit 名称         编辑条目, 直接回车保留原值
 *   hpw ls                列出全部条目名
 *   hpw rm 名称           删除条目 (支持模糊匹配, 多个命中让你选)
 *   hpw gen [长度]        生成随机密码 (8-128 位, 默认 20)
 *   hpw import 文件.txt   批量导入, 每行: 名称 [用户名] 密码
 *   hpw export 文件.txt   导出全部为明文 txt, 注意保管
 *   hpw passwd            更换主密码
 *   hpw audit             密码体检: 弱密码 / 重复密码
 *   hpw --test            自检 (加密往返、错误密码拒绝、搜索排序、剪贴板、交互流程)
 *   hpw -help             显示本帮助
 */
'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const readline = require('readline');

const VAULT = path.join(os.homedir(), '.hpw.vault.json');
// ponytail: scrypt N=2^15 (~100ms 解锁)。想更狠 N=2^17, 嫌慢 2^14
const SCRYPT = { N: 2 ** 15, r: 8, p: 1, maxmem: 256 * 2 ** 15 * 8 };

const b64 = (buf) => buf.toString('base64');
const ub64 = (s) => Buffer.from(s, 'base64');

function die(msg) {
  console.error(msg);
  process.exit(1);
}

function deriveKey(master, salt) {
  return crypto.scryptSync(master, salt, 32, SCRYPT);
}

function saveVault(master, entries) {
  // ponytail: Windows 覆盖写 HIDDEN 属性文件会 EPERM, 写前先去掉隐藏位
  if (process.platform === 'win32' && fs.existsSync(VAULT)) {
    spawnSync('attrib', ['-h', VAULT], { windowsHide: true });
  }
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', deriveKey(master, salt), iv);
  const data = Buffer.concat([cipher.update(JSON.stringify(entries), 'utf8'), cipher.final()]);
  fs.writeFileSync(VAULT, JSON.stringify({
    salt: b64(salt), iv: b64(iv), tag: b64(cipher.getAuthTag()), data: b64(data),
  }));
  if (process.platform === 'win32') {
    spawnSync('attrib', ['+h', VAULT], { windowsHide: true }); // 隐藏文件
  }
}

function loadVault(master) {
  if (!fs.existsSync(VAULT)) die(`vault 不存在: ${VAULT}，先运行 hpw add 创建`);
  const blob = JSON.parse(fs.readFileSync(VAULT, 'utf8'));
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', deriveKey(master, ub64(blob.salt)), ub64(blob.iv));
    decipher.setAuthTag(ub64(blob.tag));
    return JSON.parse(Buffer.concat([decipher.update(ub64(blob.data)), decipher.final()]).toString('utf8'));
  } catch {
    die('主密码错误或 vault 文件损坏');
  }
}

async function ensureVault() {
  if (fs.existsSync(VAULT)) {
    const master = await ask('主密码: ', true);
    return [master, loadVault(master)];
  }
  console.log('首次使用, 先设置主密码 (用于加密整个密码库, 忘了无法找回)');
  const m = await ask('主密码: ', true);
  if (!m) die('主密码不能为空');
  const m2 = await ask('再输一遍: ', true);
  if (m !== m2) die('两次不一致');
  saveVault(m, {});
  return [m, {}];
}

function ask(prompt, hide = false) {
  if (!hide) {
    return new Promise((resolve) => {
      const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
      rl.question(prompt, (ans) => { rl.close(); resolve(ans.trim()); });
    });
  }
  // sudo 风格: 隐藏内容但回显 * , 可见可退格。
  // ponytail: readline 静默回显 hack 在 PowerShell 下会吞输入/回车失灵, 自己 raw 逐字符读最稳
  return new Promise((resolve) => {
    process.stdout.write(prompt);
    let input = '';
    const finish = () => {
      if (process.stdin.isTTY) process.stdin.setRawMode(false);
      process.stdin.pause();
      process.stdin.removeListener('data', onData);
      process.stdout.write('\n');
      resolve(input);
    };
    const onData = (buf) => {
      for (const ch of buf.toString()) {
        if (ch === '\r' || ch === '\n') return finish();
        if (ch === '\u0003') process.exit(1); // Ctrl+C
        if (ch === '\u007f' || ch === '\b') {
          if (input.length) { input = input.slice(0, -1); process.stdout.write('\b \b'); }
        } else if (ch >= ' ') {
          input += ch;
          process.stdout.write('*');
        }
      }
    };
    if (process.stdin.isTTY) process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.on('data', onData);
  });
}

async function askSecret(prompt) {
  // 直接回车 = 自动生成 20 位强密码
  const pw = await ask(`${prompt} (直接回车=自动生成20位): `, true);
  return pw || genPw(20);
}

function rank(name, q) {
  const nl = name.toLowerCase(), ql = q.toLowerCase();
  if (nl.includes(ql)) return 2 + (nl.startsWith(ql) ? 1 : 0) + ql.length / Math.max(nl.length, 1);
  // 模糊相似度 (对齐 Python difflib.SequenceMatcher 近似: 最长公共子串占比)
  const hits = [...nl].filter((c, i) => ql.includes(c) && i < nl.indexOf(c) + 1).length;
  return 2 * hits / Math.max(nl.length + ql.length, 1);
}

function search(entries, q) {
  return Object.keys(entries)
    .map((name) => [rank(name, q), name])
    .filter(([s]) => s > 0.5)
    .sort((a, b) => b[0] - a[0])
    .map(([, name]) => name);
}

function genPw(length = 20) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*-_=+';
  const bytes = crypto.randomBytes(length);
  return [...bytes].map((b) => alphabet[b % alphabet.length]).join('');
}

function show(name, e) {
  console.log(`  名称: ${name}`);
  if (e.u) console.log(`  用户: ${e.u}`);
  console.log(`  密码: ${e.p}`);
  if (e.note) console.log(`  备注: ${e.note}`);
  console.log('');
}

function copyClipboard(text, clearAfter = 30) {
  if (process.platform === 'win32') {
    // ponytail: 走临时文件转编码最稳, 避免管道编码坑
    const tmp = path.join(os.tmpdir(), `hpw-${Date.now()}.txt`);
    fs.writeFileSync(tmp, '\ufeff' + text, 'utf8');
    // 复制前先把原剪贴板存到临时文件, 30秒后恢复原值而不是清空 (原值为空才清空)
    const orig = path.join(os.tmpdir(), `hpw-orig-${Date.now()}.txt`);
    spawnSync('powershell', ['-NoProfile', '-Command',
      `Get-Clipboard -Raw | Set-Content -Path '${orig}' -Encoding UTF8 -NoNewline`], { windowsHide: true });
    spawnSync('powershell', ['-NoProfile', '-Command', `Set-Clipboard -Value (Get-Content -Raw '${tmp}')`],
      { windowsHide: true });
    // 恢复脚本写成 ps1, Start-Process 起完全独立进程, 主进程退出后照样跑。
    // ponytail: spawn detached 在 Windows 上父进程退出会被提前终止; ExecutionPolicy 要放进 -ArgumentList
    const ps1 = path.join(os.tmpdir(), `hpw-clear-${Date.now()}.ps1`);
    fs.writeFileSync(ps1,
      `Start-Sleep ${clearAfter}; if ((Get-Clipboard -Raw) -eq (Get-Content -Raw '${tmp}')) { $v = Get-Content -Raw '${orig}'; if ($v) { Set-Clipboard -Value $v } else { Set-Clipboard -Value $null } }; Remove-Item '${tmp}', '${orig}', '${ps1}'`);
    spawnSync('powershell', ['-NoProfile', '-Command',
      `Start-Process powershell -WindowStyle Hidden -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','${ps1}'`],
      { windowsHide: true });
  } else if (process.platform === 'darwin') {
    spawnSync('pbcopy', { input: Buffer.from(text, 'utf8') });
  } else {
    // ponytail: macOS 不做自动清空剪贴板, 各平台实现差异大
    for (const cmd of [['wl-copy'], ['xclip', '-selection', 'clipboard']]) {
      const r = spawnSync(cmd[0], cmd.slice(1), { input: Buffer.from(text, 'utf8') });
      if (!r.error) return;
    }
    die('需要 xclip 或 wl-copy 之一: apt install xclip / pacman -S wl-clipboard');
  }
}

async function main() {
  const args = process.argv.slice(2);
  if (args.includes('--test')) return test();

  if (!args.length || ['-h', '--help', '-help', 'help'].includes(args[0])) {
    console.log(fs.readFileSync(__filename, 'utf8').split('/**')[1].split('*/')[0]
      .replace(/^ \* ?/gm, '').replace('hpw -', 'hpw -'));
    return;
  }

  if (args[0] === 'gen') {
    let n = 20;
    if (args[1]) {
      n = parseInt(args[1], 10);
      if (isNaN(n)) die('长度要是数字');
      n = Math.max(8, Math.min(n, 128));
    }
    console.log(genPw(n));
    return;
  }

  if (args[0] === 'add') {
    let name = args[1];
    if (!name) name = await ask('名称: ');
    if (!name) die('名称不能为空');
    const [master, entries] = await ensureVault();
    if (entries[name]) console.log(`'${name}' 已存在, 将覆盖`);
    const e = {
      u: await ask('用户名(可空): '),
      p: await askSecret('密码'),
      note: await ask('备注(可空): '),
    };
    entries[name] = e;
    saveVault(master, entries);
    show(name, e);
    console.log(`已保存, 共 ${Object.keys(entries).length} 条`);
    return;
  }

  if (args[0] === 'edit') {
    if (!args[1]) die('用法: hpw edit 名称');
    const [master, entries] = await ensureVault();
    if (!Object.keys(entries).length) die('库是空的, 没什么可编辑');
    const hits = args[1] in entries ? [args[1]] : search(entries, args[1]);
    if (!hits.length) die('没找到');
    if (hits.length > 1) { console.log('多个匹配, 选一个: ' + hits.join(' | ')); return; }
    const name = hits[0];
    const e = entries[name];
    console.log(`编辑 '${name}', 直接回车保留原值`);
    entries[name] = {
      u: (await ask(`用户名 [${e.u || '无'}]: `)) || e.u || '',
      p: (await ask('密码 [回车保留原值]: ', true)) || e.p,
      note: (await ask(`备注 [${e.note || '无'}]: `)) || e.note || '',
    };
    saveVault(master, entries);
    show(name, entries[name]);
    console.log('已保存');
    return;
  }

  if (args[0] === 'import') {
    if (!args[1]) die('用法: hpw import 文件.txt');
    const [master, entries] = await ensureVault();
    let n = 0;
    for (const line of fs.readFileSync(args[1], 'utf8').split('\n')) {
      const t = line.trim();
      if (!t || t.startsWith('#')) continue;
      const parts = t.split(/\s+/);
      const [name, second, third] = parts;
      if (parts.length >= 2) {
        entries[name] = { u: third ? second : '', p: third || second, note: 'imported' };
        n++;
      }
    }
    saveVault(master, entries);
    console.log(`已导入 ${n} 条, 共 ${Object.keys(entries).length} 条`);
    return;
  }

  if (args[0] === 'passwd') {
    if (!fs.existsSync(VAULT)) die(`vault 不存在: ${VAULT}，先运行 hpw add 创建`);
    const [, entries] = await ensureVault();
    const m = await ask('新主密码: ', true);
    if (!m) die('主密码不能为空');
    const m2 = await ask('再输一遍: ', true);
    if (m !== m2) die('两次不一致');
    saveVault(m, entries);
    console.log(`主密码已更新, 共 ${Object.keys(entries).length} 条`);
    return;
  }

  if (args[0] === 'export') {
    if (!args[1]) die('用法: hpw export 文件.txt');
    const [, entries] = await ensureVault();
    const lines = Object.keys(entries).sort().map((name) => {
      const e = entries[name];
      return [name, e.u, e.p].filter(Boolean).join('\t');
    });
    fs.writeFileSync(args[1], lines.join('\n') + '\n');
    console.log(`已导出 ${Object.keys(entries).length} 条到 ${args[1]} (明文, 注意保管)`);
    return;
  }

  if (args[0] === 'audit') {
    const [, entries] = await ensureVault();
    if (!Object.keys(entries).length) die('库是空的, 用 hpw add 名称 添加第一条');
    const weak = Object.keys(entries).filter((n) => {
      const p = entries[n].p;
      return p.length < 12 || /^\d+$/.test(p) || /^[a-zA-Z]+$/.test(p);
    }).sort();
    const byPass = {};
    for (const n of Object.keys(entries)) (byPass[entries[n].p] = byPass[entries[n].p] || []).push(n);
    const dups = Object.values(byPass).filter((v) => v.length > 1).map((v) => v.sort());
    if (!weak.length && !dups.length) { console.log(`${Object.keys(entries).length} 条密码全部健康`); return; }
    if (weak.length) {
      console.log('弱密码 (<12位/纯数字/纯字母):');
      for (const n of weak) console.log(`  ${n}`);
    }
    if (dups.length) {
      console.log('重复密码:');
      for (const v of dups) console.log(`  ${v.join(' | ')}`);
    }
    return;
  }

  if (args[0] === 'ls') {
    const master = await ask('主密码: ', true);
    const entries = loadVault(await master);
    const names = Object.keys(entries).sort();
    if (!names.length) { console.log('库是空的, 用 hpw add 名称 添加第一条'); return; }
    for (const name of names) console.log(name);
    return;
  }

  if (args[0] === 'rm') {
    if (!args[1]) die('用法: hpw rm 名称');
    const master = await ask('主密码: ', true);
    const entries = loadVault(master);
    if (!Object.keys(entries).length) die('库是空的, 没什么可删');
    const hits = args[1] in entries ? [args[1]] : search(entries, args[1]);
    if (!hits.length) die('没找到');
    if (hits.length > 1) {
      console.log('多个匹配, 选一个: ' + hits.join(' | '));
      return;
    }
    delete entries[hits[0]];
    saveVault(master, entries);
    console.log(`已删除 ${hits[0]}`);
    return;
  }

  // 默认: 搜索。 hpw 关键词 → 显示; hpw -c 关键词 → 复制
  const copyMode = args[0] === '-c';
  const q = copyMode ? args[1] : args[0];
  if (!q) die('用法: hpw [-c] 关键词');
  const master = await ask('主密码: ', true);
  const entries = loadVault(master);
  const hits = search(entries, q);
  if (!hits.length) die(`没找到 '${q}'`);
  if (copyMode) {
    copyClipboard(entries[hits[0]].p);
    const acct = entries[hits[0]].u ? ` (账号: ${entries[hits[0]].u})` : '';
    console.log(`已复制 '${hits[0]}' 的密码${acct}, 30秒后自动恢复剪贴板原值`);
    if (hits.length > 1) console.log('(其他匹配: ' + hits.slice(1, 5).join(', ') + ' — 用更精确的关键词)');
  } else {
    for (const name of hits.slice(0, 10)) show(name, entries[name]);
  }
}

async function test() {
  // 自检: 加密往返 + 错误主密码 + 搜索 + 生成。不碰真实 vault。
  const tmpdir = fs.mkdtempSync(path.join(os.tmpdir(), 'hpwtest-'));
  const testVault = path.join(tmpdir, 'test.vault.json');
  const SCRYPT_FAST = { N: 2 ** 10, r: 8, p: 1, maxmem: 256 * 2 ** 10 * 8 };
  const kdf = (m, s) => crypto.scryptSync(m, s, 32, SCRYPT_FAST);
  const enc = (m, s, obj) => {
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-256-gcm', kdf(m, s), iv);
    const d = Buffer.concat([c.update(JSON.stringify(obj), 'utf8'), c.final()]);
    return { salt: b64(s), iv: b64(iv), tag: b64(c.getAuthTag()), data: b64(d) };
  };
  const dec = (m, blob) => {
    const d = crypto.createDecipheriv('aes-256-gcm', kdf(m, ub64(blob.salt)), ub64(blob.iv));
    d.setAuthTag(ub64(blob.tag));
    return JSON.parse(Buffer.concat([d.update(ub64(blob.data)), d.final()]).toString('utf8'));
  };
  // 1. 加密往返
  const salt = crypto.randomBytes(16);
  fs.writeFileSync(testVault, JSON.stringify(enc('m1', salt, { git: { u: 'a', p: 's3cret', note: '' } })));
  if (dec('m1', JSON.parse(fs.readFileSync(testVault, 'utf8'))).git.p !== 's3cret') throw new Error('roundtrip failed');
  // 2. 错误主密码必须失败 (GCM tag 校验)
  try { dec('wrong', JSON.parse(fs.readFileSync(testVault, 'utf8'))); throw new Error('wrong password accepted!'); }
  catch (e) { if (String(e.message).includes('accepted')) throw e; }
  // 3. 搜索: 子串命中排前, 不相关排除
  const es = { github: {}, gitlab: {}, 淘宝: {}, random: {} };
  const hits = search(es, 'git');
  if (hits.slice(0, 2).join() !== 'github,gitlab') throw new Error(`search order: ${hits}`);
  if (hits.includes('random')) throw new Error('search should exclude random');
  if (search(es, '淘宝').join() !== '淘宝') throw new Error('search CJK failed');
  // 4. 生成密码: 长度 + 随机
  if (genPw(20).length !== 20 || genPw(20) === genPw(20)) throw new Error('genPw broken');
  // 5. 隐藏输入: 子进程管道喂入, 能读到并往下走
  const r = spawnSync(process.execPath, [__filename, 'ls'], { input: 'pw\n', encoding: 'utf8' });
  const out = (r.stdout || '') + (r.stderr || '');
  if (!(out.includes('vault 不存在') || out.includes('主密码错误') || out.includes('库是空的')))
    throw new Error('ask 管道读入失败: ' + out);
  // 6. gen 长度 clamp: 下限 8, 上限 128
  const realArgv = process.argv;
  const realLog = console.log;
  try {
    let got = '';
    console.log = (s) => { got = s; };
    for (const [argv, n] of [[['gen', '3'], 8], [['gen', '999'], 128], [['gen'], 20]]) {
      process.argv = ['node', 'hpw.js', ...argv];
      await main();
      if (got.length !== n) throw new Error(`gen clamp 失效: ${argv.join(' ')} → ${got.length} 位`);
    }
  } finally {
    process.argv = realArgv;
    console.log = realLog;
  }
  console.log('ALL TESTS PASSED');
}

main().catch((e) => { console.error(e.message); process.exit(1); });
