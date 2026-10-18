'use strict';
// Unit tests that need neither Python nor a browser: a tiny fake engine
// (a node script speaking the same JSON-RPC lines) exercises EngineClient.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { EngineClient } = require('../engine-client');
const { resolveEngine } = require('../engine-path');

const FAKE = `
const rl = require('readline').createInterface({ input: process.stdin });
rl.on('line', (l) => {
  const m = JSON.parse(l);
  if (m.method === 'echo') process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: m.id, result: m.params }) + '\\n');
  else if (m.method === 'job') {
    process.stdout.write(JSON.stringify({ jsonrpc: '2.0', method: 'job.event', params: { job: 'j1', type: 'progress', done: 1, total: 2 } }) + '\\n');
    process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: m.id, result: { job: 'j1' } }) + '\\n');
  } else if (m.method === 'fail') process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: m.id, error: { code: -32602, message: 'nope' } }) + '\\n');
  else if (m.method === 'die') process.exit(7);
  else if (m.method === 'noise') { process.stdout.write('not json\\n'); process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: m.id, result: 1 }) + '\\n'); }
});
rl.on('close', () => process.exit(0));
`;

function fakeEngine() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'xf-fake-'));
  const file = path.join(dir, 'engine.js');
  fs.writeFileSync(file, FAKE);
  return new EngineClient({ command: process.execPath, args: [file] });
}

test('call resolves with the result and errors carry code and message', async () => {
  const e = fakeEngine();
  try {
    assert.deepEqual(await e.call('echo', { a: 1 }), { a: 1 });
    await assert.rejects(e.call('fail'), (err) => err.code === -32602 && err.message === 'nope');
  } finally { await e.stop(); }
});

test('job events are emitted and bad lines are reported, not fatal', async () => {
  const e = fakeEngine();
  const events = []; const noise = [];
  e.on('job', (ev) => events.push(ev));
  e.on('stderr', (l) => noise.push(l));
  try {
    assert.deepEqual(await e.call('job'), { job: 'j1' });
    assert.equal(events[0].type, 'progress');
    assert.equal(await e.call('noise'), 1);
    assert.ok(noise.some((l) => /bad engine line/.test(l)));
  } finally { await e.stop(); }
});

test('pending calls reject when the engine dies', async () => {
  const e = fakeEngine();
  await assert.rejects(e.call('die'), /engine exited \(7\)/);
  await e.stop();
});

test('calls time out instead of hanging', async () => {
  const e = fakeEngine();
  try { await assert.rejects(e.call('never-answered', {}, 150), /timed out/); } finally { await e.stop(); }
});

test('stop() ends the engine by closing stdin', async () => {
  const e = fakeEngine();
  await e.call('echo', {});
  const exited = new Promise((r) => e.on('exit', (code) => r(code)));
  await e.stop();
  assert.equal(await exited, 0);
});

test('resolveEngine: env override > bundled > python', () => {
  const root = '/repo';
  assert.deepEqual(
    resolveEngine({ repoRoot: root, env: { XRAY_FORGE_ENGINE: '/x/engine' }, platform: 'linux' }),
    { kind: 'env', command: '/x/engine', args: ['serve'], cwd: undefined });

  const bundled = resolveEngine({ resourcesPath: '/res', repoRoot: root, env: {}, platform: 'linux', exists: () => true });
  assert.equal(bundled.kind, 'bundled');
  assert.equal(bundled.command, path.join('/res', 'engine', 'xray-forge-engine'));

  const win = resolveEngine({ resourcesPath: 'C:\\res', repoRoot: root, env: {}, platform: 'win32', exists: () => true });
  assert.match(win.command, /xray-forge-engine\.exe$/);

  const missing = resolveEngine({ resourcesPath: '/res', repoRoot: root, env: {}, platform: 'linux', exists: () => false });
  assert.equal(missing.kind, 'python');
  assert.deepEqual(missing.args, ['-m', 'xray_forge', 'serve']);
  assert.equal(missing.cwd, root);
  assert.equal(missing.command, 'python3');
  assert.equal(resolveEngine({ repoRoot: root, env: { XRAY_FORGE_PYTHON: 'py' }, platform: 'linux' }).command, 'py');
  assert.equal(resolveEngine({ repoRoot: root, env: {}, platform: 'win32' }).command, 'python');
});
