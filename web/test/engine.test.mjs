// The browser engine must answer like the Python engine. Expected values below were
// produced by running the Python engine on the same inputs.
import test from 'node:test';
import assert from 'node:assert/strict';
import { configMethods as m } from '../src/engine/config-methods.mjs';
import { makeMitmMethods } from '../src/engine/mitm-methods.mjs';
import { RpcError } from '../src/engine/rpc.mjs';

const U = '11111111-2222-3333-4444-555555555555';
const VLESS = `vless://${U}@cdn.example.com:443?encryption=none&security=tls&sni=cdn.example.com&fp=chrome&type=ws&host=cdn.example.com&path=%2Fchannel#CF%20worker`;
const SS_PLAIN = 'ss://aes-256-gcm:seekrit@198.51.100.7:8388#ss-plain';
const SS_B64 = 'ss://YWVzLTEyOC1nY206cHc@198.51.100.7:8388#ss-b64';
const TROJAN6 = 'trojan://pw@[2606:4700::1111]:8443?security=tls&type=grpc&serviceName=svc#v6';
const pick = (o, ...k) => Object.fromEntries(k.map((x) => [x, o[x]]));

test('parses the main link shapes', async () => {
  const v = (await m['config.parse']({ line: VLESS })).outbound;
  assert.deepEqual(pick(v, 'scheme', 'name', 'host', 'port', 'credential', 'transport', 'security', 'path'),
    { scheme: 'vless', name: 'CF worker', host: 'cdn.example.com', port: '443', credential: U, transport: 'ws', security: 'tls', path: '/channel' });
  const t = (await m['config.parse']({ line: TROJAN6 })).outbound;
  assert.deepEqual(pick(t, 'host', 'port', 'transport'), { host: '2606:4700::1111', port: '8443', transport: 'grpc' });
});

test('plain ss://method:password@host keeps both the method and the password', async () => {
  const plain = (await m['config.parse']({ line: SS_PLAIN })).outbound;
  assert.deepEqual(pick(plain, 'ss_method', 'credential', 'host', 'port'), { ss_method: 'aes-256-gcm', credential: 'seekrit', host: '198.51.100.7', port: '8388' });
  const b64 = (await m['config.parse']({ line: SS_B64 })).outbound;
  assert.deepEqual(pick(b64, 'ss_method', 'credential'), { ss_method: 'aes-128-gcm', credential: 'pw' });
  const re = await m['config.render']({ outbound: plain });
  assert.equal(re.uri, 'ss://YWVzLTI1Ni1nY206c2Vla3JpdA@198.51.100.7:8388#ss-plain');
  assert.ok(re.roundtrip_ok);
});

test('an out-of-range port still parses (validation happens elsewhere)', async () => {
  const r = await m['config.parse']({ line: `vless://${U}@h.example.com:99999#bad` });
  assert.equal(r.ok, true);
  assert.equal(r.outbound.port, '99999');
});

test('convert, dedup and override checks', async () => {
  const text = [VLESS, SS_PLAIN, TROJAN6, VLESS].join('\n');
  const c = await m['config.convert']({ text });
  assert.deepEqual(c.counts, { fixed: 4, unchanged: 0, skipped: 0 });
  assert.ok(c.lines[1].startsWith('ss://aes-256-gcm:seekrit@198.51.100.7:8388?fp=chrome&cs=TLS_AES_256_GCM_SHA384%3A'));
  assert.ok(c.lines[1].endsWith('#03_ip'));
  assert.equal((await m['config.dedup']({ lines: text.split('\n') })).removed, 1);
  assert.deepEqual(await m['config.check_override']({ ip: 'bad ip!', port: '70000' }), { ip: null, port: false });
});

test('clash export matches the Python output', async () => {
  const r = await m['config.export']({ lines: [VLESS, SS_PLAIN, TROJAN6], format: 'clash' });
  assert.equal(r.content, `proxies:
- name: CF worker
  type: vless
  server: cdn.example.com
  port: 443
  uuid: ${U}
  cipher: auto
  tls: true
  servername: cdn.example.com
  client-fingerprint: chrome
  skip-cert-verify: false
  network: ws
  ws-opts:
    path: /channel
    headers:
      Host: cdn.example.com
- name: ss-plain
  type: ss
  server: 198.51.100.7
  port: 8388
  cipher: aes-256-gcm
  password: seekrit
- name: v6
  type: trojan
  server: 2606:4700::1111
  port: 8443
  password: pw
  tls: true
  servername: 2606:4700::1111
  client-fingerprint: chrome
  skip-cert-verify: false
  network: grpc
  grpc-opts:
    grpc-service-name: svc
`);
});

test('bad requests fail with the same codes and messages', async () => {
  const fail = async (fn) => { try { await fn(); } catch (e) { assert.ok(e instanceof RpcError); return { code: e.code, message: e.message }; } assert.fail('expected an error'); };
  assert.deepEqual(await fail(() => m['config.parse']({})), { code: -32602, message: "missing a required argument: 'line'" });
  assert.deepEqual(await fail(() => m['config.parse']({ line: 'x', nope: 1 })), { code: -32602, message: 'unknown params: nope' });
  assert.deepEqual(await fail(() => m['config.export']({ lines: [], format: 'zip' })), { code: -32602, message: 'format must be one of: clash, singbox, sub' });
});

test('mitm builds a config and a guide', async () => {
  const mm = makeMitmMethods({});
  const g = await mm['mitm.groups']({});
  assert.ok(g.defaults.length > 0);
  const b = await mm['mitm.build']({ groups: g.defaults, use_generated_ca: false });
  assert.doesNotThrow(() => JSON.parse(b.content));
  assert.match((await mm['mitm.guide']({ platform: 'android' })).content, /Android/i);
});
