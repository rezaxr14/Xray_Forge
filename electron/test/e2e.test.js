'use strict';
// End-to-end: real renderer in Chromium (Playwright) <-> real Python engine
// through the same EngineClient the Electron main process uses.  Only the
// ~40-line Electron main/preload glue is replaced by a Playwright binding.
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { EngineClient } = require('../engine-client');

let playwright = null;
for (const id of ['playwright', 'playwright-core', '/opt/npm-tools/node_modules/playwright']) {
  try { playwright = require(id); break; } catch { /* try next */ }
}

const repoRoot = path.resolve(__dirname, '..', '..');
const rendererDir = path.resolve(__dirname, '..', 'renderer');
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css' };

const VLESS = 'vless://13b8ac3f-e8de-4b2d-82db-e9130d288a54@188.114.97.6:443?security=tls&sni=x.example.com&fp=chrome&type=ws&host=x.example.com&path=%2Fws#first';
const DEAD = 'vless://13b8ac3f-e8de-4b2d-82db-e9130d288a54@127.0.0.1:9?security=tls&sni=x.example.com&type=ws&host=x.example.com&path=%2F#dead';

function staticServer() {
  return new Promise((resolve) => {
    const srv = http.createServer((req, res) => {
      const rel = req.url === '/' ? '/index.html' : req.url.split('?')[0];
      const file = path.join(rendererDir, path.normalize(rel));
      if (!file.startsWith(rendererDir) || !fs.existsSync(file)) { res.writeHead(404).end(); return; }
      res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
      fs.createReadStream(file).pipe(res);
    }).listen(0, '127.0.0.1', () => resolve(srv));
  });
}

async function launch() {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'xf-home-'));
  const engine = new EngineClient({ cwd: repoRoot, env: { HOME: home, USERPROFILE: home } });
  engine.start();
  const srv = await staticServer();
  const browser = await playwright.chromium.launch();
  const page = await browser.newPage();
  const problems = [];
  page.on('pageerror', (e) => problems.push(`pageerror: ${e.message}`));
  page.on('console', (m) => { if (m.type() === 'error') problems.push(`console: ${m.text()}`); });
  await page.exposeFunction('__forgeCall', (m, p) => engine.call(m, p));
  engine.on('job', (ev) => page.evaluate((e) => window.__forgeJob(e), ev).catch(() => {}));
  await page.addInitScript(() => {
    const subs = [];
    window.__forgeJob = (ev) => subs.forEach((f) => f(ev));
    window.forge = {
      call: (m, p) => window.__forgeCall(m, p),
      onJob: (cb) => { subs.push(cb); return () => subs.splice(subs.indexOf(cb), 1); },
    };
  });
  await page.goto(`http://127.0.0.1:${srv.address().port}/`);
  const close = async () => { await browser.close(); srv.close(); await engine.stop(); };
  return { page, problems, close, engine };
}

const opts = { skip: playwright ? false : 'playwright not installed' };

test('boots, talks to the engine, no console errors', opts, async () => {
  const { page, problems, close } = await launch();
  try {
    await page.waitForFunction(() => /engine v\d/.test(document.querySelector('#engine-status').textContent));
    assert.match(await page.textContent('#engine-status'), /engine v2\.\d+\.\d+ · 3 cores/);
    assert.deepEqual(problems, []);
  } finally { await close(); }
});

test('parse, flag bad lines, edit and re-render a config', opts, async () => {
  const { page, problems, close } = await launch();
  try {
    await page.fill('#cfg-input', `${VLESS}\nnot a link`);
    await page.click('#cfg-parse');
    await page.waitForSelector('#cfg-table tbody tr:nth-child(2)');
    assert.equal(await page.locator('#cfg-table tbody tr').count(), 2);
    assert.match(await page.textContent('#cfg-table tbody tr:nth-child(1)'), /first.*vless.*188\.114\.97\.6:443.*ws/);
    assert.match(await page.textContent('#cfg-table tbody tr:nth-child(2)'), /unparsable/);
    assert.equal(await page.textContent('#cfg-count'), '1 valid / 2 total');

    await page.click('#cfg-table tbody tr:nth-child(1)');
    await page.waitForSelector('#editor:not([hidden])');
    await page.fill('#ed-form [name=name]', 'renamed');
    await page.fill('#ed-form [name=port]', '8443');
    await page.click('#ed-apply');
    await page.waitForFunction(() => document.querySelector('#ed-msg').textContent === 'Applied');
    const uri = await page.inputValue('#ed-uri');
    assert.match(uri, /^vless:\/\/.*@188\.114\.97\.6:8443\?/);
    assert.match(uri, /#renamed$/);
    assert.match(await page.textContent('#cfg-table tbody tr:nth-child(1)'), /renamed.*8443/);
    assert.deepEqual(problems, []);
  } finally { await close(); }
});

test('export produces a Clash document', opts, async () => {
  const { page, close } = await launch();
  try {
    await page.fill('#cfg-input', VLESS);
    await page.click('#cfg-parse');
    await page.waitForSelector('#cfg-table tbody tr');
    await page.selectOption('#export-format', 'clash');
    await page.click('#export-run');
    await page.waitForFunction(() => document.querySelector('#export-out').value.length > 0);
    assert.match(await page.inputValue('#export-out'), /proxies:/);
  } finally { await close(); }
});

test('convert tab removes duplicates and sends results to Configs', opts, async () => {
  const { page, close } = await launch();
  try {
    await page.click('[data-tab=convert]');
    await page.fill('#cv-input', `${VLESS}\n${VLESS}`);
    await page.click('#cv-run');
    await page.waitForFunction(() => /duplicates removed/.test(document.querySelector('#cv-msg').textContent));
    assert.match(await page.textContent('#cv-msg'), /1 duplicates removed/);
    assert.equal((await page.inputValue('#cv-output')).split('\n').length, 1);
    await page.click('#cv-send');
    await page.waitForSelector('#cfg-table tbody tr');
    assert.equal(await page.locator('#cfg-table tbody tr').count(), 1);
    assert.equal(await page.getAttribute('[data-tab=configs]', 'aria-selected'), 'true');
  } finally { await close(); }
});

test('health check streams results for an unreachable server', opts, async () => {
  const { page, problems, close } = await launch();
  try {
    await page.fill('#cfg-input', DEAD);
    await page.click('#cfg-parse');
    await page.waitForSelector('#cfg-table tbody tr');
    await page.click('[data-tab=health]');
    await page.fill('#hc-timeout', '1');
    await page.uncheck('#hc-throughput');
    await page.click('#hc-start');
    await page.waitForFunction(() => /^done/.test(document.querySelector('#hc-status').textContent), null, { timeout: 30000 });
    assert.match(await page.textContent('#hc-status'), /done: 0 of 1 passed/);
    const row = page.locator('#hc-table tbody tr').first();
    assert.match(await row.textContent(), /dead/);
    assert.ok(await row.locator('.chip.fail').count() >= 1);
    assert.equal(await page.isDisabled('#hc-start'), false);
    assert.equal(await page.isDisabled('#hc-keep'), true);
    assert.deepEqual(problems, []);
  } finally { await close(); }
});

test('health check without configs explains itself', opts, async () => {
  const { page, close } = await launch();
  try {
    await page.click('[data-tab=health]');
    await page.click('#hc-start');
    assert.match(await page.textContent('#hc-status'), /parse some in the Configs tab/);
  } finally { await close(); }
});

test('subscriptions: validate, add, toggle, remove', opts, async () => {
  const { page, close } = await launch();
  try {
    await page.click('[data-tab=subs]');
    await page.fill('#sub-url', 'file:///etc/passwd');
    await page.click('#sub-add');
    await page.waitForFunction(() => /http/.test(document.querySelector('#sub-msg').textContent));
    assert.equal(await page.locator('#sub-table tbody tr').count(), 0);

    await page.fill('#sub-url', 'https://example.com/sub');
    await page.fill('#sub-name', 'example');
    await page.click('#sub-add');
    await page.waitForSelector('#sub-table tbody tr');
    assert.match(await page.textContent('#sub-table tbody tr'), /example.*https:\/\/example\.com\/sub/);
    await page.uncheck('#sub-table tbody tr input[type=checkbox]');
    await page.click('[data-tab=configs]');
    await page.click('[data-tab=subs]');
    await page.waitForSelector('#sub-table tbody tr');
    assert.equal(await page.isChecked('#sub-table tbody tr input[type=checkbox]'), false);
    await page.click('.sub-remove');
    await page.waitForFunction(() => document.querySelectorAll('#sub-table tbody tr').length === 0);
  } finally { await close(); }
});

test('untrusted text is rendered as text, never as markup', opts, async () => {
  const { page, problems, close } = await launch();
  try {
    const evil = 'vless://13b8ac3f-e8de-4b2d-82db-e9130d288a54@188.114.97.6:443?security=tls&type=ws#<img src=x onerror=window.__pwned=1>';
    await page.fill('#cfg-input', evil);
    await page.click('#cfg-parse');
    await page.waitForSelector('#cfg-table tbody tr');
    assert.equal(await page.evaluate(() => window.__pwned), undefined);
    assert.equal(await page.locator('#cfg-table img').count(), 0);
    assert.deepEqual(problems.filter((p) => !/x:|Failed to load/.test(p)), []);
  } finally { await close(); }
});

// ---------------------------------------------------------------- step 3
test('IP scanner streams an unreachable host, saves the session, exports CSV', opts, async () => {
  const { page, problems, close } = await launch();
  try {
    await page.click('[data-tab=scan]');
    await page.fill('#sc-cidrs', '127.0.0.1/32');
    await page.fill('#sc-port', '9');
    await page.check('#sc-dead');
    await page.click('#sc-start');
    await page.waitForFunction(() => /^done/.test(document.querySelector('#sc-status').textContent), null, { timeout: 30000 });
    assert.match(await page.textContent('#sc-status'), /done: 0 alive of 1 checked/);
    assert.match(await page.textContent('#sc-table tbody tr'), /127\.0\.0\.1.*tcp filtered/);
    await page.waitForFunction(() => document.querySelectorAll('#sc-sessions option').length === 2);
    await page.selectOption('#sc-sessions', { index: 1 });
    await page.click('#sc-load');
    await page.waitForFunction(() => /^loaded/.test(document.querySelector('#sc-status').textContent));
    await page.click('#sc-export');
    await page.waitForFunction(() => document.querySelector('#sc-out').value.length > 0);
    assert.match(await page.inputValue('#sc-out'), /^ip,port,alive/);
    await page.uncheck('#sc-dead');
    assert.equal(await page.locator('#sc-table tbody tr').count(), 0);
    assert.deepEqual(problems, []);
  } finally { await close(); }
});

test('IP scanner rejects bad input with a readable message', opts, async () => {
  const { page, close } = await launch();
  try {
    await page.click('[data-tab=scan]');
    await page.click('#sc-start');
    await page.waitForFunction(() => /cidrs/.test(document.querySelector('#sc-status').textContent));
    await page.fill('#sc-cidrs', '10.0.0.0/30');
    await page.fill('#sc-port', '70000');
    await page.click('#sc-start');
    await page.waitForFunction(() => /port/.test(document.querySelector('#sc-status').textContent));
    assert.equal(await page.isDisabled('#sc-start'), false);
  } finally { await close(); }
});

test('SNI search probes pairs and reports none working on a closed port', opts, async () => {
  const { page, problems, close } = await launch();
  try {
    await page.click('[data-tab=sni]');
    await page.fill('#sn-ips', '127.0.0.1');
    await page.fill('#sn-snis', 'a.example, b.example');
    await page.fill('#sn-port', '9');
    await page.click('#sn-start');
    await page.waitForFunction(() => /^done/.test(document.querySelector('#sn-status').textContent), null, { timeout: 30000 });
    assert.match(await page.textContent('#sn-status'), /done: 0 working of 2/);
    await page.click('#sn-export');
    await page.waitForFunction(() => document.querySelector('#sn-out').value.length > 0);
    assert.match(await page.inputValue('#sn-out'), /^ip,port,sni/);
    assert.deepEqual(problems, []);
  } finally { await close(); }
});

test('scanner results hand alive IPs to the SNI tab', opts, async () => {
  const { page, close } = await launch();
  try {
    await page.click('[data-tab=scan]');
    await page.click('#sc-to-sni');
    assert.equal(await page.getAttribute('[data-tab=sni]', 'aria-selected'), 'true');
    assert.equal(await page.inputValue('#sn-ips'), '');
  } finally { await close(); }
});

test('WARP tab reports no device and explains a config request', opts, async () => {
  const { page, close } = await launch();
  try {
    await page.click('[data-tab=warp]');
    await page.waitForFunction(() => /no WARP device registered/.test(document.querySelector('#wp-status').textContent));
    await page.click('#wp-config');
    await page.waitForFunction(() => /register first/.test(document.querySelector('#wp-status').textContent));
    assert.equal(await page.inputValue('#wp-out'), '');
  } finally { await close(); }
});

test('MITM tab builds a config, shows the guide and generates a constrained CA', opts, async () => {
  const { page, problems, close } = await launch();
  try {
    await page.click('[data-tab=mitm]');
    await page.waitForSelector('#mt-groups input');
    assert.equal(await page.locator('#mt-groups input').count(), 3);
    assert.match(await page.textContent('#mt-min'), /Xray-core ≥ \d/);
    await page.click('#mt-build');
    await page.waitForFunction(() => document.querySelector('#mt-out').value.includes('inbounds'));
    assert.ok(JSON.parse(await page.inputValue('#mt-out')).outbounds.length > 0);

    await page.uncheck('#mt-groups input[value=meta]');
    await page.uncheck('#mt-groups input[value=fastly]');
    await page.click('#mt-build');
    await page.waitForFunction(() => /built/.test(document.querySelector('#mt-msg').textContent));

    await page.selectOption('#mt-platform', 'android');
    await page.click('#mt-guide');
    await page.waitForFunction(() => /MITM-DomainFronting setup/.test(document.querySelector('#mt-out').value));

    await page.fill('#mt-permitted', 'example.com');
    await page.click('#mt-ca');
    await page.waitForFunction(() => /name-constrained/.test(document.querySelector('#mt-ca-status').textContent), null, { timeout: 30000 });
    assert.doesNotMatch(await page.textContent('#mt-ca-status'), /BEGIN/);
    await page.check('#mt-use-ca');
    await page.click('#mt-build');
    await page.waitForFunction(() => document.querySelector('#mt-out').value.includes('mitm-ca.crt'));
    assert.deepEqual(problems, []);
  } finally { await close(); }
});

test('Cores tab detects, validates and saves a core path', opts, async () => {
  const fs = require('node:fs'); const os = require('node:os'); const path = require('node:path');
  if (process.platform === 'win32') return;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'forge-core-'));
  const exe = path.join(dir, 'xray');
  fs.writeFileSync(exe, '#!/bin/sh\necho "Xray 25.1.1"\n', { mode: 0o755 });
  const { page, problems, close } = await launch();
  try {
    await page.click('[data-tab=cores]');
    await page.waitForSelector('#co-table tbody tr');
    assert.equal(await page.locator('#co-table tbody tr').count(), 3);
    await page.fill('[data-core=xray]', path.join(dir, 'nope'));
    await page.click('[data-row=xray] [data-act=set]');
    await page.waitForFunction(() => /executable/.test(document.querySelector('#co-msg').textContent));
    await page.fill('[data-core=xray]', exe);
    await page.click('[data-row=xray] [data-act=set]');
    await page.waitForFunction(() => /Xray 25\.1\.1/.test(document.querySelector('#co-table').textContent));
    await page.click('[data-row=xray] [data-act=clear]');
    await page.waitForFunction(() => /cleared/.test(document.querySelector('#co-msg').textContent));
    assert.deepEqual(problems, []);
  } finally { await close(); fs.rmSync(dir, { recursive: true, force: true }); }
});
