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
const { makeFileApi } = require('../files');

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

async function launch({ home = fs.mkdtempSync(path.join(os.tmpdir(), 'xf-home-')) } = {}) {
  const engine = new EngineClient({ cwd: repoRoot, env: { HOME: home, USERPROFILE: home } });
  engine.start();
  const srv = await staticServer();
  const browser = await playwright.chromium.launch();
  const page = await browser.newPage();
  const problems = [];
  page.on('pageerror', (e) => problems.push(`pageerror: ${e.message}`));
  page.on('console', (m) => { if (m.type() === 'error') problems.push(`console: ${m.text()}`); });
  await page.exposeFunction('__forgeCall', (m, p) => engine.call(m, p));
  // Native dialogs: the real files.js with a scripted dialog (tests queue answers).
  const dialogs = { open: [], save: [], seen: [] };
  const files = makeFileApi({ dialog: {
    showOpenDialog: async (o) => { dialogs.seen.push(['open', o]); return dialogs.open.shift() || { canceled: true, filePaths: [] }; },
    showSaveDialog: async (o) => { dialogs.seen.push(['save', o]); return dialogs.save.shift() || { canceled: true }; },
  } });
  await page.exposeFunction('__forgeFile', (m, o) => files[m](o));
  engine.on('job', (ev) => page.evaluate((e) => window.__forgeJob(e), ev).catch(() => {}));
  await page.addInitScript(() => {
    const subs = [];
    window.__forgeJob = (ev) => subs.forEach((f) => f(ev));
    window.forge = {
      call: (m, p) => window.__forgeCall(m, p),
      openText: (o) => window.__forgeFile('openText', o),
      saveText: (o) => window.__forgeFile('saveText', o),
      pickPath: (o) => window.__forgeFile('pickPath', o),
      onJob: (cb) => { subs.push(cb); return () => subs.splice(subs.indexOf(cb), 1); },
    };
  });
  await page.goto(`http://127.0.0.1:${srv.address().port}/`);
  const close = async () => { await browser.close(); srv.close(); await engine.stop(); };
  return { page, problems, close, engine, dialogs, home };
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
    await page.evaluate(() => {
      window.__sent = {};
      const real = window.forge.call;
      window.forge.call = (m, p) => { window.__sent[m] = p; return real(m, p); };
    });
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

// ------------------------------------------------------------ step 5.1
test('convert rules: IP-only mode, forced endpoint, live badges, names list', opts, async () => {
  const { page, problems, close } = await launch();
  try {
    await page.click('[data-tab=convert]');
    await page.waitForFunction(() => document.querySelector('#cv-cs').value.length > 20);
    assert.equal(await page.inputValue('#cv-fp'), 'chrome');
    assert.match(await page.textContent('#cv-keys'), /\{id\}.*\{old\}/);

    // Full fix injects cs and fm.
    await page.fill('#cv-input', VLESS);
    await page.click('#cv-run');
    await page.waitForFunction(() => document.querySelector('#cv-output').value.includes('cs='));
    assert.match(await page.inputValue('#cv-output'), /fm=/);

    // Live endpoint feedback.
    await page.fill('#cv-ip', '9.9.9.9');
    await page.fill('#cv-port', '70000');
    await page.waitForFunction(() => /1-65535/.test(document.querySelector('#cv-port-badge').textContent));
    assert.equal(await page.textContent('#cv-ip-badge'), 'ipv4');
    assert.equal(await page.isChecked('#cv-ip-on'), true);
    assert.equal(await page.textContent('#cv-ep'), 'endpoint: 9.9.9.9 : 70000');
    await page.click('#cv-run');
    await page.waitForFunction(() => /port/.test(document.querySelector('#cv-msg').textContent));
    assert.equal(await page.getAttribute('#cv-msg', 'class').then((c) => c.includes('bad-text')), true);

    // IP only: nothing injected, endpoint forced, naming template + start #.
    await page.selectOption('#cv-mode', 'iponly');
    assert.equal(await page.isDisabled('#cv-fp'), true);
    assert.equal(await page.isChecked('#cv-want-cs'), false);
    await page.fill('#cv-port', '2053');
    await page.fill('#cv-template', 'n{id:03d}_{proto}');
    await page.fill('#cv-start', '40');
    await page.click('#cv-run');
    await page.waitForFunction(() => /endpoint → 9\.9\.9\.9:2053/.test(document.querySelector('#cv-msg').textContent));
    const out = await page.inputValue('#cv-output');
    assert.match(out, /@9\.9\.9\.9:2053\?/);
    assert.doesNotMatch(out, /cs=|fm=/);
    assert.match(out, /#n041_vless$/);
    assert.equal(await page.locator('#cv-names li').count(), 1);
    assert.equal(await page.textContent('#cv-names li'), 'n041_vless');

    // Clear override and reset rules.
    await page.click('#cv-ov-clear');
    assert.equal(await page.inputValue('#cv-ip'), '');
    assert.equal(await page.isChecked('#cv-ip-on'), false);
    await page.click('#cv-reset');
    assert.equal(await page.inputValue('#cv-template'), '{id:02d}_{sub}_{path}');
    assert.equal(await page.isChecked('#cv-want-cs'), true);
    assert.equal(await page.isDisabled('#cv-fp'), false);
    assert.deepEqual(problems, []);
  } finally { await close(); }
});

test('convert rules: custom switches, TLS-only, rename off, copy names/config', opts, async () => {
  const { page, problems, close } = await launch();
  try {
    await page.evaluate(() => {
      window.__clip = [];
      Object.defineProperty(navigator, 'clipboard', { value: { writeText: async (t) => { window.__clip.push(t); } }, configurable: true });
    });
    const REALITY = 'vless://13b8ac3f-e8de-4b2d-82db-e9130d288a54@203.0.113.7:443?security=reality&sni=www.microsoft.com&fp=chrome&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&sid=6ba85179&type=tcp#reality-node';
    await page.click('[data-tab=convert]');
    await page.waitForFunction(() => document.querySelector('#cv-cs').value.length > 20);
    await page.fill('#cv-input', `${VLESS}\n${REALITY}`);

    await page.selectOption('#cv-mode', 'custom');
    assert.equal(await page.isDisabled('#cv-want-cs'), false);
    await page.uncheck('#cv-want-fm');
    await page.uncheck('#cv-want-cs');
    await page.uncheck('#cv-rename');
    await page.fill('#cv-fp', 'firefox');
    await page.click('#cv-run');
    await page.waitForFunction(() => /skipped/.test(document.querySelector('#cv-msg').textContent));
    assert.match(await page.textContent('#cv-msg'), /1 skipped/);
    const lines = (await page.inputValue('#cv-output')).split('\n');
    assert.equal(lines.length, 2);
    assert.match(lines[0], /fp=firefox/);
    assert.doesNotMatch(lines[0], /cs=|fm=/);
    assert.match(lines[0], /#first$/);

    await page.uncheck('#cv-tls-only');
    await page.click('#cv-run');
    await page.waitForFunction(() => /0 skipped/.test(document.querySelector('#cv-msg').textContent));
    assert.match((await page.inputValue('#cv-output')).split('\n')[1], /fp=firefox/);

    await page.click('#cv-copy-names');
    await page.click('#cv-names li:nth-child(2)');
    await page.click('#cv-copy');
    const clip = await page.evaluate(() => window.__clip);
    assert.deepEqual(clip[0].split('\n'), ['first', 'reality-node']);
    assert.match(clip[1], /^vless:\/\/.*#reality-node$/);
    assert.equal(clip[2], await page.inputValue('#cv-output'));

    // Invalid fm is reported, not injected.
    await page.fill('#cv-fm', '{broken');
    await page.check('#cv-want-fm');
    await page.click('#cv-run');
    await page.waitForFunction(() => /fm must be valid JSON/.test(document.querySelector('#cv-msg').textContent));
    assert.deepEqual(problems, []);
  } finally { await close(); }
});

test('health: Tag names [CC] uses the exit country reported by a core', opts, async () => {
  const { page, problems, close } = await launch();
  try {
    await page.click('[data-tab=health]');
    assert.equal(await page.isDisabled('#hc-tag'), true);
    // No proxy core exists in CI, so feed the table the rows a core-backed run
    // would stream (this exercises the button and config.tag_cc, not the core).
    await page.evaluate((line) => {
      state.hcRows = [
        { line, name: 'first', scheme: 'vless', score: 90, passed: true,
          stages: [{ name: 'request', ok: true, ms: 10, data: { cc: 'DE', exit_ip: '1.1.1.1' } }] },
        { line: line + 'x', name: 'second', scheme: 'vless', score: 10, passed: false, stages: [] },
      ];
      renderHealth();
      document.querySelector('#hc-tag').disabled = false;
    }, VLESS);
    await page.click('#hc-tag');
    await page.waitForFunction(() => /tagged 1/.test(document.querySelector('#hc-status').textContent));
    assert.match(await page.textContent('#hc-table tbody tr:nth-child(1)'), /first\[DE\]/);
    assert.doesNotMatch(await page.textContent('#hc-table tbody tr:nth-child(2)'), /\[/);
    await page.click('#hc-tag');   // idempotent
    await page.waitForFunction(() => /tagged 0/.test(document.querySelector('#hc-status').textContent));
    await page.evaluate(() => { document.querySelector('#hc-keep').disabled = false; });
    await page.click('#hc-keep');
    await page.waitForSelector('#cfg-table tbody tr');
    assert.match(await page.textContent('#cfg-table tbody tr'), /first\[DE\]/);
    assert.deepEqual(problems, []);
  } finally { await close(); }
});

// ------------------------------------------------------------ step 5.2
const XHTTP = 'vless://13b8ac3f-e8de-4b2d-82db-e9130d288a54@198.51.100.4:443?security=tls&sni=a.example&type=xhttp&mode=packet-up&path=%2Fp&host=a.example&ech=AEX_abc#xh';
const VMESS = 'vmess://' + Buffer.from(JSON.stringify({ v: '2', ps: 'vm', add: '203.0.113.9', port: '443', id: 'b831381d-6324-4d53-ad4f-8cda48b30811', aid: '0', scy: 'auto', net: 'ws', host: 'c.example', path: '/v', tls: 'tls', sni: 'c.example' })).toString('base64');

async function openEditor(page, line, row = 1) {
  await page.fill('#cfg-input', line);
  await page.click('#cfg-parse');
  await page.waitForSelector(`#cfg-table tbody tr:nth-child(${row})`);
  await page.click(`#cfg-table tbody tr:nth-child(${row})`);
  await page.waitForSelector('#editor:not([hidden])');
}

test('editor: reality/xhttp/allowInsecure/header fields, applicability and extra_params', opts, async () => {
  const { page, problems, close } = await launch();
  try {
    await page.waitForFunction(() => /engine v\d/.test(document.querySelector('#engine-status').textContent));
    await openEditor(page, XHTTP);
    // xhttp link: mode enabled, reality + vmess fields greyed out
    assert.equal(await page.inputValue('#ed-form [name=mode]'), 'packet-up');
    assert.equal(await page.isDisabled('#ed-form [name=mode]'), false);
    assert.equal(await page.isDisabled('#ed-form [name=public_key]'), true);
    assert.equal(await page.isDisabled('#ed-form [name=alter_id]'), true);
    assert.equal(await page.isDisabled('#ed-form [name=ss_method]'), true);

    // changing transport greys the xhttp mode; switching to reality enables the keys
    await page.selectOption('#ed-form [name=transport]', 'ws');
    assert.equal(await page.isDisabled('#ed-form [name=mode]'), true);
    await page.selectOption('#ed-form [name=transport]', 'xhttp');
    await page.selectOption('#ed-form [name=security]', 'reality');
    assert.equal(await page.isDisabled('#ed-form [name=public_key]'), false);

    await page.selectOption('#ed-form [name=mode]', 'stream-up');
    await page.fill('#ed-form [name=public_key]', 'PBK123');
    await page.fill('#ed-form [name=short_id]', 'ab12');
    await page.fill('#ed-form [name=spider_x]', '/spx');
    await page.fill('#ed-form [name=header_type]', 'http');
    await page.fill('#ed-form [name=cs]', 'TLS_AES_128_GCM_SHA256');
    await page.check('#ed-form [name=allow_insecure]');
    await page.click('#ed-apply');
    await page.waitForFunction(() => document.querySelector('#ed-msg').textContent === 'Applied');
    const uri = await page.inputValue('#ed-uri');
    for (const part of ['mode=stream-up', 'pbk=PBK123', 'sid=ab12', 'spx=%2Fspx', 'headerType=http',
      'cs=TLS_AES_128_GCM_SHA256', 'allowInsecure=1', 'security=reality', 'ech=AEX_abc']) {
      assert.ok(uri.includes(part), `${part} missing from ${uri}`);
    }
    // the form reloads from the applied link
    assert.equal(await page.inputValue('#ed-form [name=public_key]'), 'PBK123');
    assert.equal(await page.isChecked('#ed-form [name=allow_insecure]'), true);
    assert.deepEqual(problems, []);
  } finally { await close(); }
});

test('editor: VMess scy/alterId and untouched disabled fields keep their values', opts, async () => {
  const { page, problems, close } = await launch();
  try {
    await page.waitForFunction(() => /engine v\d/.test(document.querySelector('#engine-status').textContent));
    await openEditor(page, VMESS);
    assert.equal(await page.isDisabled('#ed-form [name=alter_id]'), false);
    assert.equal(await page.inputValue('#ed-form [name=encryption]'), 'auto');
    await page.fill('#ed-form [name=encryption]', 'aes-128-gcm');
    await page.fill('#ed-form [name=alter_id]', '4');
    await page.click('#ed-apply');
    await page.waitForFunction(() => document.querySelector('#ed-msg').textContent === 'Applied');
    const decoded = JSON.parse(Buffer.from((await page.inputValue('#ed-uri')).replace('vmess://', ''), 'base64').toString());
    assert.equal(decoded.scy, 'aes-128-gcm');
    assert.equal(decoded.aid, '4');
    assert.equal(decoded.add, '203.0.113.9');
    assert.deepEqual(problems, []);
  } finally { await close(); }
});

test('editor: raw JSON round trip, validation errors and Copy link', opts, async () => {
  const { page, problems, close } = await launch();
  try {
    await page.waitForFunction(() => /engine v\d/.test(document.querySelector('#engine-status').textContent));
    await page.evaluate(() => {
      window.__clip = [];
      Object.defineProperty(navigator, 'clipboard', { value: { writeText: async (t) => { window.__clip.push(t); } }, configurable: true });
    });
    await openEditor(page, XHTTP);
    await page.click('#ed-raw summary');
    const json = JSON.parse(await page.inputValue('#ed-json'));
    assert.equal(json.extra_params.ech, 'AEX_abc');
    assert.equal(json.extra.mode, 'packet-up');
    assert.ok(!('raw' in json) || json.raw === '' || typeof json.raw === 'string');

    // form -> JSON picks up form edits
    await page.fill('#ed-form [name=name]', 'from-form');
    await page.click('#ed-to-json');
    assert.equal(JSON.parse(await page.inputValue('#ed-json')).name, 'from-form');

    // JSON -> form: edit extra_params and the port as an integer
    json.port = 2053;
    json.name = 'from-json';
    json.extra_params.pcs = 'deadbeef';
    await page.fill('#ed-json', JSON.stringify(json));
    await page.click('#ed-from-json');
    await page.waitForFunction(() => /JSON → form/.test(document.querySelector('#ed-msg').textContent));
    assert.equal(await page.inputValue('#ed-form [name=port]'), '2053');
    assert.equal(await page.inputValue('#ed-form [name=name]'), 'from-json');
    await page.click('#ed-copy');
    await page.waitForFunction(() => window.__clip.length === 1);
    const link = await page.evaluate(() => window.__clip[0]);
    assert.match(link, /@198\.51\.100\.4:2053\?/);
    assert.ok(link.includes('pcs=deadbeef') && link.includes('ech=AEX_abc'));
    assert.equal(await page.inputValue('#ed-uri'), link);
    // Copy link does not apply: the table keeps the old name until Apply
    assert.match(await page.textContent('#cfg-table tbody tr:nth-child(1)'), /xh/);

    // bad JSON / unknown field / bad port are reported and change nothing
    for (const [text, re] of [['{oops', /bad JSON/], ['{"scheme":"vless","bogus":1}', /unknown outbound fields: bogus/],
      ['{"scheme":"vless","port":"70000"}', /port must be 1\.\.65535/]]) {
      await page.fill('#ed-json', text);
      await page.click('#ed-from-json');
      await page.waitForFunction((src) => new RegExp(src).test(document.querySelector('#ed-msg').textContent), re.source);
      assert.equal(await page.inputValue('#ed-form [name=name]'), 'from-json');
    }
    // port typed into the form is validated by the engine on Apply
    await page.fill('#ed-form [name=port]', '99999');
    await page.click('#ed-apply');
    await page.waitForFunction(() => /port must be/.test(document.querySelector('#ed-msg').textContent));
    assert.match(await page.textContent('#cfg-table tbody tr:nth-child(1)'), /xh/);
    assert.deepEqual(problems.filter((p) => !/status of 400|Failed to load resource/.test(p)), []);
  } finally { await close(); }
});

test('copy falls back without the async clipboard API and the CSP stays quiet', opts, async () => {
  const { page, problems, close } = await launch();
  try {
    await page.click('[data-tab=convert]');
    await page.fill('#cv-input', VLESS);
    await page.click('#cv-run');
    await page.waitForFunction(() => document.querySelector('#cv-output').value.length > 0);
    await page.evaluate(() => Object.defineProperty(navigator, 'clipboard', { value: undefined, configurable: true }));
    await page.click('#cv-copy');
    await page.waitForFunction(() => /output copied|copy failed/.test(document.querySelector('#cv-msg').textContent));
    assert.equal(await page.locator('body > textarea').count(), 0);   // temp textarea removed again
    assert.deepEqual(problems, []);                                  // no CSP violations
  } finally { await close(); }
});

// ------------------------------------------------------------ step 5.3
const stubClipboard = (page) => page.evaluate(() => {
  window.__clip = [];
  Object.defineProperty(navigator, 'clipboard', { value: { writeText: async (t) => { window.__clip.push(t); } }, configurable: true });
});

test('scan results: select, copy IP and use as FORCE IP in the converter', opts, async () => {
  const { page, problems, close } = await launch();
  try {
    await page.waitForFunction(() => /engine v\d/.test(document.querySelector('#engine-status').textContent));
    await stubClipboard(page);
    await page.click('[data-tab=scan]');
    assert.equal(await page.isDisabled('#sc-use-ip'), true);
    await page.fill('#sc-cidrs', '127.0.0.1/32');
    await page.fill('#sc-port', '9');
    await page.check('#sc-dead');
    await page.click('#sc-start');
    await page.waitForFunction(() => /^done/.test(document.querySelector('#sc-status').textContent), null, { timeout: 30000 });

    await page.click('#sc-table tbody tr');
    assert.equal(await page.locator('#sc-table tbody tr.selected').count(), 1);
    await page.click('#sc-copy-ip');
    await page.waitForFunction(() => window.__clip.length === 1);
    assert.deepEqual(await page.evaluate(() => window.__clip), ['127.0.0.1']);
    await page.dblclick('#sc-table tbody tr');                 // double-click copies once more
    await page.waitForFunction(() => window.__clip.length === 2);
    await page.waitForTimeout(200);                            // ...and the two clicks inside it copy nothing
    assert.deepEqual(await page.evaluate(() => window.__clip), ['127.0.0.1', '127.0.0.1']);
    await page.click('#sc-use-ip');
    assert.match(await page.textContent('#sc-status'), /FORCE IP set to 127\.0\.0\.1:9/);

    await page.click('[data-tab=convert]');
    assert.equal(await page.inputValue('#cv-ip'), '127.0.0.1');
    assert.equal(await page.inputValue('#cv-port'), '9');
    assert.equal(await page.isChecked('#cv-ip-on'), true);
    assert.equal(await page.isChecked('#cv-port-on'), true);
    await page.waitForFunction(() => document.querySelector('#cv-ip-badge').textContent === 'ipv4');
    await page.fill('#cv-input', VLESS);
    await page.click('#cv-run');
    await page.waitForFunction(() => /endpoint → 127\.0\.0\.1:9/.test(document.querySelector('#cv-msg').textContent));
    assert.match(await page.inputValue('#cv-output'), /@127\.0\.0\.1:9\?/);

    // a new scan clears the selection
    await page.click('[data-tab=scan]');
    await page.click('#sc-start');
    await page.waitForFunction(() => document.querySelector('#sc-copy-ip').disabled === true);
    assert.deepEqual(problems, []);
  } finally { await close(); }
});

test('lookup panel: geo, my IP, resolve table, copy and FORCE IP (engine answers stubbed)', opts, async () => {
  const { page, problems, close } = await launch();
  try {
    await page.waitForFunction(() => /engine v\d/.test(document.querySelector('#engine-status').textContent));
    await stubClipboard(page);
    await page.evaluate(() => {
      const real = window.forge.call;
      window.__geoCalls = [];
      window.forge.call = (m, p) => {
        if (m === 'net.geo') {
          window.__geoCalls.push(p.ip);
          return Promise.resolve(p.ip === 'fail.example'
            ? { query: p.ip, text: 'lookup failed (all providers blocked?)', ok: false }
            : { query: p.ip, text: `${p.ip || '5.6.7.8'}  —  Berlin, Germany\nHetzner`, ok: true });
        }
        if (m === 'net.resolve') {
          return Promise.resolve(p.host === 'none.example' ? { host: p.host, answers: [] }
            : { host: p.host, answers: [{ ip: '104.16.1.1', sources: ['DoH:cloudflare-dns.com', 'system'] }, { ip: '10.10.34.34', sources: ['UDP:shecan'] }] });
        }
        return real(m, p);
      };
    });
    await page.click('[data-tab=scan]');

    await page.click('#net-myip');
    await page.waitForFunction(() => /done/.test(document.querySelector('#net-msg').textContent));
    assert.match(await page.textContent('#net-geo-out'), /^5\.6\.7\.8 {2}— {2}Berlin, Germany\nHetzner$/);
    await page.fill('#net-geo-q', '1.1.1.1');
    await page.press('#net-geo-q', 'Enter');
    await page.waitForFunction(() => window.__geoCalls.length === 2);
    assert.deepEqual(await page.evaluate(() => window.__geoCalls), ['', '1.1.1.1']);
    await page.fill('#net-geo-q', 'fail.example');
    await page.click('#net-geo');
    await page.waitForFunction(() => /provider failed/.test(document.querySelector('#net-msg').textContent));
    assert.ok((await page.getAttribute('#net-msg', 'class')).includes('bad-text'));

    await page.fill('#net-host', 'example.com');
    await page.click('#net-resolve');
    await page.waitForSelector('#net-res-table tbody tr:nth-child(2)');
    assert.match(await page.textContent('#net-res-table tbody tr:nth-child(1)'), /104\.16\.1\.1.*DoH:cloudflare-dns\.com, system/);
    assert.equal(await page.isDisabled('#net-use-ip'), true);
    await page.click('#net-res-table tbody tr:nth-child(2)');
    await page.click('#net-copy-ip');
    await page.waitForFunction(() => window.__clip.length === 1);
    assert.equal(await page.evaluate(() => window.__clip[0]), '10.10.34.34');
    await page.click('#net-use-ip');
    assert.equal(await page.inputValue('#cv-ip'), '10.10.34.34');
    assert.equal(await page.inputValue('#cv-port'), '');          // resolve answers carry no port
    assert.equal(await page.isChecked('#cv-port-on'), false);

    await page.fill('#net-host', 'none.example');
    await page.click('#net-resolve');
    await page.waitForFunction(() => /no answers/.test(document.querySelector('#net-msg').textContent));
    assert.equal(await page.locator('#net-res-table tbody tr').count(), 0);
    assert.equal(await page.isDisabled('#net-use-ip'), true);
    assert.deepEqual(problems, []);
  } finally { await close(); }
});

test('lookup panel against the real engine: validation errors and IP literals (offline)', opts, async () => {
  const { page, problems, close } = await launch();
  try {
    await page.waitForFunction(() => /engine v\d/.test(document.querySelector('#engine-status').textContent));
    await page.click('[data-tab=scan]');
    await page.click('#net-resolve');
    assert.match(await page.textContent('#net-msg'), /enter a host/);
    await page.fill('#net-host', 'a.com/../x');
    await page.click('#net-resolve');
    await page.waitForFunction(() => /IPv4\/IPv6 address or a domain/.test(document.querySelector('#net-msg').textContent));
    assert.equal(await page.isDisabled('#net-resolve'), false);
    await page.fill('#net-geo-q', 'x?y=1');
    await page.click('#net-geo');
    await page.waitForFunction(() => /IPv4\/IPv6 address or a domain/.test(document.querySelector('#net-msg').textContent));
    assert.equal(await page.isHidden('#net-geo-out'), true);
    await page.fill('#net-host', '9.9.9.9');
    await page.click('#net-resolve');
    await page.waitForSelector('#net-res-table tbody tr');
    assert.match(await page.textContent('#net-res-table tbody tr'), /9\.9\.9\.9.*literal/);
    assert.deepEqual(problems.filter((p) => !/status of 400|Failed to load resource/.test(p)), []);
  } finally { await close(); }
});

test('SNI results: copy IP + SNI and use the IP as FORCE IP', opts, async () => {
  const { page, problems, close } = await launch();
  try {
    await page.waitForFunction(() => /engine v\d/.test(document.querySelector('#engine-status').textContent));
    await stubClipboard(page);
    await page.click('[data-tab=sni]');
    assert.equal(await page.isDisabled('#sn-copy'), true);
    // no live host answers in CI, so feed the table the rows a search would stream
    await page.evaluate(() => {
      sn.rows.set('203.0.113.5|front.example', { ip: '203.0.113.5', sni: 'front.example', ok: true, http_ok: true, tls_ms: 40, tls_ver: 'TLSv1.3', info: '' });
      sn.rows.set('203.0.113.6|other.example', { ip: '203.0.113.6', sni: 'other.example', ok: true, http_ok: false, tls_ms: 90, tls_ver: 'TLSv1.3', info: '' });
      renderSni();
    });
    await page.click('#sn-table tbody tr:nth-child(1)');
    await page.click('#sn-copy');
    await page.waitForFunction(() => window.__clip.length === 1);
    assert.equal(await page.evaluate(() => window.__clip[0]), '203.0.113.5  sni=front.example');
    await page.click('#sn-table tbody tr:nth-child(2)');
    await page.click('#sn-use-ip');
    assert.match(await page.textContent('#sn-status'), /FORCE IP set to 203\.0\.113\.6 \(Convert tab\)/);
    await page.click('[data-tab=convert]');
    assert.equal(await page.inputValue('#cv-ip'), '203.0.113.6');
    assert.deepEqual(problems, []);
  } finally { await close(); }
});

// ------------------------------------------------------------ step 5.4
test('subscriptions: check-all-sources needs fetched configs, then streams results', opts, async () => {
  const { page, problems, close } = await launch();
  const sub = http.createServer((req, res) => { res.writeHead(200, { 'content-type': 'text/plain' }); res.end(`${DEAD}\n${DEAD}\n`); });
  await new Promise((r) => sub.listen(0, '127.0.0.1', r));
  try {
    await page.click('[data-tab=subs]');
    assert.equal(await page.isDisabled('#sk-export'), true);
    await page.click('#sk-start');
    await page.waitForFunction(() => /fetch the sources first/.test(document.querySelector('#sk-status').textContent));
    assert.equal(await page.isDisabled('#sk-start'), false);   // a refused start must not leave it locked

    await page.fill('#sub-url', `http://127.0.0.1:${sub.address().port}/s`);
    await page.click('#sub-add');
    await page.waitForSelector('#sub-table tbody tr');
    await page.click('#sub-fetch');
    await page.waitForFunction(() => /fetched: 1 configs \(1 duplicates removed\)/.test(document.querySelector('#sub-msg').textContent), null, { timeout: 30000 });

    await page.fill('#sk-timeout', '1');
    await page.uncheck('#sk-throughput');
    await page.click('#sk-start');
    await page.waitForFunction(() => /^done/.test(document.querySelector('#sk-status').textContent), null, { timeout: 30000 });
    assert.match(await page.textContent('#sk-status'), /done: 0 of 1 passed/);
    assert.equal(await page.locator('#sk-table tbody tr').count(), 1);
    assert.ok(await page.locator('#sk-table .chip.fail').count() >= 1);
    for (const b of ['#sk-export', '#sk-tagged', '#sk-load']) assert.equal(await page.isDisabled(b), true);
    assert.equal(await page.isDisabled('#sk-start'), false);
    assert.deepEqual(problems.filter((p) => !/Failed to load resource/.test(p)), []);
  } finally { sub.close(); await close(); }
});

test('subscriptions: export best N, tagged lines and best N → Configs', opts, async () => {
  const { page, problems, close } = await launch();
  try {
    await page.waitForFunction(() => /engine v\d/.test(document.querySelector('#engine-status').textContent));
    await stubClipboard(page);
    await page.click('[data-tab=subs]');
    // The run store needs working configs, which CI cannot reach; stub just
    // these two engine methods (their behaviour is covered by the Python tests)
    // and check what the UI sends and does with the answers.
    await page.evaluate((line) => {
      window.__calls = [];
      const real = window.forge.call;
      window.forge.call = (m, p) => {
        if (m === 'health.export_best') { window.__calls.push([m, p]); return Promise.resolve({ content: 'QUJD', count: 2 }); }
        if (m === 'health.tagged') { window.__calls.push([m, p]); return Promise.resolve({ lines: [line + '%20%5Bfragment%5D', line + 'b', line + 'c'] }); }
        return real(m, p);
      };
      sk.job = 'job-7';
      sk.rows = [{ line, name: 'ok', scheme: 'vless', score: 80, passed: true, stages: [], techniques: ['fragment'] }];
      skRender();
      ['#sk-export', '#sk-tagged', '#sk-load'].forEach((b) => { document.querySelector(b).disabled = false; });
    }, VLESS);
    await page.fill('#sk-n', '2');
    await page.click('#sk-export');
    await page.waitForFunction(() => document.querySelector('#sk-out').value === 'QUJD');
    assert.match(await page.textContent('#sk-status'), /subscription \(2 configs\) copied/);
    assert.deepEqual(await page.evaluate(() => window.__clip), ['QUJD']);
    assert.deepEqual(await page.evaluate(() => window.__calls[0]), ['health.export_best', { job: 'job-7', top_n: 2 }]);

    await page.click('#sk-tagged');
    await page.waitForFunction(() => /^3 working/.test(document.querySelector('#sk-status').textContent));
    assert.equal((await page.inputValue('#sk-out')).split('\n').length, 3);
    assert.deepEqual(await page.evaluate(() => window.__calls[1]), ['health.tagged', { job: 'job-7' }]);

    await page.click('#sk-load');                      // best N=2 of the 3 tagged lines
    await page.waitForFunction(() => document.querySelectorAll('#cfg-table tbody tr').length === 2);
    assert.deepEqual(problems, []);
  } finally { await close(); }
});

// ------------------------------------------------------------ step 5.5
const tmpDir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'xf-e2e-'));
const ready = (page) => page.waitForFunction(() => /engine v\d/.test(document.querySelector('#engine-status').textContent));

test('files: open links into Configs/Convert, cancel is harmless', opts, async () => {
  const { page, problems, close, dialogs } = await launch();
  try {
    await ready(page);
    const f = path.join(tmpDir(), 'links.txt');
    fs.writeFileSync(f, `${VLESS}\n${DEAD}\n`);
    dialogs.open.push({ canceled: true, filePaths: [] });
    await page.click('#cfg-open');
    await page.waitForFunction(() => /open cancelled/.test(document.querySelector('#cfg-count').textContent));
    assert.equal(await page.inputValue('#cfg-input'), '');

    dialogs.open.push({ canceled: false, filePaths: [f] });
    await page.click('#cfg-open');
    await page.waitForFunction(() => document.querySelectorAll('#cfg-table tbody tr').length === 2);
    assert.match(await page.inputValue('#cfg-input'), /first/);

    dialogs.open.push({ canceled: false, filePaths: [f] });
    await page.click('[data-tab=convert]');
    await page.click('#cv-open');
    await page.waitForFunction(() => /loaded .*links\.txt/.test(document.querySelector('#cv-msg').textContent));
    assert.match(await page.inputValue('#cv-input'), /dead/);

    dialogs.open.push({ canceled: false, filePaths: [path.join(tmpDir())] });   // a directory
    await page.click('#cv-open');
    await page.waitForFunction(() => /regular file/.test(document.querySelector('#cv-msg').textContent));
    assert.deepEqual(problems, []);
  } finally { await close(); }
});

test('files: save output, export, subscription, CSV exports and a core path', opts, async () => {
  const { page, problems, close, dialogs } = await launch();
  try {
    await ready(page);
    const dir = tmpDir();
    const target = (n) => { const p = path.join(dir, n); dialogs.save.push({ canceled: false, filePath: p }); return p; };

    await page.click('[data-tab=convert]');
    await page.click('#cv-save');                                   // nothing to save yet: no dialog
    assert.match(await page.textContent('#cv-msg'), /nothing to save/);
    assert.equal(dialogs.seen.length, 0);
    await page.fill('#cv-input', VLESS);
    await page.click('#cv-run');
    await page.waitForFunction(() => /fixed/.test(document.querySelector('#cv-msg').textContent));
    const out = await page.inputValue('#cv-output');
    const p1 = target('fixed.txt');
    await page.click('#cv-save');
    await page.waitForFunction(() => /^saved /.test(document.querySelector('#cv-msg').textContent));
    assert.equal(fs.readFileSync(p1, 'utf8'), out);
    assert.equal(dialogs.seen.at(-1)[1].defaultPath, 'vless_fixed.txt');

    await page.click('[data-tab=configs]');
    await page.fill('#cfg-input', VLESS);
    await page.click('#cfg-parse');
    await page.waitForSelector('#cfg-table tbody tr');
    await page.selectOption('#export-format', 'clash');
    await page.click('#export-run');
    await page.waitForFunction(() => document.querySelector('#export-out').value.length > 0);
    const p2 = target('c.yaml');
    await page.click('#export-save');
    await page.waitForFunction(() => /^saved /.test(document.querySelector('#export-msg').textContent));
    assert.match(fs.readFileSync(p2, 'utf8'), /proxies/);
    assert.deepEqual(dialogs.seen.at(-1)[1].defaultPath, 'config.yaml');
    assert.equal(dialogs.seen.at(-1)[1].filters[0].name, 'YAML');

    await page.click('[data-tab=subs]');
    await page.evaluate(() => { document.querySelector('#sk-out').value = 'QUJD'; });
    const p3 = target('sub.txt');
    await page.click('#sk-save');
    await page.waitForFunction(() => /^saved /.test(document.querySelector('#sk-status').textContent));
    assert.equal(fs.readFileSync(p3, 'utf8'), 'QUJD');

    await page.click('[data-tab=scan]');
    await page.evaluate(() => { document.querySelector('#sc-out').value = 'ip,ms\n1.1.1.1,5'; });
    const p4 = target('scan.csv');
    await page.click('#sc-save');
    await page.waitForFunction(() => /^saved /.test(document.querySelector('#sc-status').textContent));
    assert.equal(fs.readFileSync(p4, 'utf8'), 'ip,ms\n1.1.1.1,5');
    dialogs.save.push({ canceled: true });
    await page.click('#sc-save');
    await page.waitForFunction(() => /save cancelled/.test(document.querySelector('#sc-status').textContent));

    await page.click('[data-tab=sni]');
    await page.evaluate(() => { document.querySelector('#sn-out').value = 'ip,sni\n1.1.1.1,a'; });
    const p5 = target('sni.csv');
    await page.click('#sn-save');
    await page.waitForFunction(() => /^saved /.test(document.querySelector('#sn-status').textContent));
    assert.equal(fs.readFileSync(p5, 'utf8'), 'ip,sni\n1.1.1.1,a');

    await page.click('[data-tab=cores]');
    await page.waitForSelector('#co-table tbody tr');
    dialogs.open.push({ canceled: false, filePaths: ['/opt/some/xray'] });
    await page.click('#co-table tbody tr:first-child [data-act=browse]');
    await page.waitForFunction(() => /press Set/.test(document.querySelector('#co-msg').textContent));
    assert.equal(await page.inputValue('#co-table tbody tr:first-child input[data-core]'), '/opt/some/xray');
    assert.deepEqual(problems, []);
  } finally { await close(); }
});

test('settings: form values survive a restart and re-apply their dependent state', opts, async () => {
  const first = await launch();
  const { home } = first;
  try {
    await ready(first.page);
    const pg = first.page;
    await pg.fill('#cfg-input', VLESS);                     // links are not persisted
    await pg.click('[data-tab=health]');
    await pg.selectOption('#hc-core', '');
    await pg.fill('#hc-workers', '5');
    await pg.click('[data-tab=convert]');
    await pg.selectOption('#cv-mode', 'iponly');
    await pg.fill('#cv-template', '{id}-{host}');
    await pg.check('#cv-ip-on');
    await pg.fill('#cv-ip', '9.9.9.9');
    await pg.uncheck('#cv-dedup');
    await pg.click('[data-tab=scan]');
    await pg.check('#sc-dead');
    await pg.fill('#sc-cidrs', '10.0.0.0/30');
    // wait until the debounced save reached the engine (poll from Node: a Promise-returning
    // waitForFunction predicate counts as true at once)
    for (let i = 0; i < 100; i++) {
      if ((await first.engine.call('ui.settings_get', {})).settings['sc-cidrs'] === '10.0.0.0/30') break;
      await new Promise((r) => setTimeout(r, 100));
    }
    assert.equal((await first.engine.call('ui.settings_get', {})).settings['sc-cidrs'], '10.0.0.0/30');
    assert.equal(await pg.textContent('#settings-msg'), '');
  } finally { await first.close(); }

  const second = await launch({ home });
  try {
    const pg = second.page;
    await ready(pg);
    await pg.waitForFunction(() => document.querySelector('#cv-template').value === '{id}-{host}');
    assert.equal(await pg.inputValue('#hc-workers'), '5');
    assert.equal(await pg.inputValue('#cv-mode'), 'iponly');
    assert.equal(await pg.isDisabled('#cv-fp'), true);       // cvSyncMode ran for the restored mode
    assert.equal(await pg.isChecked('#cv-ip-on'), true);
    assert.equal(await pg.inputValue('#cv-ip'), '9.9.9.9');
    assert.equal(await pg.isChecked('#cv-dedup'), false);
    assert.equal(await pg.isChecked('#sc-dead'), true);
    assert.equal(await pg.inputValue('#sc-cidrs'), '10.0.0.0/30');
    assert.equal(await pg.inputValue('#cfg-input'), '');     // never persisted
    // restoring must not itself trigger a save that clobbers the file with defaults
    await new Promise((r) => setTimeout(r, 700));
    const saved = await pg.evaluate(async () => (await window.forge.call('ui.settings_get', {})).settings);
    assert.equal(saved['cv-template'], '{id}-{host}');
    assert.equal(saved['cv-ip'], '9.9.9.9');
    assert.deepEqual(second.problems, []);
  } finally { await second.close(); }
});

test('settings: a value the engine refuses is reported, not swallowed', opts, async () => {
  const { page, close } = await launch();
  try {
    await ready(page);
    await page.waitForFunction(() => settingsState.ready);
    await page.evaluate(() => {
      const real = window.forge.call;
      window.forge.call = (m, p) => (m === 'ui.settings_set' ? Promise.reject(new Error('cannot save settings: disk full')) : real(m, p));
    });
    await page.click('[data-tab=health]');
    await page.fill('#hc-workers', '3');
    await page.waitForFunction(() => /disk full/.test(document.querySelector('#settings-msg').textContent));
  } finally { await close(); }
});

// ------------------------------------------------------------ step 5.6a (parity gaps)
test('scan: fragment field, range presets, JSON export/save and Clear', opts, async () => {
  const { page, problems, close, dialogs } = await launch();
  try {
    await ready(page);
    await page.evaluate(() => {
      window.__sent = {};
      const real = window.forge.call;
      window.forge.call = (m, p) => { window.__sent[m] = p; return real(m, p); };
    });
    await page.click('[data-tab=scan]');
    assert.ok(await page.locator('#frag-presets option').count() >= 4);
    assert.equal(await page.inputValue('#sc-frag'), '5,94,1@2');
    await page.selectOption('#sc-preset', 'cloudflare');
    const first = (await page.inputValue('#sc-cidrs')).split('\n');
    assert.ok(first.length >= 5 && first.includes('104.16.0.0/13'));
    await page.selectOption('#sc-preset', 'cloudflare');          // adding again changes nothing
    assert.deepEqual((await page.inputValue('#sc-cidrs')).split('\n'), first);
    assert.match(await page.textContent('#sc-status'), /added 0 cloudflare/);
    assert.equal(await page.inputValue('#sc-preset'), '');

    await page.fill('#sc-cidrs', '127.0.0.1/32');
    await page.fill('#sc-port', '9');
    await page.fill('#sc-frag', 'rand:8-32@3');
    await page.check('#sc-dead');
    await page.click('#sc-start');
    await page.waitForFunction(() => /^done/.test(document.querySelector('#sc-status').textContent), null, { timeout: 30000 });
    assert.equal(await page.evaluate(() => window.__sent['scan.run'].frag), 'rand:8-32@3');
    await page.waitForFunction(() => document.querySelectorAll('#sc-sessions option').length > 1);
    await page.selectOption('#sc-sessions', { index: 1 });
    await page.selectOption('#sc-fmt', 'json');
    await page.click('#sc-export');
    await page.waitForFunction(() => document.querySelector('#sc-out').value.length > 0);
    const parsed = JSON.parse(await page.inputValue('#sc-out'));
    assert.ok(JSON.stringify(parsed).includes('127.0.0.1'));

    dialogs.save.push({ canceled: true });
    await page.click('#sc-save');
    await page.waitForFunction(() => /save cancelled/.test(document.querySelector('#sc-status').textContent));
    const [kind, o] = dialogs.seen.at(-1);
    assert.equal(kind, 'save');
    assert.match(o.defaultPath, /\.json$/);
    assert.equal(o.filters[0].name, 'JSON');

    await page.click('#sc-clear');
    assert.equal(await page.locator('#sc-table tbody tr').count(), 0);
    assert.equal(await page.inputValue('#sc-out'), '');
    assert.ok(await page.locator('#sc-sessions option').count() > 1);   // saved scans are kept
    assert.deepEqual(problems, []);
  } finally { await close(); }
});

test('SNI search: fragment field, JSON export and Clear', opts, async () => {
  const { page, problems, close } = await launch();
  try {
    await ready(page);
    await page.evaluate(() => {
      window.__sent = {};
      const real = window.forge.call;
      window.forge.call = (m, p) => { window.__sent[m] = p; return real(m, p); };
    });
    await page.click('[data-tab=sni]');
    await page.fill('#sn-ips', '127.0.0.1');
    await page.fill('#sn-snis', 'a.example');
    await page.fill('#sn-port', '9');
    await page.fill('#sn-frag', 'off');
    await page.click('#sn-start');
    await page.waitForFunction(() => /^done/.test(document.querySelector('#sn-status').textContent), null, { timeout: 30000 });
    assert.equal(await page.evaluate(() => window.__sent['sni.run'].frag), 'off');
    await page.selectOption('#sn-fmt', 'json');
    await page.click('#sn-export');
    await page.waitForFunction(() => document.querySelector('#sn-out').value.length > 0);
    JSON.parse(await page.inputValue('#sn-out'));
    await page.click('#sn-clear');
    assert.equal(await page.locator('#sn-table tbody tr').count(), 0);
    assert.equal(await page.inputValue('#sn-out'), '');
    assert.deepEqual(problems, []);
  } finally { await close(); }
});

test('health: select rows, copy a link, retest only the selected ones', opts, async () => {
  const { page, problems, close } = await launch();
  try {
    await ready(page);
    await stubClipboard(page);
    const dead2 = DEAD.replace('127.0.0.1:9', '127.0.0.1:19').replace('#dead', '#dead2');
    await page.evaluate(() => {
      window.__runs = [];
      const real = window.forge.call;
      window.forge.call = (m, p) => { if (m === 'health.run') window.__runs.push(p.lines.length); return real(m, p); };
    });
    await page.fill('#cfg-input', `${DEAD}\n${dead2}`);
    await page.click('#cfg-parse');
    await page.waitForFunction(() => document.querySelectorAll('#cfg-table tbody tr').length === 2);
    await page.click('[data-tab=health]');
    await page.fill('#hc-timeout', '1');
    await page.uncheck('#hc-throughput');
    assert.equal(await page.isDisabled('#hc-retest'), true);
    assert.equal(await page.isDisabled('#hc-copy'), true);
    await page.click('#hc-start');
    await page.waitForFunction(() => /^done: 0 of 2/.test(document.querySelector('#hc-status').textContent), null, { timeout: 30000 });

    await page.click('#hc-table tbody tr:nth-child(1)');
    assert.equal(await page.locator('#hc-table tbody tr.selected').count(), 1);
    assert.equal(await page.isDisabled('#hc-copy'), false);
    await page.click('#hc-copy');
    await page.waitForFunction(() => window.__clip.length === 1);
    const copied = await page.evaluate(() => window.__clip[0]);
    assert.ok(copied === DEAD || copied === dead2);

    await page.click('#hc-table tbody tr:nth-child(2)', { modifiers: ['Control'] });
    assert.equal(await page.locator('#hc-table tbody tr.selected').count(), 2);
    assert.equal(await page.isDisabled('#hc-copy'), true);       // copy needs exactly one row
    await page.click('#hc-table tbody tr:nth-child(2)', { modifiers: ['Control'] });   // toggle off
    assert.equal(await page.locator('#hc-table tbody tr.selected').count(), 1);

    await page.click('#hc-retest');
    await page.waitForFunction(() => window.__runs.length === 2);
    await page.waitForFunction(() => /^done: 0 of 2/.test(document.querySelector('#hc-status').textContent), null, { timeout: 30000 });
    assert.deepEqual(await page.evaluate(() => window.__runs), [2, 1]);     // all, then only the selected one
    assert.equal(await page.locator('#hc-table tbody tr').count(), 2);       // the other row was kept
    assert.equal(await page.isDisabled('#hc-start'), false);
    assert.deepEqual(problems, []);
  } finally { await close(); }
});

test('subscriptions check table: select a row and copy its link', opts, async () => {
  const { page, close } = await launch();
  try {
    await ready(page);
    await stubClipboard(page);
    await page.click('[data-tab=subs]');
    await page.evaluate((line) => {
      sk.rows = [{ line, name: 'ok', scheme: 'vless', score: 80, passed: true, stages: [] },
                 { line: line + 'x', name: 'two', scheme: 'vless', score: 10, passed: false, stages: [] }];
      skRender();
    }, VLESS);
    assert.equal(await page.isDisabled('#sk-copy'), true);
    await page.click('#sk-table tbody tr:nth-child(1)');
    await page.click('#sk-copy');
    await page.waitForFunction(() => window.__clip.length === 1);
    assert.equal(await page.evaluate(() => window.__clip[0]), VLESS);
  } finally { await close(); }
});

// ------------------------------------------------------------ step 5.7 (tester knobs)
test('health/check: anti-DPI options are sent only when set, and are remembered', opts, async () => {
  const first = await launch();
  const { home } = first;
  const record = (page) => page.evaluate(() => {
    window.__sent = [];
    const real = window.forge.call;
    window.forge.call = (m, p) => { if (m === 'health.run' || m === 'sub.check') window.__sent.push([m, p]); return real(m, p); };
  });
  try {
    const pg = first.page;
    await ready(pg);
    await record(pg);
    await pg.fill('#cfg-input', DEAD);
    await pg.click('#cfg-parse');
    await pg.waitForSelector('#cfg-table tbody tr');
    await pg.click('[data-tab=health]');
    await pg.fill('#hc-timeout', '1');
    await pg.uncheck('#hc-throughput');
    await pg.click('#hc-start');                               // nothing filled in: defaults stay in charge
    await pg.waitForFunction(() => /^done/.test(document.querySelector('#hc-status').textContent), null, { timeout: 30000 });
    assert.deepEqual(await pg.evaluate(() => Object.keys(window.__sent[0][1]).sort()), ['lines', 'throughput', 'timeout', 'workers']);

    await pg.click('#hc-adv summary');
    await pg.fill('#hc-frag', 'off 7,8@1');
    await pg.fill('#hc-fake', 'www.microsoft.com');
    await pg.fill('#hc-front', 'front.example');
    await pg.check('#hc-rec');
    await pg.check('#hc-pad');
    await pg.click('#hc-start');
    await pg.waitForFunction(() => window.__sent.length === 2);
    const p = await pg.evaluate(() => window.__sent[1][1]);
    assert.deepEqual(p.frag_variants, ['off', '7,8@1']);
    assert.equal(p.fake_sni, 'www.microsoft.com');
    assert.equal(p.front_host, 'front.example');
    assert.equal(p.record_frag, true);
    assert.equal(p.pad_hello, true);
    await pg.waitForFunction(() => /^done/.test(document.querySelector('#hc-status').textContent), null, { timeout: 30000 });

    await pg.fill('#hc-fake', 'bad host');                     // the engine's validation reaches the status line
    await pg.click('#hc-start');
    await pg.waitForFunction(() => /plain host name/.test(document.querySelector('#hc-status').textContent));
    assert.equal(await pg.isDisabled('#hc-start'), false);
    await pg.fill('#hc-fake', 'www.microsoft.com');

    await pg.click('[data-tab=subs]');
    await pg.click('#sk-adv summary');
    await pg.fill('#sk-fake', 'f.example');
    await pg.check('#sk-pad');
    await pg.click('#sk-start');
    await pg.waitForFunction(() => window.__sent.some(([m]) => m === 'sub.check'));
    const sk2 = await pg.evaluate(() => window.__sent.find(([m]) => m === 'sub.check')[1]);
    assert.equal(sk2.fake_sni, 'f.example');
    assert.equal(sk2.pad_hello, true);
    assert.equal('record_frag' in sk2, false);
    for (let i = 0; i < 100; i++) {
      if ((await first.engine.call('ui.settings_get', {})).settings['sk-fake'] === 'f.example') break;
      await new Promise((r) => setTimeout(r, 100));
    }
  } finally { await first.close(); }

  const second = await launch({ home });
  try {
    await ready(second.page);
    await second.page.waitForFunction(() => document.querySelector('#hc-fake').value === 'www.microsoft.com');
    assert.equal(await second.page.inputValue('#hc-frag'), 'off 7,8@1');
    assert.equal(await second.page.isChecked('#hc-rec'), true);
    assert.equal(await second.page.inputValue('#sk-fake'), 'f.example');
    assert.equal(await second.page.isChecked('#sk-pad'), true);
  } finally { await second.close(); }
});
