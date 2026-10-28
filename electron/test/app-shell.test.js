'use strict';
// The Electron main-process logic, driven through a fake `electron` module:
// window security options, navigation/window-open policy, IPC validation and
// sender checks, permission denial, job forwarding, quit/activate, single instance.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const { startApp } = require('../app-shell');

function fake({ packaged = false, lock = true } = {}) {
  const log = { quit: 0, external: [], order: [], ipc: {}, appEvents: {}, windows: [], stderr: [], permission: null };
  class Win {
    constructor(opts) {
      this.opts = opts; this.destroyed = false; this.sent = []; this.loaded = null; this.minimized = false; this.focused = 0; this.restored = 0;
      this.wc = {
        events: {}, send: (...a) => this.sent.push(a),
        on: (ev, fn) => { this.wc.events[ev] = fn; },
        setWindowOpenHandler: (fn) => { this.wc.openHandler = fn; },
        session: {
          setPermissionRequestHandler: (fn) => { log.permission = { ...(log.permission || {}), request: fn }; },
          setPermissionCheckHandler: (fn) => { log.permission = { ...(log.permission || {}), check: fn }; },
        },
      };
      this.webContents = this.wc;
      log.windows.push(this);
    }
    loadFile(f) { this.loaded = f; }
    isDestroyed() { return this.destroyed; }
    isMinimized() { return this.minimized; }
    restore() { this.restored++; this.minimized = false; }
    focus() { this.focused++; }
    static getAllWindows() { return log.windows.filter((w) => !w.destroyed); }
  }
  const electron = {
    app: {
      isPackaged: packaged,
      whenReady: () => Promise.resolve(),
      on: (ev, fn) => { log.appEvents[ev] = fn; },
      quit: () => { log.quit++; log.order.push('quit'); },
      requestSingleInstanceLock: () => lock,
    },
    BrowserWindow: Win,
    dialog: { tag: 'dialog' },
    ipcMain: { handle: (ch, fn) => { log.ipc[ch] = fn; } },
    shell: { openExternal: (u) => log.external.push(u) },
  };
  class FakeEngine extends EventEmitter {
    constructor(spec) { super(); this.spec = spec; this.started = 0; this.calls = []; log.engine = this; }
    start() { this.started++; log.order.push('engine.start'); }
    async stop() { await new Promise((r) => setTimeout(r, 5)); log.order.push('engine.stop'); }
    async call(m, p) { this.calls.push([m, p]); return { ok: m }; }
  }
  const filesCalls = [];
  const makeFileApi = (deps) => {
    log.fileDeps = deps;
    return { openText: async (o) => { filesCalls.push(['openText', o]); return 'o'; }, saveText: async (o) => { filesCalls.push(['saveText', o]); return 's'; },
      pickPath: async (o) => { filesCalls.push(['pickPath', o]); return 'p'; } };
  };
  const logs = [];
  const deps = {
    electron, EngineClient: FakeEngine, makeFileApi, rootDir: path.join('/app', 'electron'),
    resolveEngine: (o) => { log.resolveOpts = o; return { kind: 'dev', command: 'py', args: ['-m', 'x'] }; },
    resourcesPath: '/res', log: (...a) => logs.push(a.join(' ')), errorLog: (...a) => log.stderr.push(a.join(' ')),
  };
  return { deps, log, filesCalls, logs };
}
const trusted = (win) => ({ sender: win.webContents, senderFrame: { url: 'file:///app/electron/renderer/index.html' } });

async function boot(opts) {
  const f = fake(opts);
  const shell = startApp(f.deps);
  await shell.ready;
  return { ...f, shell, win: f.log.windows[0] };
}

test('window: sandboxed renderer, isolated context, no node, our preload and icon', async () => {
  const { win } = await boot();
  const wp = win.opts.webPreferences;
  assert.equal(wp.contextIsolation, true); assert.equal(wp.nodeIntegration, false); assert.equal(wp.sandbox, true);
  assert.equal(wp.preload, path.join('/app', 'electron', 'preload.js'));
  assert.equal(wp.webSecurity, undefined);                      // never weakened
  assert.equal(win.opts.icon, path.join('/app', 'electron', 'assets', 'icon.png'));
  assert.equal(win.loaded, path.join('/app', 'electron', 'renderer', 'index.html'));
});

test('engine: resolved for dev/packaged, started once on ready, stderr logged', async () => {
  const dev = await boot();
  assert.equal(dev.log.resolveOpts.resourcesPath, undefined);
  assert.equal(dev.log.resolveOpts.repoRoot, path.resolve('/app'));
  assert.equal(dev.log.engine.started, 1);
  dev.log.engine.emit('stderr', 'boom');
  assert.deepEqual(dev.log.stderr, ['[engine] boom']);
  const packaged = await boot({ packaged: true });
  assert.equal(packaged.log.resolveOpts.resourcesPath, '/res');
});

test('navigation is blocked and new windows only open https links externally', async () => {
  const { win, log } = await boot();
  let prevented = 0;
  win.wc.events['will-navigate']({ preventDefault: () => prevented++ });
  assert.equal(prevented, 1);
  let attach = 0;
  win.wc.events['will-attach-webview']({ preventDefault: () => attach++ });
  assert.equal(attach, 1);
  for (const url of ['https://example.com/a', 'HTTPS://Example.com']) {
    assert.deepEqual(win.wc.openHandler({ url }), { action: 'deny' });
  }
  for (const url of ['http://example.com', 'file:///etc/passwd', 'javascript:alert(1)', 'https://', 'not a url', '', 'ftp://x/y', 'data:text/html,hi']) {
    assert.deepEqual(win.wc.openHandler({ url }), { action: 'deny' });
  }
  assert.deepEqual(log.external, ['https://example.com/a', 'https://example.com/']);
});

test('permissions: every request and check is denied', async () => {
  const { log } = await boot();
  const results = [];
  log.permission.request({}, 'media', (ok) => results.push(ok));
  log.permission.request({}, 'geolocation', (ok) => results.push(ok));
  assert.deepEqual(results, [false, false]);
  assert.equal(log.permission.check({}, 'clipboard-read'), false);
});

test('forge:call validates its arguments and forwards to the engine', async () => {
  const { log, win } = await boot();
  const call = log.ipc['forge:call'];
  await assert.rejects(() => call(trusted(win), 5, {}), /method must be a string/);
  await assert.rejects(() => call(trusted(win), { a: 1 }, {}), /method must be a string/);
  assert.deepEqual(await call(trusted(win), 'engine.info', { a: 1 }), { ok: 'engine.info' });
  await call(trusted(win), 'm1'); await call(trusted(win), 'm2', [1, 2]); await call(trusted(win), 'm3', 'str'); await call(trusted(win), 'm4', null);
  assert.deepEqual(log.engine.calls, [['engine.info', { a: 1 }], ['m1', {}], ['m2', {}], ['m3', {}], ['m4', {}]]);
});

test('file handlers coerce options to plain objects and reach the file api', async () => {
  const { log, win, filesCalls } = await boot();
  assert.equal(log.fileDeps.dialog.tag, 'dialog');
  assert.equal(log.fileDeps.getWindow(), win);
  for (const [ch, name] of [['forge:openText', 'openText'], ['forge:saveText', 'saveText'], ['forge:pickPath', 'pickPath']]) {
    await log.ipc[ch](trusted(win), { kind: 'k' });
    await log.ipc[ch](trusted(win), [1]);
    await log.ipc[ch](trusted(win), 'x');
    await log.ipc[ch](trusted(win), undefined);
    const mine = filesCalls.filter((c) => c[0] === name).map((c) => c[1]);
    assert.deepEqual(mine, [{ kind: 'k' }, {}, {}, {}]);
  }
});

test('IPC refuses senders that are not the main window or not a local file', async () => {
  const { log, win } = await boot();
  const other = { sender: { id: 'other' }, senderFrame: { url: 'file:///x' } };
  const remote = { sender: win.webContents, senderFrame: { url: 'https://evil.example/' } };
  const orphan = { sender: win.webContents, senderFrame: null };
  const ghost = { sender: win.webContents };
  for (const ch of ['forge:call', 'forge:openText', 'forge:saveText', 'forge:pickPath']) {
    for (const ev of [other, remote, orphan, ghost, undefined, null]) {
      await assert.rejects(() => log.ipc[ch](ev, 'engine.info', {}), /untrusted sender/, `${ch}`);
    }
  }
  assert.equal(log.engine.calls.length, 0);
  win.destroyed = true;                                          // a destroyed window trusts nobody
  await assert.rejects(() => log.ipc['forge:call'](trusted(win), 'engine.info', {}), /untrusted sender/);
});

test('job events reach the window only while it is alive', async () => {
  const { log, win } = await boot();
  log.engine.emit('job', { job: 'a', type: 'item' });
  assert.deepEqual(win.sent, [['forge:job', { job: 'a', type: 'item' }]]);
  win.destroyed = true;
  log.engine.emit('job', { job: 'b' });
  assert.equal(win.sent.length, 1);
});

test('closing all windows stops the engine first, then quits once', async () => {
  const { log } = await boot();
  await log.appEvents['window-all-closed']();
  assert.deepEqual(log.order.slice(-2), ['engine.stop', 'quit']);
  assert.equal(log.quit, 1);
});

test('activate recreates the window only when none is open', async () => {
  const { log, win } = await boot();
  log.appEvents.activate();
  assert.equal(log.windows.length, 1);
  win.destroyed = true;
  log.appEvents.activate();
  assert.equal(log.windows.length, 2);
  // the new window is the one IPC trusts and jobs go to
  const w2 = log.windows[1];
  assert.deepEqual(await log.ipc['forge:call'](trusted(w2), 'm'), { ok: 'm' });
  await assert.rejects(() => log.ipc['forge:call'](trusted(win), 'm'), /untrusted sender/);
  log.engine.emit('job', { job: 'z' });
  assert.equal(w2.sent.length, 1);
});

test('a second instance quits without starting an engine; the first one is focused', async () => {
  const second = fake({ lock: false });
  const shell = startApp(second.deps);
  await shell.ready;
  assert.equal(second.log.quit, 1);
  assert.equal(second.log.windows.length, 0);
  assert.equal(second.log.engine, undefined);

  const { log, win } = await boot();
  win.minimized = true;
  log.appEvents['second-instance']();
  assert.equal(win.restored, 1); assert.equal(win.focused, 1);
  log.appEvents['second-instance']();
  assert.equal(win.restored, 1); assert.equal(win.focused, 2);
});
