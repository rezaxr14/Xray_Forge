'use strict';
// The Electron main-process logic, with `electron` and the engine pieces passed in
// so tests can drive it with fakes (see test/app-shell.test.js).  main.js is the
// thin wrapper that wires in the real modules.
const path = require('node:path');

function startApp({ electron, EngineClient, resolveEngine, makeFileApi, rootDir, resourcesPath,
  log = console.log, errorLog = console.error }) {
  const { app, BrowserWindow, dialog, ipcMain, shell } = electron;

  // One instance only: two engines would fight over ~/.xray_forge.
  if (!app.requestSingleInstanceLock()) {
    app.quit();
    return { ready: Promise.resolve(), getWindow: () => null };
  }

  const repoRoot = path.resolve(rootDir, '..');
  // Packaged: the PyInstaller engine bundle in <resources>/engine; dev: python -m xray_forge.
  const spec = resolveEngine({ resourcesPath: app.isPackaged ? resourcesPath : undefined, repoRoot });
  log(`[engine] ${spec.kind}: ${spec.command} ${spec.args.join(' ')}`);
  const engine = new EngineClient(spec);
  let win = null;

  // Only our own window, showing our own local page, may talk to the engine or open dialogs.
  const trusted = (e) => Boolean(e && win && !win.isDestroyed() && e.sender === win.webContents
    && e.senderFrame && typeof e.senderFrame.url === 'string' && e.senderFrame.url.startsWith('file://'));
  const guard = (fn) => async (e, ...args) => {
    if (!trusted(e)) throw new Error('untrusted sender');
    return fn(...args);
  };

  function externalHttps(url) {
    try {
      const u = new URL(url);
      return u.protocol === 'https:' ? u.href : null;
    } catch { return null; }
  }

  function createWindow() {
    win = new BrowserWindow({
      width: 1280, height: 860, backgroundColor: '#0f1419', title: 'Xray Forge',
      icon: path.join(rootDir, 'assets', 'icon.png'),
      webPreferences: {
        preload: path.join(rootDir, 'preload.js'),
        contextIsolation: true, nodeIntegration: false, sandbox: true,
      },
    });
    win.loadFile(path.join(rootDir, 'renderer', 'index.html'));
    const wc = win.webContents;
    // Never navigate the app window, never open new Electron windows or webviews.
    wc.on('will-navigate', (e) => e.preventDefault());
    wc.on('will-attach-webview', (e) => e.preventDefault());
    wc.setWindowOpenHandler(({ url }) => {
      const href = externalHttps(url);
      if (href) shell.openExternal(href);
      return { action: 'deny' };
    });
    // The app needs no camera, location, notifications, clipboard-read, ...: deny them all.
    wc.session.setPermissionRequestHandler((_wc, _permission, callback) => callback(false));
    wc.session.setPermissionCheckHandler(() => false);
  }

  const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});

  const ready = app.whenReady().then(() => {
    engine.on('job', (ev) => win && !win.isDestroyed() && win.webContents.send('forge:job', ev));
    engine.on('stderr', (l) => errorLog('[engine]', l));
    engine.start();
    ipcMain.handle('forge:call', guard((method, params) => {
      if (typeof method !== 'string') throw new Error('method must be a string');
      return engine.call(method, obj(params));
    }));
    const files = makeFileApi({ dialog, getWindow: () => win });
    ipcMain.handle('forge:openText', guard((o) => files.openText(obj(o))));
    ipcMain.handle('forge:saveText', guard((o) => files.saveText(obj(o))));
    ipcMain.handle('forge:pickPath', guard((o) => files.pickPath(obj(o))));
    createWindow();
  });

  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
  app.on('second-instance', () => {
    if (!win || win.isDestroyed()) return;
    if (win.isMinimized()) win.restore();
    win.focus();
  });
  app.on('window-all-closed', async () => {
    await engine.stop();
    app.quit();
  });
  return { ready, getWindow: () => win };
}

module.exports = { startApp };
