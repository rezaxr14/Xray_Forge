'use strict';
const path = require('node:path');
const { app, BrowserWindow, dialog, ipcMain, shell } = require('electron');
const { EngineClient } = require('./engine-client');
const { resolveEngine } = require('./engine-path');
const { makeFileApi } = require('./files');

const repoRoot = path.resolve(__dirname, '..');
// Packaged: the PyInstaller engine bundle in <resources>/engine; dev: python -m xray_forge.
const spec = resolveEngine({
  resourcesPath: app.isPackaged ? process.resourcesPath : undefined, repoRoot,
});
console.log(`[engine] ${spec.kind}: ${spec.command} ${spec.args.join(' ')}`);
const engine = new EngineClient(spec);
let win = null;

function createWindow() {
  win = new BrowserWindow({
    width: 1280, height: 860, backgroundColor: '#0f1419', title: 'Xray Forge',
    icon: path.join(__dirname, 'assets', 'icon.png'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true, nodeIntegration: false, sandbox: true,
    },
  });
  win.loadFile(path.join(__dirname, 'renderer', 'index.html'));
  // Never navigate the app window, never open new Electron windows.
  win.webContents.on('will-navigate', (e) => e.preventDefault());
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https:\/\//.test(url)) shell.openExternal(url);
    return { action: 'deny' };
  });
}

app.whenReady().then(() => {
  engine.on('job', (ev) => win && !win.isDestroyed() && win.webContents.send('forge:job', ev));
  engine.on('stderr', (l) => console.error('[engine]', l));
  engine.start();
  ipcMain.handle('forge:call', (_e, method, params) => {
    if (typeof method !== 'string') throw new Error('method must be a string');
    return engine.call(method, params && typeof params === 'object' ? params : {});
  });
  const files = makeFileApi({ dialog, getWindow: () => win });
  const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});
  ipcMain.handle('forge:openText', (_e, o) => files.openText(obj(o)));
  ipcMain.handle('forge:saveText', (_e, o) => files.saveText(obj(o)));
  ipcMain.handle('forge:pickPath', (_e, o) => files.pickPath(obj(o)));
  createWindow();
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});

app.on('window-all-closed', async () => {
  await engine.stop();
  app.quit();
});
