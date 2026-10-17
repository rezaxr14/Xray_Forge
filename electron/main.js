'use strict';
const path = require('node:path');
const { app, BrowserWindow, ipcMain, shell } = require('electron');
const { EngineClient } = require('./engine-client');

const repoRoot = path.resolve(__dirname, '..');
// When packaged, the frozen engine sits next to the app (see ROADMAP step 4).
const engine = new EngineClient({ cwd: repoRoot });
let win = null;

function createWindow() {
  win = new BrowserWindow({
    width: 1280, height: 860, backgroundColor: '#0f1419', title: 'Xray Forge',
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
  createWindow();
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});

app.on('window-all-closed', async () => {
  await engine.stop();
  app.quit();
});
