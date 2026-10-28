'use strict';
// The only bridge between the sandboxed renderer and the engine.
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('forge', {
  call: (method, params) => ipcRenderer.invoke('forge:call', method, params),
  // Native dialogs live in the main process; the renderer asks by file kind.
  openText: (opts) => ipcRenderer.invoke('forge:openText', opts),
  saveText: (opts) => ipcRenderer.invoke('forge:saveText', opts),
  pickPath: (opts) => ipcRenderer.invoke('forge:pickPath', opts),
  onJob: (cb) => {
    const handler = (_e, ev) => cb(ev);
    ipcRenderer.on('forge:job', handler);
    return () => ipcRenderer.removeListener('forge:job', handler);
  },
});
