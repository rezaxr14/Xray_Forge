'use strict';
// The only bridge between the sandboxed renderer and the engine.
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('forge', {
  call: (method, params) => ipcRenderer.invoke('forge:call', method, params),
  onJob: (cb) => {
    const handler = (_e, ev) => cb(ev);
    ipcRenderer.on('forge:job', handler);
    return () => ipcRenderer.removeListener('forge:job', handler);
  },
});
