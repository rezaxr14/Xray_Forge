'use strict';
// File open/save for the renderer. The renderer never sees a path it did not
// get from a native dialog the user just confirmed, and it can only ask for a
// kind of file ("text", "csv", ...), never supply arbitrary dialog filters.
const nodePath = require('node:path');
const nodeFs = require('node:fs');

const MAX_OPEN_BYTES = 8 * 1024 * 1024;
const MAX_SAVE_CHARS = 64 * 1024 * 1024;
const KINDS = {
  text: { name: 'Text files', extensions: ['txt'] },
  csv: { name: 'CSV', extensions: ['csv'] },
  json: { name: 'JSON', extensions: ['json'] },
  yaml: { name: 'YAML', extensions: ['yaml', 'yml'] },
};
const ALL = { name: 'All files', extensions: ['*'] };

function filtersFor(kind) {
  if (kind === undefined || kind === 'all') return [ALL];
  if (!Object.hasOwn(KINDS, kind)) throw new Error(`unknown file kind: ${String(kind).slice(0, 20)}`);
  return [KINDS[kind], ALL];
}

// A suggested file name is only a suggestion, but keep it a plain name.
function safeName(name) {
  const base = nodePath.basename(String(name || '')).replace(/[\u0000-\u001f<>:"/\\|?*]/g, '_').slice(0, 120);
  return base && base !== '.' && base !== '..' ? base : 'export.txt';
}

function makeFileApi({ dialog, fs = nodeFs, getWindow = () => undefined }) {
  const parent = () => { const w = getWindow(); return w && !w.isDestroyed() ? w : undefined; };
  const show = (fn, opts) => { const w = parent(); return w ? fn(w, opts) : fn(opts); };
  return {
    async openText({ kind, title } = {}) {
      const r = await show(dialog.showOpenDialog, {
        title: typeof title === 'string' ? title.slice(0, 80) : undefined,
        properties: ['openFile'], filters: filtersFor(kind),
      });
      if (r.canceled || !r.filePaths.length) return null;
      const file = r.filePaths[0];
      const st = await fs.promises.stat(file);
      if (!st.isFile()) throw new Error('not a regular file');
      if (st.size > MAX_OPEN_BYTES) throw new Error(`file is larger than ${MAX_OPEN_BYTES / 1048576} MB`);
      return { path: file, text: (await fs.promises.readFile(file)).toString('utf8') };
    },
    async saveText({ text, defaultName, kind } = {}) {
      if (typeof text !== 'string') throw new Error('text must be a string');
      if (text.length > MAX_SAVE_CHARS) throw new Error('text is too large to save');
      const r = await show(dialog.showSaveDialog, {
        defaultPath: safeName(defaultName), filters: filtersFor(kind),
      });
      if (r.canceled || !r.filePath) return null;
      // Exports can hold credentials (share links): owner-only, like the engine's own files.
      await fs.promises.writeFile(r.filePath, text, { encoding: 'utf8', mode: 0o600 });
      return r.filePath;
    },
    async pickPath({ title } = {}) {
      const r = await show(dialog.showOpenDialog, {
        title: typeof title === 'string' ? title.slice(0, 80) : undefined,
        properties: ['openFile'], filters: [ALL],
      });
      return r.canceled || !r.filePaths.length ? null : r.filePaths[0];
    },
  };
}

module.exports = { makeFileApi, safeName, filtersFor, MAX_OPEN_BYTES };
