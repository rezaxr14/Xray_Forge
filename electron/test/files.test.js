'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { makeFileApi, safeName, filtersFor, MAX_OPEN_BYTES } = require('../files');

function fakeDialog({ open = {}, save = {} } = {}) {
  const calls = [];
  return {
    calls,
    showOpenDialog: async (...a) => { calls.push(['open', ...a]); return open; },
    showSaveDialog: async (...a) => { calls.push(['save', ...a]); return save; },
  };
}
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'xf-files-'));

test('openText reads the chosen file; cancel gives null', async () => {
  const f = path.join(tmp(), 'a.txt');
  fs.writeFileSync(f, 'vless://x\nsecond');
  const api = makeFileApi({ dialog: fakeDialog({ open: { canceled: false, filePaths: [f] } }) });
  assert.deepEqual(await api.openText({ kind: 'text' }), { path: f, text: 'vless://x\nsecond' });
  const none = makeFileApi({ dialog: fakeDialog({ open: { canceled: true, filePaths: [] } }) });
  assert.equal(await none.openText(), null);
});

test('openText refuses directories and oversized files', async () => {
  const d = tmp();
  const dirApi = makeFileApi({ dialog: fakeDialog({ open: { canceled: false, filePaths: [d] } }) });
  await assert.rejects(dirApi.openText(), /regular file/);
  const big = path.join(d, 'big.txt');
  fs.writeFileSync(big, Buffer.alloc(MAX_OPEN_BYTES + 1));
  const bigApi = makeFileApi({ dialog: fakeDialog({ open: { canceled: false, filePaths: [big] } }) });
  await assert.rejects(bigApi.openText(), /larger than/);
});

test('saveText writes owner-only, returns the path, and null on cancel', async () => {
  const f = path.join(tmp(), 'out.txt');
  const dlg = fakeDialog({ save: { canceled: false, filePath: f } });
  const api = makeFileApi({ dialog: dlg });
  assert.equal(await api.saveText({ text: 'héllo ✓', defaultName: 'x.txt', kind: 'text' }), f);
  assert.equal(fs.readFileSync(f, 'utf8'), 'héllo ✓');
  if (process.platform !== 'win32') assert.equal(fs.statSync(f).mode & 0o077, 0);
  assert.equal(dlg.calls[0][1].defaultPath, 'x.txt');
  const cancel = makeFileApi({ dialog: fakeDialog({ save: { canceled: true } }) });
  assert.equal(await cancel.saveText({ text: 'a' }), null);
});

test('saveText validates what the renderer sends', async () => {
  const api = makeFileApi({ dialog: fakeDialog({ save: { canceled: true } }) });
  for (const bad of [undefined, 5, null, {}, ['a']]) await assert.rejects(api.saveText({ text: bad }), /text must be a string/);
  await assert.rejects(api.saveText({ text: 'a', kind: '__proto__' }), /unknown file kind/);
  await assert.rejects(api.saveText({ text: 'a', kind: 'exe' }), /unknown file kind/);
});

test('the dialog is parented to a live window only', async () => {
  const f = path.join(tmp(), 'p.txt');
  const dlg = fakeDialog({ save: { canceled: false, filePath: f } });
  const win = { isDestroyed: () => false };
  await makeFileApi({ dialog: dlg, getWindow: () => win }).saveText({ text: 'a' });
  assert.equal(dlg.calls[0][1], win);
  const dead = { isDestroyed: () => true };
  await makeFileApi({ dialog: dlg, getWindow: () => dead }).saveText({ text: 'a' });
  assert.equal(typeof dlg.calls[1][1], 'object');
  assert.notEqual(dlg.calls[1][1], dead);
});

test('suggested names are reduced to a plain file name', () => {
  assert.equal(safeName('../../etc/passwd'), 'passwd');
  assert.equal(safeName('a<b>:c.txt'), 'a_b__c.txt');
  assert.equal(safeName('..'), 'export.txt');
  assert.equal(safeName(''), 'export.txt');
  assert.equal(safeName(undefined), 'export.txt');
  assert.equal(safeName('x'.repeat(300)).length, 120);
  assert.deepEqual(filtersFor('csv').map((x) => x.name), ['CSV', 'All files']);
  assert.deepEqual(filtersFor().map((x) => x.name), ['All files']);
});

test('pickPath returns the chosen path or null', async () => {
  const api = makeFileApi({ dialog: fakeDialog({ open: { canceled: false, filePaths: ['/opt/xray'] } }) });
  assert.equal(await api.pickPath({ title: 'core' }), '/opt/xray');
  const none = makeFileApi({ dialog: fakeDialog({ open: { canceled: true, filePaths: [] } }) });
  assert.equal(await none.pickPath(), null);
});
