'use strict';
// Every local module the main process (and preload) loads must be listed in the
// electron-builder "files" array, or the packaged app starts with "Cannot find module".
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));

function localRequires(file, seen = new Set()) {
  const rel = path.relative(root, file);
  if (seen.has(rel)) return seen;
  seen.add(rel);
  const src = fs.readFileSync(file, 'utf8');
  for (const m of src.matchAll(/require\(\s*['"](\.{1,2}\/[^'"]+)['"]\s*\)/g)) {
    let target = path.resolve(path.dirname(file), m[1]);
    if (!fs.existsSync(target) && fs.existsSync(`${target}.js`)) target = `${target}.js`;
    assert.ok(fs.existsSync(target), `${rel} requires missing ${m[1]}`);
    localRequires(target, seen);
  }
  return seen;
}

test('package.json main exists and every module it loads is shipped', () => {
  assert.equal(pkg.main, 'main.js');
  const needed = new Set([...localRequires(path.join(root, pkg.main)), ...localRequires(path.join(root, 'preload.js'))]);
  assert.ok(needed.has('app-shell.js') && needed.has('engine-client.js') && needed.has('files.js'));
  const shipped = new Set(pkg.build.files);
  for (const f of needed) assert.ok(shipped.has(f), `${f} is loaded at startup but missing from build.files`);
});

test('tests and other dev-only files are not shipped', () => {
  for (const f of pkg.build.files) assert.doesNotMatch(f, /test/);
});
