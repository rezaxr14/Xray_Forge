// Static guarantees for the app shell: strict CSP friendly code, a complete manifest and an offline build.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const walk = (d) => readdirSync(d).flatMap((n) => { const f = join(d, n); return statSync(f).isDirectory() ? walk(f) : [f]; });

test('UI code never builds markup from strings or runs dynamic code', () => {
  for (const f of walk(join(root, 'src/ui')).filter((x) => x.endsWith('.mjs'))) {
    const src = readFileSync(f, 'utf8');
    assert.doesNotMatch(src, /innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function\(/, f);
    assert.doesNotMatch(src, /\bstyle:\s*['"`]|setAttribute\(['"]style/, `${f} sets an inline style attribute (blocked by the CSP)`);
  }
});

test('index.html has a strict CSP and only same-origin scripts and styles', () => {
  const html = readFileSync(join(root, 'index.html'), 'utf8');
  assert.match(html, /Content-Security-Policy/);
  assert.match(html, /script-src 'self'/);
  assert.doesNotMatch(html, /<script(?![^>]*\bsrc=)/, 'no inline scripts');
  assert.doesNotMatch(html, /https?:\/\/(?!www\.w3\.org)[^"' ]+\.(js|css)/, 'no remote assets');
});

test('manifest icons exist and use relative paths', () => {
  const m = JSON.parse(readFileSync(join(root, 'manifest.webmanifest'), 'utf8'));
  assert.equal(m.display, 'standalone');
  for (const i of m.icons) {
    assert.ok(!i.src.startsWith('/'), 'relative so it works under /Xray_Forge/');
    assert.ok(existsSync(join(root, i.src)), i.src);
  }
  assert.ok(m.icons.some((i) => i.purpose === 'maskable'));
});

test('build precaches every shipped file under a content version', () => {
  execFileSync(process.execPath, [join(root, 'scripts/build.mjs')], { stdio: 'pipe' });
  const sw = readFileSync(join(root, 'dist/sw.js'), 'utf8');
  assert.doesNotMatch(sw, /__VERSION__|__PRECACHE__/);
  const list = JSON.parse(sw.match(/const PRECACHE = (\[.*\]);/)[1]);
  for (const f of ['./', 'manifest.webmanifest', 'styles/app.css', 'src/ui/app.mjs', 'src/engine/config-methods.mjs', 'icons/icon-192.png']) assert.ok(list.includes(f), f);
  for (const f of list.filter((x) => x !== './')) assert.ok(existsSync(join(root, 'dist', f)), f);
});
