// Copies the app into dist/ and stamps the service worker with a content hash and file list.
import { cpSync, rmSync, mkdirSync, readFileSync, writeFileSync, readdirSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const dist = join(root, 'dist');
rmSync(dist, { recursive: true, force: true });
mkdirSync(dist, { recursive: true });
for (const p of ['index.html', 'manifest.webmanifest', 'styles', 'src', 'icons']) cpSync(join(root, p), join(dist, p), { recursive: true });
writeFileSync(join(dist, '.nojekyll'), '');
writeFileSync(join(dist, '404.html'), readFileSync(join(dist, 'index.html')));

const walk = (d) => readdirSync(d).flatMap((n) => { const f = join(d, n); return statSync(f).isDirectory() ? walk(f) : [f]; });
const files = walk(dist).map((f) => relative(dist, f).split('\\').join('/')).filter((f) => f !== '.nojekyll' && f !== '404.html').sort();
const hash = createHash('sha256');
for (const f of files) { hash.update(f); hash.update(readFileSync(join(dist, f))); }
const version = hash.digest('hex').slice(0, 12);
const precache = ['./', ...files.filter((f) => f !== 'index.html')];
const sw = readFileSync(join(root, 'sw.js'), 'utf8').replace('__VERSION__', version).replace('__PRECACHE__', JSON.stringify(precache));
writeFileSync(join(dist, 'sw.js'), sw);
console.log(`built dist/ (${files.length + 1} files, version ${version})`);
