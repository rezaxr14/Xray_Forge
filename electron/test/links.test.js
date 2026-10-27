'use strict';
// Every link in the renderer page must be an https URL that the main process opens in the
// system browser (target=_blank -> setWindowOpenHandler -> shell.openExternal): the app
// window itself never navigates (will-navigate is prevented).
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const html = fs.readFileSync(path.join(__dirname, '..', 'renderer', 'index.html'), 'utf8');
const anchors = [...html.matchAll(/<a\b([^>]*)>/gi)].map((m) => m[1]);
const attr = (s, name) => (s.match(new RegExp(`\\b${name}\\s*=\\s*"([^"]*)"`, 'i')) || [])[1];

test('the About panel links to the project', () => {
  assert.ok(anchors.length >= 2, `expected at least 2 links, found ${anchors.length}`);
  assert.ok(anchors.some((a) => attr(a, 'href') === 'https://github.com/rezaxr14/Xray_Forge'));
});

test('every link is https, opens outside the app and cannot reach window.opener', () => {
  for (const a of anchors) {
    const href = attr(a, 'href');
    assert.match(href || '', /^https:\/\/[a-z0-9.-]+\//i, `bad href in <a${a}>`);
    assert.equal(attr(a, 'target'), '_blank', `missing target=_blank in <a${a}>`);
    const rel = (attr(a, 'rel') || '').split(/\s+/);
    assert.ok(rel.includes('noopener') && rel.includes('noreferrer'), `rel must be "noopener noreferrer" in <a${a}>`);
    assert.equal(attr(a, 'style'), undefined, 'CSP forbids inline styles');
  }
});

test('the only javascript: or http: URLs allowed in the page are none', () => {
  assert.doesNotMatch(html, /(?:href|src|action)\s*=\s*"(?:javascript:|http:)/i);
});
