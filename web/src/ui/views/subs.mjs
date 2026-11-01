import { h, icon } from '../dom.mjs';
import { call, textToLines } from '../forge.mjs';
import { MAX_SUB_BYTES } from '../../engine/subscription.mjs';
import { copyText, toast, guarded, openTextFile } from '../feedback.mjs';
import { load, save } from '../store.mjs';
import { workspace, setText, changed, linesOf } from '../state.mjs';

const PRESETS = [{ id: 'patterniha-f', name: 'Patterniha-F', url: 'https://raw.githubusercontent.com/patterniha/Free-Configs/main/configs.txt', note: 'Free daily configs published on GitHub. Downloaded only when you press Fetch. They are public, so check them before trusting them.' }];

export function createSubs({ go }) {
  let subs = load('subs', []);
  const body = h('div', { class: 'stack' });
  const url = h('input', { type: 'url', placeholder: 'https://example.com/subscription', autocapitalize: 'off', spellcheck: 'false', 'aria-label': 'Subscription URL' });
  const name = h('input', { type: 'text', placeholder: 'Name (optional)', 'aria-label': 'Name' });
  const persist = () => save('subs', subs);

  async function fetchText(u) {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), 15000);
    try {
      const res = await fetch(u, { signal: ctl.signal, credentials: 'omit', referrerPolicy: 'no-referrer', cache: 'no-store' });
      if (!res.ok) throw new Error(`The server answered ${res.status}`);
      const text = await res.text();
      if (text.length > MAX_SUB_BYTES) throw new Error('That subscription is larger than 8 MB');
      return text;
    } catch (e) {
      if (e.name === 'AbortError') throw new Error('The request timed out after 15 seconds');
      if (e instanceof TypeError) throw new Error('The browser could not read that URL. Most servers do not allow web pages to download them. Open the link in a new tab, copy the text, and use "Paste subscription text" instead.');
      throw e;
    }
  }

  function ingest(text, label) {
    const r = textToLines(text);
    if (!r.supported) { toast(`${r.format === 'clash' ? 'Clash YAML' : 'sing-box JSON'} subscriptions need the desktop app`, 'bad'); return null; }
    if (!r.lines.length) { toast('No share links found in that text', 'bad'); return null; }
    toast(`${label}: ${r.lines.length} links`);
    return r.lines;
  }

  async function addToWorkspace(lines) {
    const merged = [...linesOf(workspace.text), ...lines];
    const d = await call('config.dedup', { lines: merged });
    setText(d.lines.join('\n')); workspace.rows = []; changed();
    toast(`Added to Configs: ${d.lines.length} total, ${d.removed} duplicates removed`);
    go('configs');
  }

  const fetchOne = (s) => guarded(async () => {
    s.status = 'fetching'; render();
    try {
      const lines = ingest(await fetchText(s.url), s.name || s.url);
      s.status = lines ? 'ok' : 'no links'; s.count = lines ? lines.length : 0; s.when = new Date().toISOString(); persist(); render();
      if (lines) await addToWorkspace(lines);
    } catch (e) { s.status = 'error'; persist(); render(); throw e; }
  });

  function add(u, n) {
    u = u.trim();
    if (!/^https?:\/\//i.test(u)) { toast('Subscription URLs start with http:// or https://', 'bad'); return; }
    if (subs.some((s) => s.url === u)) { toast('That URL is already in the list', 'bad'); return; }
    subs.push({ url: u, name: n.trim(), enabled: true, status: '', count: 0, when: '' }); persist(); render();
  }

  function render() {
    const list = subs.length ? h('table', { class: 'table' },
      h('thead', {}, h('tr', {}, h('th', {}, 'Source'), h('th', {}, 'Last fetch'), h('th', {}))),
      h('tbody', {}, subs.map((s, i) => h('tr', {},
        h('td', {}, h('div', {}, s.name || new URL(s.url).host), h('div', { class: 'hint mono' }, s.url)),
        h('td', { class: 'muted' }, s.when ? `${s.count} links · ${new Date(s.when).toLocaleString()}` : (s.status || 'Not fetched')),
        h('td', {}, h('div', { class: 'row end' },
          h('button', { class: 'btn', onclick: () => fetchOne(s) }, icon('refresh', 18), 'Fetch'),
          h('button', { class: 'btn quiet danger icon-only', 'aria-label': `Remove ${s.name || s.url}`, onclick: () => { subs.splice(i, 1); persist(); render(); } }, icon('trash', 18)))))))) : h('p', { class: 'muted' }, 'No sources yet.');
    const pasted = h('textarea', { rows: 5, spellcheck: 'false', placeholder: 'Paste the subscription text here (plain or base64)', 'aria-label': 'Subscription text' });
    body.replaceChildren(
      h('div', { class: 'notice info' }, icon('info'), h('div', {}, 'Browsers only let a page download URLs whose server allows it. Sources that refuse show a clear message and can be pasted instead. Clash YAML and sing-box JSON subscriptions need the desktop app.')),
      h('div', { class: 'card stack' }, h('h2', {}, 'Add a source'),
        h('div', { class: 'grid2' }, url, name),
        h('div', { class: 'row' },
          h('button', { class: 'btn primary', onclick: () => { add(url.value, name.value); url.value = ''; name.value = ''; } }, icon('plus', 18), 'Add'),
          ...PRESETS.map((p) => h('button', { class: 'btn', title: p.note, onclick: () => add(p.url, p.name) }, `Add ${p.name}`)))),
      h('div', { class: 'card' }, h('h2', {}, 'Sources'), list),
      h('div', { class: 'card stack' }, h('h2', {}, 'Paste subscription text'),
        pasted,
        h('div', { class: 'row' },
          h('button', { class: 'btn primary', onclick: () => guarded(async () => { const l = ingest(pasted.value, 'Pasted text'); if (l) await addToWorkspace(l); }) }, 'Read and add to Configs'),
          h('button', { class: 'btn', onclick: async () => { const f = await openTextFile(); if (f) pasted.value = f.text; } }, icon('open', 18), 'Open a file'))));
  }
  render();
  return { id: 'subs', title: 'Subscriptions', el: h('div', { class: 'page' }, body), actions: () => [] };
}
