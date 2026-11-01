import { h, icon } from '../dom.mjs';
import { call } from '../forge.mjs';
import { copyText, openTextFile, saveTextFile, toast, guarded } from '../feedback.mjs';
import { load, save, debounce } from '../store.mjs';
import { workspace, setText, changed, linesOf } from '../state.mjs';

export function createConvert({ info, go }) {
  const d = info.defaults;
  const saved = load('convert', {});
  const st = {
    mode: 'full', wantFp: true, wantCs: true, wantFm: true, tlsOnly: true, rename: true, dedup: true,
    fp: d.fp, cs: d.cs, fm: JSON.stringify(d.fm), template: d.template, start: 1,
    ipOn: false, ip: '', portOn: false, port: '', ...saved,
  };
  let names = [];
  const persist = debounce(() => save('convert', st), 300);

  const input = h('textarea', { rows: 8, spellcheck: 'false', placeholder: 'Paste links to fix: fingerprint, fragment, names and endpoint', 'aria-label': 'Links to convert' });
  const output = h('textarea', { rows: 10, readOnly: true, spellcheck: 'false', 'aria-label': 'Converted links' });
  const summary = h('p', { class: 'hint', role: 'status' }, 'Nothing converted yet.');
  const namesList = h('ul', { class: 'names' });
  const ipBadge = h('span', { class: 'badge', role: 'status' });
  const portBadge = h('span', { class: 'badge', role: 'status' });

  const bind = (key, el, kind = 'value') => {
    const set = () => { st[key] = kind === 'check' ? el.checked : el.value; persist(); sync(); };
    if (kind === 'check') el.checked = !!st[key]; else el.value = st[key];
    el.addEventListener('input', set);
    el.addEventListener('change', set);
    return el;
  };
  const text = (key, extra = {}) => bind(key, h('input', { type: 'text', autocapitalize: 'off', spellcheck: 'false', ...extra }));
  const check = (key, label) => { const el = bind(key, h('input', { type: 'checkbox' }), 'check'); return h('label', { class: 'check' }, el, label); };
  const mode = bind('mode', h('select', {}, h('option', { value: 'full' }, 'Full fix: fingerprint, ciphers and fragment'), h('option', { value: 'iponly' }, 'Endpoint only: inject nothing'), h('option', { value: 'custom' }, 'Custom: pick below')));
  const cWant = { fp: check('wantFp', 'Fingerprint'), cs: check('wantCs', 'Cipher suites'), fm: check('wantFm', 'Fragment') };
  const fp = text('fp'); const cs = text('cs'); const fm = text('fm', { class: 'mono' });
  const tls = check('tlsOnly', 'Only touch TLS links');
  const rename = check('rename', 'Rename'); const dedup = check('dedup', 'Remove duplicates');
  const template = text('template', { class: 'mono' });
  const start = bind('start', h('input', { type: 'number', min: 0, max: 99999 }));
  const ipOn = bind('ipOn', h('input', { type: 'checkbox' }), 'check'); const ip = text('ip', { placeholder: 'IPv4, IPv6 or domain' });
  const portOn = bind('portOn', h('input', { type: 'checkbox' }), 'check'); const port = text('port', { placeholder: '1 to 65535' });

  function sync() {
    if (st.mode === 'full') Object.assign(st, { wantFp: true, wantCs: true, wantFm: true });
    if (st.mode === 'iponly') Object.assign(st, { wantFp: false, wantCs: false, wantFm: false });
    for (const [k, key] of [['fp', 'wantFp'], ['cs', 'wantCs'], ['fm', 'wantFm']]) {
      cWant[k].querySelector('input').checked = st[key];
      cWant[k].querySelector('input').disabled = st.mode !== 'custom';
    }
    for (const el of [fp, cs, fm, tls.querySelector('input')]) el.disabled = st.mode === 'iponly';
    if (document.activeElement === ip && ip.value.trim()) { st.ipOn = true; ipOn.checked = true; }
    if (document.activeElement === port && port.value.trim()) { st.portOn = true; portOn.checked = true; }
    checkOverride();
  }
  const checkOverride = debounce(() => guarded(async () => {
    const o = { ip: st.ipOn ? st.ip.trim() : '', port: st.portOn ? st.port.trim() : '' };
    const r = await call('config.check_override', o);
    const ipBad = !!o.ip && r.ip == null; const portBad = !!o.port && r.port === false;
    ipBadge.textContent = o.ip ? (ipBad ? 'Not an IP or domain' : r.ip) : ''; ipBadge.className = `badge ${ipBad ? 'bad' : 'good'}`;
    portBadge.textContent = o.port ? (portBad ? 'Must be 1 to 65535' : 'OK') : ''; portBadge.className = `badge ${portBad ? 'bad' : 'good'}`;
  }), 150);

  const want = (k) => st.mode !== 'iponly' && st[k];
  const run = () => guarded(async () => {
    const params = {
      text: input.value, dedup: st.dedup, fp: st.fp, cs: st.cs, fm: st.fm, tls_only: st.tlsOnly, rename: st.rename,
      want_fp: want('wantFp'), want_cs: want('wantCs'), want_fm: want('wantFm'), start: Number(st.start || 1),
      ip: st.ipOn ? st.ip.trim() : '', port: st.portOn ? st.port.trim() : '',
    };
    if (st.template.trim()) params.template = st.template.trim();
    const r = await call('config.convert', params);
    output.value = r.lines.join('\n');
    names = r.names;
    namesList.replaceChildren(...names.map((n) => h('li', { tabindex: 0, role: 'button', title: 'Copy this config', onclick: () => copyText(n.line, 'config'), onkeydown: (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); copyText(n.line, 'config'); } } }, n.name || '(unnamed)')));
    const c = r.counts;
    summary.textContent = `${c.fixed} fixed · ${c.unchanged} unchanged · ${c.skipped} skipped · ${r.removed} duplicates removed`;
  });
  const reset = () => { Object.assign(st, { mode: 'full', fp: d.fp, cs: d.cs, fm: JSON.stringify(d.fm), template: d.template, start: 1, tlsOnly: true, rename: true, dedup: true, ipOn: false, ip: '', portOn: false, port: '' }); for (const [el, key] of [[mode, 'mode'], [fp, 'fp'], [cs, 'cs'], [fm, 'fm'], [template, 'template'], [start, 'start'], [ip, 'ip'], [port, 'port']]) el.value = st[key]; for (const [el, key] of [[tls.querySelector('input'), 'tlsOnly'], [rename.querySelector('input'), 'rename'], [dedup.querySelector('input'), 'dedup'], [ipOn, 'ipOn'], [portOn, 'portOn']]) el.checked = st[key]; persist(); sync(); toast('Rules reset'); };

  const fld = (label, el, extra) => h('label', { class: 'field' }, h('span', {}, label), el, extra);
  const root = h('div', { class: 'page stack' },
    h('div', { class: 'card stack' },
      h('div', { class: 'row' }, h('h2', { class: 'grow' }, 'Links'),
        h('button', { class: 'btn', onclick: async () => { const f = await openTextFile(); if (f) { input.value = f.text; toast(`Loaded ${f.name}`); } } }, icon('open', 18), 'Open file'),
        h('button', { class: 'btn', onclick: () => { input.value = workspace.text; toast('Loaded your configs'); } }, 'Use my configs')),
      input),
    h('div', { class: 'card stack' }, h('h2', {}, 'Rules'),
      fld('Mode', mode),
      h('div', { class: 'row' }, cWant.fp, cWant.cs, cWant.fm),
      h('div', { class: 'grid2' }, fld('Fingerprint', fp), fld('Fragment mask (JSON)', fm)),
      fld('Cipher suites', cs), h('div', { class: 'row' }, tls, rename, dedup)),
    h('div', { class: 'card stack' }, h('h2', {}, 'Names'),
      h('div', { class: 'grid2' }, fld('Template', template), fld('Start number', start)),
      h('p', { class: 'hint' }, `Keys: ${info.template_keys.map((k) => `{${k}}`).join(' ')}`)),
    h('div', { class: 'card stack' }, h('h2', {}, 'Force one endpoint'),
      h('p', { class: 'hint' }, 'Changes only the address clients connect to. The host header, SNI and path stay as they are.'),
      h('div', { class: 'grid2' },
        h('div', { class: 'stack' }, h('label', { class: 'check' }, ipOn, 'Force address'), ip, ipBadge),
        h('div', { class: 'stack' }, h('label', { class: 'check' }, portOn, 'Force port'), port, portBadge))),
    h('div', { class: 'row' },
      h('button', { class: 'btn primary', onclick: run }, icon('bolt', 18), 'Convert'),
      h('button', { class: 'btn', onclick: reset }, 'Reset rules'), summary),
    h('div', { class: 'card stack' },
      h('div', { class: 'row' }, h('h2', { class: 'grow' }, 'Result'),
        h('button', { class: 'btn', onclick: () => copyText(output.value, 'result') }, icon('copy', 18), 'Copy'),
        h('button', { class: 'btn', onclick: () => saveTextFile(output.value, 'converted.txt') }, icon('save', 18), 'Save'),
        h('button', { class: 'btn primary', onclick: () => guarded(async () => { if (!output.value.trim()) { toast('Nothing to send yet', 'bad'); return; } setText(linesOf(output.value).join('\n')); workspace.rows = []; changed(); go('configs'); }) }, 'Edit in Configs')),
      output, h('details', {}, h('summary', { class: 'muted' }, 'Names'), namesList)));
  sync();
  return { id: 'convert', title: 'Convert', el: root, actions: () => [] };
}
