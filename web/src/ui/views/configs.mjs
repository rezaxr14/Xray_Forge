import { h, icon } from '../dom.mjs';
import { call } from '../forge.mjs';
import { openDialog } from '../dialog.mjs';
import { copyText, openTextFile, saveTextFile, toast, guarded } from '../feedback.mjs';
import { workspace, setText, linesOf, changed, SAMPLE } from '../state.mjs';

// Editor layout, ported from the desktop app. `at` puts a value under outbound.extra;
// `when` says whether a field applies to the link as currently edited.
const REALITY = (o, f) => (f.security || '').toLowerCase() === 'reality';
const SECTIONS = [
  ['Basic', [
    { key: 'scheme', label: 'Protocol', kind: 'readonly' },
    { key: 'name', label: 'Name', kind: 'text', wide: true },
    { key: 'host', label: 'Address', kind: 'text' },
    { key: 'port', label: 'Port', kind: 'text' },
    { key: 'credential', label: 'ID / password', kind: 'text', wide: true },
    { key: 'ss_method', label: 'Shadowsocks method', kind: 'text', when: (o) => o.scheme === 'ss' },
  ]],
  ['Transport', [
    { key: 'transport', label: 'Type', kind: 'select', options: 'transports' },
    { key: 'path', label: 'Path', kind: 'text' },
    { key: 'host_header', label: 'Host header', kind: 'text' },
    { key: 'service_name', label: 'gRPC service name', kind: 'text' },
    { key: 'header_type', label: 'Header type', kind: 'text' },
    { key: 'mode', at: 'extra', label: 'xhttp mode', kind: 'select', options: 'xhttp_modes', when: (o, f) => (f.transport || '') === 'xhttp' },
  ]],
  ['Security', [
    { key: 'security', label: 'Security', kind: 'select', options: 'securities' },
    { key: 'sni', label: 'SNI', kind: 'text' },
    { key: 'fingerprint', label: 'Fingerprint', kind: 'text' },
    { key: 'alpn', label: 'ALPN', kind: 'text' },
    { key: 'allow_insecure', label: 'Skip certificate check', kind: 'check', wide: true },
  ]],
  ['Reality, VMess and cipher suites', [
    { key: 'flow', label: 'Flow', kind: 'select', options: 'flows' },
    { key: 'public_key', label: 'Reality public key', kind: 'text', wide: true, when: REALITY },
    { key: 'short_id', label: 'Reality short id', kind: 'text', when: REALITY },
    { key: 'spider_x', label: 'Reality spiderX', kind: 'text', when: REALITY },
    { key: 'cs', at: 'extra', label: 'Cipher suites', kind: 'text', wide: true },
    { key: 'encryption', label: 'VMess cipher', kind: 'text', when: (o) => o.scheme === 'vmess' },
    { key: 'alter_id', label: 'VMess alterId', kind: 'text', when: (o) => o.scheme === 'vmess' },
  ]],
];
const FIELDS = SECTIONS.flatMap(([, f]) => f);
const EXPORTS = {
  clash: ['Clash / Mihomo (YAML)', 'config.yaml', 'text/yaml'],
  singbox: ['sing-box (JSON)', 'config.json', 'application/json'],
  sub: ['Subscription (base64)', 'subscription.txt', 'text/plain'],
};

export function createConfigs({ info }) {
  let base = null;
  const els = {};
  const root = h('div', { class: 'split' });

  const countLabel = h('span', { class: 'muted' });
  const list = h('ul', { class: 'items', role: 'listbox', 'aria-label': 'Configs' });
  const listBody = h('div', { class: 'pane-body' });
  const form = h('form', { onsubmit: (e) => e.preventDefault(), autocomplete: 'off' });
  const uri = h('textarea', { rows: 4, readOnly: true, spellcheck: 'false', 'aria-label': 'Share link' });
  const json = h('textarea', { rows: 10, spellcheck: 'false', 'aria-label': 'Outbound as JSON' });
  const inspector = h('div', { class: 'pane-body' });
  const inspectorHead = h('div', { class: 'pane-head' });

  // ------------------------------------------------------------ list
  async function parseText() {
    const rows = await call('config.parse_many', { text: workspace.text });
    workspace.rows = rows;
    workspace.selected = -1;
    changed();
    renderList();
    renderInspector();
  }

  function renderList() {
    const rows = workspace.rows;
    const ok = rows.filter((r) => r.ok).length;
    countLabel.textContent = rows.length ? `${ok} valid of ${rows.length}` : '';
    if (!rows.length) {
      listBody.replaceChildren(h('div', { class: 'empty' },
        h('div', { class: 'glyph' }, icon('list', 28)),
        h('h2', {}, 'No configs yet'),
        h('p', {}, 'Paste share links, open a text file, or try three sample links to see how editing works.'),
        h('div', { class: 'row' },
          h('button', { class: 'btn primary', onclick: addLinks }, icon('plus', 18), 'Add links'),
          h('button', { class: 'btn', onclick: () => guarded(async () => { setText(SAMPLE); await parseText(); }) }, 'Try samples')),
        h('p', { class: 'hint' }, 'Everything runs on this device. Nothing is uploaded.')));
      return;
    }
    list.replaceChildren(...rows.map((c, i) => {
      const o = c.outbound;
      return h('li', { role: 'presentation' }, h('button', {
        class: `item ${c.ok ? '' : 'bad'}`, role: 'option', 'aria-selected': String(i === workspace.selected), onclick: () => select(i),
      },
      h('span', { class: 'n' }, i + 1),
      h('span', { class: 'name' }, c.ok ? (o.name || '(unnamed)') : `Unparsable: ${c.line.slice(0, 60)}`),
      h('span', { class: 'chips' }, c.ok ? Object.entries(c.supports).filter(([, v]) => v).map(([k]) => h('span', { class: 'chip ok', title: `${k} can run this link` }, k)) : null),
      h('span', { class: 'meta' }, c.ok ? [h('span', { class: 'proto' }, o.scheme), ` ${o.host}:${o.port} · ${o.transport}${o.security ? ' · ' + o.security : ''}`] : 'Could not read this link')));
    }));
    listBody.replaceChildren(list);
  }

  function select(i) {
    workspace.selected = i;
    const c = workspace.rows[i];
    renderList();
    if (!c || !c.ok) { renderInspector(); return; }
    base = c.outbound;
    renderInspector();
    root.classList.add('editing');
    changed();
  }

  // ------------------------------------------------------- inspector
  const fieldEl = (key) => form.elements[key];
  const valueOf = (f, o) => {
    const v = (f.at ? (o[f.at] || {}) : o)[f.key];
    return f.kind === 'check' ? !!v : (v == null ? '' : String(v));
  };
  const readForm = () => {
    const out = {};
    for (const f of FIELDS) { const el = fieldEl(f.key); if (el) out[f.key] = f.kind === 'check' ? el.checked : el.value.trim(); }
    return out;
  };
  function collect() {
    const o = JSON.parse(JSON.stringify(base));
    const vals = readForm();
    for (const f of FIELDS) {
      const el = fieldEl(f.key);
      if (!el || f.kind === 'readonly' || el.disabled) continue;
      if (f.at) { o[f.at] = o[f.at] || {}; if (vals[f.key]) o[f.at][f.key] = vals[f.key]; else delete o[f.at][f.key]; }
      else o[f.key] = vals[f.key];
    }
    if (!o.port) o.port = '443';
    if (!o.path) o.path = '/';
    if (!o.transport) o.transport = 'tcp';
    return o;
  }
  function syncApplicable() {
    const vals = readForm();
    const o = { ...base, ...vals };
    for (const f of FIELDS) {
      if (!f.when) continue;
      const el = fieldEl(f.key);
      const on = !!f.when(o, vals);
      el.disabled = !on;
      el.closest('label').classList.toggle('off', !on);
    }
  }
  function buildForm() {
    const lists = info.editor || {};
    form.replaceChildren(...SECTIONS.map(([title, fields]) => h('fieldset', {},
      h('span', { class: 'legend' }, title),
      h('div', { class: 'fields' }, fields.map((f) => {
        const val = valueOf(f, base);
        let input;
        if (f.kind === 'select') {
          const opts = [...(lists[f.options] || [])];
          if (!opts.includes(val)) opts.push(val);
          input = h('select', { name: f.key }, opts.map((x) => h('option', { value: x, selected: x === val }, x || '(none)')));
        } else if (f.kind === 'check') {
          input = h('input', { type: 'checkbox', name: f.key, checked: val });
        } else {
          input = h('input', { type: 'text', name: f.key, value: val, readOnly: f.kind === 'readonly', autocapitalize: 'off', spellcheck: 'false' });
        }
        input.addEventListener('input', syncApplicable);
        input.addEventListener('change', syncApplicable);
        return f.kind === 'check'
          ? h('label', { class: `check ${f.wide ? 'wide' : ''}` }, input, f.label)
          : h('label', { class: `field ${f.wide ? 'wide' : ''}` }, h('span', {}, f.label), input);
      })))));
    syncApplicable();
    json.value = JSON.stringify(base, null, 2);
  }

  async function render() {
    const r = await call('config.render', { outbound: collect() });
    uri.value = r.uri;
    return r;
  }

  function renderInspector() {
    const c = workspace.rows[workspace.selected];
    if (!c || !c.ok) {
      inspectorHead.replaceChildren(h('strong', {}, 'Editor'));
      inspector.replaceChildren(h('div', { class: 'empty' }, h('p', {}, workspace.rows.length ? 'Pick a config to edit it.' : 'Add links, then pick one to edit.')));
      return;
    }
    buildForm();
    uri.value = c.line;
    inspectorHead.replaceChildren(
      h('button', { class: 'btn quiet icon-only sheet-back', 'aria-label': 'Back to list', onclick: () => root.classList.remove('editing') }, icon('back')),
      h('strong', { class: 'grow' }, c.outbound.name || '(unnamed)'),
      h('button', { class: 'btn primary', onclick: apply }, icon('check', 18), 'Apply'),
      h('button', { class: 'btn', onclick: () => guarded(async () => { const r = await render(); await copyText(r.uri, 'link'); }) }, icon('copy', 18), 'Copy link'));
    inspector.replaceChildren(h('div', { class: 'inspector' },
      h('label', { class: 'field' }, h('span', {}, 'Share link'), uri),
      form,
      h('details', {}, h('summary', { class: 'muted' }, 'Advanced: edit as JSON'),
        h('div', { class: 'stack mt' }, json,
          h('div', { class: 'row' },
            h('button', { class: 'btn', onclick: () => { json.value = JSON.stringify(collect(), null, 2); toast('Form copied to JSON'); } }, 'Form to JSON'),
            h('button', { class: 'btn', onclick: () => guarded(async () => { const r = await call('config.from_json', { text: json.value }); base = r.outbound; buildForm(); toast('JSON loaded. Press Apply to write the link.'); }) }, 'JSON to form'))))));
  }

  async function apply() {
    await guarded(async () => {
      const r = await render();
      const parsed = await call('config.parse', { line: r.uri });
      workspace.rows[workspace.selected] = parsed;
      setText(workspace.rows.map((x) => x.line).join('\n'));
      renderList();
      if (parsed.ok) { base = parsed.outbound; buildForm(); uri.value = r.uri; }
      changed();
      toast(r.roundtrip_ok ? 'Applied' : 'Applied, but the new link does not read back', r.roundtrip_ok ? 'info' : 'bad');
    });
  }

  // --------------------------------------------------------- dialogs
  function addLinks() {
    const ta = h('textarea', { rows: 9, spellcheck: 'false', placeholder: 'vless://…\ntrojan://…\nvmess://…', value: workspace.text, 'aria-label': 'Share links' });
    openDialog('Add links', (close) => ({
      body: [
        h('p', { class: 'hint' }, 'One link per line. Existing text is kept so you can add to it.'),
        ta,
        h('div', { class: 'row' },
          h('button', { class: 'btn', type: 'button', onclick: async () => { const f = await openTextFile(); if (f) { ta.value = (ta.value.trim() ? ta.value.trimEnd() + '\n' : '') + f.text; toast(`Loaded ${f.name}`); } } }, icon('open', 18), 'Open a file'),
          h('button', { class: 'btn', type: 'button', onclick: async () => { try { const t = await navigator.clipboard.readText(); ta.value = (ta.value.trim() ? ta.value.trimEnd() + '\n' : '') + t; } catch { toast('Paste with Ctrl+V into the box', 'bad'); } } }, icon('copy', 18), 'Paste from clipboard'))],
      footer: [
        h('button', { class: 'btn', type: 'button', onclick: close }, 'Cancel'),
        h('button', { class: 'btn primary', type: 'button', onclick: () => guarded(async () => { setText(ta.value); close(); await parseText(); }) }, 'Read links')],
    }));
  }

  function exportDialog() {
    const lines = workspace.rows.filter((r) => r.ok).map((r) => r.line);
    if (!lines.length) { toast('Add at least one valid config first', 'bad'); return; }
    const sel = h('select', { 'aria-label': 'Format' }, Object.entries(EXPORTS).map(([k, v]) => h('option', { value: k }, v[0])));
    const out = h('textarea', { rows: 12, readOnly: true, spellcheck: 'false', 'aria-label': 'Exported text' });
    const run = () => guarded(async () => { out.value = (await call('config.export', { lines, format: sel.value })).content; });
    sel.addEventListener('change', run);
    openDialog('Export', () => ({
      body: [h('label', { class: 'field' }, h('span', {}, `Format for ${lines.length} configs`), sel), out],
      footer: [
        h('button', { class: 'btn', type: 'button', onclick: () => copyText(out.value, 'export') }, icon('copy', 18), 'Copy'),
        h('button', { class: 'btn primary', type: 'button', onclick: () => { const [, name, type] = EXPORTS[sel.value]; saveTextFile(out.value, name, type); } }, icon('save', 18), 'Save file')],
    }));
    run();
  }

  const dedup = () => guarded(async () => {
    const lines = workspace.rows.length ? workspace.rows.map((r) => r.line) : linesOf(workspace.text);
    const r = await call('config.dedup', { lines });
    setText(r.lines.join('\n'));
    await parseText();
    toast(r.removed ? `Removed ${r.removed} duplicates` : 'No duplicates found');
  });

  // ---------------------------------------------------------- layout
  root.append(
    h('section', { class: 'pane', 'aria-label': 'Config list' },
      h('div', { class: 'pane-head' }, countLabel, h('span', { class: 'grow' }),
        h('button', { class: 'btn', onclick: dedup, title: 'Remove duplicate configs' }, 'Remove duplicates'),
        h('button', { class: 'btn', onclick: exportDialog }, icon('download', 18), 'Export'),
        h('button', { class: 'btn primary', onclick: addLinks }, icon('plus', 18), 'Add links')),
      listBody),
    h('section', { class: 'pane', 'aria-label': 'Editor' }, inspectorHead, inspector));

  if (workspace.text.trim()) guarded(parseText); else { renderList(); renderInspector(); }
  Object.assign(els, { addLinks });
  return {
    id: 'configs', title: 'Configs', el: root, flush: true,
    actions: () => [h('button', { class: 'btn quiet', onclick: () => guarded(async () => { setText(''); workspace.rows = []; workspace.selected = -1; changed(); renderList(); renderInspector(); }) }, icon('trash', 18), 'Clear')],
    refresh: () => { if (workspace.text.trim() && !workspace.rows.length) guarded(parseText); else { renderList(); } },
  };
}
