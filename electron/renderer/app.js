'use strict';
// Renderer: plain DOM, no framework, no innerHTML (all text via textContent).
// Talks to the Python engine only through window.forge (preload bridge).

const $ = (sel, root = document) => root.querySelector(sel);

function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (v === true) el.setAttribute(k, '');
    else if (v !== false && v != null) el.setAttribute(k, v);
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

// ---------------------------------------------------------------- state
const state = { configs: [], selected: -1, info: null, hcJob: null, hcRows: [] };

// ------------------------------------------------------------- job plumbing
// Job events can arrive before the call that started the job has returned,
// so buffer them per job id until a handler registers.
const jobHandlers = new Map();
const jobBuffer = new Map();
window.forge.onJob((ev) => {
  const fn = jobHandlers.get(ev.job);
  if (fn) fn(ev);
  else { if (!jobBuffer.has(ev.job)) jobBuffer.set(ev.job, []); jobBuffer.get(ev.job).push(ev); }
});

async function runJob(method, params, onEvent, existingJob) {
  const job = existingJob || (await window.forge.call(method, params)).job;
  const wrapped = (ev) => {
    onEvent(ev);
    if (ev.type === 'done' || ev.type === 'error') { jobHandlers.delete(job); jobBuffer.delete(job); }
  };
  jobHandlers.set(job, wrapped);
  for (const ev of jobBuffer.get(job) || []) wrapped(ev);
  jobBuffer.delete(job);
  return job;
}

function say(el, text, bad = false) {
  el.textContent = text;
  el.classList.toggle('bad-text', bad);
}

async function guarded(msgEl, fn) {
  try { return await fn(); } catch (e) { say(msgEl, e.message || String(e), true); return undefined; }
}

const linesOf = (text) => text.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);

const onTab = {};

// ------------------------------------------------------------------ tabs
document.querySelectorAll('nav [role=tab]').forEach((btn) => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('nav [role=tab]').forEach((b) => b.setAttribute('aria-selected', String(b === btn)));
    document.querySelectorAll('.tab').forEach((s) => { s.hidden = s.id !== `tab-${btn.dataset.tab}`; });
    const hook = onTab[btn.dataset.tab];
    if (hook) guarded($('#engine-status'), hook);
  });
});

// --------------------------------------------------------------- configs
// Editor layout.  kind: text | select | check; `at` puts the value somewhere
// other than the top level of the outbound (extra.mode / extra.cs).
// `when(o, form)` says whether the field applies to this link; fields that do
// not apply are greyed out and keep the value the link already had.
const SECURITY_REALITY = (o, f) => (f.security || '').toLowerCase() === 'reality';
const EDIT_SECTIONS = [
  ['Basic', [
    { key: 'scheme', label: 'Protocol', kind: 'readonly' },
    { key: 'name', label: 'Name', kind: 'text', wide: true },
    { key: 'host', label: 'Address', kind: 'text' },
    { key: 'port', label: 'Port', kind: 'text' },
    { key: 'credential', label: 'ID / password', kind: 'text', wide: true },
    { key: 'ss_method', label: 'SS method', kind: 'text', when: (o) => o.scheme === 'ss' },
  ]],
  ['Transport', [
    { key: 'transport', label: 'Type', kind: 'select', options: 'transports' },
    { key: 'path', label: 'Path', kind: 'text' },
    { key: 'host_header', label: 'Host header', kind: 'text' },
    { key: 'service_name', label: 'gRPC serviceName', kind: 'text' },
    { key: 'header_type', label: 'Header type', kind: 'text' },
    { key: 'mode', at: 'extra', label: 'xhttp mode', kind: 'select', options: 'xhttp_modes',
      when: (o, f) => (f.transport || '') === 'xhttp' },
  ]],
  ['Security', [
    { key: 'security', label: 'Security', kind: 'select', options: 'securities' },
    { key: 'sni', label: 'SNI', kind: 'text' },
    { key: 'fingerprint', label: 'Fingerprint', kind: 'text' },
    { key: 'alpn', label: 'ALPN', kind: 'text' },
    { key: 'allow_insecure', label: 'allowInsecure (skip certificate check)', kind: 'check', wide: true },
  ]],
  ['Reality · VMess · cipher suites', [
    { key: 'flow', label: 'Flow', kind: 'select', options: 'flows' },
    { key: 'public_key', label: 'Reality public key (pbk)', kind: 'text', wide: true, when: SECURITY_REALITY },
    { key: 'short_id', label: 'Reality short id (sid)', kind: 'text', when: SECURITY_REALITY },
    { key: 'spider_x', label: 'Reality spiderX (spx)', kind: 'text', when: SECURITY_REALITY },
    { key: 'cs', at: 'extra', label: 'Cipher suites (cs)', kind: 'text', wide: true },
    { key: 'encryption', label: 'VMess scy', kind: 'text', when: (o) => o.scheme === 'vmess' },
    { key: 'alter_id', label: 'VMess alterId', kind: 'text', when: (o) => o.scheme === 'vmess' },
  ]],
];
const EDIT_FIELDS = EDIT_SECTIONS.flatMap(([, fields]) => fields);
const ed = { base: null };

function renderConfigs() {
  const body = $('#cfg-table tbody');
  body.replaceChildren(...state.configs.map((c, i) => {
    const o = c.outbound;
    const cores = c.ok
      ? Object.entries(c.supports).map(([k, v]) => h('span', { class: `chip ${v ? 'ok' : 'fail'}`, title: `${k}: ${v ? 'supported' : 'not supported'}` }, k))
      : [];
    return h('tr', { class: `${c.ok ? '' : 'bad'} ${i === state.selected ? 'selected' : ''}`, 'data-index': i, onclick: () => selectConfig(i) },
      h('td', {}, i + 1),
      h('td', {}, c.ok ? (o.name || '(unnamed)') : `unparsable: ${c.line.slice(0, 48)}`),
      h('td', {}, c.ok ? o.scheme : ''),
      h('td', {}, c.ok ? `${o.host}:${o.port}` : ''),
      h('td', {}, c.ok ? o.transport : ''),
      h('td', {}, c.ok ? (o.security || 'none') : ''),
      h('td', {}, cores));
  }));
  const ok = state.configs.filter((c) => c.ok).length;
  $('#cfg-count').textContent = `${ok} valid / ${state.configs.length} total`;
}

const fieldEl = (key) => $('#ed-form').elements[key];

function fieldValue(f, o) {
  const src = f.at ? (o[f.at] || {}) : o;
  const v = src[f.key];
  return f.kind === 'check' ? !!v : (v == null ? '' : String(v));
}

// Current form -> outbound.  Starts from the loaded outbound so everything the
// form has no field for (extra, extra_params, ...) survives the round trip.
function collectOutbound() {
  const o = JSON.parse(JSON.stringify(ed.base));
  const form = {};
  for (const f of EDIT_FIELDS) {
    const el = fieldEl(f.key);
    if (el) form[f.key] = f.kind === 'check' ? el.checked : el.value.trim();
  }
  for (const f of EDIT_FIELDS) {
    const el = fieldEl(f.key);
    if (!el || f.kind === 'readonly' || el.disabled) continue;   // not applicable: keep as loaded
    const val = form[f.key];
    if (f.at) {
      o[f.at] = o[f.at] || {};
      if (val) o[f.at][f.key] = val; else delete o[f.at][f.key];
    } else o[f.key] = val;
  }
  if (!o.port) o.port = '443';
  if (!o.path) o.path = '/';
  if (!o.transport) o.transport = 'tcp';
  return o;
}

// Grey out fields that do not apply to the link as currently edited.
function syncEditor() {
  const form = {};
  for (const f of EDIT_FIELDS) { const el = fieldEl(f.key); if (el) form[f.key] = f.kind === 'check' ? el.checked : el.value.trim(); }
  const o = { ...ed.base, ...form };
  for (const f of EDIT_FIELDS) {
    if (!f.when) continue;
    const el = fieldEl(f.key);
    const on = !!f.when(o, form);
    el.disabled = !on;
    el.closest('label').classList.toggle('off', !on);
  }
}

function buildEditor() {
  const info = (state.info && state.info.editor) || {};
  const o = ed.base;
  $('#ed-form').replaceChildren(...EDIT_SECTIONS.map(([title, fields]) =>
    h('fieldset', {}, h('legend', {}, title), ...fields.map((f) => {
      const val = fieldValue(f, o);
      let input;
      if (f.kind === 'select') {
        const opts = [...(info[f.options] || [])];
        if (!opts.includes(val)) opts.push(val);          // keep unusual values editable
        input = h('select', { name: f.key }, opts.map((x) => h('option', { value: x, selected: x === val }, x || '(none)')));
      } else if (f.kind === 'check') {
        input = h('input', { type: 'checkbox', name: f.key, checked: val });
      } else {
        input = h('input', { type: 'text', name: f.key, value: val, readonly: f.kind === 'readonly' });
      }
      input.addEventListener('input', syncEditor);
      input.addEventListener('change', syncEditor);
      return h('label', { class: f.wide ? 'wide' : '' }, f.kind === 'check' ? [input, f.label] : [f.label, input]);
    }))));
  syncEditor();
  $('#ed-json').value = JSON.stringify(o, null, 2);
}

function selectConfig(i) {
  state.selected = i;
  const c = state.configs[i];
  renderConfigs();
  const edBox = $('#editor');
  if (!c || !c.ok) { edBox.hidden = true; return; }
  edBox.hidden = false;
  ed.base = c.outbound;
  buildEditor();
  $('#ed-uri').value = c.line;
  say($('#ed-msg'), '');
}

async function parseInput() {
  const text = $('#cfg-input').value;
  const rows = await window.forge.call('config.parse_many', { text });
  state.configs = rows;
  state.selected = -1;
  $('#editor').hidden = true;
  renderConfigs();
}

function setConfigs(lines) {
  $('#cfg-input').value = lines.join('\n');
  return parseInput();
}

$('#cfg-parse').addEventListener('click', () => guarded($('#cfg-count'), parseInput));
$('#cfg-clear').addEventListener('click', () => { $('#cfg-input').value = ''; state.configs = []; renderConfigs(); $('#editor').hidden = true; });
$('#cfg-dedup').addEventListener('click', () => guarded($('#cfg-count'), async () => {
  const lines = state.configs.length ? state.configs.map((c) => c.line) : linesOf($('#cfg-input').value);
  const r = await window.forge.call('config.dedup', { lines });
  await setConfigs(r.lines);
  $('#cfg-count').textContent += ` (removed ${r.removed})`;
}));

$('#ed-apply').addEventListener('click', () => guarded($('#ed-msg'), async () => {
  const c = state.configs[state.selected];
  if (!c) return;
  const r = await window.forge.call('config.render', { outbound: collectOutbound() });
  const parsed = await window.forge.call('config.parse', { line: r.uri });
  state.configs[state.selected] = parsed;
  $('#cfg-input').value = state.configs.map((x) => x.line).join('\n');
  $('#ed-uri').value = r.uri;
  renderConfigs();
  if (parsed.ok) { ed.base = parsed.outbound; buildEditor(); }
  say($('#ed-msg'), r.roundtrip_ok ? 'Applied' : 'Applied, but the new link does not re-parse', !r.roundtrip_ok);
}));

$('#ed-copy').addEventListener('click', () => guarded($('#ed-msg'), async () => {
  const r = await window.forge.call('config.render', { outbound: collectOutbound() });
  $('#ed-uri').value = r.uri;
  await copyText(r.uri, $('#ed-msg'), 'link');
}));

$('#ed-to-json').addEventListener('click', () => guarded($('#ed-msg'), async () => {
  $('#ed-json').value = JSON.stringify(collectOutbound(), null, 2);
  say($('#ed-msg'), 'form → JSON');
}));

$('#ed-from-json').addEventListener('click', () => guarded($('#ed-msg'), async () => {
  const r = await window.forge.call('config.from_json', { text: $('#ed-json').value });
  ed.base = r.outbound;
  buildEditor();
  say($('#ed-msg'), 'JSON → form (press Apply to write the link)');
}));

$('#export-run').addEventListener('click', () => guarded($('#export-out'), async () => {
  const lines = state.configs.filter((c) => c.ok).map((c) => c.line);
  const r = await window.forge.call('config.export', { lines, format: $('#export-format').value });
  $('#export-out').value = r.content;
}));

// --------------------------------------------------------------- convert
const cv = { names: [], defaults: null, badgeTimer: null };

async function copyText(text, msgEl, what) {
  try {
    await navigator.clipboard.writeText(text);
    say(msgEl, `${what} copied`);
  } catch {
    // Fallback for contexts without the async clipboard API.
    const ta = h('textarea', { 'aria-hidden': 'true' });
    ta.style.position = 'fixed';        // CSSOM, not a style attribute: the CSP forbids inline styles
    ta.style.left = '-9999px';
    ta.value = text;
    document.body.append(ta);
    ta.select();
    const ok = document.execCommand && document.execCommand('copy');
    ta.remove();
    say(msgEl, ok ? `${what} copied` : 'copy failed: select the text and copy it manually', !ok);
  }
}

function cvMode() { return $('#cv-mode').value; }

function cvSyncMode() {
  const mode = cvMode();
  if (mode === 'full') for (const k of ['fp', 'cs', 'fm']) $(`#cv-want-${k}`).checked = true;
  if (mode === 'iponly') for (const k of ['fp', 'cs', 'fm']) $(`#cv-want-${k}`).checked = false;
  for (const k of ['fp', 'cs', 'fm']) {
    $(`#cv-want-${k}`).disabled = mode !== 'custom';
    $(`#cv-${k}`).disabled = mode === 'iponly';
  }
  $('#cv-tls-only').disabled = mode === 'iponly';
}

// Effective switches: "IP only" injects nothing whatever the checkboxes say.
function cvWant(k) { return cvMode() !== 'iponly' && $(`#cv-want-${k}`).checked; }

function cvOverride() {
  return {
    ip: $('#cv-ip-on').checked ? $('#cv-ip').value.trim() : '',
    port: $('#cv-port-on').checked ? $('#cv-port').value.trim() : '',
  };
}

function cvEndpointPreview() {
  const o = cvOverride();
  $('#cv-ep').textContent = `endpoint: ${o.ip || 'orig'} : ${o.port || 'orig'}`;
}

async function cvCheckOverride() {
  cvEndpointPreview();
  const o = cvOverride();
  const r = await window.forge.call('config.check_override', o);
  const ipBad = !!o.ip && r.ip == null;
  const portBad = !!o.port && r.port === false;
  say($('#cv-ip-badge'), o.ip ? (ipBad ? 'not an IP or domain' : r.ip) : '', ipBad);
  say($('#cv-port-badge'), o.port ? (portBad ? 'must be 1-65535' : 'ok') : '', portBad);
}
function cvScheduleCheck() {
  clearTimeout(cv.badgeTimer);
  cv.badgeTimer = setTimeout(() => guarded($('#cv-msg'), cvCheckOverride), 150);
}

function cvRenderNames() {
  $('#cv-names').replaceChildren(...cv.names.map((n) =>
    h('li', { tabindex: 0, role: 'button', title: 'Click to copy this config',
      onclick: () => copyText(n.line, $('#cv-msg'), 'config'),
      onkeydown: (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); copyText(n.line, $('#cv-msg'), 'config'); } } },
    n.name || '(unnamed)')));
}

function cvParams() {
  const o = cvOverride();
  const params = {
    text: $('#cv-input').value, dedup: $('#cv-dedup').checked,
    fp: $('#cv-fp').value, cs: $('#cv-cs').value, fm: $('#cv-fm').value,
    tls_only: $('#cv-tls-only').checked, rename: $('#cv-rename').checked,
    want_fp: cvWant('fp'), want_cs: cvWant('cs'), want_fm: cvWant('fm'),
    start: Number($('#cv-start').value || 1), ip: o.ip, port: o.port,
  };
  const tpl = $('#cv-template').value.trim();
  if (tpl) params.template = tpl;
  return params;
}

function cvResetRules() {
  const d = cv.defaults;
  if (!d) return;
  $('#cv-mode').value = 'full';
  $('#cv-fp').value = d.fp;
  $('#cv-cs').value = d.cs;
  $('#cv-fm').value = JSON.stringify(d.fm);
  $('#cv-template').value = d.template;
  $('#cv-start').value = '1';
  for (const id of ['tls-only', 'rename', 'dedup']) $(`#cv-${id}`).checked = true;
  cvClearOverride();
  cvSyncMode();
}

function cvClearOverride() {
  $('#cv-ip').value = ''; $('#cv-port').value = '';
  $('#cv-ip-on').checked = false; $('#cv-port-on').checked = false;
  cvScheduleCheck();
}

$('#cv-mode').addEventListener('change', cvSyncMode);
for (const id of ['cv-ip', 'cv-port', 'cv-ip-on', 'cv-port-on']) {
  $(`#${id}`).addEventListener('input', cvScheduleCheck);
  $(`#${id}`).addEventListener('change', cvScheduleCheck);
}
// Typing a value switches its override on, like ticking the box.
$('#cv-ip').addEventListener('input', () => { $('#cv-ip-on').checked = $('#cv-ip').value.trim() !== ''; });
$('#cv-port').addEventListener('input', () => { $('#cv-port-on').checked = $('#cv-port').value.trim() !== ''; });
$('#cv-ov-clear').addEventListener('click', cvClearOverride);
$('#cv-reset').addEventListener('click', cvResetRules);

$('#cv-run').addEventListener('click', () => guarded($('#cv-msg'), async () => {
  const r = await window.forge.call('config.convert', cvParams());
  $('#cv-output').value = r.lines.join('\n');
  cv.names = r.names;
  cvRenderNames();
  const c = r.counts;
  const o = cvOverride();
  const ep = o.ip || o.port ? ` · endpoint → ${o.ip || 'orig'}:${o.port || 'orig'}` : '';
  say($('#cv-msg'), `${c.fixed} fixed · ${c.unchanged} unchanged · ${c.skipped} skipped · ${r.removed} duplicates removed${ep}`);
}));
$('#cv-copy').addEventListener('click', () => {
  const text = $('#cv-output').value;
  if (!text.trim()) { say($('#cv-msg'), 'nothing to copy'); return; }
  copyText(text, $('#cv-msg'), 'output');
});
$('#cv-copy-names').addEventListener('click', () => {
  if (!cv.names.length) { say($('#cv-msg'), 'no names to copy'); return; }
  copyText(cv.names.map((n) => n.name).join('\n'), $('#cv-msg'), `${cv.names.length} names`);
});
$('#cv-send').addEventListener('click', () => guarded($('#cv-msg'), async () => {
  await setConfigs(linesOf($('#cv-output').value));
  document.querySelector('[data-tab=configs]').click();
}));

// ---------------------------------------------------------------- health
// Rows are selectable (click = only this one, Ctrl/Cmd-click = toggle). Selection is a
// Set of config lines so it survives the table being rebuilt while results stream in.
function healthRow(r, sel) {
  const cls = [r.passed ? '' : 'bad', sel && sel.has(r.line) ? 'selected' : ''].filter(Boolean).join(' ');
  const tr = h('tr', { class: cls, onclick: (e) => {
    if (!sel) return;
    if (e.ctrlKey || e.metaKey) { if (sel.has(r.line)) sel.delete(r.line); else sel.add(r.line); tr.classList.toggle('selected'); }
    else { sel.clear(); sel.add(r.line); tr.parentElement.querySelectorAll('tr.selected').forEach((x) => x.classList.remove('selected')); tr.classList.add('selected'); }
    if (sel.onchange) sel.onchange();
  } },
    h('td', {}, Math.round(r.score || 0)),
    h('td', {}, r.name || (r.line || '').slice(0, 40)),
    h('td', {}, r.scheme),
    h('td', {}, (r.stages || []).map((s) =>
      h('span', { class: `chip ${s.ok ? 'ok' : 'fail'}`, title: s.detail || '' }, `${s.name}${s.ms != null ? ' ' + Math.round(s.ms) + 'ms' : ''}`))),
    h('td', {}, (r.techniques || []).join(', ')));
  return tr;
}
const byScore = (rows) => [...rows].sort((a, b) => (b.score || 0) - (a.score || 0));
function renderHealth() {
  $('#hc-table tbody').replaceChildren(...byScore(state.hcRows).map((r) => healthRow(r, hcSel)));
}

function setHcRunning(running) {
  $('#hc-start').disabled = running;
  $('#hc-retest').disabled = running || hcSel.size === 0;
  $('#hc-cancel').disabled = !running;
}

const hcSel = new Set();
hcSel.onchange = () => {
  $('#hc-retest').disabled = hcSel.size === 0 || $('#hc-start').disabled;
  $('#hc-copy').disabled = hcSel.size !== 1;
};

// Run the health pipeline over `lines`; rows of those lines are replaced as new results stream in.
async function runHealth(lines) {
  const redo = new Set(lines);
  state.hcRows = state.hcRows.filter((r) => !redo.has(r.line));
  hcSel.clear();
  renderHealth();
  hcSel.onchange();
  $('#hc-keep').disabled = true;
  $('#hc-tag').disabled = true;
  $('#hc-progress').value = 0;
  $('#hc-progress').max = lines.length;
  setHcRunning(true);
  say($('#hc-status'), 'running…');
  const params = {
    lines, workers: Number($('#hc-workers').value), timeout: Number($('#hc-timeout').value),
    throughput: $('#hc-throughput').checked,
  };
  if ($('#hc-core').value) params.core = $('#hc-core').value;
  try {
    state.hcJob = await runJob('health.run', params, (ev) => {
      if (ev.type === 'item' && ev.data.line !== undefined) { state.hcRows.push(ev.data); renderHealth(); }
      else if (ev.type === 'progress') { $('#hc-progress').max = ev.total; $('#hc-progress').value = ev.done; say($('#hc-status'), `${ev.done}/${ev.total}`); }
      else if (ev.type === 'done') {
        setHcRunning(false);
        const passed = state.hcRows.filter((r) => r.passed).length;
        say($('#hc-status'), `${ev.cancelled ? 'cancelled' : 'done'}: ${passed} of ${state.hcRows.length} passed`);
        $('#hc-keep').disabled = passed === 0;
        $('#hc-tag').disabled = !state.hcRows.some(hcCountry);
      } else if (ev.type === 'error') { setHcRunning(false); say($('#hc-status'), ev.message, true); }
    });
  } catch (e) { setHcRunning(false); throw e; }   // a refused start must not leave Run disabled
}
$('#hc-start').addEventListener('click', () => guarded($('#hc-status'), async () => {
  const lines = state.configs.filter((c) => c.ok).map((c) => c.line);
  if (!lines.length) { say($('#hc-status'), 'No valid configs: parse some in the Configs tab first', true); return; }
  state.hcRows = [];
  await runHealth(lines);
}));
$('#hc-retest').addEventListener('click', () => guarded($('#hc-status'), async () => {
  if (!hcSel.size) { say($('#hc-status'), 'select rows to retest (Ctrl/Cmd-click for several)'); return; }
  await runHealth([...hcSel]);
}));
$('#hc-copy').addEventListener('click', () => {
  if (hcSel.size !== 1) return;
  copyText([...hcSel][0], $('#hc-status'), 'link');
});
$('#hc-cancel').addEventListener('click', () => { if (state.hcJob) window.forge.call('job.cancel', { job: state.hcJob }); });
// Exit country reported by the core-backed request stage, if any.
const hcCountry = (r) => {
  const st = (r.stages || []).find((x) => x.name === 'request' && x.data && x.data.cc);
  return st ? st.data.cc : '';
};

$('#hc-tag').addEventListener('click', () => guarded($('#hc-status'), async () => {
  const idx = [];
  const items = [];
  state.hcRows.forEach((r, i) => { const cc = hcCountry(r); if (cc) { idx.push(i); items.push({ line: r.line, cc }); } });
  if (!items.length) { say($('#hc-status'), 'no result reported an exit country (run with a proxy core)', true); return; }
  const res = await window.forge.call('config.tag_cc', { items });
  res.items.forEach((it, k) => {
    const row = state.hcRows[idx[k]];
    row.line = it.line;
    if (it.name) row.name = it.name;
  });
  hcSel.clear();
  renderHealth();
  hcSel.onchange();
  say($('#hc-status'), `tagged ${res.tagged} config name(s) with [exit-country]`);
}));

$('#hc-keep').addEventListener('click', () => guarded($('#hc-status'), async () => {
  const keep = state.hcRows.filter((r) => r.passed).sort((a, b) => b.score - a.score).map((r) => r.line);
  await setConfigs(keep);
  document.querySelector('[data-tab=configs]').click();
}));

// --------------------------------------------------------- subscriptions
async function refreshSubs() {
  const subs = await window.forge.call('sub.list', {});
  $('#sub-table tbody').replaceChildren(...subs.map((s) =>
    h('tr', {},
      h('td', {}, h('input', { type: 'checkbox', checked: s.enabled, 'aria-label': `enable ${s.url}`,
        onchange: (e) => guarded($('#sub-msg'), () => window.forge.call('sub.set_enabled', { url: s.url, enabled: e.target.checked })) })),
      h('td', {}, s.name),
      h('td', {}, s.url),
      h('td', {}, s.last_count),
      h('td', {}, s.last_status || '—'),
      h('td', {}, h('button', { class: 'sub-remove', onclick: () => guarded($('#sub-msg'), async () => { await window.forge.call('sub.remove', { url: s.url }); await refreshSubs(); }) }, 'Remove')))));
}
$('#sub-add').addEventListener('click', () => guarded($('#sub-msg'), async () => {
  await window.forge.call('sub.add', { url: $('#sub-url').value.trim(), name: $('#sub-name').value.trim() });
  $('#sub-url').value = ''; $('#sub-name').value = '';
  say($('#sub-msg'), '');
  await refreshSubs();
}));
$('#sub-fetch').addEventListener('click', () => guarded($('#sub-msg'), async () => {
  say($('#sub-msg'), 'fetching…');
  await runJob('sub.fetch', {}, async (ev) => {
    if (ev.type === 'done') {
      const t = ev.result || {};
      say($('#sub-msg'), t.total !== undefined ? `fetched: ${t.total} configs (${t.removed} duplicates removed)` : 'fetched');
      await refreshSubs();
    }
    else if (ev.type === 'error') say($('#sub-msg'), ev.message, true);
  });
}));
$('#sub-load').addEventListener('click', () => guarded($('#sub-msg'), async () => {
  const r = await window.forge.call('sub.configs', { dedupe: true });
  await setConfigs(r.lines);
  document.querySelector('[data-tab=configs]').click();
}));

// Check every enabled source (engine-side: configs never cross the pipe) and
// export the best N from the engine's own scores.
const sk = { rows: [], job: '', sel: new Set() };
sk.sel.onchange = () => { $('#sk-copy').disabled = sk.sel.size !== 1; };
const skSetRunning = (on) => { $('#sk-start').disabled = on; $('#sk-cancel').disabled = !on; };
const skRender = () => $('#sk-table tbody').replaceChildren(...byScore(sk.rows).filter((r) => r.line !== undefined).map((r) => healthRow(r, sk.sel)));
const skOpts = () => {
  const o = { workers: Number($('#sk-workers').value), timeout: Number($('#sk-timeout').value), throughput: $('#sk-throughput').checked };
  if ($('#sk-core').value) o.core = $('#sk-core').value;
  return o;
};
$('#sk-start').addEventListener('click', () => guarded($('#sk-status'), async () => {
  sk.rows = []; sk.job = ''; sk.sel.clear(); sk.sel.onchange();
  skRender();
  $('#sk-out').value = '';
  ['#sk-export', '#sk-tagged', '#sk-load'].forEach((b) => { $(b).disabled = true; });
  skSetRunning(true);
  say($('#sk-status'), 'starting…');
  try {
    const r = await window.forge.call('sub.check', skOpts());
    sk.job = r.job;
    $('#sk-progress').max = r.total; $('#sk-progress').value = 0;
    say($('#sk-status'), `checking ${r.total} configs (${r.removed} duplicates removed)…`);
    await runJob('sub.check', {}, (ev) => {
      if (ev.type === 'item') { sk.rows.push(ev.data); skRender(); }
      else if (ev.type === 'progress') { $('#sk-progress').max = ev.total; $('#sk-progress').value = ev.done; say($('#sk-status'), `${ev.done}/${ev.total}`); }
      else if (ev.type === 'done') {
        skSetRunning(false);
        const passed = sk.rows.filter((x) => x.passed).length;
        say($('#sk-status'), `${ev.cancelled ? 'cancelled' : 'done'}: ${passed} of ${sk.rows.filter((x) => x.line !== undefined).length} passed`);
        ['#sk-export', '#sk-tagged', '#sk-load'].forEach((b) => { $(b).disabled = passed === 0; });
      } else if (ev.type === 'error') { skSetRunning(false); say($('#sk-status'), ev.message, true); }
    }, r.job);
  } catch (e) { skSetRunning(false); throw e; }
}));
$('#sk-copy').addEventListener('click', () => { if (sk.sel.size === 1) copyText([...sk.sel][0], $('#sk-status'), 'link'); });
$('#sk-cancel').addEventListener('click', () => { if (sk.job) window.forge.call('job.cancel', { job: sk.job }); });
const skTopN = () => Number($('#sk-n').value);
$('#sk-export').addEventListener('click', () => guarded($('#sk-status'), async () => {
  const r = await window.forge.call('health.export_best', { job: sk.job, top_n: skTopN() });
  $('#sk-out').value = r.content;
  say($('#sk-status'), r.count ? `best ${r.count} working config(s) as a base64 subscription` : 'no working configs to export', !r.count);
  if (r.content) copyText(r.content, $('#sk-status'), `subscription (${r.count} configs)`);
}));
$('#sk-tagged').addEventListener('click', () => guarded($('#sk-status'), async () => {
  const r = await window.forge.call('health.tagged', { job: sk.job });
  $('#sk-out').value = r.lines.join('\n');
  say($('#sk-status'), `${r.lines.length} working config(s), names tagged with the techniques that worked`);
}));
$('#sk-load').addEventListener('click', () => guarded($('#sk-status'), async () => {
  const r = await window.forge.call('health.tagged', { job: sk.job });
  await setConfigs(r.lines.slice(0, skTopN()));
  document.querySelector('[data-tab=configs]').click();
}));

// ------------------------------------------------------------- helpers
const call = (m, p = {}) => window.forge.call(m, p);
const fmtMs = (v) => (v == null ? '' : String(Math.round(v)));

// Highlight one row without rebuilding the table (rebuilding between the two
// clicks of a double-click would swallow the dblclick).
function markSelected(tr) {
  const body = tr.parentElement;
  body.querySelectorAll('tr.selected').forEach((x) => x.classList.remove('selected'));
  tr.classList.add('selected');
}

// "Use as FORCE IP": fill the Convert tab's endpoint override.
function useAsForceIp(ip, port, msgEl) {
  $('#cv-ip').value = ip;
  $('#cv-ip-on').checked = true;
  if (port) { $('#cv-port').value = String(port); $('#cv-port-on').checked = true; }
  cvScheduleCheck();
  say(msgEl, `FORCE IP set to ${ip}${port ? ':' + port : ''} (Convert tab)`);
}

function fillSelect(sel, items, placeholder) {
  const keep = sel.value;
  sel.replaceChildren(h('option', { value: '' }, placeholder),
    ...items.map((i) => h('option', { value: i.name }, `${i.name} (${i.label})`)));
  if ([...sel.options].some((o) => o.value === keep)) sel.value = keep;
}

async function refreshScanSessions() {
  const list = await call('scan.sessions');
  const items = list.map((x) => ({ name: x.name, label: `${x.alive}/${x.total} alive${x.pending ? `, ${x.pending} pending` : ''}` }));
  fillSelect($('#sc-sessions'), items, '(none)');
  fillSelect($('#sn-from-scan'), items, '(none)');
}

function progressHandlers(prefix) {
  return {
    progress: (ev) => { $(`#${prefix}-progress`).max = ev.total || 1; $(`#${prefix}-progress`).value = ev.done; },
  };
}

// --------------------------------------------------------------- scanner
const sc = { rows: new Map(), job: null, selected: '' };

function renderScan() {
  const showDead = $('#sc-dead').checked;
  const rows = [...sc.rows.values()].filter((r) => r.alive || showDead)
    .sort((a, b) => (a.alive === b.alive ? (a.ms ?? 9e9) - (b.ms ?? 9e9) : a.alive ? -1 : 1));
  $('#sc-table tbody').replaceChildren(...rows.map((r) => h('tr', {
    class: `${r.alive ? '' : 'bad'} ${sc.selected === r.ip ? 'selected' : ''}`,
    onclick: (e) => selectScanRow(r, e.currentTarget),
    ondblclick: () => copyText(r.ip, $('#sc-status'), 'IP') },
    h('td', {}, r.ip), h('td', {}, r.port), h('td', {}, fmtMs(r.ms)), h('td', {}, fmtMs(r.jitter)),
    h('td', {}, r.tls), h('td', {}, r.cc), h('td', {}, r.isp), h('td', {}, r.info))));
}
$('#sc-dead').addEventListener('change', renderScan);

function clearScanSelection() {
  sc.selected = '';
  $('#sc-copy-ip').disabled = true;
  $('#sc-use-ip').disabled = true;
}
function selectScanRow(r, tr) {
  sc.selected = r.ip;
  markSelected(tr);
  $('#sc-copy-ip').disabled = false;
  $('#sc-use-ip').disabled = false;
}
$('#sc-copy-ip').addEventListener('click', () => { if (sc.selected) copyText(sc.selected, $('#sc-status'), 'IP'); });
$('#sc-use-ip').addEventListener('click', () => {
  const r = sc.rows.get(sc.selected);
  if (r) useAsForceIp(r.ip, r.port, $('#sc-status'));
});

function scStatus() {
  const all = [...sc.rows.values()];
  return `${all.filter((r) => r.alive).length} alive of ${all.length} checked`;
}

async function startScan(resume) {
  const cidrs = linesOf($('#sc-cidrs').value);
  const params = {
    cidrs, count: Number($('#sc-count').value), port: $('#sc-port').value,
    workers: Number($('#sc-workers').value), geo: $('#sc-geo').checked,
  };
  if ($('#sc-sni').value.trim()) params.sni = $('#sc-sni').value.trim();
  params.frag = $('#sc-frag').value.trim() || 'off';
  if (resume) { params.resume = true; params.session = $('#sc-sessions').value; }
  const r = await call('scan.run', params);
  sc.rows = new Map();
  clearScanSelection();
  renderScan();
  $('#sc-progress').value = 0;
  $('#sc-start').disabled = true; $('#sc-resume').disabled = true; $('#sc-cancel').disabled = false;
  say($('#sc-status'), `scanning ${r.targets} IPs…`);
  sc.job = r.job;
  await runJob(null, null, (ev) => {
    if (ev.type === 'item') { sc.rows.set(ev.data.ip, ev.data); renderScan(); }
    else if (ev.type === 'progress') { $('#sc-progress').max = ev.total; $('#sc-progress').value = ev.done; say($('#sc-status'), `${ev.done}/${ev.total} · ${scStatus()}`); }
    else if (ev.type === 'done' || ev.type === 'error') {
      $('#sc-start').disabled = false; $('#sc-resume').disabled = false; $('#sc-cancel').disabled = true;
      say($('#sc-status'), ev.type === 'error' ? ev.message : `${ev.cancelled ? 'cancelled' : 'done'}: ${scStatus()}`, ev.type === 'error');
      refreshScanSessions().catch(() => {});
    }
  }, r.job);
}

$('#sc-start').addEventListener('click', () => guarded($('#sc-status'), () => startScan(false)));
$('#sc-resume').addEventListener('click', () => guarded($('#sc-status'), () => startScan(true)));
$('#sc-cancel').addEventListener('click', () => { if (sc.job) call('job.cancel', { job: sc.job }); });
$('#sc-load').addEventListener('click', () => guarded($('#sc-status'), async () => {
  const name = $('#sc-sessions').value;
  if (!name) { say($('#sc-status'), 'choose a saved scan first', true); return; }
  const r = await call('scan.get', { session: name });
  sc.rows = new Map(r.results.map((x) => [x.ip, x]));
  clearScanSelection();
  renderScan();
  say($('#sc-status'), `loaded ${name}: ${scStatus()}${r.pending ? `, ${r.pending} pending` : ''}`);
}));
$('#sc-export').addEventListener('click', () => guarded($('#sc-status'), async () => {
  const name = $('#sc-sessions').value;
  if (!name) { say($('#sc-status'), 'choose a saved scan to export', true); return; }
  $('#sc-out').value = (await call('scan.export', { session: name, format: $('#sc-fmt').value })).content;
}));
$('#sc-clear').addEventListener('click', () => {
  sc.rows = new Map(); clearScanSelection(); renderScan(); $('#sc-out').value = '';
  say($('#sc-status'), 'cleared (saved scans are kept)');
});
$('#sc-preset').addEventListener('change', () => {
  const key = $('#sc-preset').value;
  const ranges = (state.info && state.info.ranges && state.info.ranges[key]) || [];
  const have = new Set(linesOf($('#sc-cidrs').value));
  const add = ranges.filter((c) => !have.has(c));
  $('#sc-cidrs').value = [...have, ...add].join('\n');
  $('#sc-cidrs').dispatchEvent(new Event('input', { bubbles: true }));
  $('#sc-preset').value = '';
  say($('#sc-status'), key ? `added ${add.length} ${key} range(s)` : '');
});
$('#sc-to-sni').addEventListener('click', () => {
  const ips = [...sc.rows.values()].filter((r) => r.alive).sort((a, b) => a.ms - b.ms).map((r) => r.ip);
  $('#sn-ips').value = ips.join('\n');
  document.querySelector('[data-tab=sni]').click();
});
onTab.scan = refreshScanSessions;

// ------------------------------------------------------- lookup (geo, DNS)
const net = { selected: '' };

async function runGeo(ip) {
  say($('#net-msg'), ip ? `looking up ${ip}…` : 'looking up your IP…');
  const r = await call('net.geo', { ip });
  const out = $('#net-geo-out');
  out.hidden = false;
  out.textContent = r.text;
  say($('#net-msg'), r.ok ? 'done' : 'every lookup provider failed', !r.ok);
}
$('#net-myip').addEventListener('click', () => guarded($('#net-msg'), () => runGeo('')));
$('#net-geo').addEventListener('click', () => guarded($('#net-msg'), () => runGeo($('#net-geo-q').value.trim())));

function selectNetRow(ip, tr) {
  net.selected = ip;
  markSelected(tr);
  $('#net-copy-ip').disabled = false;
  $('#net-use-ip').disabled = false;
}

$('#net-resolve').addEventListener('click', () => guarded($('#net-msg'), async () => {
  const host = $('#net-host').value.trim();
  if (!host) { say($('#net-msg'), 'enter a host', true); return; }
  say($('#net-msg'), `resolving ${host}…`);
  $('#net-resolve').disabled = true;
  try {
    const r = await call('net.resolve', { host });
    $('#net-res-box').hidden = false;
    net.selected = '';
    $('#net-copy-ip').disabled = true;
    $('#net-use-ip').disabled = true;
    $('#net-res-table tbody').replaceChildren(...r.answers.map((a) => h('tr', {
      onclick: (e) => selectNetRow(a.ip, e.currentTarget),
      ondblclick: () => copyText(a.ip, $('#net-msg'), 'IP') },
    h('td', {}, a.ip), h('td', {}, a.sources.join(', ')))));
    say($('#net-msg'), r.answers.length ? `resolved ${r.answers.length} IP(s)` : 'no answers', !r.answers.length);
  } finally { $('#net-resolve').disabled = false; }
}));
$('#net-host').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('#net-resolve').click(); });
$('#net-geo-q').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('#net-geo').click(); });
$('#net-copy-ip').addEventListener('click', () => { if (net.selected) copyText(net.selected, $('#net-msg'), 'IP'); });
$('#net-use-ip').addEventListener('click', () => { if (net.selected) useAsForceIp(net.selected, '', $('#net-msg')); });

// ------------------------------------------------------------ SNI search
const sn = { rows: new Map(), job: null, session: '', selected: '' };

function clearSniSelection() {
  sn.selected = '';
  $('#sn-copy').disabled = true;
  $('#sn-use-ip').disabled = true;
}
function selectSniRow(r, tr) {
  sn.selected = `${r.ip}|${r.sni}`;
  markSelected(tr);
  $('#sn-copy').disabled = false;
  $('#sn-use-ip').disabled = false;
}
$('#sn-copy').addEventListener('click', () => {
  const r = sn.rows.get(sn.selected);
  if (r) copyText(`${r.ip}  sni=${r.sni}`, $('#sn-status'), 'IP + SNI');
});
$('#sn-use-ip').addEventListener('click', () => {
  const r = sn.rows.get(sn.selected);
  if (r) useAsForceIp(r.ip, '', $('#sn-status'));
});

function renderSni() {
  const rows = [...sn.rows.values()].filter((r) => r.ok)
    .sort((a, b) => (b.http_ok - a.http_ok) || ((a.tls_ms ?? 9e9) - (b.tls_ms ?? 9e9)));
  $('#sn-table tbody').replaceChildren(...rows.map((r) => h('tr', {
    class: sn.selected === `${r.ip}|${r.sni}` ? 'selected' : '',
    onclick: (e) => selectSniRow(r, e.currentTarget),
    ondblclick: () => copyText(`${r.ip}  sni=${r.sni}`, $('#sn-status'), 'IP + SNI') },
    h('td', {}, r.ip), h('td', {}, r.sni), h('td', {}, fmtMs(r.tls_ms)), h('td', {}, r.tls_ver),
    h('td', {}, h('span', { class: `chip ${r.http_ok ? 'ok' : 'fail'}` }, r.http_ok ? 'ok' : 'no')),
    h('td', {}, r.info))));
}

$('#sn-start').addEventListener('click', () => guarded($('#sn-status'), async () => {
  const params = {
    ips: linesOf($('#sn-ips').value.replace(/[,\s]+/g, '\n')),
    snis: linesOf($('#sn-snis').value.replace(/[,\s]+/g, '\n')),
    presets: $('#sn-presets').checked, http_check: $('#sn-http').checked,
    port: $('#sn-port').value, workers: Number($('#sn-workers').value),
    frag: $('#sn-frag').value.trim() || 'off',
  };
  if ($('#sn-from-scan').value) params.from_scan = $('#sn-from-scan').value;
  const r = await call('sni.run', params);
  sn.rows = new Map(); sn.session = r.session; clearSniSelection(); renderSni();
  $('#sn-start').disabled = true; $('#sn-cancel').disabled = false;
  say($('#sn-status'), `probing ${r.pairs} (IP, SNI) pairs…`);
  sn.job = r.job;
  await runJob(null, null, (ev) => {
    if (ev.type === 'item') { sn.rows.set(`${ev.data.ip}|${ev.data.sni}`, ev.data); renderSni(); }
    else if (ev.type === 'progress') { $('#sn-progress').max = ev.total; $('#sn-progress').value = ev.done; say($('#sn-status'), `${ev.done}/${ev.total} · ${[...sn.rows.values()].filter((x) => x.ok).length} working`); }
    else if (ev.type === 'done' || ev.type === 'error') {
      $('#sn-start').disabled = false; $('#sn-cancel').disabled = true;
      say($('#sn-status'), ev.type === 'error' ? ev.message : `${ev.cancelled ? 'cancelled' : 'done'}: ${[...sn.rows.values()].filter((x) => x.ok).length} working of ${sn.rows.size}`, ev.type === 'error');
    }
  }, r.job);
}));
$('#sn-cancel').addEventListener('click', () => { if (sn.job) call('job.cancel', { job: sn.job }); });
$('#sn-export').addEventListener('click', () => guarded($('#sn-status'), async () => {
  if (!sn.session) { say($('#sn-status'), 'run a search first', true); return; }
  $('#sn-out').value = (await call('sni.export', { session: sn.session, format: $('#sn-fmt').value })).content;
}));
$('#sn-clear').addEventListener('click', () => {
  sn.rows = new Map(); clearSniSelection(); renderSni(); $('#sn-out').value = '';
  say($('#sn-status'), 'cleared (saved searches are kept)');
});
onTab.sni = refreshScanSessions;

// ------------------------------------------------------------------ WARP
const wp = { job: null };

async function refreshWarp() {
  const st = await call('warp.status');
  $('#wp-status').textContent = st.registered
    ? `registered · device ${st.device_id}… · endpoint ${st.endpoint}` : 'no WARP device registered yet';
  $('#wp-register').textContent = st.registered ? 'Re-register device' : 'Register WARP device';
}
onTab.warp = refreshWarp;

$('#wp-register').addEventListener('click', () => guarded($('#wp-status'), async () => {
  say($('#wp-status'), 'registering…');
  await call('warp.register', {}).catch((e) => { throw e; });
  await refreshWarp();
}));
$('#wp-scan').addEventListener('click', () => guarded($('#wp-status'), async () => {
  const r = await call('warp.scan', { count: Number($('#wp-count').value) });
  $('#wp-table tbody').replaceChildren();
  $('#wp-scan').disabled = true; $('#wp-cancel').disabled = false;
  wp.job = r.job;
  await runJob(null, null, (ev) => {
    if (ev.type === 'item') {
      $('#wp-table tbody').append(h('tr', { onclick: () => { $('#wp-endpoint').value = ev.data.endpoint; } },
        h('td', {}, ev.data.endpoint), h('td', {}, fmtMs(ev.data.ms))));
    } else if (ev.type === 'progress') { $('#wp-progress').max = ev.total; $('#wp-progress').value = ev.done; }
    else if (ev.type === 'done' || ev.type === 'error') {
      $('#wp-scan').disabled = false; $('#wp-cancel').disabled = true;
      if (ev.type === 'error') say($('#wp-status'), ev.message, true);
    }
  }, r.job);
}));
$('#wp-cancel').addEventListener('click', () => { if (wp.job) call('job.cancel', { job: wp.job }); });
$('#wp-config').addEventListener('click', () => guarded($('#wp-status'), async () => {
  const params = { format: $('#wp-format').value };
  if ($('#wp-endpoint').value.trim()) params.endpoint = $('#wp-endpoint').value.trim();
  $('#wp-out').value = (await call('warp.config', params)).content;
}));

// ----------------------------------------------------------- MITM fronting
async function loadMitm() {
  const g = await call('mitm.groups');
  $('#mt-min').textContent = `requires Xray-core ≥ ${g.min_xray_version}`;
  const box = $('#mt-groups');
  if (box.querySelector('input')) return;
  for (const name of Object.keys(g.groups)) {
    box.append(h('label', {}, h('input', { type: 'checkbox', value: name, checked: g.defaults.includes(name) }), name));
  }
  const ca = await call('mitm.ca_paths');
  $('#mt-ca-status').textContent = ca.exists ? `CA exists: ${ca.cert}` : 'no CA generated yet';
}
onTab.mitm = loadMitm;

const mtGroups = () => [...document.querySelectorAll('#mt-groups input:checked')].map((i) => i.value);
$('#mt-build').addEventListener('click', () => guarded($('#mt-msg'), async () => {
  const r = await call('mitm.build', { groups: mtGroups(), use_generated_ca: $('#mt-use-ca').checked });
  $('#mt-out').value = r.content;
  say($('#mt-msg'), `built · needs Xray-core ≥ ${r.min_xray_version}`);
}));
$('#mt-guide').addEventListener('click', () => guarded($('#mt-msg'), async () => {
  $('#mt-out').value = (await call('mitm.guide', { platform: $('#mt-platform').value })).content;
  say($('#mt-msg'), '');
}));
$('#mt-ca').addEventListener('click', () => guarded($('#mt-msg'), async () => {
  const params = { cn: $('#mt-cn').value.trim() };
  const pd = $('#mt-permitted').value.split(/[,\s]+/).filter(Boolean);
  if (pd.length) params.permitted_domains = pd;
  const r = await call('mitm.generate_ca', params);
  $('#mt-ca-status').textContent = `CA written: ${r.cert}${r.constrained ? ' (name-constrained)' : ''}`;
  say($('#mt-msg'), r.note);
}));

// ------------------------------------------------------- native file dialogs
// Opening and saving go through the main process (files.js): the renderer only
// names a kind of file and gets back text or the path the user picked.
async function openTextInto(textarea, msgEl, title) {
  if (!window.forge.openText) { say(msgEl, 'opening files needs the desktop app', true); return null; }
  const r = await window.forge.openText({ kind: 'text', title });
  if (!r) { say(msgEl, 'open cancelled'); return null; }
  textarea.value = r.text;
  textarea.dispatchEvent(new Event('input', { bubbles: true }));
  say(msgEl, `loaded ${r.path}`);
  return r;
}
async function saveTextAs(text, name, kind, msgEl) {
  if (!text || !text.trim()) { say(msgEl, 'nothing to save'); return; }
  if (!window.forge.saveText) { say(msgEl, 'saving files needs the desktop app', true); return; }
  const p = await window.forge.saveText({ text, defaultName: name, kind });
  say(msgEl, p ? `saved ${p}` : 'save cancelled');
}
const EXPORT_FILES = { clash: ['config.yaml', 'yaml'], singbox: ['config.json', 'json'], sub: ['subscription.txt', 'text'] };

$('#cfg-open').addEventListener('click', () => guarded($('#cfg-count'), async () => {
  if (await openTextInto($('#cfg-input'), $('#cfg-count'), 'Open links')) await parseInput();
}));
$('#cv-open').addEventListener('click', () => guarded($('#cv-msg'), () => openTextInto($('#cv-input'), $('#cv-msg'), 'Open links')));
$('#cv-save').addEventListener('click', () => guarded($('#cv-msg'), () => saveTextAs($('#cv-output').value, 'vless_fixed.txt', 'text', $('#cv-msg'))));
$('#export-save').addEventListener('click', () => guarded($('#export-msg'), () => {
  const [name, kind] = EXPORT_FILES[$('#export-format').value] || ['export.txt', 'text'];
  return saveTextAs($('#export-out').value, name, kind, $('#export-msg'));
}));
$('#sk-save').addEventListener('click', () => guarded($('#sk-status'), () => saveTextAs($('#sk-out').value, 'best_sub.txt', 'text', $('#sk-status'))));
$('#sc-save').addEventListener('click', () => guarded($('#sc-status'), () => saveTextAs($('#sc-out').value, `${$('#sc-sessions').value || 'scan'}.${$('#sc-fmt').value}`, $('#sc-fmt').value, $('#sc-status'))));
$('#sn-save').addEventListener('click', () => guarded($('#sn-status'), () => saveTextAs($('#sn-out').value, `${sn.session || 'sni_search'}.${$('#sn-fmt').value}`, $('#sn-fmt').value, $('#sn-status'))));

// ------------------------------------------------------------------ boot
(async () => {
  try {
    state.info = await window.forge.call('engine.info', {});
    $('#engine-status').textContent = `engine v${state.info.version} · ${state.info.cores.length} cores`;
    cv.defaults = state.info.defaults;
    cvResetRules();
    $('#cv-keys').textContent = (state.info.template_keys || []).map((k) => `{${k}}`).join(' ');
    for (const c of state.info.cores) { $('#hc-core').append(h('option', { value: c }, c)); $('#sk-core').append(h('option', { value: c }, c)); }
    for (const f of state.info.frag_presets || []) $('#frag-presets').append(h('option', { value: f }));
    const labels = { cloudflare: 'Cloudflare', fastly: 'Fastly', warp: 'WARP' };
    for (const k of Object.keys(state.info.ranges || {})) $('#sc-preset').append(h('option', { value: k }, labels[k] || k));
    await loadSettings();
  } catch (e) {
    $('#engine-status').textContent = `engine unavailable: ${e.message}`;
  }
})();

// ------------------------------------------------------ settings persistence
// Form controls worth remembering between runs. Pasted links and results are
// deliberately not here (they can hold credentials); the order matters: the
// convert mode is applied first because changing it adjusts the switches.
const PERSIST = [
  'cv-mode', 'cv-want-fp', 'cv-want-cs', 'cv-want-fm', 'cv-tls-only', 'cv-rename', 'cv-dedup',
  'cv-fp', 'cv-cs', 'cv-fm', 'cv-template', 'cv-start', 'cv-ip-on', 'cv-ip', 'cv-port-on', 'cv-port',
  'export-format', 'hc-workers', 'hc-timeout', 'hc-core', 'hc-throughput',
  'sk-workers', 'sk-timeout', 'sk-core', 'sk-throughput', 'sk-n',
  'sc-cidrs', 'sc-count', 'sc-port', 'sc-sni', 'sc-frag', 'sc-workers', 'sc-geo', 'sc-dead', 'sc-fmt',
  'sn-snis', 'sn-presets', 'sn-http', 'sn-port', 'sn-frag', 'sn-workers', 'sn-fmt',
  'wp-count', 'wp-format', 'mt-use-ca', 'mt-platform', 'mt-cn', 'mt-permitted',
];
// `ready` is false until the saved values are restored, so the events fired while
// restoring never trigger a save of a half-restored form.
const settingsState = { timer: null, ready: false };

function settingValue(el) {
  return el.type === 'checkbox' ? el.checked : el.value;
}

function collectSettings() {
  const out = {};
  for (const id of PERSIST) {
    const el = document.getElementById(id);
    if (!el) continue;
    const v = settingValue(el);
    if (typeof v === 'string' && v.length > 4000) continue;   // the engine caps values at 4096
    out[id] = v;
  }
  return out;
}

async function loadSettings() {
  let saved = {};
  try { saved = (await window.forge.call('ui.settings_get', {})).settings || {}; } catch { return; }
  try {
    for (const id of PERSIST) {
      const el = document.getElementById(id);
      if (!el || !(id in saved)) continue;
      const v = saved[id];
      if (el.type === 'checkbox') el.checked = v === true;
      else if (el.tagName === 'SELECT') { if ([...el.options].some((o) => o.value === String(v))) el.value = String(v); else continue; }
      else el.value = String(v);
      el.dispatchEvent(new Event('input', { bubbles: true }));
      el.dispatchEvent(new Event('change', { bubbles: true }));
    }
  } finally { settingsState.ready = true; }
}

function saveSettingsSoon() {
  if (!settingsState.ready) return;
  clearTimeout(settingsState.timer);
  settingsState.timer = setTimeout(() => guarded($('#settings-msg'), async () => {
    await window.forge.call('ui.settings_set', { settings: collectSettings() });
    say($('#settings-msg'), '');
  }).then(() => {}), 400);
}
for (const ev of ['input', 'change']) {
  document.addEventListener(ev, (e) => { if (e.target && PERSIST.includes(e.target.id)) saveSettingsSoon(); });
}

// ------------------------------------------------------------------ Cores
function renderCores(rows) {
  const body = $('#co-table tbody');
  body.replaceChildren();
  for (const r of rows) {
    const input = h('input', { type: 'text', 'data-core': r.name, value: r.configured || r.path || '',
      placeholder: 'absolute path to executable', size: 40 });
    const apply = async (path) => {
      await guarded($('#co-msg'), async () => {
        const res = await call('core.set_path', { name: r.name, path });
        say($('#co-msg'), path ? `${res.display_name}: ${res.version}` : `${res.display_name}: path cleared`);
        await refreshCores(true);
      });
    };
    body.append(h('tr', { 'data-row': r.name },
      h('td', {}, r.display_name), h('td', {}, r.found ? (r.ok ? 'yes' : 'found, no version') : 'no'),
      h('td', {}, r.version), h('td', {}, r.source || ''), h('td', {}, input),
      h('td', {}, h('button', { 'data-act': 'browse', onclick: () => guarded($('#co-msg'), async () => {
        if (!window.forge.pickPath) { say($('#co-msg'), 'browsing needs the desktop app', true); return; }
        const p = await window.forge.pickPath({ title: `Select ${r.display_name}` });
        if (p) { input.value = p; say($('#co-msg'), 'press Set to use it'); }
      }) }, 'Browse…'), h('button', { 'data-act': 'set', onclick: () => apply(input.value.trim()) }, 'Set'),
        h('button', { 'data-act': 'clear', onclick: () => apply('') }, 'Clear'))));
  }
}
async function refreshCores(keepMsg) {
  if (!keepMsg) say($('#co-msg'), 'detecting…');
  const rows = await call('core.detect');
  renderCores(rows);
  if (!keepMsg) say($('#co-msg'), `${rows.filter((r) => r.found).length} of ${rows.length} cores found`);
}
onTab.cores = () => guarded($('#co-msg'), () => refreshCores(false));
$('#co-detect').addEventListener('click', onTab.cores);
