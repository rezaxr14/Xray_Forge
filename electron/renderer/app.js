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

async function runJob(method, params, onEvent) {
  const { job } = await window.forge.call(method, params);
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

// ------------------------------------------------------------------ tabs
document.querySelectorAll('nav [role=tab]').forEach((btn) => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('nav [role=tab]').forEach((b) => b.setAttribute('aria-selected', String(b === btn)));
    document.querySelectorAll('.tab').forEach((s) => { s.hidden = s.id !== `tab-${btn.dataset.tab}`; });
    if (btn.dataset.tab === 'subs') refreshSubs();
  });
});

// --------------------------------------------------------------- configs
const EDIT_FIELDS = [
  ['name', 'Name', 'text', 'wide'], ['host', 'Host', 'text'], ['port', 'Port', 'text'],
  ['credential', 'ID / password', 'text', 'wide'],
  ['transport', 'Transport', ['tcp', 'ws', 'grpc', 'httpupgrade', 'xhttp', 'kcp']],
  ['security', 'Security', ['', 'none', 'tls', 'reality']],
  ['sni', 'SNI', 'text'], ['host_header', 'Host header', 'text'],
  ['path', 'Path', 'text'], ['fingerprint', 'Fingerprint', 'text'],
  ['alpn', 'ALPN', 'text'], ['flow', 'Flow', 'text'],
  ['public_key', 'Reality public key', 'text', 'wide'], ['short_id', 'Reality short id', 'text'],
  ['service_name', 'gRPC service', 'text'],
];

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

function selectConfig(i) {
  state.selected = i;
  const c = state.configs[i];
  renderConfigs();
  const ed = $('#editor');
  if (!c || !c.ok) { ed.hidden = true; return; }
  ed.hidden = false;
  const form = $('#ed-form');
  form.replaceChildren(...EDIT_FIELDS.map(([key, label, kind, cls]) => {
    const val = c.outbound[key] ?? '';
    const input = Array.isArray(kind)
      ? h('select', { name: key }, kind.map((o) => h('option', { value: o, selected: o === val }, o || '(none)')))
      : h('input', { name: key, type: 'text', value: val });
    if (Array.isArray(kind) && !kind.includes(val)) input.append(h('option', { value: val, selected: true }, val));
    return h('label', { class: cls || '' }, label, input);
  }));
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
  const outbound = { ...c.outbound };
  for (const el of $('#ed-form').elements) if (el.name) outbound[el.name] = el.value;
  const r = await window.forge.call('config.render', { outbound });
  const parsed = await window.forge.call('config.parse', { line: r.uri });
  state.configs[state.selected] = parsed;
  $('#cfg-input').value = state.configs.map((x) => x.line).join('\n');
  $('#ed-uri').value = r.uri;
  renderConfigs();
  say($('#ed-msg'), r.roundtrip_ok ? 'Applied' : 'Applied, but the new link does not re-parse', !r.roundtrip_ok);
}));

$('#export-run').addEventListener('click', () => guarded($('#export-out'), async () => {
  const lines = state.configs.filter((c) => c.ok).map((c) => c.line);
  const r = await window.forge.call('config.export', { lines, format: $('#export-format').value });
  $('#export-out').value = r.content;
}));

// --------------------------------------------------------------- convert
$('#cv-run').addEventListener('click', () => guarded($('#cv-msg'), async () => {
  const params = { text: $('#cv-input').value, dedup: $('#cv-dedup').checked };
  const tpl = $('#cv-template').value.trim();
  if (tpl) params.template = tpl;
  const r = await window.forge.call('config.convert', params);
  $('#cv-output').value = r.lines.join('\n');
  const c = r.counts;
  say($('#cv-msg'), `${c.fixed} fixed · ${c.unchanged} unchanged · ${c.skipped} skipped · ${r.removed} duplicates removed`);
}));
$('#cv-send').addEventListener('click', () => guarded($('#cv-msg'), async () => {
  await setConfigs(linesOf($('#cv-output').value));
  document.querySelector('[data-tab=configs]').click();
}));

// ---------------------------------------------------------------- health
function renderHealth() {
  const rows = [...state.hcRows].sort((a, b) => (b.score || 0) - (a.score || 0));
  $('#hc-table tbody').replaceChildren(...rows.map((r) =>
    h('tr', { class: r.passed ? '' : 'bad' },
      h('td', {}, Math.round(r.score || 0)),
      h('td', {}, r.name || r.line.slice(0, 40)),
      h('td', {}, r.scheme),
      h('td', {}, (r.stages || []).map((s) =>
        h('span', { class: `chip ${s.ok ? 'ok' : 'fail'}`, title: s.detail || '' }, `${s.name}${s.ms != null ? ' ' + Math.round(s.ms) + 'ms' : ''}`))),
      h('td', {}, (r.techniques || []).join(', ')))));
}

function setHcRunning(running) {
  $('#hc-start').disabled = running;
  $('#hc-cancel').disabled = !running;
}

$('#hc-start').addEventListener('click', () => guarded($('#hc-status'), async () => {
  const lines = state.configs.filter((c) => c.ok).map((c) => c.line);
  if (!lines.length) { say($('#hc-status'), 'No valid configs: parse some in the Configs tab first', true); return; }
  state.hcRows = [];
  renderHealth();
  $('#hc-keep').disabled = true;
  $('#hc-progress').value = 0;
  $('#hc-progress').max = lines.length;
  setHcRunning(true);
  say($('#hc-status'), 'running…');
  const params = {
    lines, workers: Number($('#hc-workers').value), timeout: Number($('#hc-timeout').value),
    throughput: $('#hc-throughput').checked,
  };
  if ($('#hc-core').value) params.core = $('#hc-core').value;
  state.hcJob = await runJob('health.run', params, (ev) => {
    if (ev.type === 'item' && ev.data.line !== undefined) { state.hcRows.push(ev.data); renderHealth(); }
    else if (ev.type === 'progress') { $('#hc-progress').max = ev.total; $('#hc-progress').value = ev.done; say($('#hc-status'), `${ev.done}/${ev.total}`); }
    else if (ev.type === 'done') {
      setHcRunning(false);
      const passed = state.hcRows.filter((r) => r.passed).length;
      say($('#hc-status'), `${ev.cancelled ? 'cancelled' : 'done'}: ${passed} of ${state.hcRows.length} passed`);
      $('#hc-keep').disabled = passed === 0;
    } else if (ev.type === 'error') { setHcRunning(false); say($('#hc-status'), ev.message, true); }
  });
}));
$('#hc-cancel').addEventListener('click', () => { if (state.hcJob) window.forge.call('job.cancel', { job: state.hcJob }); });
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
    if (ev.type === 'done') { say($('#sub-msg'), 'fetched'); await refreshSubs(); }
    else if (ev.type === 'error') say($('#sub-msg'), ev.message, true);
  });
}));
$('#sub-load').addEventListener('click', () => guarded($('#sub-msg'), async () => {
  const r = await window.forge.call('sub.configs', { dedupe: true });
  await setConfigs(r.lines);
  document.querySelector('[data-tab=configs]').click();
}));

// ------------------------------------------------------------------ boot
(async () => {
  try {
    state.info = await window.forge.call('engine.info', {});
    $('#engine-status').textContent = `engine v${state.info.version} · ${state.info.cores.length} cores`;
    $('#cv-template').value = state.info.defaults.template;
    for (const c of state.info.cores) $('#hc-core').append(h('option', { value: c }, c));
  } catch (e) {
    $('#engine-status').textContent = `engine unavailable: ${e.message}`;
  }
})();
