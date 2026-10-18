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

// ------------------------------------------------------------- helpers
const call = (m, p = {}) => window.forge.call(m, p);
const fmtMs = (v) => (v == null ? '' : String(Math.round(v)));

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
const sc = { rows: new Map(), job: null };

function renderScan() {
  const showDead = $('#sc-dead').checked;
  const rows = [...sc.rows.values()].filter((r) => r.alive || showDead)
    .sort((a, b) => (a.alive === b.alive ? (a.ms ?? 9e9) - (b.ms ?? 9e9) : a.alive ? -1 : 1));
  $('#sc-table tbody').replaceChildren(...rows.map((r) => h('tr', { class: r.alive ? '' : 'bad' },
    h('td', {}, r.ip), h('td', {}, r.port), h('td', {}, fmtMs(r.ms)), h('td', {}, fmtMs(r.jitter)),
    h('td', {}, r.tls), h('td', {}, r.cc), h('td', {}, r.isp), h('td', {}, r.info))));
}
$('#sc-dead').addEventListener('change', renderScan);

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
  if (resume) { params.resume = true; params.session = $('#sc-sessions').value; }
  const r = await call('scan.run', params);
  sc.rows = new Map();
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
  renderScan();
  say($('#sc-status'), `loaded ${name}: ${scStatus()}${r.pending ? `, ${r.pending} pending` : ''}`);
}));
$('#sc-export').addEventListener('click', () => guarded($('#sc-status'), async () => {
  const name = $('#sc-sessions').value;
  if (!name) { say($('#sc-status'), 'choose a saved scan to export', true); return; }
  $('#sc-out').value = (await call('scan.export', { session: name, format: 'csv' })).content;
}));
$('#sc-to-sni').addEventListener('click', () => {
  const ips = [...sc.rows.values()].filter((r) => r.alive).sort((a, b) => a.ms - b.ms).map((r) => r.ip);
  $('#sn-ips').value = ips.join('\n');
  document.querySelector('[data-tab=sni]').click();
});
onTab.scan = refreshScanSessions;

// ------------------------------------------------------------ SNI search
const sn = { rows: new Map(), job: null, session: '' };

function renderSni() {
  const rows = [...sn.rows.values()].filter((r) => r.ok)
    .sort((a, b) => (b.http_ok - a.http_ok) || ((a.tls_ms ?? 9e9) - (b.tls_ms ?? 9e9)));
  $('#sn-table tbody').replaceChildren(...rows.map((r) => h('tr', {},
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
  };
  if ($('#sn-from-scan').value) params.from_scan = $('#sn-from-scan').value;
  const r = await call('sni.run', params);
  sn.rows = new Map(); sn.session = r.session; renderSni();
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
  $('#sn-out').value = (await call('sni.export', { session: sn.session, format: 'csv' })).content;
}));
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
      h('td', {}, h('button', { 'data-act': 'set', onclick: () => apply(input.value.trim()) }, 'Set'),
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
