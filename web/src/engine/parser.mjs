// Port of xray_forge/core/parser.py: share-link parsing, the converter and the exporters.
import {
  PyValueError, b64DecodePad, isAscii, isIPv4, isIPv6, parseQsl, pyInt, pyIsAlpha, pyIsDigit, pySplitLines,
  pyStrip, pyStripChars, pyFormat, quote, unquote, urlencode, urlsplit, urlunsplit,
} from './pycompat.mjs';
import { IPV4_RE, PROXY_SCHEMES } from './config.mjs';
import { Outbound, vmessJsonToOutbound } from './models.mjs';
import { dumpClashYaml } from './yaml-dump.mjs';
import { handlerFor } from './protocols.mjs';

export const PARSE_SCHEMES = new Set([...PROXY_SCHEMES, 'hysteria2', 'hy2', 'tuic', 'wireguard', 'wg']);

// ------------------------------------------------------------------ small helpers

const DOMAIN_RE = /^(?=.{1,253}$)(?!-)[A-Za-z0-9_-]{1,63}(?:\.(?!-)[A-Za-z0-9_-]{1,63})+\.?$/;

export function classifyEndpoint(v) {
  v = pyStrip(v || '');
  if (!v) return null;
  if (isIPv4(v)) return 'ipv4';
  if (isIPv6(v)) return 'ipv6';
  if (DOMAIN_RE.test(v)) return 'domain';
  return null;
}

// v.isdigit() and 1 <= int(v) <= 65535  (int() raises for digit-like characters it cannot read)
export function validPort(v) {
  if (!pyIsDigit(v)) return false;
  const n = pyInt(v);
  return n >= 1n && n <= 65535n;
}

export function sanitize(s, maxlen = 64) {
  s = unquote(s || '');
  s = s.replace(/[^A-Za-z0-9._-]+/g, '_');
  s = pyStripChars(s.replace(/_{2,}/g, '_'), '_.-');
  return pyStripChars(Array.from(s).slice(0, maxlen).join(''), '_.-');
}

export const isIp = (host) => IPV4_RE.test(host || '');

export function splitNetloc(netloc) {
  const at = netloc.indexOf('@');
  const hostport = at >= 0 ? netloc.slice(at + 1) : netloc;
  if (hostport.startsWith('[')) {
    const rest0 = hostport.slice(1);
    const close = rest0.indexOf(']');
    const host = close >= 0 ? rest0.slice(0, close) : rest0;
    const rest = close >= 0 ? rest0.slice(close + 1) : '';
    return [host, rest.replace(/^:+/, '')];
  }
  const colon = hostport.lastIndexOf(':');
  if (colon >= 0) {
    const host = hostport.slice(0, colon);
    const port = hostport.slice(colon + 1);
    if (pyIsDigit(port)) return [host, port];
  }
  return [hostport, ''];
}

export function buildNetloc(userinfo, host, port) {
  let hostpart = host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
  if (port) hostpart = `${hostpart}:${port}`;
  return userinfo ? `${userinfo}@${hostpart}` : hostpart;
}

const get = (m, k, d = '') => (m.has(k) ? m.get(k) : d);

export function pickDomain(params, netlocHost) {
  for (const key of ['host', 'sni']) {
    const v = pyStrip(get(params, key));
    if (v && !isIp(v)) return v;
  }
  for (const key of ['host', 'sni']) {
    const v = pyStrip(get(params, key));
    if (v) return v;
  }
  return netlocHost || '';
}

export function subdomainOf(host) {
  host = pyStripChars(pyStrip(host || ''), '.').toLowerCase();
  if (!host) return 'host';
  if (isIp(host)) return 'ip';
  if (host.includes(':')) return 'v6';
  return sanitize(host.split('.')[0], 32) || 'host';
}

const pad3 = (n) => String(n).padStart(3, '0');

export function makeNamer(template, startId) {
  const used = new Set();
  return function nameFor(i, params, ip, port, scheme, oldName) {
    const dom = pickDomain(params, ip);
    const keys = {
      id: startId + i,
      sub: subdomainOf(dom),
      path: sanitize(get(params, 'path')),
      ip: pyStripChars((ip || '').replaceAll(':', '-'), '[]'),
      port: port || '',
      host: sanitize(dom),
      net: sanitize(dom.includes('.') ? dom.split('.').slice(1).join('.') : dom),
      sni: sanitize(get(params, 'sni')),
      proto: scheme || 'vless',
      old: sanitize(oldName, 32),
    };
    let base;
    try {
      base = pyFormat(template, keys);
    } catch {
      base = `${pad3(startId + i)}_${keys.sub}`;
    }
    base = sanitize(base, 80) || `cfg_${pad3(startId + i)}`;
    let cand = base;
    if (used.has(cand) && keys.ip) cand = `${base}_${keys.ip}`;
    let n = 2;
    while (used.has(cand)) { cand = `${base}_${n}`; n += 1; }
    used.add(cand);
    return cand;
  };
}

function firstWins(pairs) {
  const m = new Map();
  for (const [k, v] of pairs) { const lk = k.toLowerCase(); if (!m.has(lk)) m.set(lk, v); }
  return m;
}

// ------------------------------------------------------------------ converter

export function fixUri(line, fp, cs, fm, tlsOnly, rename, namer, idx, ovIp = '', ovPort = '',
  wantFp = true, wantCs = true, wantFm = true) {
  line = pyStrip(line);
  if (!line) return [line, 'blank', null];
  let parts;
  try { parts = urlsplit(line); } catch (e) { if (e instanceof PyValueError) return [line, 'skipped', null]; throw e; }
  if (!PROXY_SCHEMES.has(parts.scheme.toLowerCase()) || !parts.netloc.includes('@')) return [line, 'skipped', null];
  let params;
  try { params = parseQsl(parts.query, true); } catch (e) { if (e instanceof PyValueError) return [line, 'skipped', null]; throw e; }

  const pd = firstWins(params);
  const inject = [];
  if (wantFp && fp) inject.push(['fp', fp]);
  if (wantCs && cs) inject.push(['cs', cs]);
  if (wantFm && fm) inject.push(['fm', fm]);
  const injecting = inject.length > 0;

  const security = pd.get('security');
  if (injecting && tlsOnly && security !== undefined && security.toLowerCase() !== 'tls') return [line, 'skipped', null];

  const oldName = unquote(parts.fragment);
  const [ip, port] = splitNetloc(parts.netloc);
  const userinfo = parts.netloc.includes('@') ? parts.netloc.slice(0, parts.netloc.lastIndexOf('@')) : '';
  let effIp = ovIp || ip;
  let effPort = ovPort || port;
  let netloc;
  if (ovIp || ovPort) netloc = buildNetloc(userinfo, effIp, effPort);
  else { netloc = parts.netloc; effIp = ip; effPort = port; }

  const name = namer(idx, pd, effIp, effPort, parts.scheme.toLowerCase(), oldName);

  let query;
  if (injecting) {
    const drop = new Set(inject.map(([k]) => k));
    const lower = params.map(([k]) => k.toLowerCase());
    let at;
    if (wantFp && lower.includes('fp')) at = lower.indexOf('fp');
    else {
      let anchor = -1;
      lower.forEach((k, i) => { if ((k === 'sni' || k === 'security') && i > anchor) anchor = i; });
      at = anchor + 1;
    }
    const out = [];
    let placed = false;
    params.forEach(([k, v], i) => {
      if (i === at && !placed) { out.push(...inject); placed = true; }
      if (drop.has(k.toLowerCase())) return;
      out.push([k, v]);
    });
    if (!placed) out.push(...inject);
    query = urlencode(out);
  } else query = parts.query;

  const frag = rename ? quote(name, '') : parts.fragment;
  const next = urlunsplit({ scheme: parts.scheme, netloc, path: parts.path, query, fragment: frag });
  return [next, next === line ? 'unchanged' : 'fixed', name];
}

export function appendNameSuffix(line, suffix) {
  line = pyStrip(line);
  if (!suffix) return [line, '', false];
  if (line.toLowerCase().startsWith('vmess://')) {
    const out = parseTarget(line);
    const handler = out !== null ? handlerFor('vmess') : null;
    if (out === null || handler === null) return [line, '', false];
    if (out.name.endsWith(suffix)) return [line, out.name, false];
    out.name = `${out.name}${suffix}`;
    return [handler.toUri(out), out.name, true];
  }
  let parts;
  try { parts = urlsplit(line); } catch (e) { if (e instanceof PyValueError) return [line, '', false]; throw e; }
  if (!PARSE_SCHEMES.has(parts.scheme.toLowerCase())) return [line, '', false];
  let name = unquote(parts.fragment);
  if (name.endsWith(suffix)) return [line, name, false];
  name = `${name}${suffix}`;
  const next = urlunsplit({ scheme: parts.scheme, netloc: parts.netloc, path: parts.path, query: parts.query, fragment: quote(name, '') });
  return [next, name, true];
}

export function tagNameWithCc(line, cc) {
  const code = pyStrip(cc || '').toUpperCase();
  if (Array.from(code).length !== 2 || !pyIsAlpha(code)) return [pyStrip(line || ''), '', false];
  return appendNameSuffix(line, `[${code}]`);
}

export function convertBlock(text, fp, cs, fm, tlsOnly, rename, template, startId, ovIp = '', ovPort = '',
  wantFp = true, wantCs = true, wantFm = true) {
  const namer = makeNamer(template, startId);
  const lines = [];
  const names = [];
  const counts = { fixed: 0, unchanged: 0, skipped: 0 };
  let idx = 0;
  for (const raw of pySplitLines(text)) {
    if (!pyStrip(raw)) continue;
    idx += 1;
    const [next, st, name] = fixUri(raw, fp, cs, fm, tlsOnly, rename, namer, idx, ovIp, ovPort, wantFp, wantCs, wantFm);
    if (st === 'fixed' || st === 'unchanged') {
      counts[st] += 1;
      lines.push(next);
      names.push([name || '', next]);
    } else if (st === 'skipped') {
      counts.skipped += 1;
      lines.push(pyStrip(raw));
    }
  }
  return [lines, names, counts];
}

// ------------------------------------------------------------------ parse_target

const MODELED_PARAMS = new Set(['security', 'sni', 'host', 'path', 'type', 'fp', 'alpn', 'servicename',
  'service_name', 'headertype', 'flow', 'pbk', 'sid', 'spx', 'allowinsecure', 'insecure', 'cs', 'encryption',
  'mode', 'plugin', 'obfs', 'obfs-password', 'up', 'down', 'congestion_control', 'udp_relay_mode']);
const TRANSPORT_ALIASES = { raw: 'tcp', splithttp: 'xhttp' };

function unmodeledParams(query, transport = '') {
  const kept = new Map();
  const seen = new Set();
  for (const [k, v] of parseQsl(query, true)) {
    const lk = k.toLowerCase();
    if (seen.has(lk)) continue;
    seen.add(lk);
    if (MODELED_PARAMS.has(lk)) {
      if (lk === 'mode' && transport !== 'xhttp') { /* only modeled for xhttp */ }
      else if (lk === 'encryption' && pyStrip(v).toLowerCase() !== 'none') { /* real data (mlkem...) */ }
      else continue;
    }
    kept.set(k, v);
  }
  return kept;
}

const rpartition = (s, sep) => {
  const i = s.lastIndexOf(sep);
  return i < 0 ? ['', '', s] : [s.slice(0, i), sep, s.slice(i + sep.length)];
};
const partition = (s, sep) => {
  const i = s.indexOf(sep);
  return i < 0 ? [s, '', ''] : [s.slice(0, i), sep, s.slice(i + sep.length)];
};
const orStr = (a, b) => (a ? a : b);

function parseSs(line, parts) {
  const params = firstWins(parseQsl(parts.query, true));
  const name = unquote(parts.fragment) || '';
  // the whole userinfo: parts.username stops at the first ':' and would cut "method:password" to the method
  const userinfo = parts.netloc.includes('@') ? parts.netloc.slice(0, parts.netloc.lastIndexOf('@')) : '';
  if (parts.netloc && !parts.netloc.includes('@')) {
    let decoded;
    try { decoded = b64DecodePad(parts.netloc); } catch (e) { if (e instanceof PyValueError) return null; throw e; }
    const [cred, , hostportRaw] = rpartition(decoded, '@');
    const [host, port] = splitNetloc(hostportRaw);
    const [method, , password] = partition(cred, ':');
    if (!host) return null;
    return new Outbound({
      scheme: 'ss', name: name || `${host}:${port}`, host, port: port || '443', credential: password,
      ss_method: method, transport: 'tcp', raw: pyStrip(line), extra: { plugin: get(params, 'plugin') },
    });
  }
  let method = '';
  let password = '';
  if (userinfo.includes(':')) {
    const at = userinfo.indexOf(':');
    method = userinfo.slice(0, at);
    password = userinfo.slice(at + 1);
  } else {
    try {
      const cred = b64DecodePad(userinfo);
      [method, , password] = partition(cred, ':');
    } catch (e) { if (e instanceof PyValueError) return null; throw e; }
  }
  const [host, port] = splitNetloc(parts.netloc);
  if (!host || !method) return null;
  return new Outbound({
    scheme: 'ss', name: name || `${host}:${port}`, host, port: port || '443', credential: unquote(password),
    ss_method: unquote(method), transport: 'tcp', allow_insecure: false, raw: pyStrip(line),
    extra: { plugin: get(params, 'plugin') }, extra_params: unmodeledParams(parts.query),
  });
}

function parseHysteria2(line, parts) {
  const [host, port] = splitNetloc(parts.netloc);
  if (!host) return null;
  const params = firstWins(parseQsl(parts.query, true));
  const password = orStr(unquote(parts.username || ''), parts.password || '');
  const name = unquote(parts.fragment) || `${host}:${port}`;
  return new Outbound({
    scheme: 'hysteria2', name, host, port: port || '443', credential: password, transport: 'udp', security: 'tls',
    sni: get(params, 'sni') || host, fingerprint: get(params, 'fp', 'chrome'),
    allow_insecure: ['1', 'true'].includes(get(params, 'insecure', '0')), alpn: 'h3',
    extra: { obfs: get(params, 'obfs'), 'obfs-password': get(params, 'obfs-password'), up: get(params, 'up'), down: get(params, 'down') },
    extra_params: unmodeledParams(parts.query), raw: pyStrip(line),
  });
}

function parseTuic(line, parts) {
  const [host, port] = splitNetloc(parts.netloc);
  if (!host) return null;
  const params = firstWins(parseQsl(parts.query, true));
  const uuid = unquote(parts.username || '');
  const password = parts.password ? unquote(parts.password) : '';
  const name = unquote(parts.fragment) || `${host}:${port}`;
  return new Outbound({
    scheme: 'tuic', name, host, port: port || '443', credential: uuid, transport: 'udp', security: 'tls',
    sni: get(params, 'sni') || host, fingerprint: get(params, 'fp', 'chrome'),
    allow_insecure: ['1', 'true'].includes(get(params, 'insecure', '0')), alpn: get(params, 'alpn', 'h3'),
    extra: { password, congestion_control: get(params, 'congestion_control', 'bbr'), udp_relay_mode: get(params, 'udp_relay_mode', 'native') },
    extra_params: unmodeledParams(parts.query), raw: pyStrip(line),
  });
}

export function parseTarget(line) {
  line = pyStrip(line || '');
  if (!line || !line.includes('://')) return null;
  let parts;
  try { parts = urlsplit(line); } catch (e) { if (e instanceof PyValueError) return null; throw e; }
  const scheme = parts.scheme.toLowerCase();
  if (scheme === 'vmess') {
    if (!parts.netloc.includes('@')) return vmessJsonToOutbound(line.slice('vmess://'.length), line);
  }
  if (scheme === 'ss') return parseSs(line, parts);
  if (scheme === 'hysteria2' || scheme === 'hy2') return parseHysteria2(line, parts);
  if (scheme === 'tuic') return parseTuic(line, parts);
  if (scheme === 'wireguard' || scheme === 'wg') return null;
  if (!PROXY_SCHEMES.has(scheme) || !parts.netloc.includes('@')) return null;
  const [host, port] = splitNetloc(parts.netloc);
  if (!host) return null;
  const pd = firstWins(parseQsl(parts.query, true));
  const sni = get(pd, 'sni') || get(pd, 'host') || host;
  const hdr = get(pd, 'host') || sni;
  let path = get(pd, 'path') || '/';
  if (!path.startsWith('/')) path = '/' + path;
  const name = unquote(parts.fragment) || `${host}:${port}`;
  let credential = unquote(parts.username || '');
  if (parts.password) credential += ':' + unquote(parts.password);
  const security = get(pd, 'security').toLowerCase();
  let transport = get(pd, 'type', 'tcp').toLowerCase() || 'tcp';
  transport = Object.prototype.hasOwnProperty.call(TRANSPORT_ALIASES, transport) ? TRANSPORT_ALIASES[transport] : transport;
  return new Outbound({
    name, scheme, host, port: port || '443', credential, transport, security, sni, host_header: hdr, path,
    fingerprint: get(pd, 'fp', 'chrome'), alpn: get(pd, 'alpn'),
    service_name: get(pd, 'servicename') || get(pd, 'service_name'), header_type: get(pd, 'headertype'),
    flow: get(pd, 'flow'), public_key: get(pd, 'pbk'), short_id: get(pd, 'sid'), spider_x: get(pd, 'spx'),
    allow_insecure: ['1', 'true'].includes(get(pd, 'allowinsecure', '0')),
    extra: { cs: get(pd, 'cs'), mode: get(pd, 'mode') }, extra_params: unmodeledParams(parts.query, transport), raw: line,
  });
}

// ------------------------------------------------------------------ exporters

function transportFields(t) {
  const tr = t.transport.toLowerCase();
  const f = {};
  if (tr === 'ws') { f.network = 'ws'; f.ws_path = t.path; f.ws_host = t.host_header; }
  else if (tr === 'grpc') { f.network = 'grpc'; f.service_name = t.service_name; }
  else if (tr === 'httpupgrade') { f.network = 'httpupgrade'; f.ws_path = t.path; f.ws_host = t.host_header; }
  else if (tr === 'xhttp') {
    f.network = 'xhttp'; f.ws_path = t.path; f.ws_host = t.host_header;
    f.xhttp_mode = Object.prototype.hasOwnProperty.call(t.extra, 'mode') ? t.extra.mode : 'auto';
  }
  return f;
}

const XRAY_ONLY_TRANSPORTS = new Set(['xhttp', 'kcp', 'mkcp']);
export const needsXray = (t) => ['vless', 'vmess', 'trojan'].includes(t.scheme) && XRAY_ONLY_TRANSPORTS.has((t.transport || '').toLowerCase());

// int(x) if str(x).isdigit() else dflt
const portInt = (v, dflt = 443) => (pyIsDigit(String(v)) ? Number(pyInt(String(v))) : dflt);
const ex = (t, k, d = undefined) => (Object.prototype.hasOwnProperty.call(t.extra, k) ? t.extra[k] : d);
const truthy = (v) => v !== undefined && v !== null && v !== '' && v !== false && v !== 0;
const alpnList = (a) => a.split(',').map((x) => pyStrip(x)).filter((x) => x);

export function outToClash(t) {
  if (needsXray(t)) return null;
  const px = {
    name: t.name,
    type: { hysteria2: 'hysteria2', tuic: 'tuic', wireguard: 'wireguard' }[t.scheme] || t.scheme,
    server: t.host,
    port: portInt(t.port),
  };
  const tr = transportFields(t);
  if (t.scheme === 'vless') {
    px.uuid = t.credential;
    px.cipher = t.security === 'reality' ? 'none' : 'auto';
    if (t.flow) px.flow = t.flow;
  } else if (t.scheme === 'vmess') {
    px.uuid = t.credential;
    px.alterId = portInt(t.alter_id, 0);
    px.cipher = t.encryption || 'auto';
  } else if (t.scheme === 'trojan') {
    px.password = t.credential;
  } else if (t.scheme === 'ss') {
    const [method, password] = t.ssSplit();
    px.cipher = method;
    px.password = password;
    if (truthy(ex(t, 'plugin'))) px.plugin = t.extra.plugin;
    return px;
  } else if (t.scheme === 'hysteria2') {
    px.password = t.credential;
    px.up = ex(t, 'up', '') || '50 Mbps';
    px.down = ex(t, 'down', '') || '100 Mbps';
    if (truthy(ex(t, 'obfs'))) {
      px.obfs = t.extra.obfs;
      if (truthy(ex(t, 'obfs-password'))) px['obfs-password'] = t.extra['obfs-password'];
    }
  } else if (t.scheme === 'tuic') {
    px.uuid = t.credential;
    px.password = ex(t, 'password', '');
    px['congestion-controller'] = ex(t, 'congestion_control', 'bbr');
    px['udp-relay-mode'] = ex(t, 'udp_relay_mode', 'native');
  } else if (t.scheme === 'wireguard') {
    px['private-key'] = ex(t, 'private_key', '');
    px['public-key'] = ex(t, 'peer_public_key', '');
    px.ip = (ex(t, 'ipv4') || '172.16.0.2').split('/')[0];
    px.ipv6 = (ex(t, 'ipv6') || '').split('/')[0] || null;
    px.mtu = Number(pyInt(ex(t, 'mtu', 1280)));
    if (truthy(ex(t, 'reserved'))) px.reserved = t.extra.reserved;
    const o = {};
    for (const [k, v] of Object.entries(px)) if (v !== null && v !== '') o[k] = v;
    return o;
  } else return null;

  if (t.security === 'tls' || t.security === 'reality') {
    px.tls = true;
    px.servername = t.sni || t.host;
    px['client-fingerprint'] = t.fingerprint || 'chrome';
    px['skip-cert-verify'] = t.allow_insecure;
    if (t.security === 'reality') {
      const ro = {};
      if (t.public_key) ro['public-key'] = t.public_key;
      if (t.short_id) ro['short-id'] = t.short_id;
      px['reality-opts'] = ro;
    }
    if (t.alpn) px.alpn = alpnList(t.alpn);
  } else if (t.scheme === 'hysteria2' || t.scheme === 'tuic') {
    px.sni = t.sni || t.host;
    px['skip-cert-verify'] = t.allow_insecure;
  }

  if (tr.network === 'ws') { px.network = 'ws'; px['ws-opts'] = { path: tr.ws_path, headers: { Host: tr.ws_host } }; }
  else if (tr.network === 'grpc') { px.network = 'grpc'; px['grpc-opts'] = { 'grpc-service-name': tr.service_name }; }
  else if (tr.network === 'httpupgrade') { px.network = 'httpupgrade'; px['httpupgrade-opts'] = { path: tr.ws_path, host: tr.ws_host }; }
  return px;
}

export function outToSingbox(t) {
  if (needsXray(t)) return null;
  const ob = { tag: t.name, type: t.scheme, server: t.host, server_port: portInt(t.port) };
  const tr = transportFields(t);
  if (t.scheme === 'vless') {
    ob.uuid = t.credential;
    if (t.flow) ob.flow = t.flow;
  } else if (t.scheme === 'vmess') {
    ob.uuid = t.credential;
    ob.alter_id = portInt(t.alter_id, 0);
    ob.security = t.encryption || 'auto';
  } else if (t.scheme === 'trojan') {
    ob.password = t.credential;
  } else if (t.scheme === 'ss') {
    const [method, password] = t.ssSplit();
    ob.method = method;
    ob.password = password;
    return ob;
  } else if (t.scheme === 'hysteria2') {
    ob.password = t.credential;
    if (truthy(ex(t, 'obfs'))) ob.obfs = { type: t.extra.obfs, password: ex(t, 'obfs-password', '') };
  } else if (t.scheme === 'tuic') {
    ob.uuid = t.credential;
    ob.password = ex(t, 'password', '');
    ob.congestion_control = ex(t, 'congestion_control', 'bbr');
    ob.udp_relay_mode = ex(t, 'udp_relay_mode', 'native');
  } else if (t.scheme === 'wireguard') {
    ob.type = 'wireguard';
    ob.local_address = [ex(t, 'ipv4'), ex(t, 'ipv6')].filter((a) => truthy(a));
    ob.private_key = ex(t, 'private_key', '');
    ob.peer_public_key = ex(t, 'peer_public_key', '');
    if (truthy(ex(t, 'reserved'))) ob.reserved = t.extra.reserved;
    ob.mtu = Number(pyInt(ex(t, 'mtu', 1280)));
    ob.local_address = ob.local_address.filter((a) => truthy(a));
    if (!ob.local_address.length) ob.local_address = ['172.16.0.2/32'];
    return ob;
  } else return null;

  if (t.security === 'tls' || t.security === 'reality') {
    const tls = { enabled: true, server_name: t.sni || t.host, insecure: t.allow_insecure };
    if (t.security === 'reality') {
      tls.reality = { enabled: true };
      if (t.public_key) tls.reality.public_key = t.public_key;
      if (t.short_id) tls.reality.short_id = t.short_id;
    } else tls.utls = { enabled: true, fingerprint: t.fingerprint || 'chrome' };
    if (t.alpn) tls.alpn = alpnList(t.alpn);
    ob.tls = tls;
  } else if (t.scheme === 'hysteria2' || t.scheme === 'tuic') {
    ob.tls = { enabled: true, server_name: t.sni || t.host, insecure: t.allow_insecure };
  }

  if (tr.network === 'ws') ob.transport = { type: 'ws', path: tr.ws_path, headers: { Host: tr.ws_host } };
  else if (tr.network === 'grpc') ob.transport = { type: 'grpc', service_name: tr.service_name };
  else if (tr.network === 'httpupgrade') ob.transport = { type: 'httpupgrade', path: tr.ws_path, host: tr.ws_host };
  return ob;
}

function collect(lines, fn) {
  const out = [];
  for (const item of lines) {
    const t = item instanceof Outbound ? item : parseTarget(item);
    if (!t) continue;
    const r = fn(t);
    if (r) out.push(r);
  }
  return out;
}

export const exportToClash = (lines) => dumpClashYaml(collect(lines, outToClash));

export function exportToSingbox(lines) {
  // json.dumps(..., indent=2, ensure_ascii=False): the shared Python-style dumper lives with the MITM module
  return pyJsonDumpsLazy({ outbounds: collect(lines, outToSingbox) });
}

export function exportToSub(lines) {
  const raw = lines.map((l) => pyStrip(l)).filter((l) => l).join('\n');
  return b64EncodeStd(raw);
}

import { b64Encode as b64EncodeStd } from './pycompat.mjs';
import { pyJsonDumps } from './domainfront.mjs';
const pyJsonDumpsLazy = (v) => pyJsonDumps(v, { indent: 2, ensureAscii: false });

export { isAscii };
