// Port of xray_forge/core/protocols/*: one handler per protocol (share-link rendering and
// the per-core "can this core run it" renderers that engine.info / config.parse report).
import { PyValueError, b64Encode, pyInt, pyIsDigit, pyStrip, quote, urlencode } from './pycompat.mjs';
import { pyJsonDumps } from './domainfront.mjs';
import { Outbound } from './models.mjs';
import { IPV4_RE } from './config.mjs';
import { outToClash, outToSingbox, parseTarget } from './parser.mjs';

const tru = (v) => v !== undefined && v !== null && v !== '' && v !== false && v !== 0;
const ex = (o, k, d = undefined) => (Object.prototype.hasOwnProperty.call(o.extra, k) ? o.extra[k] : d);
const portOr = (v, d = 443) => (pyIsDigit(String(v)) ? Number(pyInt(String(v))) : d);
const alpnList = (a) => a.split(',').map((x) => pyStrip(x)).filter((x) => x);

function appendExtraParams(params, out) {
  const present = new Set(params.map(([k]) => k.toLowerCase()));
  for (const [k, v] of out.extra_params || []) {
    if (!present.has(k.toLowerCase())) { params.push([k, pyStrVal(v)]); present.add(k.toLowerCase()); }
  }
  return params;
}
import { pyStr as pyStrVal } from './pycompat.mjs';

function hostport(out) {
  const host = out.host.includes(':') && !out.host.startsWith('[') ? `[${out.host}]` : out.host;
  return `${host}:${out.port || '443'}`;
}

const nameOf = (out) => quote(out.name || `${out.host}:${out.port}`, '');

class ProtocolHandler {
  parse(line) {
    const out = parseTarget(line);
    return out && this.schemes.includes(out.scheme) ? out : null;
  }
  xrayOutbound() { return null; }
  singboxOutbound(out) { return outToSingbox(out); }
  clashProxy(out) { return outToClash(out); }
}

function xrayTransportSettings(out) {
  const tr = out.transport.toLowerCase();
  const stream = { network: tr || 'tcp' };
  if (tr === 'ws') stream.wsSettings = { path: out.path, headers: { Host: out.host_header } };
  else if (tr === 'grpc') stream.grpcSettings = { serviceName: out.service_name };
  else if (tr === 'httpupgrade') stream.httpupgradeSettings = { path: out.path, host: out.host_header };
  else if (tr === 'xhttp') {
    const xs = { path: out.path };
    if (out.host_header) xs.host = out.host_header;
    if (tru(ex(out, 'mode'))) xs.mode = out.extra.mode;
    stream.xhttpSettings = xs;
  } else {
    stream.network = 'tcp';
    if (out.header_type) stream.tcpSettings = { header: { type: out.header_type } };
  }
  return stream;
}

function xraySecuritySettings(out) {
  const sec = (out.security || '').toLowerCase();
  const stream = { security: sec === 'tls' || sec === 'reality' ? sec : 'none' };
  const fp = out.fingerprint || 'chrome';
  if (sec === 'reality') {
    const rs = { show: false, fingerprint: fp };
    const sni = out.sni || out.host_header;
    if (sni && !IPV4_RE.test(sni)) rs.serverName = sni;
    if (out.public_key) rs.publicKey = out.public_key;
    if (out.short_id) rs.shortId = out.short_id;
    if (out.spider_x) rs.spiderX = out.spider_x;
    stream.realitySettings = rs;
  } else if (sec === 'tls') {
    const ts = { allowInsecure: out.allow_insecure, fingerprint: fp };
    const sni = out.sni || out.host_header;
    if (sni && !IPV4_RE.test(sni)) ts.serverName = sni;
    if (tru(ex(out, 'cs'))) ts.cipherSuites = out.extra.cs;
    if (out.alpn) ts.alpn = alpnList(out.alpn);
    stream.tlsSettings = ts;
  }
  return stream;
}
export const xrayStream = (out) => ({ ...xrayTransportSettings(out), ...xraySecuritySettings(out) });

const linkParams = (out, firstEncryption) => {
  const params = [];
  if (firstEncryption !== undefined) params.push(['encryption', firstEncryption]);
  return params;
};

function streamLinkParams(out, params, { tuple }) {
  void tuple;
  if (out.security) params.push(['security', out.security]);
  if (out.sni) params.push(['sni', out.sni]);
  if (out.fingerprint) params.push(['fp', out.fingerprint]);
  return params;
}

function uriTail(out, params) {
  if (out.host_header) params.push(['host', out.host_header]);
  if (out.path && ['ws', 'httpupgrade', 'xhttp'].includes(out.transport)) params.push(['path', out.path]);
  if (out.service_name) params.push(['serviceName', out.service_name]);
  if (out.header_type) params.push(['headerType', out.header_type]);
  if (out.transport === 'xhttp' && tru(ex(out, 'mode'))) params.push(['mode', out.extra.mode]);
}

function realityParams(out, params) {
  if (out.security === 'reality') {
    if (out.public_key) params.push(['pbk', out.public_key]);
    if (out.short_id) params.push(['sid', out.short_id]);
    if (out.spider_x) params.push(['spx', out.spider_x]);
  }
}

class VlessHandler extends ProtocolHandler {
  schemes = ['vless'];
  toUri(out) {
    const params = linkParams(out, out.extra_params.get('encryption') || 'none');
    streamLinkParams(out, params, {});
    if (out.transport) params.push(['type', out.transport]);
    uriTail(out, params);
    if (out.alpn) params.push(['alpn', out.alpn]);
    if (out.flow) params.push(['flow', out.flow]);
    if (out.allow_insecure) params.push(['allowInsecure', '1']);
    realityParams(out, params);
    if (tru(ex(out, 'cs'))) params.push(['cs', out.extra.cs]);
    const qs = urlencode(appendExtraParams(params, out));
    return `vless://${quote(out.credential, '')}@${hostport(out)}?${qs}#${nameOf(out)}`;
  }
  xrayOutbound(out) {
    return {
      protocol: 'vless',
      settings: { vnext: [{ address: out.host, port: portOr(out.port),
        users: [{ id: out.credential, encryption: out.extra_params.get('encryption') || 'none', flow: out.flow || '' }] }] },
    };
  }
}

class VmessHandler extends ProtocolHandler {
  schemes = ['vmess'];
  toUri(out) {
    const payload = {
      v: '2', ps: out.name, add: out.host, port: out.port, id: out.credential, aid: out.alter_id || '0',
      scy: out.encryption || 'auto', net: out.transport || 'tcp', type: out.header_type || 'none',
      host: out.host_header, path: out.path, tls: out.isTls() ? 'tls' : '', sni: out.sni, alpn: out.alpn, fp: out.fingerprint,
    };
    for (const [k, v] of out.extra_params || []) if (!Object.prototype.hasOwnProperty.call(payload, k)) payload[k] = v;
    return 'vmess://' + b64Encode(pyJsonDumps(payload, { ensureAscii: false }));
  }
  xrayOutbound(out) {
    let aid;
    try { aid = Number(pyInt(out.alter_id)); } catch { aid = 0; }
    return {
      protocol: 'vmess',
      settings: { vnext: [{ address: out.host, port: portOr(out.port),
        users: [{ id: out.credential, alterId: aid, security: out.encryption || 'auto' }] }] },
    };
  }
}

class TrojanHandler extends ProtocolHandler {
  schemes = ['trojan'];
  toUri(out) {
    const params = [];
    streamLinkParams(out, params, {});
    params.push(['type', out.transport || 'tcp']);
    uriTail(out, params);
    realityParams(out, params);
    if (out.flow) params.push(['flow', out.flow]);
    if (out.alpn) params.push(['alpn', out.alpn]);
    if (out.allow_insecure) params.push(['allowInsecure', '1']);
    if (tru(ex(out, 'cs'))) params.push(['cs', out.extra.cs]);
    const qs = urlencode(appendExtraParams(params, out));
    return `trojan://${quote(out.credential, '')}@${hostport(out)}?${qs}#${nameOf(out)}`;
  }
  xrayOutbound(out) {
    return { protocol: 'trojan', settings: { servers: [{ address: out.host, port: portOr(out.port), password: out.credential }] } };
  }
}

class ShadowsocksHandler extends ProtocolHandler {
  schemes = ['ss'];
  toUri(out) {
    const [method, password] = out.ssSplit();
    const userinfo = b64Encode(`${method}:${password}`, true).replace(/=+$/, '');
    let params = [];
    if (tru(ex(out, 'plugin'))) params.push(['plugin', out.extra.plugin]);
    params = appendExtraParams(params, out);
    const qs = params.length ? '?' + urlencode(params) : '';
    return `ss://${userinfo}@${hostport(out)}${qs}#${nameOf(out)}`;
  }
  xrayOutbound(out) {
    const [method, password] = out.ssSplit();
    return { protocol: 'shadowsocks', settings: { servers: [{ address: out.host, port: portOr(out.port), method, password }] } };
  }
}

class Hysteria2Handler extends ProtocolHandler {
  schemes = ['hysteria2', 'hy2'];
  toUri(out) {
    let params = [];
    if (out.sni) params.push(['sni', out.sni]);
    if (out.allow_insecure) params.push(['insecure', '1']);
    if (tru(ex(out, 'obfs'))) {
      params.push(['obfs', out.extra.obfs]);
      if (tru(ex(out, 'obfs-password'))) params.push(['obfs-password', out.extra['obfs-password']]);
    }
    if (tru(ex(out, 'up'))) params.push(['up', out.extra.up]);
    if (tru(ex(out, 'down'))) params.push(['down', out.extra.down]);
    params = appendExtraParams(params, out);
    const qs = params.length ? '?' + urlencode(params) : '';
    return `hysteria2://${quote(out.credential, '')}@${hostport(out)}${qs}#${nameOf(out)}`;
  }
}

class TuicHandler extends ProtocolHandler {
  schemes = ['tuic'];
  toUri(out) {
    let params = [];
    if (out.sni) params.push(['sni', out.sni]);
    if (out.alpn) params.push(['alpn', out.alpn]);
    if (tru(ex(out, 'congestion_control'))) params.push(['congestion_control', out.extra.congestion_control]);
    if (tru(ex(out, 'udp_relay_mode'))) params.push(['udp_relay_mode', out.extra.udp_relay_mode]);
    if (out.allow_insecure) params.push(['insecure', '1']);
    params = appendExtraParams(params, out);
    const qs = params.length ? '?' + urlencode(params) : '';
    const i = out.credential.indexOf(':');
    const user = i < 0 ? out.credential : out.credential.slice(0, i);
    const pwd = i < 0 ? '' : out.credential.slice(i + 1);
    const password = ex(out, 'password', '') || pwd;
    const auth = password ? `${quote(user, '')}:${quote(password, '')}` : quote(user, '');
    return `tuic://${auth}@${hostport(out)}${qs}#${nameOf(out)}`;
  }
}

function reserved(extra) {
  const cid = Object.prototype.hasOwnProperty.call(extra, 'client_id') ? extra.client_id : '';
  if (typeof cid !== 'string') { const e = new Error(`fromhex() argument must be str, not ${cid === null ? 'NoneType' : typeof cid}`); e.name = 'TypeError'; throw e; }
  if (/^(?:[0-9A-Fa-f]{2}\s*)*$/.test(cid) && cid.replace(/\s+/g, '').length === 6) {
    const h = cid.replace(/\s+/g, '');
    return [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16));
  }
  return [0, 0, 0];
}

class WireGuardHandler extends ProtocolHandler {
  schemes = ['wireguard', 'wg'];
  toUri() { const e = new Error('WireGuard has no share-link form'); e.name = 'NotImplementedError'; throw e; }
  xrayOutbound(out) {
    const peer = { publicKey: ex(out, 'peer_public_key', ''), allowedIPs: ['0.0.0.0/0', '::/0'], endpoint: out.endpoint };
    if (tru(ex(out, 'pre_shared_key'))) peer.preSharedKey = out.extra.pre_shared_key;
    return {
      protocol: 'wireguard',
      settings: {
        secretKey: ex(out, 'private_key', ''),
        address: [ex(out, 'ipv4'), ex(out, 'ipv6')].filter(tru),
        peers: [peer], mtu: Number(pyInt(ex(out, 'mtu', 1280))), reserved: reserved(out.extra),
      },
    };
  }
  singboxOutbound(out) {
    const local = [ex(out, 'ipv4'), ex(out, 'ipv6')].filter(tru);
    return {
      type: 'wireguard', tag: out.name || 'warp', server: out.host, server_port: portOr(out.port, 2408),
      local_address: local.length ? local : ['172.16.0.2/32'],
      private_key: ex(out, 'private_key', ''), peer_public_key: ex(out, 'peer_public_key', ''),
      reserved: reserved(out.extra), mtu: Number(pyInt(ex(out, 'mtu', 1280))),
    };
  }
  clashProxy(out) {
    const proxy = {
      name: out.name || 'WARP', type: 'wireguard', server: out.host, port: portOr(out.port, 2408),
      ip: (ex(out, 'ipv4') || '172.16.0.2/32').split('/')[0],
      'private-key': ex(out, 'private_key', ''), 'public-key': ex(out, 'peer_public_key', ''),
      mtu: Number(pyInt(ex(out, 'mtu', 1280))), reserved: reserved(out.extra),
    };
    if (tru(ex(out, 'ipv6'))) proxy.ipv6 = out.extra.ipv6.split('/')[0];
    return proxy;
  }
}

const HANDLERS = new Map();
for (const h of [new VlessHandler(), new VmessHandler(), new TrojanHandler(), new ShadowsocksHandler(),
  new Hysteria2Handler(), new TuicHandler(), new WireGuardHandler()]) {
  for (const s of h.schemes) HANDLERS.set(s, h);
}

export const handlerFor = (scheme) => HANDLERS.get((scheme || '').toLowerCase()) || null;
export const supportedSchemes = () => [...HANDLERS.keys()].sort();

// core name -> does it have a renderer for this outbound (exceptions mean "no", as in the Python cores)
const CORES = {
  xray: (h, out) => h.xrayOutbound(out),
  singbox: (h, out) => h.singboxOutbound(out),
  mihomo: (h, out) => h.clashProxy(out),
};
export const CORE_NAMES = Object.keys(CORES);

export function coreSupport(out) {
  const res = {};
  for (const name of CORE_NAMES) {
    const h = handlerFor(out.scheme);
    let ok = false;
    if (h) {
      try { ok = CORES[name](h, out) != null; } catch { ok = false; }
    }
    res[name] = ok;
  }
  return res;
}

export { Outbound, PyValueError };
