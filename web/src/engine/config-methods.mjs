// Port of the config.* methods of xray_forge/engine/methods.py (and engine.info).
// Each method takes the JSON-RPC params object and returns Python's exact result, or throws an
// RpcError with Python's code and message.
import { APP_ERROR, INVALID_PARAMS, METHOD_NOT_FOUND, RpcError, invalidParams } from './rpc.mjs';
import {
  DEFAULT_CS, DEFAULT_FM, DEFAULT_FP, DEFAULT_TEMPLATE, CF_RANGES, FASTLY_RANGES, FLOWS, FRAG_PRESETS, MAX_LINES,
  MAX_START, PROTOCOL_VERSION, SECURITIES, TEMPLATE_KEYS, TRANSPORTS, WARP_RANGES, XHTTP_MODES,
} from './config.mjs';
import { FIELD_NAMES, Outbound, deepCopy } from './models.mjs';
import {
  classifyEndpoint, convertBlock, exportToClash, exportToSingbox, exportToSub, parseTarget, tagNameWithCc, validPort,
} from './parser.mjs';
import { CORE_NAMES, coreSupport, handlerFor, supportedSchemes } from './protocols.mjs';
import { dedupConfigs } from './dedup.mjs';
import { PyFloat, PyJSONDecodeError, pyInt, pyJsonLoads, pyIntFromStr, pySplitLines, pyStrip, unquote, urlsplit } from './pycompat.mjs';

const isStr = (v) => typeof v === 'string';
const isInt = (v) => (typeof v === 'number' && Number.isInteger(v)) || typeof v === 'bigint';
const isDict = (v) => v !== null && typeof v === 'object' && !Array.isArray(v) && !(v instanceof PyFloat) && !(v instanceof Map);

function optStr(v, what) {
  if (v === null || v === undefined) return '';
  if (!(isStr(v) || isInt(v)) ) throw invalidParams(`${what} must be a string`);
  return pyStrip(String(v));
}

function overrideIp(v) {
  const ip = optStr(v, 'ip');
  if (ip && classifyEndpoint(ip) === null) throw invalidParams('ip must be an IPv4/IPv6 address or a domain');
  return ip;
}

function overridePort(v) {
  const port = optStr(v, 'port');
  if (port && !validPort(port)) throw invalidParams('port must be 1..65535');
  return port;
}

function startId(v) {
  if (typeof v === 'boolean') throw invalidParams('start must be an integer');
  let n;
  try { n = pyInt(v); } catch (e) {
    if (e.name === 'ValueError' || e.name === 'TypeError' || e.name === 'OverflowError') throw invalidParams('start must be an integer');
    throw e;
  }
  if (n < 0n || n > BigInt(MAX_START)) throw invalidParams(`start must be 0..${MAX_START}`);
  return Number(n);
}

function maskJson(fm) {
  let parsed;
  try { parsed = pyJsonLoads(fm); } catch (e) {
    if (e instanceof PyJSONDecodeError) throw invalidParams('fm must be valid JSON');
    throw e;
  }
  if (!(isDict(parsed) || Array.isArray(parsed))) throw invalidParams('fm must be a JSON object or array');
  return fm;
}

const outboundDict = (out) => { const d = out.to_dict(); delete d.raw; return d; };

function lines(v) {
  if (!Array.isArray(v) || !v.every(isStr)) throw invalidParams('lines must be a list of strings');
  if (v.length > MAX_LINES) throw invalidParams(`too many lines (max ${MAX_LINES})`);
  return v.map((s) => pyStrip(s)).filter((s) => s);
}

function describe(line) {
  const out = parseTarget(line);
  if (out === null) return { line, ok: false };
  return { line, ok: true, outbound: outboundDict(out), supports: coreSupport(out) };
}

const OUT_STR_FIELDS = ['scheme', 'name', 'host', 'port', 'credential', 'transport', 'security', 'sni', 'host_header',
  'path', 'fingerprint', 'alpn', 'service_name', 'header_type', 'public_key', 'short_id', 'spider_x', 'flow',
  'ss_method', 'alter_id', 'encryption', 'raw'];
const OUT_NUM_AS_STR = ['port', 'alter_id'];
const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

function outboundFromObj(obj) {
  if (!isDict(obj)) throw invalidParams('outbound must be an object');
  const bad = Object.keys(obj).filter((k) => !FIELD_NAMES.includes(k)).sort();
  if (bad.length) throw invalidParams(`unknown outbound fields: ${bad.join(', ')}`);
  const data = {};
  for (const k of Object.keys(obj)) data[k] = obj[k];
  for (const key of OUT_STR_FIELDS) {
    if (!has(data, key)) continue;
    let v = data[key];
    if (OUT_NUM_AS_STR.includes(key) && isInt(v)) data[key] = v = String(v);
    if (!isStr(v)) throw invalidParams(`${key} must be a string`);
  }
  if (has(data, 'allow_insecure') && typeof data.allow_insecure !== 'boolean') throw invalidParams('allow_insecure must be true or false');
  for (const key of ['extra', 'extra_params']) {
    if (has(data, key) && !isDict(data[key])) throw invalidParams(`${key} must be an object`);
  }
  for (const [k, v] of Object.entries(data.extra_params || {})) {
    if (!(isStr(v) || isInt(v) || typeof v === 'number' || v instanceof PyFloat || typeof v === 'boolean')) {
      throw invalidParams(`extra_params.${k} must be a string or number`);
    }
  }
  if (data.port && !validPort(data.port)) throw invalidParams('port must be 1..65535');
  data.raw = '';
  if (has(data, 'extra_params')) data.extra_params = new Map(Object.entries(data.extra_params));
  return Outbound.fromDict(data);
}

function boundParams(spec, params) {
  // Dispatcher._call: params must be an object, unknown names are rejected, then the call is bound.
  if (params === null || params === undefined) params = {};
  if (!isDict(params)) throw invalidParams('params must be an object');
  const names = spec.map((s) => s.name);
  const unknown = Object.keys(params).filter((k) => !names.includes(k)).sort();
  if (unknown.length) throw invalidParams(`unknown params: ${unknown.join(', ')}`);
  const out = {};
  for (const s of spec) {
    if (has(params, s.name)) out[s.name] = params[s.name];
    else if (s.required) throw invalidParams(`missing a required argument: '${s.name}'`);
    else out[s.name] = s.default;
  }
  return out;
}

const req = (name) => ({ name, required: true });
const opt = (name, def) => ({ name, required: false, default: def });

export function engineInfo({ version, methods }) {
  return {
    version, protocol: PROTOCOL_VERSION, schemes: supportedSchemes(), cores: [...CORE_NAMES], methods: [...methods],
    defaults: { fp: DEFAULT_FP, cs: DEFAULT_CS, fm: deepCopy(DEFAULT_FM), template: DEFAULT_TEMPLATE },
    template_keys: [...TEMPLATE_KEYS], frag_presets: [...FRAG_PRESETS],
    ranges: { cloudflare: [...CF_RANGES], fastly: [...FASTLY_RANGES], warp: [...WARP_RANGES] },
    editor: { transports: [...TRANSPORTS], flows: [...FLOWS], securities: [...SECURITIES], xhttp_modes: [...XHTTP_MODES] },
  };
}

const IMPL = {
  'config.parse': { spec: [req('line')], fn: ({ line }) => {
    if (!isStr(line)) throw invalidParams('line must be a string');
    return describe(pyStrip(line));
  } },
  'config.parse_many': { spec: [req('text')], fn: ({ text }) => {
    if (!isStr(text)) throw invalidParams('text must be a string');
    return lines(pySplitLines(text)).map(describe);
  } },
  'config.render': { spec: [req('outbound')], fn: ({ outbound }) => {
    const out = outboundFromObj(outbound);
    const h = handlerFor(out.scheme);
    if (h === null) throw invalidParams(`unsupported scheme: ${pyReprStr(out.scheme)}`);
    const uri = h.toUri(out);
    return { uri, roundtrip_ok: parseTarget(uri) !== null, supports: coreSupport(out) };
  } },
  'config.from_json': { spec: [req('text')], fn: ({ text }) => {
    if (!isStr(text)) throw invalidParams('text must be a string');
    let obj;
    try { obj = pyJsonLoads(text); } catch (e) {
      if (e instanceof PyJSONDecodeError) throw invalidParams(`bad JSON: ${e.message}`);
      throw e;
    }
    const out = outboundFromObj(obj);
    if (handlerFor(out.scheme) === null) throw invalidParams(`unsupported scheme: ${pyReprStr(out.scheme)}`);
    return { outbound: outboundDict(out), supports: coreSupport(out) };
  } },
  'config.convert': {
    spec: [req('text'), opt('fp', DEFAULT_FP), opt('cs', DEFAULT_CS), opt('fm', null), opt('template', DEFAULT_TEMPLATE),
      opt('start', 1), opt('ip', ''), opt('port', ''), opt('rename', true), opt('tls_only', true),
      opt('want_fp', true), opt('want_cs', true), opt('want_fm', true), opt('dedup', false)],
    fn: (p) => {
      if (!isStr(p.text)) throw invalidParams('text must be a string');
      for (const [what, val] of [['fp', p.fp], ['cs', p.cs], ['template', p.template]]) {
        if (!isStr(val)) throw invalidParams(`${what} must be a string`);
      }
      let fm = p.fm;
      if (fm === null) fm = JSON.stringify(DEFAULT_FM);
      if (!isStr(fm)) throw invalidParams('fm must be a string');
      for (const [what, val] of [['rename', p.rename], ['tls_only', p.tls_only], ['want_fp', p.want_fp],
        ['want_cs', p.want_cs], ['want_fm', p.want_fm], ['dedup', p.dedup]]) {
        if (typeof val !== 'boolean') throw invalidParams(`${what} must be true or false`);
      }
      const fp = pyStrip(p.fp); const cs = pyStrip(p.cs); fm = pyStrip(fm);
      if (p.want_fm && fm) maskJson(fm);
      const ip = overrideIp(p.ip);
      const port = overridePort(p.port);
      const start = startId(p.start);
      const [outLines0, names, counts] = convertBlock(p.text, fp, cs, fm, p.tls_only, p.rename,
        pyStrip(p.template) || DEFAULT_TEMPLATE, start, ip, port, p.want_fp, p.want_cs, p.want_fm);
      let outLines = outLines0;
      let removed = 0;
      if (p.dedup) [outLines, removed] = dedupConfigs(outLines0);
      const left = new Map();
      for (const l of outLines) left.set(l, (left.get(l) || 0) + 1);
      const kept = [];
      for (let [name, line] of names) {
        if ((left.get(line) || 0) > 0) {
          left.set(line, left.get(line) - 1);
          if (!p.rename) name = unquote(urlsplit(line).fragment);
          kept.push({ name, line });
        }
      }
      return { lines: outLines, counts, removed, names: kept };
    },
  },
  'config.check_override': { spec: [opt('ip', ''), opt('port', '')], fn: (p) => {
    const ip = optStr(p.ip, 'ip');
    const port = optStr(p.port, 'port');
    return { ip: ip ? classifyEndpoint(ip) : '', port: port ? validPort(port) : null };
  } },
  'config.tag_cc': { spec: [req('items')], fn: ({ items }) => {
    if (!Array.isArray(items) || items.length > MAX_LINES) throw invalidParams(`items must be a list (max ${MAX_LINES})`);
    const res = [];
    let tagged = 0;
    for (const it of items) {
      if (!isDict(it) || !isStr(it.line) || (has(it, 'cc') && !isStr(it.cc))) throw invalidParams('each item needs a string line and cc');
      const [line, name, changed] = tagNameWithCc(it.line, has(it, 'cc') ? it.cc : '');
      tagged += changed ? 1 : 0;
      res.push({ line, name, changed });
    }
    return { items: res, tagged };
  } },
  'config.export': { spec: [req('lines'), req('format')], fn: (p) => {
    const ls = lines(p.lines);
    const fn = { clash: exportToClash, singbox: exportToSingbox, sub: exportToSub }[p.format];
    if (!isStr(p.format) || !has({ clash: 1, singbox: 1, sub: 1 }, p.format) || !fn) throw invalidParams('format must be one of: clash, singbox, sub');
    return { format: p.format, count: ls.length, content: fn(ls) };
  } },
  'config.dedup': { spec: [req('lines')], fn: ({ lines: l }) => {
    const [out, removed] = dedupConfigs(lines(l));
    return { lines: out, removed };
  } },
};
import { pyReprStr } from './pycompat.mjs';

export const CONFIG_METHOD_NAMES = Object.keys(IMPL);

export const configMethods = Object.fromEntries(Object.entries(IMPL).map(([name, { spec, fn }]) => [name, async (params) => {
  try {
    return fn(boundParams(spec, params));
  } catch (e) {
    if (e instanceof RpcError) throw e;
    // Dispatcher: any other failure is an application error "Type: text"
    throw new RpcError(APP_ERROR, `${e.name || 'Error'}: ${e.message}`);
  }
}]));

export { INVALID_PARAMS, METHOD_NOT_FOUND, pyIntFromStr };
