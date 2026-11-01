// Port of xray_forge/core/models.py: the typed outbound (one proxy config).
import { b64DecodePad, b64Encode, pyJsonLoads, pyStr, pyTruthy, PyValueError } from './pycompat.mjs';

const LEGACY_ALIASES = { uuid: 'credential', hdr: 'host_header', type: 'transport', fp: 'fingerprint' };

// Dataclass field order: config.parse returns the fields in exactly this order.
export const FIELD_NAMES = ['scheme', 'name', 'host', 'port', 'credential', 'transport', 'security', 'sni',
  'host_header', 'path', 'fingerprint', 'alpn', 'service_name', 'header_type', 'public_key', 'short_id',
  'spider_x', 'flow', 'allow_insecure', 'ss_method', 'alter_id', 'encryption', 'extra', 'extra_params', 'raw'];

export function deepCopy(v) {
  if (Array.isArray(v)) return v.map(deepCopy);
  if (v instanceof Map) return new Map([...v].map(([k, x]) => [k, deepCopy(x)]));
  if (v !== null && typeof v === 'object' && v.constructor === Object) {
    const o = {};
    for (const [k, x] of Object.entries(v)) Object.defineProperty(o, k, { value: deepCopy(x), enumerable: true, writable: true, configurable: true });
    return o;
  }
  return v; // primitives, PyFloat (immutable)
}

export class Outbound {
  constructor(fields = {}) {
    this.scheme = 'vless';
    this.name = '';
    this.host = '';
    this.port = '443';
    this.credential = '';
    this.transport = 'tcp';
    this.security = '';
    this.sni = '';
    this.host_header = '';
    this.path = '/';
    this.fingerprint = 'chrome';
    this.alpn = '';
    this.service_name = '';
    this.header_type = '';
    this.public_key = '';
    this.short_id = '';
    this.spider_x = '';
    this.flow = '';
    this.allow_insecure = false;
    this.ss_method = '';
    this.alter_id = '0';
    this.encryption = 'none';
    this.extra = {};
    this.extra_params = new Map();   // insertion-ordered, safe for any key
    this.raw = '';
    for (const k of Object.keys(fields)) {
      if (!FIELD_NAMES.includes(k)) throw new TypeError(`unexpected field ${k}`);
      this[k] = fields[k];
    }
    if (!(this.extra_params instanceof Map)) this.extra_params = new Map(Object.entries(this.extra_params || {}));
  }

  get(key, dflt = undefined) {
    const attr = LEGACY_ALIASES[key] || key;
    if (FIELD_NAMES.includes(attr)) return this[attr];
    if (Object.prototype.hasOwnProperty.call(this.extra, key)) return this.extra[key];
    return dflt;
  }

  get endpoint() { return `${this.host}:${this.port}`; }
  get effective_sni() { return this.sni || this.host_header || this.host; }
  isTls() { return ['tls', 'reality'].includes(this.security.toLowerCase()); }
  isReality() { return this.security.toLowerCase() === 'reality'; }

  // [method, password]; credential holds the password (legacy "method:password" tolerated).
  ssSplit() {
    const cred = this.credential;
    if (this.ss_method) {
      if (cred.startsWith(this.ss_method + ':')) return [this.ss_method, cred.slice(cred.indexOf(':') + 1)];
      return [this.ss_method, cred];
    }
    const i = cred.indexOf(':');
    if (i >= 0) return [cred.slice(0, i), cred.slice(i + 1)];
    return ['aes-256-gcm', cred];
  }

  // Plain object in dataclass order (dataclasses.asdict): deep copies, extra_params as an object.
  to_dict() {
    const d = {};
    for (const k of FIELD_NAMES) {
      const v = this[k];
      Object.defineProperty(d, k, {
        value: k === 'extra_params' ? mapToObject(v) : deepCopy(v), enumerable: true, writable: true, configurable: true,
      });
    }
    return d;
  }

  static fromDict(data) {
    const f = {};
    for (const k of FIELD_NAMES) if (Object.prototype.hasOwnProperty.call(data, k)) f[k] = deepCopy(data[k]);
    return new Outbound(f);
  }
}

export function mapToObject(m) {
  const o = {};
  for (const [k, v] of m) Object.defineProperty(o, k, { value: deepCopy(v), enumerable: true, writable: true, configurable: true });
  return o;
}

const VMESS_MODELED = new Set(['v', 'ps', 'add', 'port', 'id', 'aid', 'scy', 'security', 'net', 'type', 'host',
  'path', 'tls', 'sni', 'alpn', 'fp']);

const dget = (o, k) => (Object.prototype.hasOwnProperty.call(o, k) ? o[k] : undefined);
const isDict = (v) => v !== null && typeof v === 'object' && !Array.isArray(v) && v.constructor === Object;

// vmess://<base64 json>
export function vmessJsonToOutbound(payload, rawLine = '') {
  let data;
  try {
    data = pyJsonLoads(b64DecodePad(payload));
  } catch (e) {
    if (e instanceof PyValueError || e.name === 'JSONDecodeError') return null;
    throw e;
  }
  if (!isDict(data) || !pyTruthy(dget(data, 'add'))) return null;
  const g = (k, dflt) => { const v = dget(data, k); return v === undefined ? dflt : v; };
  const or = (v, d) => (pyTruthy(v) ? v : d);
  const extraParams = new Map();
  for (const [k, v] of Object.entries(data)) {
    if (!VMESS_MODELED.has(k) && v !== null && v !== '') extraParams.set(k, v);
  }
  return new Outbound({
    extra_params: extraParams,
    scheme: 'vmess',
    name: pyStr(or(g('ps'), 'vmess')),
    host: pyStr(or(g('add'), '')),
    port: pyStr(or(g('port'), '443')),
    credential: pyStr(or(g('id'), '')),
    transport: pyStr(or(g('net'), 'tcp')).toLowerCase(),
    security: pyStr(g('tls', '')).toLowerCase() === 'tls' ? 'tls' : '',
    sni: pyStr(or(g('sni'), '')),
    host_header: pyStr(or(g('host'), '')),
    path: pyStr(or(g('path'), '/')),
    fingerprint: pyStr(or(g('fp'), 'chrome')),
    alpn: pyStr(or(g('alpn'), '')),
    header_type: pyStr(or(g('type'), '')),
    alter_id: pyStr(or(g('aid'), '0')),
    encryption: pyStr(or(g('scy'), or(g('security'), 'auto'))),
    raw: rawLine,
  });
}

export { b64DecodePad, b64Encode };
