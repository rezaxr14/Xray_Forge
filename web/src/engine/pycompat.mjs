// The slices of Python 3.13 behaviour the share-link engine depends on, reproduced exactly:
// str.strip/split/splitlines/isdigit, int(), urllib.parse, base64, ipaddress and json.loads.
// Parity with the Python engine is covered by web/test/engine.test.mjs.
// Plain ES module, no Node-only APIs.
import { SPACE, DIGIT_ONLY, DECIMAL_ZEROS } from './unicode-tables.mjs';

export class PyValueError extends Error {
  constructor(message) { super(message); this.name = 'ValueError'; }
}

// A JSON number Python reads as float (it has a fraction/exponent, or is NaN/Infinity).
// JS numbers cannot tell 2.0 from 2, and str(2.0) is "2.0", so parsed floats keep this marker.
export class PyFloat {
  constructor(v) { this.v = v; }
  valueOf() { return this.v; }
  toJSON() { return Number.isFinite(this.v) ? this.v : null; }
}

// ------------------------------------------------------------------ str basics

function inRanges(cp, flat) {
  let lo = 0;
  let hi = flat.length / 2 - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (cp < flat[2 * mid]) hi = mid - 1;
    else if (cp > flat[2 * mid + 1]) lo = mid + 1;
    else return true;
  }
  return false;
}

export const isSpaceCp = (cp) => inRanges(cp, SPACE);

export function decimalValue(cp) {
  // Every Unicode decimal digit sits in a run of ten starting at a "zero".
  let lo = 0;
  let hi = DECIMAL_ZEROS.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const z = DECIMAL_ZEROS[mid];
    if (cp < z) hi = mid - 1;
    else if (cp > z + 9) lo = mid + 1;
    else return cp - z;
  }
  return -1;
}

const cps = (s) => Array.from(s, (c) => c.codePointAt(0));

export function pyStrip(s) {
  const a = cps(s);
  let i = 0;
  let j = a.length;
  while (i < j && isSpaceCp(a[i])) i++;
  while (j > i && isSpaceCp(a[j - 1])) j--;
  return String.fromCodePoint(...a.slice(i, j));
}

export function pyStripChars(s, chars) {
  const set = new Set(Array.from(chars));
  const a = Array.from(s);
  let i = 0;
  let j = a.length;
  while (i < j && set.has(a[i])) i++;
  while (j > i && set.has(a[j - 1])) j--;
  return a.slice(i, j).join('');
}

export function pySplitWs(s) {
  const out = [];
  let cur = '';
  for (const ch of s) {
    if (isSpaceCp(ch.codePointAt(0))) {
      if (cur) { out.push(cur); cur = ''; }
    } else cur += ch;
  }
  if (cur) out.push(cur);
  return out;
}

const LINE_BREAKS = new Set(['\n', '\r', '\v', '\f', '\x1c', '\x1d', '\x1e', '\x85', '', '']);
export function pySplitLines(s) {
  const out = [];
  let cur = '';
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (LINE_BREAKS.has(ch)) {
      if (ch === '\r' && s[i + 1] === '\n') i++;
      out.push(cur);
      cur = '';
    } else cur += ch;
  }
  if (cur) out.push(cur);
  return out;
}

export function pyIsDigit(s) {
  if (!s) return false;
  for (const ch of s) {
    const cp = ch.codePointAt(0);
    if (decimalValue(cp) < 0 && !inRanges(cp, DIGIT_ONLY)) return false;
  }
  return true;
}

export function pyIsDecimal(s) {
  if (!s) return false;
  for (const ch of s) if (decimalValue(ch.codePointAt(0)) < 0) return false;
  return true;
}

export const pyIsAlpha = (s) => s.length > 0 && /^\p{L}+$/u.test(s);
export const isAscii = (s) => /^[\x00-\x7f]*$/.test(s);

// int(str): whitespace, sign, decimal digits (any script), single underscores between digits.
// Returns a BigInt, or null where Python raises ValueError.
export function pyIntFromStr(text) {
  const s = pyStrip(text);
  if (!s) return null;
  let i = 0;
  let neg = false;
  if (s[0] === '+' || s[0] === '-') { neg = s[0] === '-'; i = 1; }
  const body = Array.from(s.slice(i));
  if (!body.length) return null;
  let digits = '';
  let prevUnderscore = true;       // an underscore may not lead
  for (const ch of body) {
    if (ch === '_') {
      if (prevUnderscore) return null;
      prevUnderscore = true;
      continue;
    }
    const v = decimalValue(ch.codePointAt(0));
    if (v < 0) return null;
    digits += String(v);
    prevUnderscore = false;
  }
  if (prevUnderscore) return null;
  const n = BigInt(digits);
  return neg ? -n : n;
}

// ------------------------------------------------------------------ percent-encoding

const enc = new TextEncoder();
const dec = new TextDecoder('utf-8', { fatal: false, ignoreBOM: true });
export const utf8 = (s) => enc.encode(s);
export const utf8Decode = (bytes) => dec.decode(bytes);

const ALWAYS_SAFE = /^[A-Za-z0-9_.\-~]$/;
const HEX = '0123456789ABCDEF';

export function quote(s, safe = '') {
  let out = '';
  const safeSet = new Set(Array.from(safe));
  for (const b of utf8(s)) {
    const ch = String.fromCharCode(b);
    if (b < 128 && (ALWAYS_SAFE.test(ch) || safeSet.has(ch))) out += ch;
    else out += '%' + HEX[b >> 4] + HEX[b & 15];
  }
  return out;
}

const isHex = (c) => /^[0-9A-Fa-f]$/.test(c);

function unquoteToBytes(s) {
  const raw = utf8(s);
  const bytes = [];
  for (let i = 0; i < raw.length; i++) {
    if (raw[i] === 0x25 && i + 2 < raw.length &&
        isHex(String.fromCharCode(raw[i + 1])) && isHex(String.fromCharCode(raw[i + 2]))) {
      bytes.push(parseInt(String.fromCharCode(raw[i + 1], raw[i + 2]), 16));
      i += 2;
    } else bytes.push(raw[i]);
  }
  return Uint8Array.from(bytes);
}

export function unquote(s) {
  if (!s.includes('%')) return s;
  // Python splits into ASCII runs (percent-decoded, then utf-8 "replace") and the rest (kept).
  const bits = s.split(/([\x00-\x7f]+)/);
  let out = bits[0];
  for (let i = 1; i < bits.length; i += 2) {
    out += utf8Decode(unquoteToBytes(bits[i])) + bits[i + 1];
  }
  return out;
}

export function parseQsl(qs, keepBlank = true) {
  const r = [];
  const args = qs ? qs.split('&') : [];
  for (const nameValue of args) {
    if (!nameValue) continue;
    const at = nameValue.indexOf('=');
    let name;
    let value;
    if (at < 0) {
      if (!keepBlank) continue;
      name = nameValue;
      value = '';
    } else {
      name = nameValue.slice(0, at);
      value = nameValue.slice(at + 1);
    }
    if (value.length || keepBlank) {
      r.push([unquote(name.replaceAll('+', ' ')), unquote(value.replaceAll('+', ' '))]);
    }
  }
  return r;
}

export const urlencode = (pairs) => pairs.map(([k, v]) => `${quote(String(k))}=${quote(String(v))}`).join('&');

// ------------------------------------------------------------------ ipaddress (Python 3.13)

function ipv4Octets(s) {
  if (!s) return null;
  if (s.includes('/')) return null;
  const parts = s.split('.');
  if (parts.length !== 4) return null;
  for (const p of parts) {
    if (!p) return null;
    if (!/^[0-9]+$/.test(p)) return null;
    if (p.length > 3) return null;
    if (p !== '0' && p[0] === '0') return null;
    if (Number(p) > 255) return null;
  }
  return parts.map(Number);
}

export const isIPv4 = (s) => ipv4Octets(s) !== null;

function parseHextet(h) {
  if (!/^[0-9A-Fa-f]*$/.test(h)) return null;
  if (h.length > 4 || h.length === 0) return null;
  return parseInt(h, 16);
}

export function isIPv6(s) {
  if (s.includes('/')) return false;
  const pct = s.indexOf('%');
  let addr = s;
  if (pct >= 0) {
    const scope = s.slice(pct + 1);
    if (!scope || scope.includes('%')) return false;
    addr = s.slice(0, pct);
  }
  if (!addr) return false;
  const parts = addr.split(':');
  if (parts.length < 3) return false;
  if (parts[parts.length - 1].includes('.')) {
    const v4 = ipv4Octets(parts.pop());
    if (!v4) return false;
    parts.push(((v4[0] << 8) | v4[1]).toString(16), ((v4[2] << 8) | v4[3]).toString(16));
  }
  if (parts.length > 9) return false;
  let skip = null;
  for (let i = 1; i < parts.length - 1; i++) {
    if (!parts[i]) {
      if (skip !== null) return false;
      skip = i;
    }
  }
  let hi;
  let lo;
  if (skip !== null) {
    hi = skip;
    lo = parts.length - skip - 1;
    if (!parts[0]) { hi--; if (hi) return false; }
    if (!parts[parts.length - 1]) { lo--; if (lo) return false; }
    if (8 - (hi + lo) < 1) return false;
  } else {
    if (parts.length !== 8) return false;
    if (!parts[0] || !parts[parts.length - 1]) return false;
    hi = parts.length;
    lo = 0;
  }
  for (let i = 0; i < hi; i++) if (parseHextet(parts[i]) === null) return false;
  for (let i = parts.length - lo; i < parts.length; i++) if (parseHextet(parts[i]) === null) return false;
  return true;
}

// ------------------------------------------------------------------ urllib.parse

const SCHEME_CHARS = /^[A-Za-z0-9+\-.]*$/;
const C0_OR_SPACE = (() => { let s = ' '; for (let i = 0; i < 32; i++) s += String.fromCharCode(i); return s; })();

function checkBracketedHost(h) {
  if (h.startsWith('v') || h.startsWith('V')) {
    if (!/^[vV][a-fA-F0-9]+\..+$/s.test(h)) throw new PyValueError('IPvFuture address is invalid');
  } else if (isIPv4(h)) {
    throw new PyValueError('An IPv4 address cannot be in brackets');
  } else if (!isIPv6(h)) {
    throw new PyValueError(`'${h}' does not appear to be an IPv4 or IPv6 address`);
  }
}

// Mirrors urllib.parse._check_bracketed_netloc (3.13): only the host may carry brackets, and nothing
// may sit between ']' and the port.
function checkBracketedNetloc(netloc) {
  const at = netloc.lastIndexOf('@');
  const hostnameAndPort = at >= 0 ? netloc.slice(at + 1) : netloc;
  const open = hostnameAndPort.indexOf('[');
  let hostname;
  if (open >= 0) {
    if (open > 0) throw new PyValueError('Invalid IPv6 URL');
    const bracketed = hostnameAndPort.slice(open + 1);
    const close = bracketed.indexOf(']');
    hostname = close >= 0 ? bracketed.slice(0, close) : bracketed;
    const port = close >= 0 ? bracketed.slice(close + 1) : '';
    if (port && !port.startsWith(':')) throw new PyValueError('Invalid IPv6 URL');
  } else {
    const colon = hostnameAndPort.indexOf(':');
    hostname = colon >= 0 ? hostnameAndPort.slice(0, colon) : hostnameAndPort;
  }
  checkBracketedHost(hostname);
}

function checkNetloc(netloc) {
  if (!netloc || isAscii(netloc)) return;
  const n = netloc.replaceAll('@', '').replaceAll(':', '').replaceAll('#', '').replaceAll('?', '');
  const n2 = n.normalize('NFKC');
  if (n === n2) return;
  for (const c of '/?#@:') {
    if (n2.includes(c)) {
      throw new PyValueError(`netloc '${netloc}' contains invalid characters under NFKC normalization`);
    }
  }
}

export function urlsplit(input) {
  let url = input;
  // url.lstrip(C0 control or space)
  let k = 0;
  while (k < url.length && C0_OR_SPACE.includes(url[k])) k++;
  url = url.slice(k).replace(/[\t\r\n]/g, '');
  let scheme = '';
  let netloc = '';
  let query = '';
  let fragment = '';
  const i = url.indexOf(':');
  if (i > 0 && /^[A-Za-z]/.test(url[0]) && SCHEME_CHARS.test(url.slice(0, i))) {
    scheme = url.slice(0, i).toLowerCase();
    url = url.slice(i + 1);
  }
  if (url.slice(0, 2) === '//') {
    let delim = url.length;
    for (const c of '/?#') {
      const w = url.indexOf(c, 2);
      if (w >= 0) delim = Math.min(delim, w);
    }
    netloc = url.slice(2, delim);
    url = url.slice(delim);
    if ((netloc.includes('[') && !netloc.includes(']')) || (netloc.includes(']') && !netloc.includes('['))) {
      throw new PyValueError('Invalid IPv6 URL');
    }
    if (netloc.includes('[') && netloc.includes(']')) checkBracketedNetloc(netloc);
  }
  const hash = url.indexOf('#');
  if (hash >= 0) { fragment = url.slice(hash + 1); url = url.slice(0, hash); }
  const q = url.indexOf('?');
  if (q >= 0) { query = url.slice(q + 1); url = url.slice(0, q); }
  checkNetloc(netloc);
  const at = netloc.lastIndexOf('@');
  let username = null;
  let password = null;
  if (at >= 0) {
    const userinfo = netloc.slice(0, at);
    const colon = userinfo.indexOf(':');
    if (colon >= 0) { username = userinfo.slice(0, colon); password = userinfo.slice(colon + 1); } else username = userinfo;
  }
  return { scheme, netloc, path: url, query, fragment, username, password };
}

const USES_NETLOC = new Set(['', 'ftp', 'http', 'gopher', 'nntp', 'telnet', 'imap', 'wais', 'file', 'mms', 'https',
  'shttp', 'snews', 'prospero', 'rtsp', 'rtsps', 'rtspu', 'rsync', 'svn', 'svn+ssh', 'sftp', 'nfs', 'git',
  'git+ssh', 'ws', 'wss']);

export function urlunsplit({ scheme, netloc, path, query, fragment }) {
  let url = path;
  if (netloc) {
    if (url && url[0] !== '/') url = '/' + url;
    url = '//' + netloc + url;
  } else if (url.slice(0, 2) === '//') {
    url = '//' + url;
  } else if (scheme && USES_NETLOC.has(scheme) && (!url || url[0] === '/')) {
    url = '//' + url;
  }
  if (scheme) url = scheme + ':' + url;
  if (query) url = url + '?' + query;
  if (fragment) url = url + '#' + fragment;
  return url;
}

// ------------------------------------------------------------------ base64

const B64_STRICT = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export function b64DecodePad(text) {
  let compact = pySplitWs(text).join('').replaceAll('-', '+').replaceAll('_', '/');
  const cpLen = Array.from(compact).length;
  compact += '='.repeat(((4 - (cpLen % 4)) % 4));
  if (!B64_STRICT.test(compact)) throw new PyValueError('Invalid base64-encoded string');
  const bin = atob(compact);
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return utf8Decode(bytes);
}

export function b64Encode(text, urlsafe = false) {
  let bin = '';
  for (const b of utf8(text)) bin += String.fromCharCode(b);
  const out = btoa(bin);
  return urlsafe ? out.replaceAll('+', '-').replaceAll('/', '_') : out;
}

// ------------------------------------------------------------------ str.format subset (naming templates)
// Supported: {name}, {name!r|s|a}, {name:spec} for str and int values, {{ and }}, one level of
// nested {name} inside a spec, and [index] on strings.  Anything else (attribute access,
// positional fields, unknown names, bad specs) raises, which the namer turns into its fallback
// exactly as the Python `except Exception` does.  Attribute access that Python accepts
// (for example {id.real}) is not supported: documented in docs/web-app.md.

export class PyFormatError extends Error {}

function pad(body, width, fill, align, defaultAlign) {
  const len = Array.from(body).length;
  if (width <= len) return body;
  const a = align || defaultAlign;
  const n = width - len;
  if (a === '<') return body + fill.repeat(n);
  if (a === '>') return fill.repeat(n) + body;
  if (a === '^') return fill.repeat(Math.floor(n / 2)) + body + fill.repeat(n - Math.floor(n / 2));
  throw new PyFormatError("'=' alignment not allowed in string format specifier");
}

const SPEC_RE = /^(?:([^]?)([<>=^]))?([+\- ])?(#)?(0)?(\p{Nd}+)?([,_])?(?:\.(\p{Nd}+))?([a-zA-Z%])?$/u;
const specInt = (t) => Number(pyIntFromStr(t));

// non-negative float formatted like Python's 'e' 'f' 'g' '%' presentation types
function floatDigits(x, t, prec, alt) {
  const expFix = (str) => str.replace(/e([+-])(\d)$/, 'e$10$2');
  if (t === '%') return floatDigits(x * 100, 'f', prec, alt) + '%';
  if (t === 'f' || t === 'F') return x.toFixed(prec);
  if (t === 'e' || t === 'E') { const r = expFix(x.toExponential(prec)); return t === 'E' ? r.toUpperCase() : r; }
  // g / G
  const p = prec === 0 ? 1 : prec;
  if (x === 0) return alt ? (0).toFixed(p - 1) : '0';
  const exp = Math.floor(Math.log10(x));
  const e = parseInt(x.toExponential(p - 1).split('e')[1], 10);
  void exp;
  let r;
  if (e < -4 || e >= p) {
    r = expFix(x.toExponential(p - 1));
    if (!alt) r = r.replace(/\.?0+e/, 'e');
  } else {
    r = x.toFixed(Math.max(0, p - 1 - e));
    if (!alt && r.includes('.')) r = r.replace(/\.?0+$/, '');
  }
  return t === 'G' ? r.toUpperCase() : r;
}

function formatValue(value, spec) {
  const m = SPEC_RE.exec(spec);
  if (!m) throw new PyFormatError('Invalid format specifier');
  let [, fill, align, sign, alt, zero, width, group, prec, type] = m;
  // "[fill]align" is ambiguous with a lone align char; the regex above already prefers fill+align.
  const w = width ? specInt(width) : 0;
  const isInt = typeof value === 'number' || typeof value === 'bigint';
  if (!isInt) {
    if (type && type !== 's') throw new PyFormatError(`Unknown format code '${type}' for object of type 'str'`);
    if (sign) throw new PyFormatError('Sign not allowed in string format specifier');
    if (alt) throw new PyFormatError('Alternate form (#) not allowed in string format specifier');
    if (group) throw new PyFormatError(`Cannot specify '${group}' with 's'.`);
    if (align === '=') throw new PyFormatError("'=' alignment not allowed in string format specifier");
    let body = value;
    if (prec !== undefined) body = Array.from(body).slice(0, specInt(prec)).join('');
    let f = fill || ' ';
    let a = align;
    if (zero && !align) { f = '0'; a = '<'; } else if (zero && align && !fill) f = '0';
    return pad(body, w, f, a, '<');
  }
  const n = BigInt(value);
  if (prec !== undefined && 'dbxXoc'.includes(type || 'd')) throw new PyFormatError("Precision not allowed in integer format specifier");
  if (type === 'c') {
    if (sign || alt) throw new PyFormatError("Sign not allowed with integer format specifier 'c'");
    return pad(String.fromCodePoint(Number(n)), w, fill || ' ', align, '<');
  }
  let t = type || 'd';
  if (t === 'n') t = 'd';
  let digits;
  const abs = n < 0n ? -n : n;
  if ('eEfFgG%'.includes(t)) {
    digits = floatDigits(Number(abs), t, prec === undefined ? 6 : specInt(prec), !!alt);
    if (group) digits = digits.replace(/^\d+/, (ip) => ip.replace(new RegExp(`\\B(?=(.{3})+$)`, 'g'), group));
  } else if (t === 'd') digits = abs.toString(10);
  else if (t === 'b') digits = abs.toString(2);
  else if (t === 'o') digits = abs.toString(8);
  else if (t === 'x') digits = abs.toString(16);
  else if (t === 'X') digits = abs.toString(16).toUpperCase();
  else throw new PyFormatError(`Unsupported format code '${t}' for int`);
  if (group && !'eEfFgG%'.includes(t)) {
    if (group === ',' && t !== 'd') throw new PyFormatError("Cannot specify ',' with '" + t + "'.");
    const gs = group === ',' ? 3 : (t === 'd' ? 3 : 4);
    digits = digits.replace(new RegExp(`\\B(?=(.{${gs}})+$)`, 'g'), group);
  }
  const prefix = alt ? { b: '0b', o: '0o', x: '0x', X: '0X', d: '' }[t] : '';
  const sgn = n < 0n ? '-' : (sign === '+' ? '+' : (sign === ' ' ? ' ' : ''));
  if (zero && !align) {
    const bodyLen = sgn.length + prefix.length + digits.length;
    return sgn + prefix + '0'.repeat(Math.max(0, w - bodyLen)) + digits;
  }
  const a = align || '>';
  if (a === '=') {
    const bodyLen = sgn.length + prefix.length + digits.length;
    return sgn + prefix + (fill || (zero ? '0' : ' ')).repeat(Math.max(0, w - bodyLen)) + digits;
  }
  return pad(sgn + prefix + digits, w, fill || (zero ? '0' : ' '), a, '>');
}

export function pyFormat(template, values) {
  let out = '';
  let i = 0;
  while (i < template.length) {
    const c = template[i];
    if (c === '{') {
      if (template[i + 1] === '{') { out += '{'; i += 2; continue; }
      // find the matching close brace, allowing one level of nesting in the spec
      let depth = 1;
      let j = i + 1;
      while (j < template.length && depth) {
        if (template[j] === '{') depth++;
        else if (template[j] === '}') depth--;
        j++;
      }
      if (depth) throw new PyFormatError("expected '}' before end of string");
      out += renderField(template.slice(i + 1, j - 1), values);
      i = j;
    } else if (c === '}') {
      if (template[i + 1] === '}') { out += '}'; i += 2; continue; }
      throw new PyFormatError("Single '}' encountered in format string");
    } else { out += c; i++; }
  }
  return out;
}

function renderField(field, values) {
  let name = field;
  let spec = '';
  let conv = '';
  // split "name!conv:spec": the first ':' or '!' outside brackets ends the name
  let depth = 0;
  let cut = -1;
  for (let k = 0; k < field.length; k++) {
    const ch = field[k];
    if (ch === '[') depth++;
    else if (ch === ']') depth--;
    else if (!depth && (ch === ':' || ch === '!')) { cut = k; break; }
  }
  if (cut >= 0) {
    name = field.slice(0, cut);
    let rest = field.slice(cut);
    if (rest[0] === '!') {
      conv = rest[1] || '';
      if (!conv || !'rsa'.includes(conv)) throw new PyFormatError('bad conversion');
      rest = rest.slice(2);
      if (rest && rest[0] !== ':') throw new PyFormatError("expected ':' after conversion specifier");
    }
    if (rest[0] === ':') spec = rest.slice(1);
  }
  if (spec.includes('{')) spec = pyFormat(spec, values);
  const m = /^([A-Za-z_][A-Za-z0-9_]*)(?:\.(real|imag|numerator|denominator))?((?:\[[^\]]*\])*)$/.exec(name);
  if (!m || !Object.prototype.hasOwnProperty.call(values, m[1])) throw new PyFormatError(`bad field ${name}`);
  let v = values[m[1]];
  if (m[2]) {
    if (typeof v !== 'number') throw new PyFormatError(`'str' object has no attribute '${m[2]}'`);
    v = m[2] === 'imag' ? 0 : m[2] === 'denominator' ? 1 : v;
  }
  for (const idx of m[3].matchAll(/\[([^\]]*)\]/g)) {
    if (typeof v !== 'string' || !/^\d+$/.test(idx[1])) throw new PyFormatError('bad index');
    const a = Array.from(v);
    const at = parseInt(idx[1], 10);
    if (at >= a.length) throw new PyFormatError('string index out of range');
    v = a[at];
  }
  if (conv === 's') v = typeof v === 'string' ? v : String(v);
  else if (conv === 'r' || conv === 'a') v = typeof v === 'string' ? pyReprStr(v, conv === 'a') : String(v);
  return formatValue(v, spec);
}

export function pyReprStr(s, ascii = false) {
  const hasSingle = s.includes("'");
  const hasDouble = s.includes('"');
  const q = hasSingle && !hasDouble ? '"' : "'";
  let out = q;
  for (const ch of s) {
    const c = ch.codePointAt(0);
    if (ch === q || ch === '\\') out += '\\' + ch;
    else if (ch === '\n') out += '\\n';
    else if (ch === '\r') out += '\\r';
    else if (ch === '\t') out += '\\t';
    else if (c < 0x20 || c === 0x7f) out += '\\x' + c.toString(16).padStart(2, '0');
    else if (c > 0x7e && (ascii || c < 0xa0 || !/^[\p{L}\p{N}\p{P}\p{S}\p{M}]$/u.test(ch))) {
      out += c <= 0xff ? '\\x' + c.toString(16).padStart(2, '0')
        : c <= 0xffff ? '\\u' + c.toString(16).padStart(4, '0') : '\\U' + c.toString(16).padStart(8, '0');
    } else out += ch;
  }
  return out + q;
}

// ------------------------------------------------------------------ json.loads (Python 3.13 messages)

export class PyJSONDecodeError extends Error {
  // `doc` is the text, `pos` a code point offset (as in Python).
  constructor(msg, doc, pos) {
    const head = Array.from(doc).slice(0, pos).join('');
    const nl = head.lastIndexOf('\n');
    const lineno = (head.match(/\n/g) || []).length + 1;
    const colno = nl < 0 ? pos + 1 : Array.from(head.slice(nl + 1)).length + 1;
    super(`${msg}: line ${lineno} column ${colno} (char ${pos})`);
    this.name = 'JSONDecodeError';
  }
}

const WS = ' \t\n\r';
const ESCAPES = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };

export function pyJsonLoads(text) {
  // Positions are code point offsets in Python; this port indexes UTF-16 units and converts for messages.
  const s = text;
  const cpPos = (p) => Array.from(s.slice(0, p)).length;
  const fail = (msg, p) => { throw new PyJSONDecodeError(msg, s, cpPos(p)); };
  if (s.startsWith('﻿')) throw new PyJSONDecodeError('Unexpected UTF-8 BOM (decode using utf-8-sig)', s, 0);

  const skip = (p) => { while (p < s.length && WS.includes(s[p])) p++; return p; };

  function scanString(end) {
    const begin = end - 1;
    let out = '';
    for (;;) {
      let p = end;
      while (p < s.length && s[p] !== '"' && s[p] !== '\\' && s.charCodeAt(p) > 0x1f) p++;
      if (p >= s.length) fail('Unterminated string starting at', begin);
      out += s.slice(end, p);
      const term = s[p];
      end = p + 1;
      if (term === '"') return [out, end];
      if (term !== '\\') fail('Invalid control character at', p);
      if (end >= s.length) fail('Unterminated string starting at', begin);
      const esc = s[end];
      if (esc !== 'u') {
        if (!Object.prototype.hasOwnProperty.call(ESCAPES, esc)) fail('Invalid \\escape', end - 1);
        out += ESCAPES[esc];
        end += 1;
      } else {
        const hex = (at) => {
          const h = s.slice(at + 1, at + 5);
          if (h.length === 4 && /^[0-9A-Fa-f]{4}$/.test(h)) return parseInt(h, 16);
          return fail('Invalid \\uXXXX escape', at);
        };
        let uni = hex(end);
        end += 5;
        if (uni >= 0xd800 && uni <= 0xdbff && s.slice(end, end + 2) === '\\u') {
          const uni2 = hex(end + 1);
          if (uni2 >= 0xdc00 && uni2 <= 0xdfff) {
            uni = 0x10000 + (((uni - 0xd800) << 10) | (uni2 - 0xdc00));
            end += 6;
          }
        }
        out += String.fromCodePoint(uni);
      }
    }
  }

  const NUM = /(-?(?:0|[1-9][0-9]*))(\.[0-9]+)?([eE][-+]?[0-9]+)?/y;

  function scanOnce(idx) {
    const ch = s[idx];
    if (ch === undefined) fail('Expecting value', idx);
    if (ch === '"') return scanString(idx + 1);
    if (ch === '{') return scanObject(idx + 1);
    if (ch === '[') return scanArray(idx + 1);
    if (s.startsWith('null', idx)) return [null, idx + 4];
    if (s.startsWith('true', idx)) return [true, idx + 4];
    if (s.startsWith('false', idx)) return [false, idx + 5];
    NUM.lastIndex = idx;
    const m = NUM.exec(s);
    if (m) {
      const [whole, int, frac, exp] = m;
      if (frac || exp) return [new PyFloat(Number(whole)), idx + whole.length];
      const big = BigInt(int);
      const asNum = Number(int);
      return [Number.isSafeInteger(asNum) ? asNum : big, idx + whole.length];
    }
    if (s.startsWith('NaN', idx)) return [new PyFloat(NaN), idx + 3];
    if (s.startsWith('Infinity', idx)) return [new PyFloat(Infinity), idx + 8];
    if (s.startsWith('-Infinity', idx)) return [new PyFloat(-Infinity), idx + 9];
    return fail('Expecting value', idx);
  }

  function scanObject(end) {
    const obj = {};
    let next = s[end];
    if (next !== '"') {
      if (next !== undefined && WS.includes(next)) { end = skip(end); next = s[end]; }
      if (next === '}') return [obj, end + 1];
      if (next !== '"') fail('Expecting property name enclosed in double quotes', end);
    }
    end += 1;
    for (;;) {
      let key;
      [key, end] = scanString(end);
      if (s[end] !== ':') {
        end = skip(end);
        if (s[end] !== ':') fail("Expecting ':' delimiter", end);
      }
      end = skip(end + 1);
      let value;
      [value, end] = scanOnce(end);
      Object.defineProperty(obj, key, { value, enumerable: true, writable: true, configurable: true });
      end = skip(end);
      const c = s[end];
      end += 1;
      if (c === '}') break;
      if (c !== ',') fail("Expecting ',' delimiter", end - 1);
      const comma = end - 1;
      end = skip(end);
      const n2 = s[end];
      end += 1;
      if (n2 !== '"') {
        if (n2 === '}') fail('Illegal trailing comma before end of object', comma);
        fail('Expecting property name enclosed in double quotes', end - 1);
      }
    }
    return [obj, end];
  }

  function scanArray(end) {
    const arr = [];
    end = skip(end);
    if (s[end] === ']') return [arr, end + 1];
    for (;;) {
      let value;
      [value, end] = scanOnce(end);
      arr.push(value);
      end = skip(end);
      const c = s[end];
      end += 1;
      if (c === ']') break;
      if (c !== ',') fail("Expecting ',' delimiter", end - 1);
      const comma = end - 1;
      end = skip(end);
      if (s[end] === ']') fail('Illegal trailing comma before end of array', comma);
    }
    return [arr, end];
  }

  let [value, end] = scanOnce(skip(0));
  end = skip(end);
  if (end !== s.length) fail('Extra data', end);
  return value;
}

// ------------------------------------------------------------------ str() / int() / bool() of decoded JSON values

export function pyFloatStr(v) {
  if (Number.isNaN(v)) return 'nan';
  if (v === Infinity) return 'inf';
  if (v === -Infinity) return '-inf';
  if (v === 0) return Object.is(v, -0) ? '-0.0' : '0.0';
  const sign = v < 0 ? '-' : '';
  const [mant, expStr] = Math.abs(v).toExponential().split('e');
  const digits = mant.replace('.', '');
  const exp = parseInt(expStr, 10);
  if (exp >= -4 && exp < 16) {
    if (exp >= 0) {
      const intPart = digits.length > exp + 1 ? digits.slice(0, exp + 1) : digits.padEnd(exp + 1, '0');
      const frac = digits.length > exp + 1 ? digits.slice(exp + 1) : '0';
      return `${sign}${intPart}.${frac}`;
    }
    return `${sign}0.${'0'.repeat(-exp - 1)}${digits}`;
  }
  const m = digits.length > 1 ? `${digits[0]}.${digits.slice(1)}` : digits;
  const e = Math.abs(exp) < 10 ? `0${Math.abs(exp)}` : String(Math.abs(exp));
  return `${sign}${m}e${exp < 0 ? '-' : '+'}${e}`;
}

const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v) && !(v instanceof PyFloat) && !(v instanceof Map);

export function pyRepr(v, ascii = false) {
  if (typeof v === 'string') return pyReprStr(v, ascii);
  if (v === null || v === undefined) return 'None';
  if (v === true) return 'True';
  if (v === false) return 'False';
  if (typeof v === 'bigint') return v.toString();
  if (typeof v === 'number') return Number.isInteger(v) ? String(v) : pyFloatStr(v);
  if (v instanceof PyFloat) return pyFloatStr(v.v);
  if (Array.isArray(v)) return '[' + v.map((x) => pyRepr(x, ascii)).join(', ') + ']';
  if (v instanceof Map) return '{' + [...v].map(([k, x]) => `${pyRepr(k, ascii)}: ${pyRepr(x, ascii)}`).join(', ') + '}';
  return '{' + Object.entries(v).map(([k, x]) => `${pyReprStr(k, ascii)}: ${pyRepr(x, ascii)}`).join(', ') + '}';
}

// str(v) for a decoded JSON value
export function pyStr(v) {
  return typeof v === 'string' ? v : pyRepr(v);
}

export function pyTruthy(v) {
  if (v === null || v === undefined || v === false) return false;
  if (typeof v === 'number') return v !== 0;
  if (typeof v === 'bigint') return v !== 0n;
  if (v instanceof PyFloat) return v.v !== 0;
  if (typeof v === 'string' || Array.isArray(v)) return v.length > 0;
  if (v instanceof Map) return v.size > 0;
  if (typeof v === 'object') return Object.keys(v).length > 0;
  return true;
}

const typeName = (v) => (v === null || v === undefined ? 'NoneType' : typeof v === 'string' ? 'str'
  : typeof v === 'boolean' ? 'bool' : Array.isArray(v) ? 'list' : isPlainObject(v) ? 'dict' : 'float');

// int(x): returns a BigInt or throws a Python-style error (ValueError / TypeError / OverflowError).
export function pyInt(v) {
  if (typeof v === 'boolean') return v ? 1n : 0n;
  if (typeof v === 'bigint') return v;
  if (typeof v === 'number' || v instanceof PyFloat) {
    const n = v instanceof PyFloat ? v.v : v;
    if (Number.isNaN(n)) throw new PyValueError('cannot convert float NaN to integer');
    if (!Number.isFinite(n)) { const e = new Error('cannot convert float infinity to integer'); e.name = 'OverflowError'; throw e; }
    return BigInt(Math.trunc(n));
  }
  if (typeof v === 'string') {
    const r = pyIntFromStr(v);
    if (r === null) throw new PyValueError(`invalid literal for int() with base 10: ${pyReprStr(v)}`);
    return r;
  }
  const e = new Error(`int() argument must be a string, a bytes-like object or a real number, not '${typeName(v)}'`);
  e.name = 'TypeError';
  throw e;
}
