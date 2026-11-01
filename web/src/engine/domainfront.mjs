// MITM-DomainFronting Xray config generator (port of xray_forge/core/domainfront.py,
// minus generate_ca / write_config which need `cryptography` and the filesystem).
// Dependency-free, no Node-only APIs.
import { PyFloat, pyTruthy, pyFloatStr } from './pycompat.mjs';
export { pyTruthy };

export const MITM_DF_XRAY_MIN_VERSION = '26.2.6';
export const MITM_DEFAULT_CERT = 'mycert.crt';
export const MITM_DEFAULT_KEY = 'mycert.key';
export const MITM_SOCKS_PORT = 10808;
export const MITM_H11_PORT = 11666;
export const MITM_H2_PORT = 11777;
export const MITM_FAKE_DNS_SNI = 'www.microsoft.com';

export const ROUTE_GROUPS = {
  google: {
    cover_sni: 'www.google.com',
    verify: 'fromMitM,www.google.com,dns.google,www.googlevideo.com,www.youtube.com',
    domains: ['geosite:google'],
    h11_domains: ['domain:googlevideo.com'],
    redirect: null,
  },
  meta: {
    cover_sni: 'www.microsoft.com',
    verify: 'fromMitM,www.google.com,www.microsoft.com,www.whatsapp.com,' +
      'www.facebook.com,www.ar.meta.com,www.fb.com,www.whatsapp.net,' +
      'www.atlassolutions.com,www.secure.facebook.com,' +
      'www.extern.facebook.com,www.internet.org,www.oculus.com,' +
      'www.wit.ai,www.facebook-dns.com,www.instagram.com,' +
      'www.meta.com,www.external-disputes.meta.com,www.fbe2e.com,' +
      'www.cloud.x2p.facebook.net,www.secure.latest.facebook.com',
    domains: ['geosite:meta'],
    h11_domains: [],
    redirect: null,
  },
  fastly: {
    cover_sni: 'github.githubassets.com',
    verify: 'fromMitM,www.python.org,pypi.org,fastly.com,www.fastly.com,' +
      'developer.fastly.com,reddit.com,githubassets.com,github.com,' +
      'github.io,githubusercontent.com,github.githubassets.com',
    domains: ['geosite:fastly', 'geosite:reddit', 'geosite:cnn', 'domain:buzzfeed.com'],
    h11_domains: [],
    redirect: 'fastly.redirect:443',
  },
};

const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

export function defaultOptions() {
  return {
    cert_file: MITM_DEFAULT_CERT,
    key_file: MITM_DEFAULT_KEY,
    socks_port: MITM_SOCKS_PORT,
    h11_port: MITM_H11_PORT,
    h2_port: MITM_H2_PORT,
    fingerprint: 'chrome',
    dns_front_sni: MITM_FAKE_DNS_SNI,
    dns_redirect: ['1.1.1.1', '1.0.0.1'],
    groups: ['google', 'meta', 'fastly'],
    direct_domains: ['domain:ir', 'geosite:private', 'geosite:category-ir', 'geosite:khanacademy'],
    block_ads: true,
  };
}

export const DEFAULT_GROUPS = defaultOptions().groups;

export function buildConfig(overrides = {}) {
  const o = defaultOptions();
  for (const k of Object.keys(overrides || {})) if (has(o, k)) o[k] = overrides[k];

  const inbounds = [{
    tag: 'mixed-in',
    port: o.socks_port,
    protocol: 'mixed',
    sniffing: { enabled: true, destOverride: ['fakedns', 'tls'], routeOnly: false },
    settings: { udp: true, ip: '127.0.0.1' },
    streamSettings: { sockopt: { tcpKeepAliveInterval: 1, tcpKeepAliveIdle: 11 } },
  }];
  for (const [tag, alpn, port] of [
    ['tls-decrypt-h11', ['http/1.1'], o.h11_port],
    ['tls-decrypt-h211', ['h2', 'http/1.1'], o.h2_port],
  ]) {
    inbounds.push({
      port,
      tag,
      protocol: 'tunnel',
      settings: { network: 'tcp', port: 443, followRedirect: true },
      streamSettings: {
        security: 'tls',
        tlsSettings: {
          alpn,
          certificates: [{ usage: 'issue', certificateFile: o.cert_file, keyFile: o.key_file }],
        },
      },
    });
  }

  const happy = { tryDelayMs: 300, prioritizeIPv6: false, interleave: 2, maxConcurrentTry: 20 };
  const forceIpSockopt = () => ({ domainStrategy: 'ForceIP', happyEyeballs: { ...happy } });

  const repackOutbound = (tag, sni, verify, redirect = null) => {
    const ob = {
      tag,
      protocol: 'direct',
      streamSettings: {
        security: 'tls',
        tlsSettings: {
          serverName: sni,
          verifyPeerCertByName: verify,
          alpn: ['fromMitM'],
          fingerprint: o.fingerprint,
        },
        sockopt: forceIpSockopt(),
      },
    };
    if (pyTruthy(redirect)) ob.settings = { redirect };
    return ob;
  };

  const outbounds = [
    { tag: 'block', protocol: 'block' },
    { tag: 'direct', protocol: 'direct', streamSettings: { sockopt: forceIpSockopt() } },
    { tag: 'dns-out', protocol: 'dns', settings: { userLevel: 1 } },
    { tag: 'redirect-out-h11', protocol: 'direct', settings: { redirect: `127.0.0.1:${o.h11_port}` } },
    { tag: 'redirect-out-h211', protocol: 'direct', settings: { redirect: `127.0.0.1:${o.h2_port}` } },
  ];

  const dnsHosts = { 'dns.redirect': o.dns_redirect };
  const rules = [];

  for (const gname of o.groups) {
    const g = has(ROUTE_GROUPS, gname) ? ROUTE_GROUPS[gname] : null;
    if (!g) continue;
    const tag = `tls-repack-${gname}`;
    outbounds.push(repackOutbound(tag, g.cover_sni, g.verify, g.redirect));
    if (g.redirect) dnsHosts[g.redirect.split(':')[0] + '.redirect'] = g.cover_sni;
    rules.push({ outboundTag: tag, domain: [...g.domains], inboundTag: ['tls-decrypt-h211'] });
    for (const dom of g.h11_domains || []) {
      rules.push({ outboundTag: tag, domain: [dom], inboundTag: ['tls-decrypt-h11'] });
    }
    rules.push({ outboundTag: 'block', inboundTag: ['tls-decrypt-h11'] });
  }
  outbounds.push(repackOutbound(
    'tls-repack-dns', o.dns_front_sni,
    `fromMitM,${o.dns_front_sni},www.google.com,dns.google,cloudflare-dns.com,one.one.one.one`,
    `${o.dns_redirect.slice(0, 1).join('.')}:443`));
  rules.unshift({ outboundTag: 'tls-repack-dns', inboundTag: ['no-filter-dns'] });

  if (pyTruthy(o.block_ads)) {
    rules.unshift({ outboundTag: 'block', domain: ['geosite:category-ads-all'] });
  }

  const groupDomains = [];
  for (const g of o.groups) {
    for (const d of (has(ROUTE_GROUPS, g) ? ROUTE_GROUPS[g].domains : null) || []) groupDomains.push(d);
  }
  rules.push(
    { outboundTag: 'dns-out', port: 53 },
    { outboundTag: 'direct', domain: [...o.direct_domains] },
    { outboundTag: 'redirect-out-h11', network: 'tcp', port: 443, domain: ['domain:googlevideo.com'] },
    { outboundTag: 'redirect-out-h211', network: 'tcp', port: 443, domain: groupDomains },
    { outboundTag: 'block', ip: ['10.10.34.0/24', '2001:4188:2:600::/64'] },
    { outboundTag: 'direct', ip: ['geoip:private', 'geoip:ir'] },
    { outboundTag: 'direct', ip: ['0.0.0.0/0', '::/0'] },
    { outboundTag: 'block', port: '0-65535' },
  );

  return {
    remarks: 'Xray-Forge MITM-DomainFronting',
    version: { min: MITM_DF_XRAY_MIN_VERSION },
    log: { loglevel: 'warning', dnsLog: false, access: 'none' },
    policy: {
      levels: {
        0: { uplinkOnly: 0, downlinkOnly: 0 },
        1: { uplinkOnly: 0, downlinkOnly: 0, connIdle: 6 },
      },
    },
    dns: {
      hosts: dnsHosts,
      servers: [
        { address: 'fakedns', domains: ['domain:ir', 'geosite:private', 'geosite:category-ir'] },
        { tag: 'no-filter-dns', address: 'h2c://1.1.1.1/dns-query', timeoutMs: 6000, finalQuery: true },
        { address: 'localhost', domains: ['domain:ir', 'geosite:private', 'geosite:category-ir'], finalQuery: true },
      ],
      queryStrategy: 'UseSystem',
      useSystemHosts: true,
      serveStale: true,
    },
    fakedns: [{ ipRange: '198.18.0.0/15', poolSize: 65535 }],
    inbounds,
    outbounds,
    routing: { domainStrategy: 'IPOnDemand', rules },
  };
}

export function opensslCommand(commonName = 'Xray Forge MITM CA') {
  return 'openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes ' +
    `-subj "/CN=${commonName}/O=Xray Forge (personal)" ` +
    '-addext "basicConstraints=critical,CA:TRUE" ' +
    '-addext "keyUsage=critical,keyCertSign,cRLSign,digitalSignature" ' +
    `-keyout ${MITM_DEFAULT_KEY} -out ${MITM_DEFAULT_CERT}`;
}

export function setupGuide(platform = 'windows') {
  const p = (pyTruthy(platform) ? String(platform) : 'windows').toLowerCase();
  const cert = MITM_DEFAULT_CERT;
  if (p === 'windows') {
    return 'MITM-DomainFronting setup (Windows):\n' +
      `1. Trust ${cert}: right-click > Install Certificate > Local Machine >\n` +
      "   'Place all certificates in the following store' >\n" +
      '   Trusted Root Certification Authorities.\n' +
      '   (Chrome/Edge use the Windows store; Firefox imports its own — see\n' +
      '   Firefox: Settings > Privacy & Security > Certificates > View\n' +
      '   Certificates > Authorities > Import.)\n' +
      '2. Import the generated JSON into v2rayN as a *custom config*\n' +
      '   (core type: xray, leave the SOCKS port field EMPTY).\n' +
      "3. Enable 'Set system proxy' and pick the config.\n" +
      '4. Toggle ON/OFF by selecting/deselecting the config.\n' +
      'Keep mycert.key private — never share it.';
  }
  if (p === 'android') {
    return 'MITM-DomainFronting setup (Android, no root):\n' +
      `1. Copy ${cert} and mycert.key to the phone.\n` +
      '2. v2rayNG > Asset files: add both files.\n' +
      `3. Trust ${cert}: Settings > Security & privacy > More security\n` +
      '   settings > Install from device storage > CA certificate.\n' +
      '4. Import the JSON config (import from locally) and run it.\n' +
      '   Keep default port 10808 and enable the Hev TUN feature.\n' +
      '5. Browsers only (Chromium works; Firefox: About Firefox > tap logo\n' +
      "   5x > Secret Settings > 'Use third party CA certificates').\n" +
      'Keep mycert.key private — never share it.';
  }
  if (p === 'firefox') {
    return 'Firefox-specific trust (any OS):\n' +
      'Settings > Privacy & Security > Certificates > View Certificates >\n' +
      'Authorities > Import... > select mycert.crt > tick\n' +
      "'Trust this CA to identify websites'.\n" +
      'Keep mycert.key private — never share it.';
  }
  return setupGuide('windows');
}

// ---------------------------------------------------------------------------
// Python json.dumps clone (ensure_ascii=True; indent -> ',' + newline, ': ')
// ---------------------------------------------------------------------------

function pyFloatRepr(v) {
  if (Number.isNaN(v)) return 'NaN';
  if (v === Infinity) return 'Infinity';
  if (v === -Infinity) return '-Infinity';
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

function pyNumber(v) {
  // JS cannot tell 1 from 1.0: integral values within the safe range print as ints.
  if (Number.isInteger(v) && Math.abs(v) <= Number.MAX_SAFE_INTEGER) return String(v);
  return pyFloatRepr(v);
}

const ESC = { '"': '\\"', '\\': '\\\\', '\n': '\\n', '\r': '\\r', '\t': '\\t', '\b': '\\b', '\f': '\\f' };

function pyString(s) {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    const c = s.charCodeAt(i);
    if (ESC[ch] !== undefined) out += ESC[ch];
    else if (c < 0x20 || c > 0x7e && c !== 0x7f) out += '\\u' + c.toString(16).padStart(4, '0');
    else out += ch;
  }
  return out + '"';
}

export function pyJsonDumps(value, { indent = null, ensureAscii = true } = {}) {
  const itemSep = indent === null || indent === undefined ? ', ' : ',';
  const str = ensureAscii ? pyString : (s) => {
    let out = '"';
    for (const ch of s) {
      const c = ch.codePointAt(0);
      if (ESC[ch] !== undefined) out += ESC[ch];
      else if (c < 0x20) out += '\\u' + c.toString(16).padStart(4, '0');
      else out += ch;
    }
    return out + '"';
  };
  const pad = (n) => (typeof indent === 'string' ? indent : ' '.repeat(indent)).repeat(n);
  const enc = (v, level) => {
    if (v === null || v === undefined) return 'null';
    if (v === true) return 'true';
    if (v === false) return 'false';
    if (typeof v === 'number') return pyNumber(v);
    if (v instanceof PyFloat) return Number.isFinite(v.v) ? pyFloatStr(v.v) : (Number.isNaN(v.v) ? 'NaN' : (v.v > 0 ? 'Infinity' : '-Infinity'));
    if (typeof v === 'bigint') return v.toString();
    if (typeof v === 'string') return str(v);
    const nl = indent === null || indent === undefined ? null : '\n' + pad(level + 1);
    const close = nl === null ? '' : '\n' + pad(level);
    if (Array.isArray(v)) {
      if (v.length === 0) return '[]';
      return '[' + (nl ?? '') + v.map((x) => enc(x, level + 1)).join(itemSep + (nl ?? '')) + close + ']';
    }
    const keys = Object.keys(v);
    if (keys.length === 0) return '{}';
    return '{' + (nl ?? '') +
      keys.map((k) => str(k) + ': ' + enc(v[k], level + 1)).join(itemSep + (nl ?? '')) + close + '}';
  };
  return enc(value, 0);
}
