// Port of the constants in xray_forge/core/config.py that the engine API exposes.
export const DEFAULT_FP = 'chrome';

export const DEFAULT_CS = [
  'TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256', 'TLS_AES_128_GCM_SHA256',
  'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
  'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
  'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256', 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
  'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA', 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
  'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
].join(':');

export const DEFAULT_FM = {
  tcp: [
    { type: 'fragment', settings: { packets: 'tlshello', lengths: ['5', '94', '1'], delays: ['0'], maxSplit: '0' } },
    { type: 'fragment', settings: { packets: '1-1', lengths: ['109', '1'], delays: ['1'], maxSplit: '355' } },
  ],
};

export const DEFAULT_TEMPLATE = '{id:02d}_{sub}_{path}';
export const TEMPLATE_KEYS = ['id', 'sub', 'path', 'ip', 'port', 'host', 'net', 'sni', 'proto', 'old'];
export const PROXY_SCHEMES = new Set(['vless', 'trojan', 'vmess', 'ss']);
export const TRANSPORTS = ['ws', 'grpc', 'httpupgrade', 'tcp', 'xhttp', 'http2'];
export const FLOWS = ['', 'xtls-rprx-vision'];
export const SECURITIES = ['', 'none', 'tls', 'reality'];
export const XHTTP_MODES = ['', 'auto', 'packet-up', 'stream-up', 'stream-one'];
export const FRAG_PRESETS = ['5,94,1@2', 'rand:8-32@3', 'rand:1-16@2', 'off'];

export const CF_RANGES = ['104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '162.158.0.0/15', '198.41.128.0/17',
  '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '131.0.72.0/22'];
export const FASTLY_RANGES = ['23.235.32.0/20', '43.249.72.0/22', '103.244.50.0/24', '103.245.222.0/23',
  '103.245.224.0/24', '104.156.80.0/20', '140.248.64.0/18', '146.75.0.0/16', '151.101.0.0/16', '157.52.64.0/18',
  '167.82.0.0/17', '172.111.64.0/18', '185.31.16.0/22', '199.27.72.0/21', '199.232.0.0/16'];
export const WARP_RANGES = ['162.159.192.0/24', '162.159.193.0/24', '162.159.195.0/24', '188.114.96.0/23',
  '188.114.98.0/23'];

// Python's `^\d{1,3}(?:\.\d{1,3}){3}$` (Unicode \d; `$` also matches before a final newline)
export const IPV4_RE = /^\p{Nd}{1,3}(?:\.\p{Nd}{1,3}){3}\n?$/u;

export const MAX_LINES = 20000;
export const MAX_START = 99999;
export const PROTOCOL_VERSION = 1;
