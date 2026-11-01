// Subscription text -> share links, for the formats a browser can decode on its own.
// Mirrors xray_forge.core.subscription.decode_subscription / sniff_format.  Clash YAML and
// sing-box JSON conversion needs the full protocol registry round trip and stays desktop-only.
import { b64DecodePad, pyStrip, pySplitLines } from './pycompat.mjs';

export const MAX_SUB_BYTES = 8 * 1024 * 1024;
const B64_RE = /^[A-Za-z0-9+/_-]+={0,2}$/;
const SCHEMES = ['vless', 'trojan', 'vmess', 'ss', 'socks', 'http', 'hysteria2', 'tuic'];

function b64ToText(compact) {
  let std = compact.replace(/-/g, '+').replace(/_/g, '/');
  std += '='.repeat((4 - (std.length % 4)) % 4);
  return b64DecodePad(std);
}

const compactOf = (text) => text.replace(/\s+/gu, '');

export function isBase64Config(text) {
  const stripped = pyStrip(text);
  if (!stripped) return false;
  const compact = compactOf(stripped);
  if (compact.length < 16 || !B64_RE.test(compact)) return false;
  let decoded;
  try { decoded = b64ToText(compact); } catch { return false; }
  return SCHEMES.some((s) => decoded.startsWith(`${s}://`)) || decoded.includes('vless://') || decoded.includes('trojan://');
}

export function decodeSubscription(text) {
  text = pyStrip(text);
  if (!text) return [];
  let decoded = text;
  if (isBase64Config(text)) {
    try { decoded = b64ToText(compactOf(text)); } catch { decoded = text; }
  }
  const lines = [];
  for (const raw of pySplitLines(decoded)) {
    const line = pyStrip(raw);
    if (line && line.includes('://')) lines.push(line);
  }
  return lines;
}

export function sniffFormat(text) {
  const s = pyStrip(text);
  if (!s) return 'plain';
  if (s.startsWith('{') || s.startsWith('[')) {
    try {
      const d = JSON.parse(s);
      if (d && typeof d === 'object' && !Array.isArray(d) && ('outbounds' in d || 'inbounds' in d)) return 'singbox';
    } catch { /* not JSON */ }
    return 'plain';
  }
  if ((s.includes('proxies:') && (s.includes('- name') || s.includes('- {'))) || s.startsWith('proxies:')) return 'clash';
  return isBase64Config(s) ? 'base64' : 'plain';
}

// -> { format, lines, supported }
export function textToLines(text) {
  const format = sniffFormat(text);
  if (format === 'clash' || format === 'singbox') return { format, lines: [], supported: false };
  return { format, lines: decodeSubscription(text), supported: true };
}
