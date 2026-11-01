// Port of xray_forge/core/dedup.py: drop duplicates by (scheme, uuid, host, port).
import { parseTarget } from './parser.mjs';

export function dedupConfigs(lines) {
  const seen = new Set();
  const out = [];
  let removed = 0;
  for (const line of lines) {
    const t = parseTarget(line);
    if (!t) { out.push(line); continue; }
    const key = JSON.stringify([t.scheme, t.credential, t.host, t.port]);
    if (seen.has(key)) { removed += 1; continue; }
    seen.add(key);
    out.push(line);
  }
  return [out, removed];
}
