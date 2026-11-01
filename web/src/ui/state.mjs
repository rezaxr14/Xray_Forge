import { load, save } from './store.mjs';

// Links the user is working on, shared by Configs and Convert.
export const workspace = {
  text: load('links', ''),
  rows: [],          // config.parse_many rows
  selected: -1,
  listeners: new Set(),
};
export const linesOf = (text) => text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
export function setText(text) { workspace.text = text; save('links', text); }
export function onWorkspace(fn) { workspace.listeners.add(fn); return () => workspace.listeners.delete(fn); }
export function changed() { workspace.listeners.forEach((fn) => fn()); }

export const SAMPLE = [
  'vless://11111111-2222-3333-4444-555555555555@cdn.example.com:443?encryption=none&security=tls&sni=cdn.example.com&fp=chrome&type=ws&host=cdn.example.com&path=%2Fchannel#Sample%20VLESS%20WS',
  'vless://11111111-2222-3333-4444-555555555555@203.0.113.7:443?security=reality&sni=www.example.org&fp=chrome&pbk=EXAMPLEPUBLICKEYEXAMPLEPUBLICKEYEXAMPLEPUB0&sid=6ba85179&type=tcp&flow=xtls-rprx-vision#Sample%20Reality',
  'trojan://sample-password@198.51.100.20:443?security=tls&sni=t.example.com&type=grpc&serviceName=svc#Sample%20Trojan%20gRPC',
].join('\n');
