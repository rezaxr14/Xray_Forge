import { h, icon } from '../dom.mjs';

const PANELS = {
  health: ['Health check', 'shield', 'Tests each config through a real core with DNS, TCP, TLS and transfer stages.', 'A browser cannot start Xray, sing-box or Mihomo, and cannot open raw sockets.'],
  scanner: ['IP scanner', 'radar', 'Scans Cloudflare and Fastly ranges for reachable, fast endpoints.', 'Scanning needs raw TCP and ICMP, which web pages are not allowed to use.'],
  sni: ['SNI search', 'search', 'Finds domains that complete a TLS handshake from your network.', 'A page cannot read TLS handshake results or bypass cross-origin rules.'],
  warp: ['WARP, MASQUE and Psiphon', 'lock', 'Registers WARP accounts and runs MASQUE and Psiphon tunnels.', 'Tunnels need to run local processes and network sockets.'],
  cores: ['Cores', 'download', 'Downloads and manages the Xray, sing-box and Mihomo programs.', 'A browser cannot save or run programs.'],
};
export const DESKTOP_IDS = Object.keys(PANELS);

export function createDesktop(id) {
  const [title, ic, what, why] = PANELS[id];
  return {
    id, title, actions: () => [],
    el: h('div', { class: 'page' }, h('div', { class: 'empty' },
      h('div', { class: 'glyph' }, icon(ic, 28)), h('h2', {}, `${title} runs in the desktop app`), h('p', {}, what), h('p', { class: 'hint' }, why),
      h('a', { class: 'btn primary', href: 'https://github.com/rezaxr14/Xray_Forge/releases', target: '_blank', rel: 'noopener noreferrer' }, icon('download', 18), 'Get the desktop app'))),
  };
}
