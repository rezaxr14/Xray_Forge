import { h, icon } from '../dom.mjs';
import { VERSION } from '../forge.mjs';

const REPO = 'https://github.com/rezaxr14/Xray_Forge';
export function createAbout({ info, go, installPrompt }) {
  const cap = (ic, t, d, off) => h('div', {}, icon(ic), h('div', {}, h('b', {}, t), h('span', { class: 'muted' }, d)));
  const installBtn = h('button', { class: 'btn primary', hidden: true, onclick: async () => { const p = installPrompt.event; if (!p) return; p.prompt(); await p.userChoice; installPrompt.event = null; installBtn.hidden = true; } }, icon('download', 18), 'Install this app');
  installPrompt.onChange = () => { installBtn.hidden = !installPrompt.event; };
  installPrompt.onChange();
  return {
    id: 'about', title: 'About', actions: () => [],
    el: h('div', { class: 'page stack' },
      h('div', { class: 'card stack' },
        h('h2', {}, `Xray Forge ${VERSION}`),
        h('p', { class: 'muted' }, 'Edit, fix and convert proxy configs. This web app runs the same rules as the desktop app, entirely in your browser. Nothing you enter is sent anywhere, and there is no account or server.'),
        h('div', { class: 'row' }, installBtn,
          h('button', { class: 'btn', onclick: () => go('mitm') }, icon('shield', 18), 'MITM fronting'),
          h('a', { class: 'btn', href: REPO, target: '_blank', rel: 'noopener noreferrer' }, 'Source code'),
          h('a', { class: 'btn', href: `${REPO}/releases`, target: '_blank', rel: 'noopener noreferrer' }, 'Desktop app'))),
      h('div', { class: 'card stack' }, h('h2', {}, 'Works in the browser'),
        h('div', { class: 'cap' },
          cap('list', 'Configs', 'Read, edit and re-export VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC and WireGuard links.'),
          cap('convert', 'Convert', 'Fingerprint, cipher suites, fragment, naming and endpoint override in bulk.'),
          cap('cloud', 'Subscriptions', 'Plain and base64 lists, from a URL that allows it or pasted text.'),
          cap('search', 'DNS servers', 'Catalog of ad-blocking, privacy, malware-filtering and anti-sanction DNS, with setup steps.'),
          cap('shield', 'MITM fronting', 'Builds the Xray config and setup guide.'),
          cap('download', 'Export', 'Clash / Mihomo YAML, sing-box JSON and base64 subscriptions.'))),
      h('div', { class: 'card stack' }, h('h2', {}, 'Needs the desktop app'),
        h('p', { class: 'hint' }, 'Browsers cannot run programs, open raw network sockets or change system settings such as DNS and the proxy.'),
        h('div', { class: 'row' }, ['health', 'scanner', 'sni', 'warp', 'cores'].map((id) => h('button', { class: 'btn', onclick: () => go(id) }, { health: 'Health check', scanner: 'IP scanner', sni: 'SNI search', warp: 'WARP and tunnels', cores: 'Cores' }[id])))),
      h('div', { class: 'card' }, h('h2', {}, 'Engine'),
        h('dl', { class: 'kv' }, h('dt', {}, 'Protocols'), h('dd', {}, info.schemes.join(', ')), h('dt', {}, 'Cores covered'), h('dd', {}, info.cores.join(', ')), h('dt', {}, 'Storage'), h('dd', {}, 'This browser only (local storage)'))),
    ),
  };
}
