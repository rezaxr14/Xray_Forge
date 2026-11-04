import { h, icon } from '../dom.mjs';
import { DNS_CATEGORIES, DNS_PRESETS } from '../../engine/dns-presets.mjs';
import { copyText } from '../feedback.mjs';
import { load, save } from '../store.mjs';

const GUIDES = [
  ['Windows 11', ['Settings, Network and internet, pick Wi-Fi or Ethernet, then Hardware properties.', 'Next to DNS server assignment choose Edit, switch to Manual and turn IPv4 on.', 'Type the preferred and alternate addresses. Under DNS over HTTPS pick On (manual template) and paste the encrypted DNS address if the list has one.']],
  ['macOS', ['System Settings, Network, pick your connection, Details, then DNS.', 'Press the plus button and add each address. Remove the old ones.']],
  ['Android', ['Settings, Network and internet, Private DNS.', 'Choose "Private DNS provider hostname" and enter the DNS-over-TLS name (the line starting "TLS name"). Android needs a name here, not an address.']],
  ['iPhone and iPad', ['Settings, Wi-Fi, tap the i next to your network, Configure DNS, Manual.', 'Delete the old servers and add the new addresses.']],
  ['Linux', ['Run "resolvectl dns <interface> <address> <address>", or set the DNS in your network manager.']],
  ['Router', ['Open the router page, find DNS under Internet or WAN, and enter the addresses. Every device on that network then uses them.']],
];

export function createDns() {
  let cat = load('dnsCat', 'ads');
  let v6 = false;
  const chips = h('div', { class: 'seg', role: 'group', 'aria-label': 'Kind of DNS server' });
  const list = h('div', { class: 'stack' });
  const v6box = h('input', { type: 'checkbox' });
  v6box.addEventListener('change', () => { v6 = v6box.checked; render(); });

  function render() {
    chips.replaceChildren(...[['all', 'All'], ...DNS_CATEGORIES.map((c) => [c.id, c.name])].map(([id, name]) =>
      h('button', { 'aria-pressed': String(cat === id), onclick: () => { cat = id; save('dnsCat', id); render(); } }, name)));
    const rows = DNS_PRESETS.filter((p) => cat === 'all' || p.category === cat);
    const note = (DNS_CATEGORIES.find((c) => c.id === cat) || {}).note;
    list.replaceChildren(note ? h('p', { class: 'hint' }, note) : null, ...rows.map((p) => {
      const servers = p.v4.concat(v6 ? p.v6 : []);
      return h('div', { class: 'card stack' },
        h('div', { class: 'row' },
          h('h2', { class: 'grow' }, p.name, p.unverified ? h('span', { class: 'chip', title: 'Not re-checked against the provider. Confirm the addresses on their site.' }, 'check address') : null),
          h('button', { class: 'btn', onclick: () => copyText(servers.join('\n'), `${p.name} addresses`) }, icon('copy', 18), 'Copy addresses')),
        h('div', { class: 'mono' }, servers.join('   ')),
        p.note ? h('p', { class: 'hint' }, p.note) : null,
        p.doh || p.dot ? h('div', { class: 'row' },
          p.doh ? h('button', { class: 'btn quiet', onclick: () => copyText(p.doh, 'encrypted DNS address') }, icon('copy', 16), `DoH: ${p.doh.replace('https://', '')}`) : null,
          p.dot ? h('button', { class: 'btn quiet', onclick: () => copyText(p.dot, 'TLS name') }, icon('copy', 16), `TLS name: ${p.dot}`) : null) : null);
    }));
  }
  render();

  return {
    id: 'dns', title: 'DNS servers', actions: () => [],
    el: h('div', { class: 'page stack' },
      h('div', { class: 'notice info' }, icon('info'), h('div', {}, 'A web page cannot change your computer\'s DNS. Pick a server here, copy its addresses and set them in your system, or use the desktop app, which applies them in one click and tests which is fastest.')),
      h('div', { class: 'notice' }, icon('warn'), h('div', {}, 'A different DNS server helps with blocking that happens at DNS level and blocks ad domains. It does not get past blocking by IP address or by site name in the TLS handshake. Use a config for that.')),
      chips, h('label', { class: 'check' }, v6box, 'Also show IPv6 addresses'), list,
      h('div', { class: 'card stack' }, h('h2', {}, 'How to set it'),
        GUIDES.map(([t, steps]) => h('details', {}, h('summary', {}, t), h('ol', { class: 'steps' }, steps.map((s) => h('li', {}, s))))))),
  };
}
