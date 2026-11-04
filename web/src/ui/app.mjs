import { h, icon, $ } from './dom.mjs';
import { call } from './forge.mjs';
import { load, save } from './store.mjs';
import { createConfigs } from './views/configs.mjs';
import { createConvert } from './views/convert.mjs';
import { createSubs } from './views/subs.mjs';
import { createMitm } from './views/mitm.mjs';
import { createAbout } from './views/about.mjs';
import { createDns } from './views/dns.mjs';
import { createDesktop, DESKTOP_IDS } from './views/desktop.mjs';

const installPrompt = { event: null, onChange: () => {} };
window.addEventListener('beforeinstallprompt', (e) => { e.preventDefault(); installPrompt.event = e; installPrompt.onChange(); });

const NAV = [
  ['configs', 'Configs', 'list'], ['convert', 'Convert', 'convert'], ['subs', 'Subscriptions', 'cloud'], ['dns', 'DNS servers', 'search'], ['mitm', 'MITM fronting', 'shield'],
];
const DESKTOP = [['health', 'Health check', 'shield'], ['scanner', 'IP scanner', 'radar'], ['sni', 'SNI search', 'search'], ['warp', 'WARP and tunnels', 'lock'], ['cores', 'Cores', 'download']];
const BOTTOM = [['configs', 'Configs', 'list'], ['convert', 'Convert', 'convert'], ['subs', 'Sources', 'cloud'], ['dns', 'DNS', 'search'], ['about', 'More', 'more']];

async function main() {
  const info = await call('engine.info');
  const views = new Map();
  const go = (id) => { location.hash = `#/${id}`; };
  const ctx = { info, go, installPrompt };
  const factories = {
    configs: () => createConfigs(ctx), convert: () => createConvert(ctx), subs: () => createSubs(ctx), dns: () => createDns(ctx), mitm: () => createMitm(ctx), about: () => createAbout(ctx),
    ...Object.fromEntries(DESKTOP_IDS.map((id) => [id, () => createDesktop(id)])),
  };
  const get = (id) => { if (!views.has(id)) views.set(id, factories[id]()); return views.get(id); };

  const title = h('h1', {}); const actions = h('div', { class: 'row' }); const content = h('div', { class: 'view' });
  const navLink = (id, label, ic, tag) => h('a', { class: 'navbtn', href: `#/${id}`, 'data-id': id }, icon(ic), label, tag ? h('span', { class: 'tag' }, tag) : null);
  const rail = h('nav', { class: 'rail', 'aria-label': 'Sections' },
    h('div', { class: 'brand' }, h('img', { src: 'icons/icon-192.png', alt: '', width: 30, height: 30 }), 'Xray Forge'),
    ...NAV.map(([id, l, i]) => navLink(id, l, i)),
    h('div', { class: 'group' }, 'In the desktop app'),
    ...DESKTOP.map(([id, l, i]) => navLink(id, l, i)),
    h('div', { class: 'spacer' }),
    navLink('about', 'About', 'info'),
    h('button', { class: 'navbtn', onclick: toggleTheme, 'aria-label': 'Switch between light and dark' }, icon('sun'), 'Theme'));
  const bottom = h('nav', { class: 'bottomnav', 'aria-label': 'Sections' }, BOTTOM.map(([id, l, i]) => h('a', { href: `#/${id}`, 'data-id': id }, icon(i), l)));
  const main = h('main', { class: 'main' }, h('header', { class: 'topbar' }, title, actions), content);
  document.getElementById('app').replaceChildren(rail, main, bottom);

  function toggleTheme() {
    const cur = document.documentElement.dataset.theme || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    const next = cur === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next; save('theme', next);
  }
  const t = load('theme', ''); if (t) document.documentElement.dataset.theme = t;

  function show() {
    const id = (location.hash.match(/^#\/(\w+)/) || [])[1];
    const v = get(factories[id] ? id : (load('last', 'configs') in factories ? load('last', 'configs') : 'configs'));
    save('last', v.id);
    title.textContent = v.title;
    document.title = `${v.title} · Xray Forge`;
    actions.replaceChildren(...v.actions());
    content.classList.toggle('flush', !!v.flush);
    content.replaceChildren(v.el);
    if (v.refresh) v.refresh();
    for (const a of document.querySelectorAll('[data-id]')) {
      if (a.dataset.id === v.id) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current');
    }
    content.scrollTop = 0;
  }
  addEventListener('hashchange', show);
  show();
}

main().catch((e) => {
  const box = document.getElementById('app');
  box.replaceChildren(h('div', { class: 'empty' }, h('h2', {}, 'The app could not start'), h('p', {}, String(e && e.message ? e.message : e))));
});

if ('serviceWorker' in navigator && location.protocol.startsWith('http')) {
  addEventListener('load', () => navigator.serviceWorker.register('sw.js').catch(() => {}));
}
