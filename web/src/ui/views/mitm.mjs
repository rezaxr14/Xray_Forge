import { h, icon } from '../dom.mjs';
import { call } from '../forge.mjs';
import { opensslCommand } from '../../engine/domainfront.mjs';
import { copyText, saveTextFile, toast, guarded } from '../feedback.mjs';

export function createMitm() {
  const out = h('textarea', { rows: 16, readOnly: true, spellcheck: 'false', placeholder: 'The generated config or guide appears here', 'aria-label': 'Output' });
  const groups = h('div', { class: 'pill-row' });
  const platform = h('select', { 'aria-label': 'Platform' }, h('option', { value: 'windows' }, 'Windows'), h('option', { value: 'android' }, 'Android'));
  const min = h('span', { class: 'hint' });
  let kind = 'config';
  const picked = () => [...groups.querySelectorAll('input:checked')].map((i) => i.value);

  guarded(async () => {
    const g = await call('mitm.groups');
    min.textContent = `Needs Xray-core ${g.min_xray_version} or newer`;
    groups.replaceChildren(...Object.keys(g.groups).map((n) => h('label', { class: 'check' }, h('input', { type: 'checkbox', value: n, checked: g.defaults.includes(n) }), n)));
  });

  const root = h('div', { class: 'page stack' },
    h('div', { class: 'notice' }, icon('warn'), h('div', {}, 'Generating a personal certificate authority needs OpenSSL, which a browser cannot run. This page builds the Xray config and the setup guide; the guide includes the exact OpenSSL commands to run yourself.')),
    h('div', { class: 'card stack' }, h('h2', {}, 'Service families'), groups, min,
      h('div', { class: 'row' },
        h('button', { class: 'btn primary', onclick: () => guarded(async () => { const r = await call('mitm.build', { groups: picked(), use_generated_ca: false }); out.value = r.content; kind = 'config'; toast('Config built'); }) }, icon('bolt', 18), 'Build Xray config'),
        platform,
        h('button', { class: 'btn', onclick: () => guarded(async () => { out.value = (await call('mitm.guide', { platform: platform.value })).content; kind = 'guide'; }) }, 'Show setup guide'),
        h('button', { class: 'btn', onclick: () => { out.value = `Run this once in a terminal to create mycert.crt and mycert.key:\n\n${opensslCommand()}\n\nKeep mycert.key private.`; kind = 'guide'; } }, 'Show OpenSSL command'))),
    h('div', { class: 'card stack' },
      h('div', { class: 'row' }, h('h2', { class: 'grow' }, 'Output'),
        h('button', { class: 'btn', onclick: () => copyText(out.value, 'output') }, icon('copy', 18), 'Copy'),
        h('button', { class: 'btn', onclick: () => saveTextFile(out.value, kind === 'config' ? 'xray-mitm.json' : 'mitm-guide.txt', kind === 'config' ? 'application/json' : 'text/plain') }, icon('save', 18), 'Save')),
      out));
  return { id: 'mitm', title: 'MITM fronting', el: root, actions: () => [] };
}
