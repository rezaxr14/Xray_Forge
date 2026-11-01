import { h, icon } from './dom.mjs';

// Native <dialog>: focus trap, Esc to close and a backdrop for free.
// build(close) returns { body: Node[], footer: Node[] }.
export function openDialog(title, build) {
  const dlg = h('dialog');
  const close = () => dlg.close();
  const { body, footer = [] } = build(close);
  dlg.append(h('form', { method: 'dialog', onsubmit: (e) => e.preventDefault() },
    h('div', { class: 'dlg-head' }, h('h2', {}, title),
      h('button', { type: 'button', class: 'btn quiet icon-only', 'aria-label': 'Close', onclick: close }, icon('x'))),
    h('div', { class: 'dlg-body' }, body),
    footer.length ? h('div', { class: 'dlg-foot' }, footer) : null));
  dlg.addEventListener('close', () => dlg.remove());
  dlg.addEventListener('click', (e) => { if (e.target === dlg) close(); });
  document.body.append(dlg);
  dlg.showModal();
  return dlg;
}
