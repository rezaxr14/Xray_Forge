// Toasts, clipboard, file open and save: the browser replacements for the desktop dialogs.
import { h } from './dom.mjs';

let host;
export function toast(text, kind = 'info') {
  host ||= document.getElementById('toasts');
  if (!host) return;
  const el = h('div', { class: `toast ${kind}`, role: kind === 'bad' ? 'alert' : 'status' }, text);
  host.append(el);
  setTimeout(() => el.classList.add('leaving'), kind === 'bad' ? 5200 : 2600);
  setTimeout(() => el.remove(), kind === 'bad' ? 5600 : 3000);
}

export async function copyText(text, what = 'text') {
  if (!text || !String(text).trim()) { toast('Nothing to copy', 'bad'); return false; }
  try {
    await navigator.clipboard.writeText(text);
    toast(`Copied ${what}`);
    return true;
  } catch {
    const ta = h('textarea', { 'aria-hidden': 'true' });
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    ta.value = text;
    document.body.append(ta);
    ta.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch { ok = false; }
    ta.remove();
    toast(ok ? `Copied ${what}` : 'Copy was blocked: select the text and copy it by hand', ok ? 'info' : 'bad');
    return ok;
  }
}

export function openTextFile(accept = '.txt,.json,.yaml,.yml,.conf,text/*') {
  return new Promise((resolve) => {
    const input = h('input', { type: 'file', accept });
    input.addEventListener('change', async () => {
      const f = input.files && input.files[0];
      resolve(f ? { name: f.name, text: await f.text() } : null);
    });
    input.addEventListener('cancel', () => resolve(null));
    input.click();
  });
}

export function saveTextFile(text, name, type = 'text/plain') {
  if (!text || !String(text).trim()) { toast('Nothing to save', 'bad'); return false; }
  const url = URL.createObjectURL(new Blob([text], { type: `${type};charset=utf-8` }));
  const a = h('a', { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 4000);
  toast(`Saved ${name}`);
  return true;
}

// Run an engine call; surface RpcError text as a toast instead of an unhandled rejection.
export async function guarded(fn) {
  try { return await fn(); } catch (e) { toast(e && e.message ? e.message : String(e), 'bad'); return undefined; }
}
