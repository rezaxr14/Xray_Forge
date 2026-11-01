// The browser's `window.forge.call`: the same method names as the desktop engine, answered locally.
import { configMethods, engineInfo, CONFIG_METHOD_NAMES } from '../engine/config-methods.mjs';
import { makeMitmMethods } from '../engine/mitm-methods.mjs';
import { textToLines } from '../engine/subscription.mjs';
import { RpcError, METHOD_NOT_FOUND } from '../engine/rpc.mjs';

export const VERSION = '2.1-web';
const mitm = makeMitmMethods({ dataDir: '~/.xray_forge' });
const methods = { ...configMethods, ...mitm };
const names = [...CONFIG_METHOD_NAMES, ...Object.keys(mitm)].sort();

export async function call(method, params = {}) {
  if (method === 'engine.info') return engineInfo({ version: VERSION, methods: names });
  const fn = methods[method];
  if (!fn) throw new RpcError(METHOD_NOT_FOUND, `${method} needs the desktop app`);
  return fn(params);
}

export { textToLines };
