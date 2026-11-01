// Engine methods mitm.groups / mitm.build / mitm.guide / mitm.ca_paths (browser: never a generated CA).
import { RpcError, invalidParams } from './rpc.mjs';
import {
  ROUTE_GROUPS, DEFAULT_GROUPS, MITM_DF_XRAY_MIN_VERSION, buildConfig, setupGuide, pyJsonDumps, pyTruthy,
} from './domainfront.mjs';

const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

function joinPath(a, ...rest) {
  let p = a;
  for (const r of rest) p = p === '' || p.endsWith('/') ? p + r : p + '/' + r;
  return p;
}

function strList(v, what) {
  if (!Array.isArray(v) || !v.every((x) => typeof x === 'string')) {
    throw invalidParams(`${what} must be a list of strings`);
  }
  // Python str.strip() strips Unicode whitespace; JS trim() is the same set closely enough.
  return v.map((x) => x.trim()).filter((x) => x.length > 0);
}

// Mirrors Dispatcher._call: params default {}, must be an object, unknown names rejected.
function checkParams(params, allowed) {
  if (params === null || params === undefined) params = {};
  if (typeof params !== 'object' || Array.isArray(params)) throw invalidParams('params must be an object');
  const unknown = Object.keys(params).filter((k) => !allowed.includes(k)).sort();
  if (unknown.length) throw invalidParams(`unknown params: ${unknown.join(', ')}`);
  return params;
}

export function makeMitmMethods({ dataDir = '~/.xray_forge' } = {}) {
  const caPaths = () => {
    const base = joinPath(dataDir, 'mitm');
    return { cert: joinPath(base, 'mitm-ca.crt'), key: joinPath(base, 'mitm-ca.key'), exists: false };
  };
  return {
    'mitm.groups': async (params) => {
      checkParams(params, []);
      const groups = {};
      for (const [k, v] of Object.entries(ROUTE_GROUPS)) groups[k] = { domains: v.domains, cover_sni: v.cover_sni };
      return { groups, defaults: [...DEFAULT_GROUPS], min_xray_version: MITM_DF_XRAY_MIN_VERSION };
    },
    'mitm.ca_paths': async (params) => {
      checkParams(params, []);
      return caPaths();
    },
    'mitm.build': async (params) => {
      const p = checkParams(params, ['groups', 'use_generated_ca']);
      const overrides = {};
      if (p.groups !== undefined && p.groups !== null) {
        const gl = strList(p.groups, 'groups');
        const bad = gl.filter((g) => !has(ROUTE_GROUPS, g));
        if (bad.length) throw invalidParams(`unknown groups: ${bad.join(', ')}`);
        overrides.groups = gl;
      }
      if (pyTruthy(p.use_generated_ca)) {
        const paths = caPaths();
        if (!paths.exists) throw invalidParams('no generated CA yet; generate one first');
        overrides.cert_file = paths.cert;
        overrides.key_file = paths.key;
      }
      return {
        content: pyJsonDumps(buildConfig(overrides), { indent: 2 }),
        min_xray_version: MITM_DF_XRAY_MIN_VERSION,
      };
    },
    'mitm.guide': async (params) => {
      const p = checkParams(params, ['platform']);
      const platform = has(p, 'platform') ? p.platform : 'windows';
      if (platform !== 'windows' && platform !== 'android') {
        throw invalidParams('platform must be windows or android');
      }
      return { content: setupGuide(platform) };
    },
  };
}

export { RpcError };
