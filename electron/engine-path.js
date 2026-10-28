'use strict';
// Decide how to launch the Python engine.
//   1. XRAY_FORGE_ENGINE  -> that executable (explicit override)
//   2. packaged app       -> <resources>/engine/xray-forge-engine[.exe] (PyInstaller bundle)
//   3. otherwise          -> `python -m xray_forge serve` from the repo (development)
const fs = require('node:fs');
const path = require('node:path');

function resolveEngine({ resourcesPath, repoRoot, platform = process.platform,
                         env = process.env, exists = fs.existsSync } = {}) {
  if (env.XRAY_FORGE_ENGINE) {
    return { kind: 'env', command: env.XRAY_FORGE_ENGINE, args: ['serve'], cwd: undefined };
  }
  if (resourcesPath) {
    const exe = path.join(resourcesPath, 'engine',
      platform === 'win32' ? 'xray-forge-engine.exe' : 'xray-forge-engine');
    if (exists(exe)) return { kind: 'bundled', command: exe, args: ['serve'], cwd: path.dirname(exe) };
  }
  return {
    kind: 'python',
    command: env.XRAY_FORGE_PYTHON || (platform === 'win32' ? 'python' : 'python3'),
    args: ['-m', 'xray_forge', 'serve'],
    cwd: repoRoot,
  };
}

module.exports = { resolveEngine };
