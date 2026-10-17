'use strict';
// JSON-RPC client for `python -m xray_forge serve`.
// Shared by the Electron main process and the end-to-end tests, so the tests
// exercise the same code the app runs.
const { spawn } = require('node:child_process');
const { EventEmitter } = require('node:events');
const readline = require('node:readline');

class EngineClient extends EventEmitter {
  constructor({ python = process.env.XRAY_FORGE_PYTHON || 'python3', cwd, env } = {}) {
    super();
    this.python = python;
    this.cwd = cwd;
    this.env = { ...process.env, PYTHONUNBUFFERED: '1', PYTHONIOENCODING: 'utf-8', ...env };
    this.nextId = 1;
    this.pending = new Map();
    this.proc = null;
    this.exited = null;
  }

  start() {
    if (this.proc) return;
    this.exited = new Promise((resolve) => { this._resolveExit = resolve; });
    this.proc = spawn(this.python, ['-m', 'xray_forge', 'serve'], {
      cwd: this.cwd, env: this.env, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true,
    });
    readline.createInterface({ input: this.proc.stdout }).on('line', (l) => this._onLine(l));
    readline.createInterface({ input: this.proc.stderr }).on('line', (l) => this.emit('stderr', l));
    this.proc.on('error', (e) => this._fail(e));
    this.proc.on('exit', (code, sig) => {
      this._fail(new Error(`engine exited (${code ?? sig})`));
      this.emit('exit', code, sig);
      this._resolveExit();
    });
  }

  _fail(err) {
    for (const { reject, timer } of this.pending.values()) { clearTimeout(timer); reject(err); }
    this.pending.clear();
  }

  _onLine(line) {
    let msg;
    try { msg = JSON.parse(line); } catch { this.emit('stderr', `bad engine line: ${line.slice(0, 120)}`); return; }
    if (msg.method === 'job.event') { this.emit('job', msg.params); return; }
    const p = this.pending.get(msg.id);
    if (!p) return;
    this.pending.delete(msg.id);
    clearTimeout(p.timer);
    if (msg.error) {
      const e = new Error(msg.error.message);
      e.code = msg.error.code;
      p.reject(e);
    } else p.resolve(msg.result);
  }

  call(method, params = {}, timeoutMs = 30000) {
    if (!this.proc) this.start();
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`engine call timed out: ${method}`));
      }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      try {
        this.proc.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
      } catch (e) { this.pending.delete(id); clearTimeout(timer); reject(e); }
    });
  }

  async stop() {
    if (!this.proc) return;
    try { this.proc.stdin.end(); } catch { /* already closed */ }
    const kill = setTimeout(() => this.proc && this.proc.kill(), 3000);
    await this.exited;
    clearTimeout(kill);
    this.proc = null;
  }
}

module.exports = { EngineClient };
