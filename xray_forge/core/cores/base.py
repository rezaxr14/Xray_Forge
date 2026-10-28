"""
Core adapter abstraction.

A *core* is a proxy engine that can actually run an outbound: Xray-core,
sing-box, or Mihomo (Clash.Meta).  Each :class:`CoreAdapter`

* derives its supported protocol list from the protocol handlers' renderers,
  so capability reporting can never drift from the code
* renders a full client config (local SOCKS inbound + outbounds)
* can probe a config by spawning the real binary and fetching a URL through
  its local SOCKS port
"""

from __future__ import annotations

import contextlib
import json
import os
import socket
import subprocess
import threading
import tempfile
import time
from typing import Any

from xray_forge.core.models import Outbound
from xray_forge.core.protocols import handler_for, iter_handlers, supported_schemes

from xray_forge.core.log import get_logger

log = get_logger(__name__)


class CoreAdapter:
    name: str = ""            # machine name: "xray" | "singbox" | "mihomo"
    display_name: str = ""    # human label
    config_suffix: str = ".json"
    run_args: tuple[str, ...] = ("run", "-c")

    # -------------------------------------------------------- capabilities
    def render_outbound(self, out: Outbound) -> dict[str, Any] | None:
        """Render one outbound in this core's native format (or None)."""
        raise NotImplementedError

    def supported_protocols(self) -> set[str]:
        """Protocols this core can actually run (rendered without error)."""
        caps: set[str] = set()
        for scheme in sorted(supported_schemes()):
            h = handler_for(scheme)
            if h is None:
                continue
            dummy = Outbound(scheme=scheme, name="cap", host="127.0.0.1",
                             port="443", credential="x")
            try:
                if self.render_outbound(dummy) is not None:
                    caps.add(scheme)
            except Exception:
                continue
        return caps

    def supports(self, out: Outbound) -> bool:
        return self.render_outbound(out) is not None

    # ------------------------------------------------------------- configs
    def build_client_config(self, outbounds: list[Outbound], socks_port: int,
                            frag_on: bool = False,
                            front_domain: str | None = None) -> dict[str, Any]:
        """Full client config: local socks inbound + the given outbounds."""
        raise NotImplementedError

    # --------------------------------------------------------------- probe
    def find_binary(self) -> str:
        """Path of this core's executable (see cores.discover), or ""."""
        from xray_forge.core.cores import discover
        return discover.find_binary(self.name)

    def probe(self, line: str, binary: str | None = None, timeout: float = 8.0,
              frag_on: bool = True, front_domain: str | None = None) -> dict[str, Any]:
        out = None
        from xray_forge.core.parser import parse_target
        out = parse_target(line)
        if out is None:
            return {"real": None, "cc": "", "exit_ip": "", "status": "unparsable config"}
        binary = binary or self.find_binary()
        if not binary:
            return {"real": None, "cc": "", "exit_ip": "",
                    "status": f"{self.name} core not found"}
        try:
            cfg = self.build_client_config([out], 0, frag_on=frag_on,
                                           front_domain=front_domain)
        except Exception as e:
            return {"real": None, "cc": "", "exit_ip": "",
                    "status": f"config error: {type(e).__name__}"}
        # build_client_config must be given a real port — patch it in
        port = _free_port()
        cfg = _rebind_socks_port(cfg, port)
        return run_socks_probe(self, binary, cfg, port, timeout=timeout)


# ===========================================================================
# Shared probe runner: spawn binary, wait for socks, fetch geo through it
# ===========================================================================

def _free_port() -> int:
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def _socks_inbound_key(cfg: dict) -> str | None:
    for key in ("inbounds",):
        for i, inb in enumerate(cfg.get(key, [])):
            if inb.get("protocol") in ("socks", "mixed") or inb.get("type") in ("socks", "mixed"):
                return f"{key}[{i}]"
    return None


def _rebind_socks_port(cfg: dict, port: int) -> dict:
    for inb in cfg.get("inbounds", []):
        if inb.get("protocol") in ("socks", "mixed") or inb.get("type") in ("socks", "mixed"):
            if "port" in inb:
                inb["port"] = port
            if "listen_port" in inb:
                inb["listen_port"] = port
            if inb.get("protocol") == "mixed" and "port" not in inb:
                inb["port"] = port
    return cfg


def run_socks_probe(core: "CoreAdapter", binary: str, cfg: dict[str, Any],
                    socks_port: int, timeout: float = 8.0,
                    test_host: str = "ip-api.com",
                    start_timeout: float = 5.0, stop=None) -> dict[str, Any]:
    """Spawn the core binary with ``cfg`` and fetch geo through its SOCKS port.

    ``start_timeout`` is how long to wait for the local port to open; ``stop``
    (a ``threading.Event``) cancels the wait and kills the core."""
    from xray_forge.core.socks import fetch_via_socks

    res: dict[str, Any] = {"real": None, "cc": "", "exit_ip": "", "status": ""}
    kw: dict[str, Any] = {}
    if os.name == "nt":
        kw["creationflags"] = subprocess.CREATE_NO_WINDOW

    suffix = core.config_suffix
    cfg_fd, cfg_path = tempfile.mkstemp(suffix=suffix)
    os.close(cfg_fd)
    err_fd, err_path = tempfile.mkstemp(suffix=".log")
    os.close(err_fd)
    proc: subprocess.Popen | None = None
    try:
        if suffix == ".yaml":
            import yaml
            with open(cfg_path, "w", encoding="utf-8") as f:
                yaml.dump(cfg, f, sort_keys=False)
        else:
            with open(cfg_path, "w", encoding="utf-8") as f:
                json.dump(cfg, f)
        cmd = [binary, *core.run_args, cfg_path]
        err_fh = open(err_path, "wb")
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                stderr=err_fh, **kw)
        ok = False
        end = time.time() + start_timeout
        while time.time() < end:
            if stop is not None and stop.is_set():
                res["status"] = "cancelled"
                return res
            if proc.poll() is not None:
                break
            try:
                s = socket.create_connection(("127.0.0.1", socks_port), timeout=0.3)
                s.close()
                ok = True
                break
            except OSError:
                time.sleep(0.1)
        if not ok:
            tail = ""
            try:
                with open(err_path, "r", encoding="utf-8", errors="replace") as f:
                    lines = [l for l in f.read().strip().splitlines() if l]
                tail = lines[-1][:60] if lines else ""
            except OSError:
                pass
            res["status"] = ("core exited: " + tail) if tail else "core failed to start"
            log.warning("core did not open socks port %s: %s", socks_port, res["status"])
            return res
        from xray_forge.core.probe import ProbeError
        # The fetch runs in a worker so ``stop`` is honoured while it is in flight (a tunnel that
        # accepts but never answers used to hold a cancelled job for the whole timeout).  On cancel
        # we return at once; ``finally`` kills the core, which resets the socket and ends the worker.
        box: dict[str, Any] = {}

        def _fetch() -> None:
            try:
                box["ok"] = fetch_via_socks("127.0.0.1", socks_port, test_host, 80,
                                            "/json?fields=status,countryCode,country,city,isp,query",
                                            timeout=timeout)
            except BaseException as exc:  # noqa: BLE001 - re-raised below in the caller's thread
                box["err"] = exc

        worker = threading.Thread(target=_fetch, name="socks-probe-fetch", daemon=True)
        worker.start()
        while worker.is_alive():
            worker.join(0.1)
            if stop is not None and stop.is_set() and "ok" not in box and "err" not in box:
                res["status"] = "cancelled"
                return res
        if "err" in box:
            exc = box["err"]
            if isinstance(exc, ProbeError):
                res["status"] = f"core: {exc.detail[:50]}"
                return res
            raise exc
        ms, status, body = box["ok"]
        res["real"] = ms
        try:
            d = json.loads(body.decode("utf-8", "replace"))
        except Exception:
            d = {}
        cc = str(d.get("countryCode") or "")
        if len(cc) == 2 and cc.isalpha():
            res["cc"] = cc.upper()
            res["exit_ip"] = str(d.get("query") or "")
            res["status"] = "core ok"
        else:
            res["status"] = f"core: geo odd ({status[:24]})"
        return res
    except Exception as e:
        res["status"] = f"core: {type(e).__name__}"
        return res
    finally:
        if proc and proc.poll() is None:
            try:
                proc.kill()
                proc.wait(timeout=3)
            except Exception:
                pass
        try:
            err_fh.close()
        except Exception:
            pass
        for p in (cfg_path, err_path):
            try:
                os.unlink(p)
            except OSError:
                pass


# ===========================================================================
# Reusable core runner: context manager used by the health-check pipeline
# ===========================================================================

@contextlib.contextmanager
def running_core(core: "CoreAdapter", outbounds: list[Outbound], *,
                 binary: str | None = None, socks_port: int | None = None,
                 frag_on: bool = True, front_domain: str | None = None,
                 wait: float = 5.0):
    """Context manager: run ``outbounds`` through a real core binary.

    Builds the core's client config on a free local SOCKS port, spawns the
    binary (temp config + log, ``CREATE_NO_WINDOW`` on Windows), waits until
    the port accepts connections, then yields the port number.  On exit the
    process is killed and the temp files removed.

    Raises :class:`RuntimeError` when the binary is missing or exits before
    opening the port — callers decide whether that is fatal.
    """
    binary = binary or core.find_binary()
    if not binary:
        raise RuntimeError(f"{core.name} core binary not found")
    port = socks_port or _free_port()
    cfg = core.build_client_config(outbounds, port, frag_on=frag_on,
                                   front_domain=front_domain)
    cfg = _rebind_socks_port(cfg, port)
    kw: dict[str, Any] = {}
    if os.name == "nt":
        kw["creationflags"] = subprocess.CREATE_NO_WINDOW
    cfg_fd, cfg_path = tempfile.mkstemp(suffix=core.config_suffix)
    os.close(cfg_fd)
    err_fd, err_path = tempfile.mkstemp(suffix=".log")
    os.close(err_fd)
    proc: subprocess.Popen | None = None
    err_fh = None
    try:
        if core.config_suffix == ".yaml":
            import yaml
            with open(cfg_path, "w", encoding="utf-8") as f:
                yaml.dump(cfg, f, sort_keys=False)
        else:
            with open(cfg_path, "w", encoding="utf-8") as f:
                json.dump(cfg, f)
        err_fh = open(err_path, "wb")
        proc = subprocess.Popen([binary, *core.run_args, cfg_path],
                                stdout=subprocess.DEVNULL, stderr=err_fh, **kw)
        opened = False
        end = time.time() + wait
        while time.time() < end:
            if proc.poll() is not None:
                break
            try:
                s = socket.create_connection(("127.0.0.1", port), timeout=0.3)
                s.close()
                opened = True
                break
            except OSError:
                time.sleep(0.1)
        if not opened:
            tail = ""
            try:
                with open(err_path, "r", encoding="utf-8", errors="replace") as f:
                    lines = [l for l in f.read().strip().splitlines() if l]
                tail = lines[-1][:80] if lines else ""
            except OSError:
                pass
            log.warning("%s did not open socks port %s (stderr tail: %r)",
                        core.name, port, tail)
            raise RuntimeError(("{} exited: " + tail).format(core.name) if tail
                               else f"{core.name} failed to open socks port "
                                    f"{port} within {wait:.0f}s")
        yield port
    finally:
        if proc and proc.poll() is None:
            try:
                proc.kill()
                proc.wait(timeout=3)
            except Exception:
                pass
        if err_fh:
            try:
                err_fh.close()
            except Exception:
                pass
        for p in (cfg_path, err_path):
            try:
                os.unlink(p)
            except OSError:
                pass
