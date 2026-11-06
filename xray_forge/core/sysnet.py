"""Change the system DNS servers and the system proxy (Windows, macOS, Linux).

Everything goes through a small ``Runner`` (argv in, exit code and text out) so the command lines
can be tested without touching a real machine.  Commands are built as argument lists and never
passed to a shell; interface names are only used after they were found in the system's own list;
addresses are validated with ``ipaddress`` first.  Changing these settings needs administrator
rights (root on Linux and macOS); a refusal is reported with a hint instead of a raw traceback.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from typing import Callable

from xray_forge.core.dns_presets import valid_ip

Runner = Callable[[list, float], "tuple[int, str, str]"]

HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
MAX_DNS = 4


class NetConfigError(Exception):
    def __init__(self, message: str, hint: str = ""):
        super().__init__(message)
        self.hint = hint


def default_runner(argv: list, timeout: float = 20.0) -> tuple[int, str, str]:
    kwargs: dict = {}
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                           encoding="utf-8", errors="replace", **kwargs)
    except FileNotFoundError:
        raise NetConfigError(f"{argv[0]} is not installed", "This feature needs that system tool.") from None
    except subprocess.TimeoutExpired:
        raise NetConfigError(f"{argv[0]} did not answer within {timeout:.0f} seconds") from None
    return p.returncode, p.stdout, p.stderr


def platform_name() -> str:
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def is_admin() -> bool:
    try:
        if os.name == "nt":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def clean_servers(servers) -> list[str]:
    if not isinstance(servers, (list, tuple)) or not servers:
        raise ValueError("give at least one DNS server address")
    out: list[str] = []
    for s in servers:
        ip = valid_ip(s)
        if ip not in out:
            out.append(ip)
    if len(out) > MAX_DNS:
        raise ValueError(f"at most {MAX_DNS} DNS servers")
    return out


def clean_proxy(host, port, kind) -> tuple[str, int, str]:
    if not isinstance(host, str) or not HOST_RE.match(host.strip()):
        raise ValueError("proxy address must be a host name or IP address")
    if isinstance(port, bool) or not (isinstance(port, int) or (isinstance(port, str) and port.strip().isdigit())):
        raise ValueError("proxy port must be a number from 1 to 65535")
    p = int(port)
    if not 1 <= p <= 65535:
        raise ValueError("proxy port must be a number from 1 to 65535")
    if kind not in ("http", "socks"):
        raise ValueError("proxy type must be http or socks")
    return host.strip(), p, kind


def _fail(what: str, code: int, out: str, err: str, platform: str = "") -> NetConfigError:
    text = (err or out or f"exit code {code}").strip().splitlines()
    msg = f"{what}: {text[0][:200] if text else code}"
    low = (err + out).lower()
    hint = ""
    if any(w in low for w in ("denied", "administrator", "privilege", "not permitted", "authoriz", "polkit", "access")):
        hint = {"windows": "Run Xray Forge as administrator.",
                "macos": "Run with administrator rights (an admin account or sudo).",
                }.get(platform or platform_name(), "Run with root rights (sudo) or allow it in polkit.")
    return NetConfigError(msg, hint)


class Backend:
    name = ""

    def __init__(self, run: Runner | None = None):
        self.run = run or default_runner

    def _ok(self, argv: list, what: str, timeout: float = 20.0) -> str:
        code, out, err = self.run(argv, timeout)
        if code != 0:
            raise _fail(what, code, out, err, self.name)
        return out

    def interfaces(self) -> list[dict]:
        raise NotImplementedError

    def get_dns(self, iface: dict) -> dict:
        raise NotImplementedError

    def set_dns(self, iface: dict, servers: list[str]) -> None:
        raise NotImplementedError

    def reset_dns(self, iface: dict) -> None:
        raise NotImplementedError

    def get_proxy(self) -> dict:
        raise NotImplementedError

    def set_proxy(self, host: str, port: int, kind: str) -> None:
        raise NotImplementedError

    def disable_proxy(self) -> None:
        raise NotImplementedError

    def find(self, iface_id) -> dict:
        for i in self.interfaces():
            if i["id"] == str(iface_id):
                return i
        raise NetConfigError("that network interface was not found", "refresh the list and pick one again")


# ---------------------------------------------------------------- Windows
def _ps(script: str) -> list:
    pre = "$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
    return ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", pre + script]


def _aslist(v) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _json(text: str):
    text = text.strip()
    if not text:
        return []
    try:
        return json.loads(text)
    except ValueError:
        raise NetConfigError("the system gave an answer that could not be read") from None


class WindowsBackend(Backend):
    name = "windows"
    KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

    def __init__(self, run: Runner | None = None, reg=None, refresh: Callable[[], None] | None = None):
        super().__init__(run)
        self._reg = reg
        self._refresh = refresh

    def interfaces(self) -> list[dict]:
        out = self._ok(_ps("Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | "
                           "Select-Object Name,InterfaceDescription,ifIndex,HardwareInterface | ConvertTo-Json -Compress"),
                       "listing network adapters")
        rows = _aslist(_json(out))
        found = [{"id": str(int(r["ifIndex"])), "name": str(r.get("Name") or ""),
                  "description": str(r.get("InterfaceDescription") or ""),
                  "hardware": r.get("HardwareInterface") is not False}
                 for r in rows if isinstance(r, dict) and str(r.get("ifIndex", "")).isdigit()]
        return sorted(found, key=lambda i: not i["hardware"])      # real adapters before tunnels and virtual ones

    def get_dns(self, iface: dict) -> dict:
        out = self._ok(_ps(f"Get-DnsClientServerAddress -InterfaceIndex {int(iface['id'])} | "
                           "Select-Object AddressFamily,ServerAddresses | ConvertTo-Json -Compress -Depth 3"),
                       "reading DNS servers")
        servers: list[str] = []
        for r in _aslist(_json(out)):
            if isinstance(r, dict):
                servers += [s for s in _aslist(r.get("ServerAddresses")) if isinstance(s, str)]
        return {"servers": servers, "automatic": None}      # Windows does not say whether they were typed in

    def set_dns(self, iface, servers):
        quoted = ",".join(f"'{s}'" for s in servers)      # validated IP literals only
        self._ok(_ps(f"Set-DnsClientServerAddress -InterfaceIndex {int(iface['id'])} -ServerAddresses ({quoted});"
                     "try{Clear-DnsClientCache}catch{}"), "setting DNS servers")
        now = self.get_dns(iface)["servers"]      # read it back: do not report success for a change that did not happen
        if [x.lower() for x in now] != [x.lower() for x in servers]:
            raise NetConfigError("Windows did not keep the new DNS servers",
                                 "Run Xray Forge as administrator, then check the network again.")

    def reset_dns(self, iface):
        self._ok(_ps(f"Set-DnsClientServerAddress -InterfaceIndex {int(iface['id'])} -ResetServerAddresses;"
                     "try{Clear-DnsClientCache}catch{}"), "resetting DNS servers")

    # --- proxy (per-user registry values, as the Windows settings page uses)
    def _winreg(self):
        if self._reg is not None:
            return self._reg
        import winreg
        return winreg

    def _notify(self) -> None:
        if self._refresh:
            self._refresh()
            return
        try:
            import ctypes
            f = ctypes.windll.wininet.InternetSetOptionW
            f(0, 39, 0, 0)      # INTERNET_OPTION_SETTINGS_CHANGED
            f(0, 37, 0, 0)      # INTERNET_OPTION_REFRESH
        except Exception:
            pass

    def get_proxy(self) -> dict:
        r = self._winreg()
        try:
            key = r.OpenKey(r.HKEY_CURRENT_USER, self.KEY, 0, r.KEY_READ)
            try:
                enabled = int(r.QueryValueEx(key, "ProxyEnable")[0])
                try:
                    server = str(r.QueryValueEx(key, "ProxyServer")[0])
                except OSError:
                    server = ""
            finally:
                r.CloseKey(key)
        except OSError as e:
            raise NetConfigError(f"reading the proxy setting: {e}") from None
        kind, host, port = "http", "", 0
        entry = server
        if "=" in server:
            parts = dict(p.split("=", 1) for p in server.split(";") if "=" in p)
            if "http" in parts:
                entry = parts["http"]
            elif "socks" in parts:
                kind, entry = "socks", parts["socks"]
        h, _, p = entry.rpartition(":")
        if h and p.isdigit():
            host, port = h, int(p)
        return {"enabled": bool(enabled and host), "kind": kind, "host": host, "port": port}

    def _write(self, values: dict) -> None:
        r = self._winreg()
        try:
            key = r.OpenKey(r.HKEY_CURRENT_USER, self.KEY, 0, r.KEY_WRITE)
            try:
                for name, (kind, val) in values.items():
                    r.SetValueEx(key, name, 0, kind, val)
            finally:
                r.CloseKey(key)
        except OSError as e:
            raise NetConfigError(f"changing the proxy setting: {e}") from None
        self._notify()

    def set_proxy(self, host, port, kind):
        r = self._winreg()
        addr = f"{host}:{port}" if kind == "http" else f"socks={host}:{port}"
        self._write({"ProxyServer": (r.REG_SZ, addr), "ProxyOverride": (r.REG_SZ, "<local>"),
                     "ProxyEnable": (r.REG_DWORD, 1)})

    def disable_proxy(self):
        self._write({"ProxyEnable": (self._winreg().REG_DWORD, 0)})


# ------------------------------------------------------------------ macOS
NS = "networksetup"


class MacBackend(Backend):
    name = "macos"

    def interfaces(self) -> list[dict]:
        out = self._ok([NS, "-listallnetworkservices"], "listing network services")
        res = []
        for line in out.splitlines()[1:]:           # first line is a note about the asterisk
            line = line.strip()
            if line and not line.startswith("*"):   # an asterisk marks a disabled service
                res.append({"id": line, "name": line, "description": ""})
        return res

    def get_dns(self, iface):
        out = self._ok([NS, "-getdnsservers", iface["id"]], "reading DNS servers")
        if "aren't any" in out or not out.strip():
            return {"servers": [], "automatic": True}
        return {"servers": [x.strip() for x in out.splitlines() if x.strip()], "automatic": False}

    def set_dns(self, iface, servers):
        self._ok([NS, "-setdnsservers", iface["id"], *servers], "setting DNS servers")

    def reset_dns(self, iface):
        self._ok([NS, "-setdnsservers", iface["id"], "Empty"], "resetting DNS servers")

    def _each(self, build, what):
        for i in self.interfaces():
            self._ok(build(i["id"]), what)

    def get_proxy(self) -> dict:
        ifaces = self.interfaces()
        if not ifaces:
            return {"enabled": False, "kind": "http", "host": "", "port": 0}
        svc = ifaces[0]["id"]
        for kind, flag in (("http", "-getwebproxy"), ("socks", "-getsocksfirewallproxy")):
            out = self._ok([NS, flag, svc], "reading the proxy setting")
            f = dict(l.split(": ", 1) for l in out.splitlines() if ": " in l)
            if f.get("Enabled", "No").strip() == "Yes":
                port = f.get("Port", "0").strip()
                return {"enabled": True, "kind": kind, "host": f.get("Server", "").strip(),
                        "port": int(port) if port.isdigit() else 0}
        return {"enabled": False, "kind": "http", "host": "", "port": 0}

    def set_proxy(self, host, port, kind):
        if kind == "http":
            self._each(lambda s: [NS, "-setwebproxy", s, host, str(port)], "setting the web proxy")
            self._each(lambda s: [NS, "-setsecurewebproxy", s, host, str(port)], "setting the secure web proxy")
        else:
            self._each(lambda s: [NS, "-setsocksfirewallproxy", s, host, str(port)], "setting the SOCKS proxy")

    def disable_proxy(self):
        for flag in ("-setwebproxystate", "-setsecurewebproxystate", "-setsocksfirewallproxystate"):
            self._each(lambda s, f=flag: [NS, f, s, "off"], "turning the proxy off")


# ------------------------------------------------------------------ Linux
LINK_RE = re.compile(r"^\d+:\s+([^:@\s]+)(?:@\S+)?:\s.*\bstate\s+(\S+)")
GS = "gsettings"
SCHEMA = "org.gnome.system.proxy"


class LinuxBackend(Backend):
    name = "linux"

    def interfaces(self) -> list[dict]:
        out = self._ok(["ip", "-o", "link", "show"], "listing network interfaces")
        res = []
        for line in out.splitlines():
            m = LINK_RE.match(line.strip())
            if m and m.group(1) != "lo" and m.group(2) in ("UP", "UNKNOWN"):
                res.append({"id": m.group(1), "name": m.group(1), "description": ""})
        return res

    def get_dns(self, iface):
        out = self._ok(["resolvectl", "dns", iface["id"]], "reading DNS servers")
        tail = out.split(":", 1)[1] if ":" in out and out.lstrip().startswith("Link") else out
        servers = [t for t in tail.split() if _is_ip(t)]
        return {"servers": servers, "automatic": not servers}

    def set_dns(self, iface, servers):
        self._ok(["resolvectl", "dns", iface["id"], *servers], "setting DNS servers")
        self._ok(["resolvectl", "flush-caches"], "clearing the DNS cache")

    def reset_dns(self, iface):
        self._ok(["resolvectl", "revert", iface["id"]], "resetting DNS servers")
        self._ok(["resolvectl", "flush-caches"], "clearing the DNS cache")

    def _get(self, schema, key) -> str:
        return self._ok([GS, "get", schema, key], "reading the proxy setting").strip().strip("'")

    def get_proxy(self) -> dict:
        mode = self._get(SCHEMA, "mode")
        for kind, schema in (("http", f"{SCHEMA}.http"), ("socks", f"{SCHEMA}.socks")):
            host = self._get(schema, "host")
            port = self._get(schema, "port")
            if host:
                return {"enabled": mode == "manual", "kind": kind, "host": host, "port": int(port) if port.isdigit() else 0}
        return {"enabled": False, "kind": "http", "host": "", "port": 0}

    def set_proxy(self, host, port, kind):
        schemas = [f"{SCHEMA}.http", f"{SCHEMA}.https"] if kind == "http" else [f"{SCHEMA}.socks"]
        for s in schemas:
            self._ok([GS, "set", s, "host", host], "setting the proxy address")
            self._ok([GS, "set", s, "port", str(port)], "setting the proxy port")
        self._ok([GS, "set", SCHEMA, "mode", "manual"], "turning the proxy on")

    def disable_proxy(self):
        self._ok([GS, "set", SCHEMA, "mode", "none"], "turning the proxy off")


def _is_ip(text: str) -> bool:
    try:
        valid_ip(text)
        return True
    except ValueError:
        return False


def backend(platform: str | None = None, run: Runner | None = None, **kw) -> Backend:
    p = platform or platform_name()
    if p == "windows":
        return WindowsBackend(run, **kw)
    return (MacBackend if p == "macos" else LinuxBackend)(run)
