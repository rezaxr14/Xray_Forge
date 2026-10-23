"""Download a proxy core from its official GitHub release, check it, unpack it.

Safety rules (each one is tested):

* only ``https`` and only GitHub hosts, redirects included;
* the asset must live under ``https://github.com/<official repo>/releases/download/``;
* exactly one release asset must match the platform's naming rule, else refuse (never guess);
* GitHub's own ``sha256`` digest for the asset is required and must match what was downloaded
  (no digest, no install).  This catches corrupted or swapped downloads; it cannot detect a
  compromised release, because the digest comes from the same publisher;
* size limits on the download and on the unpacked binary;
* only the known file names are written (never archive paths), into ``<data>/cores/<core>/<tag>/``;
* nothing is executed here: the caller may run the binary's version command afterwards.

The asset naming rules follow each project's published releases but could not be checked
against live data when written; a mismatch makes the install refuse rather than misbehave.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import platform as _platform
import posixpath
import re
import shutil
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from typing import Any, Callable

MAX_ASSET_BYTES = 200 * 1024 * 1024
MAX_BINARY_BYTES = 250 * 1024 * 1024
_TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
_DIGEST_RE = re.compile(r"^sha256:([0-9a-fA-F]{64})$")
_VARIANT_WORDS = re.compile(r"legacy|glibc|musl|purego|android|ios|tvos|unknown|compatible", re.I)

# core -> repo, the name we install the binary under, the names it may have inside the archive, extra files
SOURCES: dict[str, dict[str, Any]] = {
    "xray": {"repo": "XTLS/Xray-core", "binary": "xray", "inside": ("xray",), "extras": ("geoip.dat", "geosite.dat")},
    "singbox": {"repo": "SagerNet/sing-box", "binary": "sing-box", "inside": ("sing-box",), "extras": ()},
    "singbox_extended": {"repo": "shtorm-7/sing-box-extended", "binary": "sing-box-extended",
                         "inside": ("sing-box-extended", "sing-box"), "extras": ()},
    "mihomo": {"repo": "MetaCubeX/mihomo", "binary": "mihomo", "inside": ("mihomo",), "extras": ()},
}
XRAY_NAMES = {("windows", "amd64"): "Xray-windows-64.zip", ("windows", "arm64"): "Xray-windows-arm64-v8a.zip",
              ("linux", "amd64"): "Xray-linux-64.zip", ("linux", "arm64"): "Xray-linux-arm64-v8a.zip",
              ("darwin", "amd64"): "Xray-macos-64.zip", ("darwin", "arm64"): "Xray-macos-arm64-v8a.zip"}


class InstallError(Exception):
    pass


class Cancelled(Exception):
    pass


# ------------------------------------------------------------------ platform / assets
def platform_key(plat: str | None = None, machine: str | None = None) -> tuple[str, str]:
    plat = sys.platform if plat is None else plat
    machine = (_platform.machine() if machine is None else machine).lower()
    os_ = {"win32": "windows", "linux": "linux", "darwin": "darwin"}.get(plat)
    arch = {"x86_64": "amd64", "amd64": "amd64", "arm64": "arm64", "aarch64": "arm64"}.get(machine)
    if not os_ or not arch:
        raise InstallError(f"unsupported platform: {plat} {machine}")
    return os_, arch


def _asset_regex(core: str, os_: str, arch: str) -> "re.Pattern[str]":
    if core == "xray":
        return re.compile(re.escape(XRAY_NAMES[(os_, arch)]))
    if core in ("singbox", "singbox_extended"):
        return re.compile(rf"sing-box(?:-extended)?-\d[\w.+-]*-{os_}-{arch}\.(?:zip|tar\.gz)")
    return re.compile(rf"mihomo-{os_}-{arch}-v\d[\w.]*\.(?:zip|gz)")


def select_asset(core: str, assets: list[dict], os_: str, arch: str) -> dict:
    if core not in SOURCES:
        raise InstallError(f"{core} cannot be downloaded by Xray Forge")
    rx = _asset_regex(core, os_, arch)
    hits = [a for a in assets if isinstance(a, dict) and isinstance(a.get("name"), str)
            and rx.fullmatch(a["name"]) and not _VARIANT_WORDS.search(a["name"])]
    if not hits:
        raise InstallError(f"no matching {core} download for {os_}/{arch} in this release")
    if len(hits) > 1:
        raise InstallError(f"more than one {core} download matches {os_}/{arch}; refusing to guess")
    return hits[0]


# ----------------------------------------------------------------------- url policy
def url_allowed(url: str) -> bool:
    try:
        u = urllib.parse.urlsplit(url)
        host, port = u.hostname, u.port
    except ValueError:
        return False
    if u.scheme != "https" or not host or u.username or u.password or port not in (None, 443):
        return False
    return host in ("github.com", "api.github.com") or host.endswith(".githubusercontent.com")


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not url_allowed(newurl):
            raise InstallError("blocked redirect to a non-GitHub address")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class GitHubFetcher:
    """The real network side: release metadata and asset download, restricted by ``url_allowed``."""

    UA = "xray-forge-core-installer"

    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout
        self._opener = urllib.request.build_opener(_SafeRedirect)

    def _open(self, url: str, accept: str):
        if not url_allowed(url):
            raise InstallError("refusing a non-GitHub address")
        req = urllib.request.Request(url, headers={"User-Agent": self.UA, "Accept": accept})
        try:
            return self._opener.open(req, timeout=self.timeout)
        except urllib.error.HTTPError as e:
            raise InstallError(f"GitHub answered HTTP {e.code}") from None
        except (urllib.error.URLError, OSError) as e:
            raise InstallError(f"network error: {type(e).__name__}") from None

    def release(self, repo: str) -> dict:
        with self._open(f"https://api.github.com/repos/{repo}/releases/latest", "application/vnd.github+json") as r:
            data = r.read(5 * 1024 * 1024)
        try:
            obj = json.loads(data.decode("utf-8"))
        except ValueError:
            raise InstallError("unreadable release information") from None
        if not isinstance(obj, dict):
            raise InstallError("unreadable release information")
        return obj

    def download(self, url, fileobj, progress=None, stop=None, limit=None) -> int:
        limit = MAX_ASSET_BYTES if limit is None else limit
        sent = 0
        with self._open(url, "application/octet-stream") as r:
            total = int(r.headers.get("Content-Length") or 0)
            while True:
                if stop is not None and stop.is_set():
                    raise Cancelled()
                chunk = r.read(64 * 1024)
                if not chunk:
                    break
                sent += len(chunk)
                if sent > limit:
                    raise InstallError("download is too large")
                fileobj.write(chunk)
                if progress:
                    progress(sent, total or sent)
        return sent


# ------------------------------------------------------------------------- release info
def release_info(core: str, fetcher=None, plat: tuple[str, str] | None = None) -> dict:
    if core not in SOURCES:
        raise InstallError(f"{core} cannot be downloaded by Xray Forge")
    os_, arch = plat or platform_key()
    repo = SOURCES[core]["repo"]
    rel = (fetcher or GitHubFetcher()).release(repo)
    tag = rel.get("tag_name") if isinstance(rel, dict) else None
    if not isinstance(tag, str) or not _TAG_RE.match(tag):
        raise InstallError("refusing unsafe release tag")
    a = select_asset(core, rel.get("assets") or [], os_, arch)
    url = a.get("browser_download_url")
    if not isinstance(url, str) or not url.startswith(f"https://github.com/{repo}/releases/download/"):
        raise InstallError("asset is not an official release download")
    m = _DIGEST_RE.match(a.get("digest") or "")
    if not m:
        raise InstallError("the release has no sha256 digest for this asset; refusing to install unverified code")
    size = a.get("size")
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise InstallError("the release does not state a valid size")
    if size > MAX_ASSET_BYTES:
        raise InstallError("download is too large")
    return {"core": core, "repo": repo, "tag": tag, "asset": a["name"], "size": size,
            "sha256": m.group(1).lower(), "url": url}


# ----------------------------------------------------------------------------- unpack
def _pick(members: list[tuple[str, Any]], wanted: tuple[str, ...]) -> Any | None:
    """The shallowest member whose *base name* is wanted (archive paths are never used)."""
    best = None
    for name, ref in members:
        norm = name.replace("\\", "/")
        if posixpath.basename(norm) in wanted:
            depth = norm.strip("/").count("/")
            if best is None or depth < best[0]:
                best = (depth, ref)
    return best[1] if best else None


def _read_limited(fh, what: str) -> bytes:
    data = fh.read(MAX_BINARY_BYTES + 1)
    if len(data) > MAX_BINARY_BYTES:
        raise InstallError(f"{what} is too large")
    return data


def _extract(core: str, archive: str, asset: str, out_dir: str, os_: str) -> None:
    spec = SOURCES[core]
    exe = ".exe" if os_ == "windows" else ""
    names = tuple(n + e for n in spec["inside"] for e in ("", ".exe"))
    files: dict[str, bytes] = {}
    if asset.endswith(".gz") and not asset.endswith(".tar.gz"):
        with gzip.open(archive, "rb") as g:
            files[spec["binary"] + exe] = _read_limited(g, "binary")
    else:
        opened: list[tuple[str, Any]]
        if asset.endswith(".zip"):
            z = zipfile.ZipFile(archive)
            opened = [(i.filename, i) for i in z.infolist() if not i.is_dir()]
            opener = z.open
        else:
            t = tarfile.open(archive, "r:gz")
            opened = [(m.name, m) for m in t.getmembers() if m.isfile()]
            opener = t.extractfile
        bin_ref = _pick(opened, names)
        if bin_ref is not None:
            files[spec["binary"] + exe] = _read_limited(opener(bin_ref), "binary")
        for extra in spec["extras"]:
            ref = _pick(opened, (extra,))
            if ref is not None:
                files[extra] = _read_limited(opener(ref), extra)
    if spec["binary"] + exe not in files:
        raise InstallError(f"the download does not contain {spec['binary']}")
    for name, data in files.items():
        path = os.path.join(out_dir, name)
        with open(path, "wb") as f:
            f.write(data)
        if os_ != "windows":
            os.chmod(path, 0o755 if name == spec["binary"] + exe else 0o644)


# ---------------------------------------------------------------------------- install
class _HashingWriter:
    def __init__(self, fh):
        self.fh, self.h = fh, hashlib.sha256()

    def write(self, b: bytes) -> int:
        self.h.update(b)
        return self.fh.write(b)


def install(core: str, *, fetcher=None, dest_root: str | None = None, plat: tuple[str, str] | None = None,
            progress: Callable[[int, int], None] | None = None, stop=None) -> dict:
    fetcher = fetcher or GitHubFetcher()
    plat = plat or platform_key()
    info = release_info(core, fetcher, plat)
    if dest_root is None:
        from xray_forge.core import settings
        dest_root = os.path.join(settings.data_dir(), "cores")
    core_dir = os.path.join(dest_root, core)
    os.makedirs(core_dir, exist_ok=True)
    work = tempfile.mkdtemp(prefix=".dl-", dir=core_dir)
    try:
        archive = os.path.join(work, "asset")
        with open(archive, "wb") as fh:
            hw = _HashingWriter(fh)
            fetcher.download(info["url"], hw, progress=progress, stop=stop, limit=info["size"] + 1024 * 1024)
        if hw.h.hexdigest() != info["sha256"]:
            raise InstallError("checksum mismatch: the download does not match the release digest")
        out = os.path.join(work, "out")
        os.mkdir(out)
        _extract(core, archive, info["asset"], out, plat[0])
        final = os.path.join(core_dir, info["tag"])
        if os.path.isdir(final):
            shutil.rmtree(final)
        os.replace(out, final)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    exe = SOURCES[core]["binary"] + (".exe" if plat[0] == "windows" else "")
    return {"core": core, "path": os.path.join(final, exe), "tag": info["tag"], "asset": info["asset"],
            "sha256": info["sha256"], "size": info["size"]}
