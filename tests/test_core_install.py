"""Downloading proxy cores from their official GitHub releases (no network: a fake fetcher).

The real asset names/digests were not available when this was written; the
selection rules are exercised on realistic names and must refuse (never guess)
when zero or several assets match.  A real run is in docs/local-agent-runbook.md."""

from __future__ import annotations

import gzip
import hashlib
import io
import os
import stat
import sys
import tarfile
import threading
import time
import zipfile

import pytest

from xray_forge.core.cores import discover, install

posix = pytest.mark.skipif(os.name == "nt", reason="runs the extracted fake binary")
SCRIPT = b"#!/bin/sh\necho 'fake 9.9.9'\n"


# ---------------------------------------------------------------- archives
def make_zip(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in members.items():
            z.writestr(name, data)
    return buf.getvalue()


def make_targz(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


class FakeFetcher:
    """Serves release metadata and one asset body; records what was requested."""

    def __init__(self, repo_assets: dict, blobs: dict, tag="v1.2.3"):
        self.assets, self.blobs, self.tag, self.urls = repo_assets, blobs, tag, []

    def release(self, repo):
        self.urls.append(("release", repo))
        return {"tag_name": self.tag, "assets": self.assets}

    def download(self, url, fileobj, progress=None, stop=None, limit=None):
        self.urls.append(("download", url))
        data = self.blobs[url]
        sent = 0
        for i in range(0, len(data), 1024):
            if stop is not None and stop.is_set():
                raise install.Cancelled()
            chunk = data[i:i + 1024]
            fileobj.write(chunk)
            sent += len(chunk)
            if progress:
                progress(sent, len(data))
        return sent


def asset(name, body, repo="XTLS/Xray-core", digest=True, size=None):
    url = f"https://github.com/{repo}/releases/download/v1.2.3/{name}"
    a = {"name": name, "size": len(body) if size is None else size, "browser_download_url": url}
    if digest is True:
        a["digest"] = "sha256:" + sha(body)
    elif digest:
        a["digest"] = digest
    return a, {url: body}


def fetcher_for(name, body, repo="XTLS/Xray-core", **kw):
    a, blobs = asset(name, body, repo, **kw)
    return FakeFetcher([a], blobs)


# --------------------------------------------------------------- platform + selection
@pytest.mark.parametrize("plat,machine,expected", [
    ("win32", "AMD64", ("windows", "amd64")), ("win32", "ARM64", ("windows", "arm64")),
    ("linux", "x86_64", ("linux", "amd64")), ("linux", "aarch64", ("linux", "arm64")),
    ("darwin", "arm64", ("darwin", "arm64")), ("darwin", "x86_64", ("darwin", "amd64"))])
def test_platform_key(plat, machine, expected):
    assert install.platform_key(plat, machine) == expected


@pytest.mark.parametrize("plat,machine", [("freebsd14", "amd64"), ("linux", "riscv64"), ("win32", "x86")])
def test_unsupported_platforms_are_reported(plat, machine):
    with pytest.raises(install.InstallError, match="unsupported platform"):
        install.platform_key(plat, machine)


XRAY_ASSETS = ["Xray-windows-64.zip", "Xray-windows-64.zip.dgst", "Xray-windows-arm64-v8a.zip", "Xray-linux-64.zip",
               "Xray-linux-arm64-v8a.zip", "Xray-macos-64.zip", "Xray-macos-arm64-v8a.zip", "Xray-freebsd-64.zip", "Xray-linux-32.zip"]
SING_ASSETS = ["sing-box-1.12.1-windows-amd64.zip", "sing-box-1.12.1-windows-amd64-legacy-windows-7.zip" if False else "sing-box-1.12.1-legacy-windows-amd64.zip",
               "sing-box-1.12.1-linux-amd64.tar.gz", "sing-box-1.12.1-linux-amd64-glibc.tar.gz", "sing-box-1.12.1-linux-arm64.tar.gz",
               "sing-box-1.12.1-darwin-arm64.tar.gz", "sing-box-1.12.1-darwin-amd64.tar.gz", "sing-box-1.12.1-android-arm64.tar.gz",
               "sing-box_1.12.1_linux_amd64.deb"]
MIHOMO_ASSETS = ["mihomo-windows-amd64-v1.19.2.zip", "mihomo-windows-amd64-compatible-v1.19.2.zip", "mihomo-windows-amd64-v3-v1.19.2.zip",
                 "mihomo-linux-amd64-v1.19.2.gz", "mihomo-linux-amd64-compatible-v1.19.2.gz", "mihomo-linux-arm64-v1.19.2.gz",
                 "mihomo-darwin-arm64-v1.19.2.gz", "mihomo-darwin-amd64-v1.19.2.gz", "mihomo-linux-amd64-v1.19.2.deb"]


def pick(core, names, os_, arch):
    return install.select_asset(core, [{"name": n} for n in names], os_, arch)["name"]


@pytest.mark.parametrize("core,names,os_,arch,expected", [
    ("xray", XRAY_ASSETS, "windows", "amd64", "Xray-windows-64.zip"),
    ("xray", XRAY_ASSETS, "windows", "arm64", "Xray-windows-arm64-v8a.zip"),
    ("xray", XRAY_ASSETS, "linux", "amd64", "Xray-linux-64.zip"),
    ("xray", XRAY_ASSETS, "linux", "arm64", "Xray-linux-arm64-v8a.zip"),
    ("xray", XRAY_ASSETS, "darwin", "amd64", "Xray-macos-64.zip"),
    ("xray", XRAY_ASSETS, "darwin", "arm64", "Xray-macos-arm64-v8a.zip"),
    ("singbox", SING_ASSETS, "windows", "amd64", "sing-box-1.12.1-windows-amd64.zip"),
    ("singbox", SING_ASSETS, "linux", "amd64", "sing-box-1.12.1-linux-amd64.tar.gz"),
    ("singbox", SING_ASSETS, "linux", "arm64", "sing-box-1.12.1-linux-arm64.tar.gz"),
    ("singbox", SING_ASSETS, "darwin", "arm64", "sing-box-1.12.1-darwin-arm64.tar.gz"),
    ("singbox_extended", [n.replace("sing-box-", "sing-box-extended-") for n in SING_ASSETS], "linux", "amd64", "sing-box-extended-1.12.1-linux-amd64.tar.gz"),
    ("mihomo", MIHOMO_ASSETS, "windows", "amd64", "mihomo-windows-amd64-v1.19.2.zip"),
    ("mihomo", MIHOMO_ASSETS, "linux", "amd64", "mihomo-linux-amd64-v1.19.2.gz"),
    ("mihomo", MIHOMO_ASSETS, "darwin", "arm64", "mihomo-darwin-arm64-v1.19.2.gz"),
])
def test_select_asset_picks_the_plain_build_and_ignores_variants(core, names, os_, arch, expected):
    assert pick(core, names, os_, arch) == expected


def test_select_asset_refuses_when_nothing_or_several_match():
    with pytest.raises(install.InstallError, match="no matching"):
        pick("xray", ["Xray-linux-64.zip"], "windows", "amd64")
    with pytest.raises(install.InstallError, match="more than one"):
        pick("xray", ["Xray-windows-64.zip", "Xray-windows-64.zip"], "windows", "amd64")
    with pytest.raises(install.InstallError, match="cannot be downloaded"):
        install.select_asset("psiphon", [], "linux", "amd64")


# ------------------------------------------------------------------ url policy
@pytest.mark.parametrize("url,ok", [
    ("https://github.com/XTLS/Xray-core/releases/download/v1/x.zip", True),
    ("https://api.github.com/repos/XTLS/Xray-core/releases/latest", True),
    ("https://objects.githubusercontent.com/a/b", True),
    ("https://release-assets.githubusercontent.com/a/b", True),
    ("http://github.com/x", False), ("https://github.com.evil.example/x", False), ("https://evil.example/github.com", False),
    ("https://user@evil.example/", False), ("ftp://github.com/x", False), ("file:///etc/passwd", False),
    ("https://githubusercontent.com.evil.example/", False), ("https://xgithub.com/x", False), ("", False),
    ("https://user@github.com/x", False), ("https://user:pw@github.com/x", False), ("https://github.com:8443/x", False),
    ("https://github.com:443/x", True), ("https://github.com:abc/x", False)])
def test_url_policy(url, ok):
    assert install.url_allowed(url) is ok


def test_redirects_to_other_hosts_are_refused():
    handler = install._SafeRedirect()
    import urllib.request
    req = urllib.request.Request("https://github.com/a")
    with pytest.raises(install.InstallError, match="redirect"):
        handler.redirect_request(req, None, 302, "Found", {}, "https://evil.example/payload")
    assert handler.redirect_request(req, None, 302, "Found", {}, "https://objects.githubusercontent.com/p") is not None


# ----------------------------------------------------------------------- install
def run_install(tmp_path, core, fetcher, **kw):
    return install.install(core, fetcher=fetcher, dest_root=str(tmp_path / "cores"), plat=kw.pop("plat", ("linux", "amd64")), **kw)


def test_zip_install_extracts_only_the_known_files_and_marks_the_binary_executable(tmp_path):
    body = make_zip({"xray": SCRIPT, "geoip.dat": b"GEO", "geosite.dat": b"SITE", "README.md": b"r", "../evil": b"x",
                     "sub/dir/xray": b"nested", "/abs/geoip.dat": b"abs"})
    r = run_install(tmp_path, "xray", fetcher_for("Xray-linux-64.zip", body))
    d = tmp_path / "cores" / "xray" / "v1.2.3"
    assert r["path"] == str(d / "xray") and r["tag"] == "v1.2.3" and r["asset"] == "Xray-linux-64.zip" and r["sha256"] == sha(body)
    assert sorted(os.listdir(d)) == ["geoip.dat", "geosite.dat", "xray"]
    assert (d / "xray").read_bytes() == SCRIPT and (d / "geoip.dat").read_bytes() == b"GEO"
    assert not (tmp_path / "cores" / "evil").exists() and not (tmp_path / "evil").exists()
    if os.name != "nt":
        assert (d / "xray").stat().st_mode & stat.S_IXUSR
    assert os.listdir(tmp_path / "cores" / "xray") == ["v1.2.3"]            # no temp leftovers


def test_windows_binaries_get_an_exe_name(tmp_path):
    body = make_zip({"xray.exe": b"MZ"})
    r = run_install(tmp_path, "xray", fetcher_for("Xray-windows-64.zip", body), plat=("windows", "amd64"))
    assert os.path.basename(r["path"]) == "xray.exe"


def test_targz_install_for_singbox_and_the_extended_fork(tmp_path):
    body = make_targz({"sing-box-1.12.1-linux-amd64/sing-box": SCRIPT, "sing-box-1.12.1-linux-amd64/LICENSE": b"l"})
    r = run_install(tmp_path, "singbox", fetcher_for("sing-box-1.12.1-linux-amd64.tar.gz", body, "SagerNet/sing-box"))
    assert os.path.basename(r["path"]) == "sing-box" and open(r["path"], "rb").read() == SCRIPT
    ext = make_targz({"x/sing-box": SCRIPT})
    r2 = run_install(tmp_path, "singbox_extended", fetcher_for("sing-box-extended-1.12.1-linux-amd64.tar.gz", ext, "shtorm-7/sing-box-extended"))
    assert os.path.basename(r2["path"]) == "sing-box-extended"               # stored under the name we search for


def test_single_gz_install_for_mihomo(tmp_path):
    body = gzip.compress(SCRIPT)
    r = run_install(tmp_path, "mihomo", fetcher_for("mihomo-linux-amd64-v1.19.2.gz", body, "MetaCubeX/mihomo"))
    assert os.path.basename(r["path"]) == "mihomo" and open(r["path"], "rb").read() == SCRIPT


def test_an_archive_without_the_binary_is_refused_and_leaves_nothing(tmp_path):
    body = make_zip({"README.md": b"x"})
    with pytest.raises(install.InstallError, match="does not contain"):
        run_install(tmp_path, "xray", fetcher_for("Xray-linux-64.zip", body))
    assert not (tmp_path / "cores" / "xray" / "v1.2.3").exists()
    assert os.listdir(tmp_path / "cores" / "xray") == []                      # the staging download is removed too


def test_checksum_mismatch_missing_digest_and_bad_digest_are_refused(tmp_path):
    body = make_zip({"xray": SCRIPT})
    with pytest.raises(install.InstallError, match="checksum"):
        run_install(tmp_path, "xray", fetcher_for("Xray-linux-64.zip", body, digest="sha256:" + "0" * 64))
    with pytest.raises(install.InstallError, match="no sha256 digest"):
        run_install(tmp_path, "xray", fetcher_for("Xray-linux-64.zip", body, digest=False))
    for bad in ("md5:abcd", "sha256:xyz", "sha256:" + "a" * 63, "sha256:", "SHA256"):
        with pytest.raises(install.InstallError, match="no sha256 digest"):
            run_install(tmp_path, "xray", fetcher_for("Xray-linux-64.zip", body, digest=bad))
    assert not (tmp_path / "cores" / "xray" / "v1.2.3").exists()


def test_uppercase_hex_digests_are_accepted(tmp_path):
    body = make_zip({"xray": SCRIPT})
    run_install(tmp_path, "xray", fetcher_for("Xray-linux-64.zip", body, digest="sha256:" + sha(body).upper()))


def test_assets_from_foreign_hosts_or_repos_are_refused(tmp_path):
    body = make_zip({"xray": SCRIPT})
    a, blobs = asset("Xray-linux-64.zip", body)
    a["browser_download_url"] = "https://evil.example/Xray-linux-64.zip"
    with pytest.raises(install.InstallError, match="not an official"):
        run_install(tmp_path, "xray", FakeFetcher([a], {a["browser_download_url"]: body}))
    a2, b2 = asset("Xray-linux-64.zip", body, repo="someone/else")
    with pytest.raises(install.InstallError, match="not an official"):
        run_install(tmp_path, "xray", FakeFetcher([a2], b2))


def test_oversized_assets_are_refused_before_downloading(tmp_path):
    body = make_zip({"xray": SCRIPT})
    f = fetcher_for("Xray-linux-64.zip", body, size=install.MAX_ASSET_BYTES + 1)
    with pytest.raises(install.InstallError, match="too large"):
        run_install(tmp_path, "xray", f)
    assert not [u for u in f.urls if u[0] == "download"]


def test_a_zip_bomb_member_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(install, "MAX_BINARY_BYTES", 1000)
    body = make_zip({"xray": b"\0" * 1001})
    with pytest.raises(install.InstallError, match="too large"):
        run_install(tmp_path, "xray", fetcher_for("Xray-linux-64.zip", body))
    assert not (tmp_path / "cores" / "xray" / "v1.2.3").exists()


def test_progress_is_reported_and_stop_cancels_cleanly(tmp_path):
    body = make_zip({"xray": SCRIPT + b"#" * 5000})
    seen = []
    run_install(tmp_path, "xray", fetcher_for("Xray-linux-64.zip", body), progress=lambda d, t: seen.append((d, t)))
    assert seen and seen[-1][0] == seen[-1][1] == len(body) and [d for d, _ in seen] == sorted(d for d, _ in seen)
    stop = threading.Event()
    stop.set()
    other = tmp_path / "o"
    other.mkdir()
    with pytest.raises(install.Cancelled):
        install.install("xray", fetcher=fetcher_for("Xray-linux-64.zip", body), dest_root=str(other / "cores"),
                        plat=("linux", "amd64"), stop=stop)
    assert not list((other / "cores").rglob("*")) or all(p.is_dir() for p in (other / "cores").rglob("*"))


def test_reinstalling_the_same_version_replaces_it(tmp_path):
    body = make_zip({"xray": SCRIPT})
    run_install(tmp_path, "xray", fetcher_for("Xray-linux-64.zip", body))
    body2 = make_zip({"xray": SCRIPT + b"# v2\n"})
    r = run_install(tmp_path, "xray", fetcher_for("Xray-linux-64.zip", body2))
    assert open(r["path"], "rb").read().endswith(b"# v2\n")


def test_release_info_is_available_without_downloading(tmp_path):
    body = make_zip({"xray": SCRIPT})
    f = fetcher_for("Xray-linux-64.zip", body)
    info = install.release_info("xray", fetcher=f, plat=("linux", "amd64"))
    assert info == {"core": "xray", "repo": "XTLS/Xray-core", "tag": "v1.2.3", "asset": "Xray-linux-64.zip",
                    "size": len(body), "sha256": sha(body), "url": f.assets[0]["browser_download_url"]}
    assert not [u for u in f.urls if u[0] == "download"]


def test_tags_that_could_escape_the_install_directory_are_refused(tmp_path):
    body = make_zip({"xray": SCRIPT})
    f = fetcher_for("Xray-linux-64.zip", body)
    for tag in ("../../x", "a/b", "", "v1\\2", ".."):
        f.tag = tag
        with pytest.raises(install.InstallError, match="release tag"):
            run_install(tmp_path, "xray", f)


def test_the_member_nearest_the_archive_root_wins_whatever_the_order(tmp_path):
    body = make_zip({"sub/dir/xray": b"nested", "deep/er/geoip.dat": b"deep", "xray": SCRIPT, "geoip.dat": b"GEO"})
    r = run_install(tmp_path, "xray", fetcher_for("Xray-linux-64.zip", body))
    assert open(r["path"], "rb").read() == SCRIPT and open(os.path.join(os.path.dirname(r["path"]), "geoip.dat"), "rb").read() == b"GEO"


def test_windows_style_member_names_are_understood(tmp_path):
    body = make_zip({"bin\\xray": SCRIPT})
    r = run_install(tmp_path, "xray", fetcher_for("Xray-linux-64.zip", body))
    assert open(r["path"], "rb").read() == SCRIPT


@pytest.mark.parametrize("size", [True, False, None, "5", -1, 1.5])
def test_a_missing_or_odd_size_is_refused(tmp_path, size):
    body = make_zip({"xray": SCRIPT})
    f = fetcher_for("Xray-linux-64.zip", body)
    f.assets[0]["size"] = size
    with pytest.raises(install.InstallError, match="valid size"):
        run_install(tmp_path, "xray", f)


@pytest.mark.parametrize("tag", [None, 5, ["v1"], "v1 2", "-v1", ".hidden", "v" * 80])
def test_odd_tags_are_refused(tmp_path, tag):
    body = make_zip({"xray": SCRIPT})
    f = fetcher_for("Xray-linux-64.zip", body)
    f.tag = tag
    with pytest.raises(install.InstallError, match="release tag"):
        run_install(tmp_path, "xray", f)


def test_a_gz_bomb_is_refused_while_reading(tmp_path, monkeypatch):
    monkeypatch.setattr(install, "MAX_BINARY_BYTES", 1000)
    body = gzip.compress(b"\0" * 1001)
    with pytest.raises(install.InstallError, match="too large"):
        run_install(tmp_path, "mihomo", fetcher_for("mihomo-linux-amd64-v1.19.2.gz", body, "MetaCubeX/mihomo"))


# ---------------------------------------------------- the real downloader's streaming loop
class FakeResponse:
    def __init__(self, data, length=True):
        self.buf, self.headers = io.BytesIO(data), ({"Content-Length": str(len(data))} if length else {})

    def read(self, n):
        return self.buf.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def downloader(monkeypatch, data, **kw):
    g = install.GitHubFetcher()
    monkeypatch.setattr(g, "_open", lambda url, accept: FakeResponse(data, **kw))
    return g


def test_real_downloader_streams_reports_progress_and_enforces_the_limit(monkeypatch):
    data = os.urandom(200_000)
    out, seen = io.BytesIO(), []
    n = downloader(monkeypatch, data).download("https://github.com/x", out, progress=lambda d, t: seen.append((d, t)))
    assert n == len(data) and out.getvalue() == data and seen[-1] == (len(data), len(data))
    with pytest.raises(install.InstallError, match="too large"):
        downloader(monkeypatch, data).download("https://github.com/x", io.BytesIO(), limit=1000)
    seen2 = []
    downloader(monkeypatch, data, length=False).download("https://github.com/x", io.BytesIO(), progress=lambda d, t: seen2.append((d, t)))
    assert seen2[-1][0] == seen2[-1][1] == len(data)                       # no Content-Length: total follows the bytes


def test_real_downloader_stops_when_asked(monkeypatch):
    stop = threading.Event()
    stop.set()
    out = io.BytesIO()
    with pytest.raises(install.Cancelled):
        downloader(monkeypatch, b"x" * 100_000).download("https://github.com/x", out, stop=stop)
    assert out.getvalue() == b""


def test_real_fetcher_refuses_foreign_addresses_before_any_request():
    g = install.GitHubFetcher()
    for url in ("http://github.com/x", "https://evil.example/x"):
        with pytest.raises(install.InstallError, match="non-GitHub"):
            g.download(url, io.BytesIO())


def test_real_fetcher_parses_release_json(monkeypatch):
    g = install.GitHubFetcher()
    monkeypatch.setattr(g, "_open", lambda url, accept: FakeResponse(b'{"tag_name": "v1", "assets": []}'))
    assert g.release("XTLS/Xray-core")["tag_name"] == "v1"
    for bad in (b"not json", b"[1]", b"\xff\xfe"):
        monkeypatch.setattr(g, "_open", lambda url, accept, b=bad: FakeResponse(b))
        with pytest.raises(install.InstallError, match="unreadable"):
            g.release("XTLS/Xray-core")


# ---------------------- real-release findings (Windows run): mihomo's member name, leaks, stale staging
def test_mihomo_windows_zip_member_is_version_and_platform_suffixed(tmp_path):
    """Real asset: mihomo-windows-amd64-v1.19.33.zip contains mihomo-windows-amd64.exe."""
    body = make_zip({"mihomo-windows-amd64.exe": b"MZ-real"})
    r = run_install(tmp_path, "mihomo", fetcher_for("mihomo-windows-amd64-v1.19.2.zip", body, "MetaCubeX/mihomo"), plat=("windows", "amd64"))
    assert os.path.basename(r["path"]) == "mihomo.exe" and open(r["path"], "rb").read() == b"MZ-real"


@pytest.mark.parametrize("member", ["mihomo-windows-amd64-v1.19.2.exe", "mihomo.exe", "mihomo"])
def test_mihomo_member_name_variants(tmp_path, member):
    body = make_zip({member: b"BIN", "README.md": b"r"})
    r = run_install(tmp_path, "mihomo", fetcher_for("mihomo-windows-amd64-v1.19.2.zip", body, "MetaCubeX/mihomo"), plat=("windows", "amd64"))
    assert open(r["path"], "rb").read() == b"BIN"


def test_loose_member_names_do_not_match_other_programs(tmp_path):
    body = make_zip({"mihomo-config.yaml": b"x", "notmihomo.exe": b"x", "mihomo.exe.sig": b"x", "docs/mihomo-notes.txt": b"x"})
    with pytest.raises(install.InstallError, match="does not contain"):
        run_install(tmp_path, "mihomo", fetcher_for("mihomo-windows-amd64-v1.19.2.zip", body, "MetaCubeX/mihomo"), plat=("windows", "amd64"))


@pytest.mark.parametrize("make,asset_name", [(lambda: make_zip({"README.md": b"x"}), "Xray-linux-64.zip"),
                                              (lambda: make_targz({"README.md": b"x"}), "sing-box-1.12.1-linux-amd64.tar.gz")])
def test_archives_are_closed_before_cleanup(tmp_path, monkeypatch, make, asset_name):
    """An open handle blocks deleting the staging folder on Windows (it leaked a 22 MB download)."""
    opened = []
    real_zip, real_tar = zipfile.ZipFile, tarfile.open

    class Z(real_zip):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            opened.append(self)
    monkeypatch.setattr(zipfile, "ZipFile", Z)

    def T(*a, **k):
        t = real_tar(*a, **k)
        opened.append(t)
        return t
    monkeypatch.setattr(tarfile, "open", T)
    core, repo = ("xray", "XTLS/Xray-core") if asset_name.startswith("Xray") else ("singbox", "SagerNet/sing-box")
    with pytest.raises(install.InstallError):
        run_install(tmp_path, core, fetcher_for(asset_name, make(), repo))
    assert opened and all((o.fp is None) if isinstance(o, zipfile.ZipFile) else o.closed for o in opened)


def test_stale_staging_folders_from_earlier_failures_are_swept(tmp_path):
    core_dir = tmp_path / "cores" / "xray"
    old = core_dir / ".dl-old"
    fresh = core_dir / ".dl-fresh"
    for d in (old, fresh):
        d.mkdir(parents=True)
        (d / "asset").write_bytes(b"x" * 10)
    past = time.time() - 7200
    os.utime(old, (past, past))
    other = core_dir / "keep-me"                    # an old install of another version must never be swept
    other.mkdir()
    os.utime(other, (past, past))
    run_install(tmp_path, "xray", fetcher_for("Xray-linux-64.zip", make_zip({"xray": SCRIPT})))
    assert not old.exists()                        # an hour old: a dead earlier attempt
    assert fresh.exists() and other.exists()       # recent (maybe a concurrent install) and unrelated folders stay
