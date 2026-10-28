"""
Subscription source manager.

Keeps a user-defined list of subscription URLs with:

* ETag-based conditional requests (If-None-Match) so re-fetching is cheap
* a local cache in ``~/.xray_forge/cache/`` (used on 304 and on failures)
* format auto-detection (base64 / plain / Clash YAML / sing-box JSON)
* cross-source de-duplication

State lives in ``~/.xray_forge/sources.json``.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, field, asdict

from xray_forge.core.settings import data_dir
from urllib.parse import unquote, urldefrag, urlsplit

from xray_forge.core.subscription import text_to_lines, MAX_SUB_BYTES
from xray_forge.core.dedup import dedup_configs

from xray_forge.core.log import get_logger

log = get_logger(__name__)

USER_AGENT = "xray-forge/2.1-subscriber"

# One-click sources offered in the UI.  Adding one only creates a source: nothing is
# downloaded until the user fetches, and no content is ever bundled with the app.
PRESETS: tuple[dict, ...] = (
    {"id": "patterniha-f", "name": "Patterniha-F",
     "url": "https://raw.githubusercontent.com/patterniha/Free-Configs/main/configs.txt",
     "note": "Free daily configs published by patterniha on GitHub. Downloaded from GitHub only when you press "
             "Fetch; the configs are public, so check them before trusting them."},
)


@dataclass
class Source:
    url: str
    name: str = ""
    enabled: bool = True
    etag: str = ""
    last_fetch: str = ""        # iso timestamp
    last_status: str = ""       # ok / 304 / error text
    last_count: int = 0

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Source":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        url = d.get("url", "")
        return cls(**{k: v for k, v in d.items() if k in known}) if url else None


class SourceManager:
    def __init__(self, state_path: str | None = None, cache_dir: str | None = None):
        self.state_path = state_path or os.path.join(data_dir(), "sources.json")
        self.cache_dir = cache_dir or os.path.join(data_dir(), "cache")
        os.makedirs(self.cache_dir, exist_ok=True)
        self.sources: list[Source] = []
        self._lock = threading.Lock()
        self._load()

    # ------------------------------------------------------------ state io
    def _load(self) -> None:
        if not os.path.isfile(self.state_path):
            return
        try:
            with open(self.state_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for item in data.get("sources", []):
                s = Source.from_dict(item)
                if s:
                    self.sources.append(s)
        except (OSError, json.JSONDecodeError) as e:
            log.warning("cannot load sources from %s: %s", self.state_path, e)

    def _save(self) -> None:
        try:
            with open(self.state_path, "w", encoding="utf-8") as f:
                json.dump({"sources": [s.to_dict() for s in self.sources]},
                          f, indent=2, ensure_ascii=False)
        except OSError as e:
            log.warning("cannot save sources to %s: %s", self.state_path, e)

    # -------------------------------------------------------------- source
    def add(self, url: str, name: str = "") -> Source:
        """Add a source.  A ``#fragment`` is never sent to a server, so it is used as the
        display name (when none is given) and dropped from the stored URL."""
        url, frag = urldefrag(url.strip())
        name = name or unquote(frag).strip() or url
        with self._lock:
            for s in self.sources:
                if s.url == url:
                    return s
            src = Source(url=url, name=name)
            self.sources.append(src)
            self._save()
            return src

    def remove(self, url: str) -> bool:
        with self._lock:
            before = len(self.sources)
            self.sources = [s for s in self.sources if s.url != url]
            changed = len(self.sources) != before
            if changed:
                self._save()
            return changed

    def set_enabled(self, url: str, enabled: bool) -> None:
        with self._lock:
            for s in self.sources:
                if s.url == url:
                    s.enabled = enabled
            self._save()

    def list_sources(self) -> list[Source]:
        return list(self.sources)

    # --------------------------------------------------------------- cache
    def _cache_path(self, url: str) -> str:
        digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:24]
        return os.path.join(self.cache_dir, digest + ".txt")

    def _read_cache(self, url: str) -> str:
        path = self._cache_path(url)
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    return f.read()
            except OSError:
                return ""
        return ""

    def _write_cache(self, url: str, text: str) -> None:
        try:
            with open(self._cache_path(url), "w", encoding="utf-8") as f:
                f.write(text)
        except OSError as e:
            log.warning("cannot cache subscription %s: %s", url, e)

    # -------------------------------------------------------------- fetch
    def _http_get(self, url: str, etag: str = "",
                  timeout: float = 15.0) -> tuple[int, str, str]:
        """Return (status, text, new_etag). status 304 means 'use cache'."""
        if urlsplit(url).scheme.lower() not in ("http", "https"):
            raise ValueError("only http/https source URLs are supported")
        headers = {"User-Agent": USER_AGENT}
        if etag:
            headers["If-None-Match"] = etag
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = r.read(MAX_SUB_BYTES + 1)
                if len(data) > MAX_SUB_BYTES:
                    raise ValueError("response too large for a subscription")
                text = data.decode("utf-8", "replace")
                return r.status, text, (r.headers.get("ETag") or "")
        except urllib.error.HTTPError as e:
            if e.code == 304:
                return 304, "", etag
            raise

    @staticmethod
    def _require_configs(text: str) -> None:
        """A 200 that holds no configs (captive portal, error page, block page)
        must not overwrite a good cache -- it counts as a failed fetch."""
        if not text_to_lines(text):
            raise ValueError("response contained no configs (kept cache)")

    def fetch(self, src: Source, force: bool = False,
              timeout: float = 15.0) -> list[str]:
        """Fetch one source. Falls back to cache on network failure."""
        import datetime
        cached = self._read_cache(src.url)
        status_note = "ok"
        text = ""
        if not force and src.etag and cached:
            try:
                status, text, new_etag = self._http_get(src.url, src.etag, timeout)
                if status == 304:
                    status_note = "304 not modified"
                    text = cached
                else:
                    self._require_configs(text)
                    src.etag = new_etag
                    self._write_cache(src.url, text)
            except Exception as e:
                status_note = f"error: {e}"
                text = cached
        else:
            try:
                status, text, new_etag = self._http_get(src.url, "", timeout)
                self._require_configs(text)
                src.etag = new_etag
                self._write_cache(src.url, text)
            except Exception as e:
                status_note = f"error: {e}"
                text = cached
        lines = text_to_lines(text) if text else []
        src.last_fetch = datetime.datetime.now().isoformat(timespec="seconds")
        src.last_status = status_note
        src.last_count = len(lines)
        with self._lock:
            self._save()
        return lines

    def fetch_all(self, force: bool = False,
                  timeout: float = 15.0) -> dict[str, list[str]]:
        """Fetch every enabled source. Returns {url: lines}."""
        out: dict[str, list[str]] = {}
        for src in self.list_sources():
            if not src.enabled:
                continue
            out[src.url] = self.fetch(src, force=force, timeout=timeout)
        return out

    # -------------------------------------------------------------- output
    def combined_lines(self, dedupe: bool = True) -> tuple[list[str], int]:
        """All fetched/cached lines concatenated (optionally deduplicated)."""
        lines: list[str] = []
        for src in self.list_sources():
            if not src.enabled:
                continue
            cached = self._read_cache(src.url)
            if cached:
                lines.extend(text_to_lines(cached))
        if dedupe:
            lines, removed = dedup_configs(lines)
            return lines, removed
        return lines, 0
