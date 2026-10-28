"""Built-in subscription presets (Patterniha-F free daily configs) and '#name' URL fragments.

Presets are one-click *sources*: adding one never touches the network; the list is only
downloaded when the user fetches.  Offline: HTTP is monkeypatched."""

from __future__ import annotations

import pytest

from tests.test_engine import Client
from xray_forge.core import sub_source
from xray_forge.core.sub_source import SourceManager

RAW = "https://raw.githubusercontent.com/patterniha/Free-Configs/main/configs.txt"
LINK = "vless://13b8ac3f-e8de-4b2d-82db-e9130d288a54@188.114.97.6:443?security=tls&sni=x.example.com&type=ws&host=x.example.com&path=%2F#one"


@pytest.fixture
def mgr(tmp_path):
    return SourceManager(state_path=str(tmp_path / "sources.json"), cache_dir=str(tmp_path / "cache"))


@pytest.fixture
def no_network(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("adding a source must not touch the network")
    monkeypatch.setattr(SourceManager, "_http_get", boom)


# ------------------------------------------------------------------ presets
def test_the_patterniha_preset_points_at_the_raw_file_and_is_https_only():
    p = {x["id"]: x for x in sub_source.PRESETS}["patterniha-f"]
    assert p["url"] == RAW and p["name"] == "Patterniha-F"
    assert all(x["url"].startswith("https://") and "#" not in x["url"] for x in sub_source.PRESETS)
    assert len({x["id"] for x in sub_source.PRESETS}) == len(sub_source.PRESETS)


def test_presets_are_listed_with_whether_they_are_already_added(mgr, no_network):
    c = Client(sources=mgr)
    rows = c.result("sub.presets")
    row = next(r for r in rows if r["id"] == "patterniha-f")
    assert row["url"] == RAW and row["name"] == "Patterniha-F" and row["added"] is False
    assert row["note"]                                           # tells the user what it is and that it is fetched on demand
    c.result("sub.add_preset", id="patterniha-f")
    assert next(r for r in c.result("sub.presets") if r["id"] == "patterniha-f")["added"] is True


def test_adding_a_preset_creates_one_named_source_and_never_fetches(mgr, no_network):
    c = Client(sources=mgr)
    src = c.result("sub.add_preset", id="patterniha-f")
    assert src["url"] == RAW and src["name"] == "Patterniha-F" and src["enabled"] is True
    assert src["last_fetch"] == "" and src["last_count"] == 0
    again = c.result("sub.add_preset", id="patterniha-f")        # idempotent
    assert again["url"] == RAW
    assert [s["url"] for s in c.result("sub.list")] == [RAW]


def test_unknown_preset_is_an_invalid_params_error(mgr):
    resp = Client(sources=mgr).call("sub.add_preset", id="nope")
    assert resp["error"]["code"] == -32602 and "nope" in resp["error"]["message"]


def test_removing_a_preset_source_makes_it_addable_again(mgr):
    c = Client(sources=mgr)
    c.result("sub.add_preset", id="patterniha-f")
    assert c.result("sub.remove", url=RAW) is True
    assert next(r for r in c.result("sub.presets") if r["id"] == "patterniha-f")["added"] is False
    c.result("sub.add_preset", id="patterniha-f")
    assert len(c.result("sub.list")) == 1


def test_a_preset_source_fetches_through_the_normal_pipeline(mgr, monkeypatch):
    seen = []

    def fake_get(self, url, etag="", timeout=15.0):
        seen.append(url)
        return 200, LINK + "\n", "etag-1"
    monkeypatch.setattr(SourceManager, "_http_get", fake_get)
    c = Client(sources=mgr)
    c.result("sub.add_preset", id="patterniha-f")
    done = c.wait_job(c.result("sub.fetch")["job"])
    assert done["type"] == "done" and done["result"]["total"] == 1
    assert seen == [RAW]
    row = c.result("sub.list")[0]
    assert row["last_count"] == 1 and row["last_status"] == "ok"


# ------------------------------------------------------------ '#name' fragments
def test_a_url_fragment_names_the_source_and_is_not_stored_in_the_url(mgr):
    s = mgr.add(RAW + "#Patterniha-F")
    assert s.url == RAW and s.name == "Patterniha-F"


def test_fragment_is_percent_decoded_and_an_explicit_name_wins(mgr):
    assert mgr.add("https://a.example/x.txt#My%20List").name == "My List"
    assert mgr.add("https://b.example/x.txt#ignored", name="Mine").name == "Mine"
    assert mgr.add("https://c.example/x.txt#").name == "https://c.example/x.txt"      # empty fragment: no name from it
    assert mgr.add("https://d.example/x.txt").name == "https://d.example/x.txt"


def test_same_url_with_different_fragments_is_one_source(mgr):
    a = mgr.add("https://a.example/x.txt?k=1#one")
    b = mgr.add("https://a.example/x.txt?k=1#two")
    assert a is b and len(mgr.list_sources()) == 1 and a.url == "https://a.example/x.txt?k=1"


def test_engine_sub_add_accepts_the_fragment_form(mgr):
    c = Client(sources=mgr)
    r = c.result("sub.add", url=RAW + "#Patterniha-F")
    assert r["url"] == RAW and r["name"] == "Patterniha-F"
    assert next(x for x in c.result("sub.presets") if x["id"] == "patterniha-f")["added"] is True


def test_engine_still_rejects_non_http_urls_even_with_a_fragment(mgr):
    resp = Client(sources=mgr).call("sub.add", url="file:///etc/passwd#x")
    assert resp["error"]["code"] == -32602
    resp = Client(sources=mgr).call("sub.add", url="javascript:alert(1)#https://x")
    assert resp["error"]["code"] == -32602
