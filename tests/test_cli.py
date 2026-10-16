"""CLI end-to-end tests (offline, tmp files)."""

from __future__ import annotations

import json

import pytest

from xray_forge.cli import main, build_parser
from tests.fixtures import VLESS_TLS_WS, SS_SIP002


def test_version(capsys):
    assert main(["version"]) == 0
    assert "2.1.0" in capsys.readouterr().out


def test_parser_subcommands():
    parser = build_parser()
    minimal = {"convert": ["convert", "a", "b"],
               "export": ["export", "a", "b", "--format", "clash"],
               "test": ["test", "a"],
               "scan": ["scan", "1.2.3.0/24"],
               "geo": ["geo"],
               "mitm": ["mitm"],
               "warp": ["warp", "config"],
               "subs": ["subs", "list"]}
    for cmd in ("gui", "version", "convert", "export", "test", "scan", "geo",
                "mitm", "warp", "subs"):
        argv = minimal.get(cmd, [cmd])
        args = parser.parse_args(argv)
        assert args.cmd == cmd


def test_convert_end_to_end(tmp_path, capsys):
    infile = tmp_path / "in.txt"
    outfile = tmp_path / "out.txt"
    infile.write_text(VLESS_TLS_WS + "\n", encoding="utf-8")
    rc = main(["convert", str(infile), str(outfile), "--template", "{id}_{sub}"])
    assert rc == 0
    out = outfile.read_text(encoding="utf-8").strip()
    assert out.startswith("vless://")
    assert "converted 1 fixed" in capsys.readouterr().out


def test_export_end_to_end(tmp_path):
    infile = tmp_path / "in.txt"
    infile.write_text(VLESS_TLS_WS + "\n" + SS_SIP002 + "\n", encoding="utf-8")
    clash = tmp_path / "clash.yaml"
    sb = tmp_path / "sb.json"
    sub = tmp_path / "sub.txt"
    assert main(["export", str(infile), str(clash), "--format", "clash"]) == 0
    assert main(["export", str(infile), str(sb), "--format", "singbox"]) == 0
    assert main(["export", str(infile), str(sub), "--format", "sub"]) == 0
    import yaml, base64
    proxies = yaml.safe_load(clash.read_text(encoding="utf-8"))["proxies"]
    assert [p["type"] for p in proxies] == ["vless", "ss"]
    obs = json.loads(sb.read_text(encoding="utf-8"))["outbounds"]
    assert [o["type"] for o in obs] == ["vless", "ss"]
    raw = base64.b64decode(sub.read_text(encoding="utf-8")).decode()
    assert raw.count("://") == 2


def test_export_unknown_format_fails(tmp_path):
    infile = tmp_path / "in.txt"
    infile.write_text(VLESS_TLS_WS, encoding="utf-8")
    with pytest.raises(SystemExit):
        main(["export", str(infile), str(tmp_path / "o"), "--format", "bogus"])


def test_mitm_generation(tmp_path, capsys):
    out = tmp_path / "mdf.json"
    assert main(["mitm", "-o", str(out), "--groups", "google,meta"]) == 0
    cfg = json.loads(out.read_text(encoding="utf-8"))
    tags = [o["tag"] for o in cfg["outbounds"]]
    assert "tls-repack-google" in tags and "tls-repack-meta" in tags
    assert "tls-repack-fastly" not in tags
    assert "config written" in capsys.readouterr().out


def test_mitm_guide_print(tmp_path, capsys):
    main(["mitm", "-o", str(tmp_path / "m.json"), "--guide"])
    captured = capsys.readouterr().out
    assert "Trusted Root" in captured
    assert "never share" in captured


def test_subs_add_list_remove(tmp_path, capsys):
    assert main(["subs", "add", "--url", "https://example.com/sub",
                 "--name", "demo"]) == 0
    main(["subs", "list"])
    outtxt = capsys.readouterr().out
    assert "example.com/sub" in outtxt and "demo" in outtxt
    assert main(["subs", "remove", "--url", "https://example.com/sub"]) == 0
    main(["subs", "list"])
    assert "example.com/sub" not in capsys.readouterr().out


def test_subs_list_empty(tmp_path, capsys):
    main(["subs", "list"])
    assert capsys.readouterr().out.strip() == ""


def test_warp_config_without_account_exits(tmp_path):
    with pytest.raises(SystemExit):
        main(["warp", "config"])
