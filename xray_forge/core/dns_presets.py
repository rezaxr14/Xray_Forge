"""Catalog of well-known public DNS services.

A DNS change helps with DNS-level blocking (many ad domains, malware hosts, and censorship that
only poisons DNS answers).  It does not defeat IP or SNI blocking; that is what the proxy cores
are for.  Addresses are published by each provider; entries with ``unverified`` were not
re-checked against the provider's site when they were added, so confirm them there first.
"""

from __future__ import annotations

import ipaddress

CATEGORIES: tuple[dict, ...] = (
    {"id": "ads", "name": "Ads and trackers", "note": "Blocks known advertising and tracking domains."},
    {"id": "privacy", "name": "Privacy", "note": "No filtering; the provider's logging policy is the point."},
    {"id": "malware", "name": "Malware and phishing", "note": "Blocks known malicious domains."},
    {"id": "family", "name": "Family", "note": "Also blocks adult content."},
    {"id": "sanctions", "name": "Anti-sanction (Iran)",
     "note": "Resolvers that route around sanction blocks. Traffic is resolved by a third party; use only ones you trust."},
)


def _p(pid, name, category, v4, v6=(), *, doh="", dot="", note="", unverified=False):
    return {"id": pid, "name": name, "category": category, "v4": list(v4), "v6": list(v6),
            "doh": doh, "dot": dot, "note": note, "unverified": unverified}


PRESETS: tuple[dict, ...] = (
    _p("adguard", "AdGuard DNS", "ads", ["94.140.14.14", "94.140.15.15"],
       ["2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"],
       doh="https://dns.adguard-dns.com/dns-query", dot="dns.adguard-dns.com",
       note="Blocks ads, trackers and phishing."),
    _p("controld-ads", "Control D, ads and trackers", "ads", ["76.76.2.2", "76.76.10.2"],
       doh="https://freedns.controld.com/p2", note="Free Control D profile that blocks ads and trackers."),
    _p("mullvad-adblock", "Mullvad, ad blocking", "ads", ["194.242.2.3"],
       doh="https://adblock.dns.mullvad.net/dns-query", dot="adblock.dns.mullvad.net",
       note="Single address. Blocks ads and trackers."),
    _p("cloudflare", "Cloudflare", "privacy", ["1.1.1.1", "1.0.0.1"],
       ["2606:4700:4700::1111", "2606:4700:4700::1001"],
       doh="https://cloudflare-dns.com/dns-query", dot="one.one.one.one", note="Fast, no filtering."),
    _p("google", "Google", "privacy", ["8.8.8.8", "8.8.4.4"],
       ["2001:4860:4860::8888", "2001:4860:4860::8844"],
       doh="https://dns.google/dns-query", dot="dns.google", note="Fast, no filtering."),
    _p("quad9-open", "Quad9, unfiltered", "privacy", ["9.9.9.10", "149.112.112.10"],
       ["2620:fe::10", "2620:fe::fe:10"], doh="https://dns10.quad9.net/dns-query", dot="dns10.quad9.net",
       note="Quad9 without malware blocking."),
    _p("adguard-open", "AdGuard DNS, non-filtering", "privacy", ["94.140.14.140", "94.140.14.141"],
       ["2a10:50c0::1:ff", "2a10:50c0::2:ff"],
       doh="https://unfiltered.adguard-dns.com/dns-query", dot="unfiltered.adguard-dns.com"),
    _p("mullvad", "Mullvad", "privacy", ["194.242.2.2"], doh="https://dns.mullvad.net/dns-query",
       dot="dns.mullvad.net", note="Single address. No filtering, no logging."),
    _p("dnssb", "DNS.SB", "privacy", ["185.222.222.222", "45.11.45.11"],
       doh="https://doh.dns.sb/dns-query", dot="dot.sb"),
    _p("controld-open", "Control D, unfiltered", "privacy", ["76.76.2.0", "76.76.10.0"],
       doh="https://freedns.controld.com/p0"),
    _p("quad9", "Quad9", "malware", ["9.9.9.9", "149.112.112.112"], ["2620:fe::fe", "2620:fe::9"],
       doh="https://dns.quad9.net/dns-query", dot="dns.quad9.net", note="Blocks known malicious domains."),
    _p("cloudflare-malware", "Cloudflare, malware blocking", "malware", ["1.1.1.2", "1.0.0.2"],
       ["2606:4700:4700::1112", "2606:4700:4700::1002"],
       doh="https://security.cloudflare-dns.com/dns-query", dot="security.cloudflare-dns.com"),
    _p("cleanbrowsing-security", "CleanBrowsing, security", "malware", ["185.228.168.9", "185.228.169.9"]),
    _p("controld-malware", "Control D, malware", "malware", ["76.76.2.1", "76.76.10.1"],
       doh="https://freedns.controld.com/p1"),
    _p("opendns", "OpenDNS", "malware", ["208.67.222.222", "208.67.220.220"],
       doh="https://doh.opendns.com/dns-query", note="Cisco OpenDNS, phishing protection."),
    _p("cloudflare-family", "Cloudflare, family", "family", ["1.1.1.3", "1.0.0.3"],
       ["2606:4700:4700::1113", "2606:4700:4700::1003"],
       doh="https://family.cloudflare-dns.com/dns-query", dot="family.cloudflare-dns.com"),
    _p("adguard-family", "AdGuard DNS, family", "family", ["94.140.14.15", "94.140.15.16"],
       ["2a10:50c0::bad1:ff", "2a10:50c0::bad2:ff"],
       doh="https://family.adguard-dns.com/dns-query", dot="family.adguard-dns.com"),
    _p("cleanbrowsing-family", "CleanBrowsing, family", "family", ["185.228.168.168", "185.228.169.168"]),
    _p("opendns-family", "OpenDNS FamilyShield", "family", ["208.67.222.123", "208.67.220.123"]),
    _p("shecan", "Shecan", "sanctions", ["178.22.122.100", "185.51.200.2"], note="Free tier addresses from shecan.ir."),
    _p("electro", "Electro", "sanctions", ["78.157.42.100", "78.157.42.101"]),
    _p("begzar", "Begzar", "sanctions", ["185.55.226.26", "185.55.225.25"]),
    _p("radar", "Radar Game", "sanctions", ["10.202.10.10", "10.202.10.11"],
       note="Private addresses; they answer only on Iranian networks."),
    _p("403", "403.online", "sanctions", ["10.202.10.202", "10.202.10.102"],
       note="Private addresses; they answer only on Iranian networks.", unverified=True),
)

_IDS = {p["id"] for p in PRESETS}
assert len(_IDS) == len(PRESETS)


def valid_ip(text: str) -> str:
    """The normalised address, or ValueError."""
    try:
        return str(ipaddress.ip_address(text.strip()))
    except (ValueError, AttributeError):
        raise ValueError(f"not an IP address: {str(text)[:60]!r}") from None


def servers_of(preset: dict, ipv6: bool = False) -> list[str]:
    return list(preset["v4"]) + (list(preset["v6"]) if ipv6 else [])


def find(pid: str) -> dict | None:
    for p in PRESETS:
        if p["id"] == pid:
            return p
    return None
