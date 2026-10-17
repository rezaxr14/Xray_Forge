"""
MITM-DomainFronting config generator (Xray-core >= 26.2.6).

Technique (documented in XTLS/Xray-core#4348 and patterniha/MITM-DomainFronting;
re-implemented here from public documentation, no upstream code is copied):

1. Xray-core runs two local ``tunnel`` inbounds that terminate the machine's
   TLS traffic (port-443 redirect) using a *personal* CA via the
   ``"usage": "issue"`` certificate setting ("Instant Certificate").
2. The decrypted SNI/host is re-packed by ``tls-repack-*`` outbounds that send
   the request to the real service with a *fake benign SNI*
   (``verifyPeerCertByName: "fromMitM"`` + a cover name such as
   ``www.google.com``) — i.e. domain fronting against the CDN front.
3. Routing decides which service families (google / meta / fastly / dns) are
   repacked and which go direct (Iranian/private ranges).

The user MUST generate their own CA (never share crt/key between people) and
trust it in the OS/browser.  This module can generate that CA with the
optional ``cryptography`` package, or print the equivalent openssl command.
"""

from __future__ import annotations

import json
import os
from typing import Any

from xray_forge.core.config import (
    MITM_DF_XRAY_MIN_VERSION, MITM_DEFAULT_CERT, MITM_DEFAULT_KEY,
    MITM_SOCKS_PORT, MITM_H11_PORT, MITM_H2_PORT, MITM_FAKE_DNS_SNI,
)

# Service families that tolerate domain fronting (documented upstream).
ROUTE_GROUPS: dict[str, dict[str, Any]] = {
    "google": {
        "cover_sni": "www.google.com",
        "verify": "fromMitM,www.google.com,dns.google,www.googlevideo.com,www.youtube.com",
        "domains": ["geosite:google"],
        "h11_domains": ["domain:googlevideo.com"],
        "redirect": None,
    },
    "meta": {
        "cover_sni": "www.microsoft.com",
        "verify": ("fromMitM,www.google.com,www.microsoft.com,www.whatsapp.com,"
                   "www.facebook.com,www.ar.meta.com,www.fb.com,www.whatsapp.net,"
                   "www.atlassolutions.com,www.secure.facebook.com,"
                   "www.extern.facebook.com,www.internet.org,www.oculus.com,"
                   "www.wit.ai,www.facebook-dns.com,www.instagram.com,"
                   "www.meta.com,www.external-disputes.meta.com,www.fbe2e.com,"
                   "www.cloud.x2p.facebook.net,www.secure.latest.facebook.com"),
        "domains": ["geosite:meta"],
        "h11_domains": [],
        "redirect": None,
    },
    "fastly": {
        "cover_sni": "github.githubassets.com",
        "verify": ("fromMitM,www.python.org,pypi.org,fastly.com,www.fastly.com,"
                   "developer.fastly.com,reddit.com,githubassets.com,github.com,"
                   "github.io,githubusercontent.com,github.githubassets.com"),
        "domains": ["geosite:fastly", "geosite:reddit", "geosite:cnn",
                    "domain:buzzfeed.com"],
        "h11_domains": [],
        "redirect": "fastly.redirect:443",
    },
}


def default_options() -> dict[str, Any]:
    return {
        "cert_file": MITM_DEFAULT_CERT,
        "key_file": MITM_DEFAULT_KEY,
        "socks_port": MITM_SOCKS_PORT,
        "h11_port": MITM_H11_PORT,
        "h2_port": MITM_H2_PORT,
        "fingerprint": "chrome",
        "dns_front_sni": MITM_FAKE_DNS_SNI,
        "dns_redirect": ["1.1.1.1", "1.0.0.1"],
        "groups": ["google", "meta", "fastly"],   # which families to enable
        "direct_domains": ["domain:ir", "geosite:private", "geosite:category-ir",
                           "geosite:khanacademy"],
        "block_ads": True,
    }


# ===========================================================================
# Config generation
# ===========================================================================

def build_config(**overrides) -> dict[str, Any]:
    """Build the MITM-DomainFronting Xray-core config as a dict."""
    o = default_options()
    o.update({k: v for k, v in overrides.items() if k in o})

    inbounds: list[dict[str, Any]] = [
        {
            "tag": "mixed-in",
            "port": o["socks_port"],
            "protocol": "mixed",
            "sniffing": {"enabled": True, "destOverride": ["fakedns", "tls"],
                         "routeOnly": False},
            "settings": {"udp": True, "ip": "127.0.0.1"},
            "streamSettings": {"sockopt": {"tcpKeepAliveInterval": 1,
                                           "tcpKeepAliveIdle": 11}},
        },
    ]
    # TLS-decrypt tunnel inbounds (h1-only and h1/h2 alpn variants)
    for tag, alpn, port in (("tls-decrypt-h11", ["http/1.1"], o["h11_port"]),
                            ("tls-decrypt-h211", ["h2", "http/1.1"], o["h2_port"])):
        inbounds.append({
            "port": port,
            "tag": tag,
            "protocol": "tunnel",
            "settings": {"network": "tcp", "port": 443, "followRedirect": True},
            "streamSettings": {
                "security": "tls",
                "tlsSettings": {
                    "alpn": alpn,
                    "certificates": [{
                        "usage": "issue",
                        "certificateFile": o["cert_file"],
                        "keyFile": o["key_file"],
                    }],
                },
            },
        })

    happy = {"tryDelayMs": 300, "prioritizeIPv6": False,
             "interleave": 2, "maxConcurrentTry": 20}
    force_ip_sockopt = {"domainStrategy": "ForceIP", "happyEyeballs": happy}

    def repack_outbound(tag: str, sni: str, verify: str,
                        redirect: str | None = None) -> dict[str, Any]:
        ob: dict[str, Any] = {"tag": tag, "protocol": "direct",
                              "streamSettings": {
                                  "security": "tls",
                                  "tlsSettings": {
                                      "serverName": sni,
                                      "verifyPeerCertByName": verify,
                                      "alpn": ["fromMitM"],
                                      "fingerprint": o["fingerprint"],
                                  },
                                  "sockopt": dict(force_ip_sockopt)}}
        if redirect:
            ob["settings"] = {"redirect": redirect}
        return ob

    outbounds: list[dict[str, Any]] = [
        {"tag": "block", "protocol": "block"},
        {"tag": "direct", "protocol": "direct",
         "streamSettings": {"sockopt": dict(force_ip_sockopt)}},
        {"tag": "dns-out", "protocol": "dns", "settings": {"userLevel": 1}},
        {"tag": "redirect-out-h11", "protocol": "direct",
         "settings": {"redirect": f"127.0.0.1:{o['h11_port']}"}},
        {"tag": "redirect-out-h211", "protocol": "direct",
         "settings": {"redirect": f"127.0.0.1:{o['h2_port']}"}},
    ]

    dns_hosts: dict[str, Any] = {
        "dns.redirect": o["dns_redirect"],
    }
    rules: list[dict[str, Any]] = []
    h2_tags: list[str] = []

    for gname in o["groups"]:
        g = ROUTE_GROUPS.get(gname)
        if not g:
            continue
        tag = f"tls-repack-{gname}"
        outbounds.append(repack_outbound(tag, g["cover_sni"], g["verify"],
                                         g.get("redirect")))
        h2_tags.append(tag)
        if g.get("redirect"):
            dns_hosts[g["redirect"].split(":")[0] + ".redirect"] = \
                g["cover_sni"]
        # h2 inbound routing
        rule: dict[str, Any] = {"outboundTag": tag,
                                "domain": list(g["domains"]),
                                "inboundTag": ["tls-decrypt-h211"]}
        rules.append(rule)
        # h1 inbound routing (googlevideo-only for google, else nothing)
        for dom in g.get("h11_domains", []):
            rules.append({"outboundTag": tag, "domain": [dom],
                          "inboundTag": ["tls-decrypt-h11"]})
        rules.append({"outboundTag": "block", "inboundTag": ["tls-decrypt-h11"]})
    # dns repack (DoH through fronting)
    outbounds.append(repack_outbound(
        "tls-repack-dns", o["dns_front_sni"],
        f"fromMitM,{o['dns_front_sni']},www.google.com,dns.google,"
        f"cloudflare-dns.com,one.one.one.one",
        redirect=f"{'.'.join(o['dns_redirect'][:1])}:443"))
    rules.insert(0, {"outboundTag": "tls-repack-dns",
                     "inboundTag": ["no-filter-dns"]})

    if o["block_ads"]:
        rules.insert(0, {"outboundTag": "block",
                         "domain": ["geosite:category-ads-all"]})

    rules += [
        {"outboundTag": "dns-out", "port": 53},
        {"outboundTag": "direct", "domain": list(o["direct_domains"])},
        {"outboundTag": "redirect-out-h11", "network": "tcp", "port": 443,
         "domain": ["domain:googlevideo.com"]},
        {"outboundTag": "redirect-out-h211", "network": "tcp", "port": 443,
         "domain": [d for g in o["groups"] for d in
                    (ROUTE_GROUPS.get(g, {}).get("domains") or [])]},
        {"outboundTag": "block", "ip": ["10.10.34.0/24", "2001:4188:2:600::/64"]},
        {"outboundTag": "direct", "ip": ["geoip:private", "geoip:ir"]},
        {"outboundTag": "direct", "ip": ["0.0.0.0/0", "::/0"]},
        {"outboundTag": "block", "port": "0-65535"},
    ]

    return {
        "remarks": "Xray-Forge MITM-DomainFronting",
        "version": {"min": MITM_DF_XRAY_MIN_VERSION},
        "log": {"loglevel": "warning", "dnsLog": False, "access": "none"},
        "policy": {"levels": {
            "0": {"uplinkOnly": 0, "downlinkOnly": 0},
            "1": {"uplinkOnly": 0, "downlinkOnly": 0, "connIdle": 6}}},
        "dns": {
            "hosts": dns_hosts,
            "servers": [
                {"address": "fakedns",
                 "domains": ["domain:ir", "geosite:private",
                             "geosite:category-ir"]},
                {"tag": "no-filter-dns",
                 "address": "h2c://1.1.1.1/dns-query",
                 "timeoutMs": 6000, "finalQuery": True},
                {"address": "localhost",
                 "domains": ["domain:ir", "geosite:private",
                             "geosite:category-ir"], "finalQuery": True},
            ],
            "queryStrategy": "UseSystem", "useSystemHosts": True,
            "serveStale": True,
        },
        "fakedns": [{"ipRange": "198.18.0.0/15", "poolSize": 65535}],
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"domainStrategy": "IPOnDemand", "rules": rules},
    }


def write_config(path: str, **overrides) -> str:
    """Generate the config and write it as JSON. Returns the path."""
    cfg = build_config(**overrides)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    return path


# ===========================================================================
# Per-user certificate generation (never share crt/key between users!)
# ===========================================================================

def generate_ca(common_name: str, crt_path: str, key_path: str,
                days: int = 365,
                permitted_domains: list[str] | None = None) -> tuple[str, str]:
    """Generate a self-signed CA cert/key pair (needs the ``cryptography`` pkg).

    The cert is a CA with key usages Certificate Signing + CRL Signing, as
    required by the Instant-Certificate MITM technique.  Returns (crt, key).

    The CA private key can mint a certificate for *any* site, so it is written
    owner-only, valid for ``days`` (default one year) and -- when
    ``permitted_domains`` is given -- name-constrained: even if the key leaks,
    a trust store honouring RFC 5280 will only accept certificates for those
    DNS names (and their subdomains).
    """
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime
    except ImportError as e:
        raise RuntimeError(
            "certificate generation needs the 'cryptography' package "
            "(pip install cryptography) — or use openssl_command()") from e

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Xray Forge (personal)"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                           critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False), critical=True))
    if permitted_domains:
        builder = builder.add_extension(
            x509.NameConstraints(
                permitted_subtrees=[x509.DNSName(d.lstrip("*.")) for d in permitted_domains],
                excluded_subtrees=None),
            critical=True)
    cert = builder.sign(key, hashes.SHA256())
    from xray_forge.core.fsutil import write_private
    write_private(key_path, key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
    write_private(crt_path, cert.public_bytes(serialization.Encoding.PEM), mode=0o644)
    return crt_path, key_path


def openssl_command(common_name: str = "Xray Forge MITM CA") -> str:
    """Equivalent openssl command for users without the cryptography pkg."""
    return ("openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes "
            f'-subj "/CN={common_name}/O=Xray Forge (personal)" '
            '-addext "basicConstraints=critical,CA:TRUE" '
            '-addext "keyUsage=critical,keyCertSign,cRLSign,digitalSignature" '
            f'-keyout {MITM_DEFAULT_KEY} -out {MITM_DEFAULT_CERT}')


# ===========================================================================
# Setup guidance (Windows / Android / Firefox) — our own words
# ===========================================================================

def setup_guide(platform: str = "windows") -> str:
    p = (platform or "windows").lower()
    cert = MITM_DEFAULT_CERT
    if p == "windows":
        return (
            "MITM-DomainFronting setup (Windows):\n"
            f"1. Trust {cert}: right-click > Install Certificate > Local Machine >\n"
            "   'Place all certificates in the following store' >\n"
            "   Trusted Root Certification Authorities.\n"
            "   (Chrome/Edge use the Windows store; Firefox imports its own — see\n"
            "   Firefox: Settings > Privacy & Security > Certificates > View\n"
            "   Certificates > Authorities > Import.)\n"
            "2. Import the generated JSON into v2rayN as a *custom config*\n"
            "   (core type: xray, leave the SOCKS port field EMPTY).\n"
            "3. Enable 'Set system proxy' and pick the config.\n"
            "4. Toggle ON/OFF by selecting/deselecting the config.\n"
            "Keep mycert.key private — never share it.")
    if p == "android":
        return (
            "MITM-DomainFronting setup (Android, no root):\n"
            f"1. Copy {cert} and mycert.key to the phone.\n"
            "2. v2rayNG > Asset files: add both files.\n"
            f"3. Trust {cert}: Settings > Security & privacy > More security\n"
            "   settings > Install from device storage > CA certificate.\n"
            "4. Import the JSON config (import from locally) and run it.\n"
            "   Keep default port 10808 and enable the Hev TUN feature.\n"
            "5. Browsers only (Chromium works; Firefox: About Firefox > tap logo\n"
            "   5x > Secret Settings > 'Use third party CA certificates').\n"
            "Keep mycert.key private — never share it.")
    if p == "firefox":
        return (
            "Firefox-specific trust (any OS):\n"
            "Settings > Privacy & Security > Certificates > View Certificates >\n"
            "Authorities > Import... > select mycert.crt > tick\n"
            "'Trust this CA to identify websites'.\n"
            "Keep mycert.key private — never share it.")
    return setup_guide("windows")
