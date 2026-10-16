"""
Core configuration and constants for Xray Forge.
"""

import json
import re

DEFAULT_FP = "chrome"

FINGERPRINTS = [
    "chrome",
    "firefox",
    "safari",
    "edge",
    "ios",
    "android",
    "opera",
    "brave",
    "vivaldi",
    "qq",
    "sogou",
    "random",
    "randomized",
    "unsafe",
]

# --- MMDF / domain-fronting / fake-SNI presets (patterniha MMDF tricks) ---
FAKE_SNI_PRESETS = [
    "letsencrypt.org",
    "www.microsoft.com",
    "www.google.com",
    "www.apple.com",
    "cloudflare.com",
    "fastly.com",
    "edgecastcdn.net",
    "akamaiedge.net",
]
DOMAIN_FRONT_FRONTS = [
    "d192x8k13n3.cloudfront.net",
    "www.cloudflare.com",
    "www.fastly.com",
    "edgecastcdn.net",
]

DEFAULT_CS = ":".join([
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
])

DEFAULT_FM = {
    "tcp": [
        {"type": "fragment",
         "settings": {"packets": "tlshello", "lengths": ["5", "94", "1"],
                      "delays": ["0"], "maxSplit": "0"}},
        {"type": "fragment",
         "settings": {"packets": "1-1", "lengths": ["109", "1"],
                      "delays": ["1"], "maxSplit": "355"}},
    ]
}

DEFAULT_TEMPLATE = "{id:02d}_{sub}_{path}"
PROXY_SCHEMES = {"vless", "trojan", "vmess", "ss"}
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

MODE_FULL = "⚡ Full fix   (fp→chrome + cs + fm)"
MODE_IPONLY = "🎯 IP only   (no injection)"
MODE_CUSTOM = "🛠 Custom"
MODES = [MODE_FULL, MODE_IPONLY, MODE_CUSTOM]

CF_RANGES = [
    "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "162.158.0.0/15",
    "198.41.128.0/17", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "131.0.72.0/22",
]

FRAG_PRESETS = ["5,94,1@2", "rand:8-32@3", "rand:1-16@2", "off"]
TEST_TARGET_DEFAULT = "http://www.gstatic.com/generate_204"

GEO_VIA_TUNNEL = [
    ("http", "ip-api.com",
     "/json/?fields=status,countryCode,country,city,isp,query"),
    ("https", "ipwho.is", "/"),
    ("https", "ipinfo.io", "/json"),
]

DOH_ENDPOINTS = [
    "https://1.1.1.1/dns-query",
    "https://8.8.8.8/resolve",
    "https://free.shecan.ir/dns-query",
    "https://dns.403.online/dns-query",
]

DOH_SERVERS = (("1.1.1.1", "/dns-query"), ("8.8.8.8", "/resolve"))

IRAN_UDP_RESOLVERS = [
    ("178.22.122.100", "shecan"),
    ("185.55.226.26", "begzar"),
    ("10.202.10.202", "403online")
]


def compact_json(obj) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
