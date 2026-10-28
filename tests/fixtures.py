"""
Sample share-links and expected Outbound fields for every supported protocol.
"""

from __future__ import annotations

import base64
import json

VLESS_TLS_WS = (
    "vless://13b8ac3f-e8de-4b2d-82db-e9130d288a54@188.114.97.6:443"
    "?encryption=none&security=tls&sni=edgestuff.pages.dev&fp=chrome"
    "&type=ws&host=edgestuff.pages.dev&path=%2Fchannel#CF%20worker"
)

VLESS_REALITY = (
    "vless://13b8ac3f-e8de-4b2d-82db-e9130d288a54@188.114.97.6:443"
    "?security=reality&sni=www.microsoft.com&fp=chrome"
    "&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&sid=6ba85179"
    "&spx=%2F&type=tcp&flow=xtls-rprx-vision#reality-node"
)

VMESS_PAYLOAD = {
    "v": "2", "ps": "vm-test", "add": "104.18.1.1", "port": "443",
    "id": "b831381d-6324-4d53-ad4f-8cda48b30811", "aid": "0",
    "scy": "auto", "net": "ws", "host": "cdn.example.com",
    "path": "/vmray", "tls": "tls", "sni": "cdn.example.com",
    "alpn": "", "fp": "chrome",
}
VMESS_B64 = "vmess://" + base64.b64encode(
    json.dumps(VMESS_PAYLOAD).encode()).decode()

TROJAN_TLS = (
    "trojan://passw0rd@203.0.113.10:443"
    "?security=tls&sni=trojan.example.com&fp=firefox&type=ws"
    "&host=trojan.example.com&path=%2Ftj#trojan-node"
)

SS_SIP002 = "ss://" + base64.urlsafe_b64encode(
    b"aes-256-gcm:seekrit-password").decode().rstrip("=") + \
    "@198.51.100.7:8388#ss-node"

HYSTERIA2 = (
    "hysteria2://hy2pass@203.0.113.50:443"
    "?sni=hy2.example.com&insecure=1&obfs=salamander&obfs-password=obfspass"
    "#hy2-node"
)

TUIC = (
    "tuic://tuic-uuid:tuicpass@203.0.113.60:443"
    "?sni=tuic.example.com&alpn=h3&congestion_control=bbr&udp_relay_mode=native"
    "#tuic-node"
)

ALL_LINES = [VLESS_TLS_WS, VLESS_REALITY, VMESS_B64, TROJAN_TLS,
             SS_SIP002, HYSTERIA2, TUIC]
