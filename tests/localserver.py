"""In-process HTTP(S) server with a throw-away CA, for transport tests.

Real sockets and a real TLS handshake on 127.0.0.1 -- no mocks -- so tests
exercise TLSClient / tls_connect / direct_get_text exactly as production does.
Needs the optional ``cryptography`` package (tests importorskip it).
"""

from __future__ import annotations

import datetime
import ipaddress
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _pem_key(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def make_pki(directory: str) -> dict[str, str]:
    """CA + a leaf for localhost / 127.0.0.1.  Returns file paths."""
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = (x509.CertificateBuilder()
          .subject_name(_name("xray-forge test CA")).issuer_name(_name("xray-forge test CA"))
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(days=1))
          .not_valid_after(now + datetime.timedelta(days=2))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(x509.KeyUsage(
              digital_signature=True, key_cert_sign=True, crl_sign=True,
              content_commitment=False, key_encipherment=False,
              data_encipherment=False, key_agreement=False,
              encipher_only=False, decipher_only=False), critical=True)
          .sign(ca_key, hashes.SHA256()))
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (x509.CertificateBuilder()
            .subject_name(_name("localhost")).issuer_name(ca.subject)
            .public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=2))
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                           critical=False)
            .sign(ca_key, hashes.SHA256()))
    paths = {k: os.path.join(directory, k) for k in ("ca.pem", "leaf.pem", "leaf.key")}
    with open(paths["ca.pem"], "wb") as f:
        f.write(ca.public_bytes(serialization.Encoding.PEM))
    with open(paths["leaf.pem"], "wb") as f:
        f.write(leaf.public_bytes(serialization.Encoding.PEM))
    with open(paths["leaf.key"], "wb") as f:
        f.write(_pem_key(leaf_key))
    return paths


class LocalServer:
    """``routes``: path -> (status, headers, body_bytes, send_content_length)."""

    def __init__(self, directory: str, routes: dict, tls: bool = True):
        self.routes = routes
        self.pki = make_pki(directory) if tls else {}
        routes_ref = routes

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"   # close-delimited unless told otherwise

            def log_message(self, *a):
                pass

            def do_GET(self):
                status, headers, body, with_len = routes_ref.get(
                    self.path, (404, {}, b"nope", True))
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                if with_len:
                    self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except OSError:
                    pass

        class Quiet(HTTPServer):
            def handle_error(self, request, client_address):
                pass                         # clients that reject our cert

        self.httpd = Quiet(("127.0.0.1", 0), Handler)
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(self.pki["leaf.pem"], self.pki["leaf.key"])
            self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        self.scheme = "https" if tls else "http"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def base(self) -> str:
        return f"{self.scheme}://127.0.0.1:{self.port}"

    @property
    def cafile(self) -> str:
        return self.pki.get("ca.pem", "")

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
