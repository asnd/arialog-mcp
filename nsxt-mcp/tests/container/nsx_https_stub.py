"""Real HTTPS NSX stub for packaged execution; all non-GET methods are unsupported."""

import base64
import ssl
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).parents[1]))
from stub_nsx import NSXStub  # noqa: E402

stub = NSXStub()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            status, body = 200, b"ok"
        else:
            auth = self.headers.get("Authorization", "Basic Og==")
            try:
                _, password = base64.b64decode(auth.split(" ", 1)[1]).decode().split(":", 1)
            except (ValueError, IndexError):
                password = ""
            if password not in ("pw", "synthetic-password"):
                status, body = 401, b"{}"
            elif (
                self.headers["Host"].startswith("nsx-fail")
                and self.path == "/api/v1/cluster/status"
            ):
                status, body = 503, b"{}"
            else:
                response = stub(
                    httpx.Request(
                        "GET",
                        "https://" + self.headers["Host"] + self.path,
                        headers=dict(self.headers),
                    )
                )
                status, body = response.status_code, response.content
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


if __name__ == "__main__":
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain("/config/server.crt", "/config/server.key")
    server = ThreadingHTTPServer(("0.0.0.0", 8443), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
