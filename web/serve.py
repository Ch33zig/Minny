"""Development server for the Minny UI.

`python -m http.server` from dist/ cannot see fixtures/, so the mock switch dies.
This serves the repository root instead, maps / to dist/index.html, and optionally
proxies /api to a running FastAPI process so live mode can be tested from the same
origin with no CORS setup.

    python web/serve.py                       # http://localhost:8080/?mock=1
    python web/serve.py --api http://127.0.0.1:8000
"""

import argparse
import os
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Handler(SimpleHTTPRequestHandler):
    api_base = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT, **kwargs)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self.path = "/dist/index.html"
        elif self.path.startswith("/?"):
            self.path = "/dist/index.html" + self.path[1:]
        if self.path.startswith("/api/"):
            return self._proxy("GET")
        return super().do_GET()

    def do_POST(self):
        if self.path.startswith("/api/"):
            return self._proxy("POST")
        self.send_error(405)

    def _proxy(self, method):
        if not self.api_base:
            self.send_response(503)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                b'{"error":{"code":"no_api","message":'
                b'"Dev server started without --api. Append ?mock=1 to use fixtures."}}'
            )
            return
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        req = Request(self.api_base.rstrip("/") + self.path, data=body, method=method)
        req.add_header("Accept", self.headers.get("Accept", "*/*"))
        if body:
            req.add_header("Content-Type", self.headers.get("Content-Type", "application/json"))
        try:
            with urlopen(req, timeout=300) as upstream:
                self.send_response(upstream.status)
                for key, value in upstream.headers.items():
                    if key.lower() not in ("transfer-encoding", "connection", "content-length"):
                        self.send_header(key, value)
                self.end_headers()
                # Streamed chunk-by-chunk so SSE on /api/stream stays live.
                while True:
                    chunk = upstream.read(1024)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    self.wfile.flush()
        except HTTPError as exc:
            self.send_response(exc.code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(exc.read())
        except (URLError, BrokenPipeError, ConnectionResetError):
            pass

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--api", default=os.environ.get("MINNY_API"),
                        help="Base URL of the FastAPI process, e.g. http://127.0.0.1:8000")
    args = parser.parse_args()
    Handler.api_base = args.api
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print("Minny UI   http://localhost:%d/?mock=1   (fixtures, no backend needed)" % args.port)
    print("           http://localhost:%d/          (live API: %s)" % (args.port, args.api or "not configured"))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    main()
