"""Static server for the original EXL Code-Governance frontend (Next.js static export)."""
import http.server, mimetypes, os, socketserver
from urllib.parse import urlparse

ROOT = os.path.dirname(os.path.abspath(__file__))
SITE, HTML = os.path.join(ROOT, "site"), os.path.join(ROOT, "html")
PORT = int(os.environ.get("PORT", "3000"))
SEC_HEADERS = [
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
]
for a, b in ((".css", "text/css"), (".js", "application/javascript"), (".woff2", "font/woff2")):
    mimetypes.add_type(b, a)


def shell_for(path):
    p = path.strip("/")
    cands = ["index.html"] if p == "" else [p.replace("/", "__") + ".html"]
    parts = p.split("/")
    if len(parts) == 2 and parts[0] in ("scans", "findings"):
        cands.append(f"dyn_{parts[0]}__abc123.html")
    for c in cands:
        fp = os.path.join(HTML, c)
        if os.path.isfile(fp):
            return fp
    return os.path.join(HTML, "index.html") if os.path.isfile(os.path.join(HTML, "index.html")) else None


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype, cache="no-cache"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", cache)
        for k, v in SEC_HEADERS:
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_HEAD = lambda self: self.do_GET()

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/liveness":
            return self._send(200, b'{"status":"alive"}', "application/json")
        if path.startswith("/_next/") or os.path.splitext(path)[1]:
            fp = os.path.normpath(os.path.join(SITE, path.lstrip("/").replace("/", os.sep)))
            if fp.startswith(SITE) and os.path.isfile(fp):
                with open(fp, "rb") as f:
                    return self._send(200, f.read(), mimetypes.guess_type(fp)[0] or "application/octet-stream",
                                      "public, max-age=31536000, immutable" if "/_next/static/" in path else "no-cache")
            return self._send(404, b"not found", "text/plain")
        _pp = path.strip("/").split("/")
        if len(_pp) == 2 and _pp[0] in ("scans", "findings") and _pp[1] != "new":
            with open(os.path.join(ROOT, "detail.html"), "rb") as f:
                return self._send(200, f.read(), "text/html; charset=utf-8")
        fp = shell_for(path)
        if fp:
            with open(fp, "rb") as f:
                return self._send(200, f.read(), "text/html; charset=utf-8")
        return self._send(404, b"not found", "text/plain")


class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    S(("0.0.0.0", PORT), H).serve_forever()
