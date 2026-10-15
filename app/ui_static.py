"""Serve the bundled UI (Next.js static export) from the same origin as the API."""
import mimetypes
import os

from fastapi import Request
from fastapi.responses import FileResponse, Response

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui")
SITE = os.path.join(ROOT, "site")
HTML = os.path.join(ROOT, "html")
mimetypes.add_type("text/css", ".css")
mimetypes.add_type("application/javascript", ".js")
mimetypes.add_type("font/woff2", ".woff2")


def shell_for(path: str):
    p = path.strip("/")
    if p == "ai-inventory":
        return os.path.join(ROOT, "ai_inventory_board.html")
    if p == "selftest":
        return os.path.join(ROOT, "selftest.html")
    if p == "findings":
        return os.path.join(ROOT, "findings_board.html")
    if p == "repo-architecture":
        return os.path.join(ROOT, "repo_architecture.html")
    if p == "controls":
        return os.path.join(ROOT, "controls_board.html")
    parts0 = p.split("/")
    if len(parts0) == 2 and parts0[0] in ("scans", "findings") and parts0[1] != "new":
        return os.path.join(ROOT, "detail.html")
    if p == "":
        cands = ["index.html"]
    else:
        cands = [p.replace("/", "__") + ".html"]
        parts = p.split("/")
        if len(parts) == 2 and parts[0] in ("scans", "findings"):
            cands.append(f"dyn_{parts[0]}__abc123.html")
    for c in cands:
        fp = os.path.join(HTML, c)
        if os.path.isfile(fp):
            return fp
    return None


async def ui_middleware(request: Request, call_next):
    if request.method in ("GET", "HEAD"):
        path = request.url.path
        if path.startswith("/_next/") or (path.count("/") == 1 and os.path.splitext(path)[1] in (".ico", ".svg", ".png", ".woff2", ".txt")):
            fp = os.path.normpath(os.path.join(SITE, path.lstrip("/").replace("/", os.sep)))
            if fp.startswith(SITE) and os.path.isfile(fp):
                return FileResponse(fp, media_type=mimetypes.guess_type(fp)[0] or "application/octet-stream",
                                    headers={"Cache-Control": "no-cache"})
        elif "text/html" in request.headers.get("accept", "") and not path.startswith(("/docs", "/redoc", "/openapi", "/static")):
            fp = shell_for(path)
            if fp:
                return FileResponse(fp, media_type="text/html; charset=utf-8", headers={"Cache-Control": "no-cache"})
    return await call_next(request)
