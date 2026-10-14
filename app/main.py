"""Code-to-Governance Intelligence Platform â€” FastAPI entrypoint (API + static UI)."""
import logging
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import auth, db
from .routes_core import router as core
from .routes_findings import router as findings
from .routes_governance import router as governance
from .routes_graph_export import router as graph_export
from .routes_runtime import router as runtime
from .ui_routes import router as ui
from .ui_routes2 import router as ui2
from .ui_static import ui_middleware
from .governance_ops import router as gov_ops
from . import ops
from .ops import router as ops_router
from .pii_detect import router as detect_router
from .arch_map import router as arch_map_router

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")

_DOCS = os.getenv("ENABLE_API_DOCS", "").lower() in ("1", "true", "yes")
app = FastAPI(
    title="Code-to-Governance Intelligence Platform",
    version="1.1.0",
    description="Turn an AI application repository into governance-ready, traceable technical evidence.",
    docs_url="/docs" if _DOCS else None,
    redoc_url=None,
    openapi_url="/openapi.json" if _DOCS else None,
)

origins = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]  # same-origin UI: no CORS by default
if origins:
    app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["*"], allow_headers=["*"], expose_headers=["X-Gate", "Content-Disposition"])


@app.middleware("http")
async def security_headers(request, call_next):
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    return resp


@app.middleware("http")
async def count_requests(request, call_next):
    import time as _t
    t0 = _t.time()
    resp = await call_next(request)
    from .ui_routes import STATS
    STATS["requests"] += 1
    STATS["latency_total_ms"] += (_t.time() - t0) * 1000
    if resp.status_code >= 500:
        STATS["errors_5xx"] += 1
    return resp


app.middleware("http")(ui_middleware)


@app.on_event("startup")
def startup() -> None:
    db._connect()
    auth.bootstrap()
    ops.start()


for r in (arch_map_router, gov_ops, ops_router, detect_router, ui2, ui, core, findings, governance, runtime, graph_export):
    app.include_router(r)

STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(os.path.join(STATIC, "index.html"))


app.mount("/static", StaticFiles(directory=STATIC), name="static")

