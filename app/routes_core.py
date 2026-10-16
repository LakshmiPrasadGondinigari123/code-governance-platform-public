"""Auth, tenants, SSO, health/ops, scans."""
import asyncio
import json
import os
import secrets
import shutil
import time
import urllib.parse
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, File, Header, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse, StreamingResponse
from pydantic import BaseModel

from . import auth, bus, db, llm, scans as scan_mod
from .common import audit, now, scan_or_404, latest_scans

router = APIRouter()
_login_failures = {}
_sso_states = {}


class LoginRequest(BaseModel):
    username: str
    password: str


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str = "viewer"


class CreateTenantRequest(BaseModel):
    id: str
    name: str
    admin_username: Optional[str] = None
    admin_password: Optional[str] = None


class CreateScanRequest(BaseModel):
    git_url: str


# ------------------------------------------------------------------ auth
@router.post("/auth/login")
def login(req: LoginRequest):
    key = req.username.lower()
    fails = [t for t in _login_failures.get(key, []) if time.time() - t < 300]
    if len(fails) >= 10:
        raise HTTPException(429, "Too many failed attempts. Try again in a few minutes.")
    u = db.get("users", "_global", req.username)
    if not u or u.get("disabled") or not auth.verify_password(req.password, u["password_hash"]):
        fails.append(time.time())
        _login_failures[key] = fails
        raise HTTPException(401, "Invalid username or password")
    _login_failures.pop(key, None)
    session = auth.issue_token(u)
    audit({"tenant_id": u["tenant_id"], "username": u["username"], "role": u["role"]}, "auth.login")
    return session


@router.get("/auth/me")
def whoami(user: dict = Depends(auth.current_user)):
    return {
        "username": user["username"], "role": user["role"], "tenant_id": user["tenant_id"],
        "platform_admin": auth.is_platform_admin(user),
        "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(user["exp"])),
    }


@router.post("/auth/logout")
def logout(user: dict = Depends(auth.current_user)):
    """Real invalidation: the token's jti is stored in a revocation list checked on every request."""
    auth.revoke(user)
    audit(user, "auth.logout")
    return {"status": "logged_out"}


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


@router.post("/auth/password")
def change_password(req: ChangePasswordRequest, user: dict = Depends(auth.current_user)):
    """Self-service password change: verifies the current password, enforces a minimum length, revokes the session."""
    u = db.get("users", "_global", user["username"])
    if not u or not auth.verify_password(req.current_password, u["password_hash"]):
        raise HTTPException(401, "Current password is incorrect")
    if len(req.new_password) < 8:
        raise HTTPException(422, "New password must be at least 8 characters")
    if req.new_password == req.current_password:
        raise HTTPException(422, "New password must differ from the current one")
    u["password_hash"] = auth.hash_password(req.new_password)
    db.put("users", "_global", user["username"], u)
    auth.revoke(user)
    audit(user, "auth.password_change", user["username"])
    return {"status": "password_changed", "detail": "Sign in again with the new password."}


@router.get("/auth/users")
def list_users(user: dict = Depends(auth.require("admin"))):
    return [auth.public_user(u) for u in db.items("users", "_global", newest_first=False) if u["tenant_id"] == user["tenant_id"]]


@router.post("/auth/users")
def create_user(req: CreateUserRequest, user: dict = Depends(auth.require("admin"))):
    u = auth.create_user(req.username, req.password, req.role, user["tenant_id"])
    audit(user, "user.create", req.username, {"role": req.role})
    return auth.public_user(u)


@router.delete("/auth/users/{username}")
def delete_user(username: str, user: dict = Depends(auth.require("admin"))):
    if username == user["username"]:
        raise HTTPException(400, "You cannot delete your own account")
    target = db.get("users", "_global", username)
    if not target or target["tenant_id"] != user["tenant_id"]:
        raise HTTPException(404, "user not found")
    admins = [u for u in db.items("users", "_global") if u["tenant_id"] == user["tenant_id"] and u["role"] == "admin"]
    if target["role"] == "admin" and len(admins) <= 1:
        raise HTTPException(400, "Cannot delete the last admin of a tenant")
    db.delete("users", "_global", username)
    audit(user, "user.delete", username)
    return {"status": "deleted", "username": username}


@router.post("/tenants")
def create_tenant(req: CreateTenantRequest, user: dict = Depends(auth.require("admin"))):
    if not auth.is_platform_admin(user):
        raise HTTPException(403, "Platform admin only")
    tid = req.id.strip().lower()
    if not tid.replace("-", "").replace("_", "").isalnum():
        raise HTTPException(400, "tenant id must be alphanumeric (- and _ allowed)")
    if db.get("tenants", "_global", tid):
        raise HTTPException(409, "tenant already exists")
    if bool(req.admin_username) != bool(req.admin_password):
        raise HTTPException(400, "provide both admin_username and admin_password, or neither")
    t = db.put("tenants", "_global", tid, {"id": tid, "name": req.name, "created_at": now()})
    admin = None
    if req.admin_username:
        admin = auth.public_user(auth.create_user(req.admin_username, req.admin_password, "admin", tid))
    audit(user, "tenant.create", tid)
    return {**t, "admin": admin}


@router.get("/tenants")
def list_tenants(user: dict = Depends(auth.require("admin"))):
    if not auth.is_platform_admin(user):
        raise HTTPException(403, "Platform admin only")
    return db.items("tenants", "_global", newest_first=False)


# ------------------------------------------------------------------ SSO (OIDC)
def _oidc():
    iss = os.getenv("OIDC_ISSUER", "").rstrip("/")
    cid, sec, redir = os.getenv("OIDC_CLIENT_ID"), os.getenv("OIDC_CLIENT_SECRET"), os.getenv("OIDC_REDIRECT_URI")
    if not (iss and cid and sec and redir):
        return None
    return {"issuer": iss, "client_id": cid, "client_secret": sec, "redirect_uri": redir,
            "name": os.getenv("OIDC_PROVIDER_NAME", "SSO"), "role": os.getenv("OIDC_DEFAULT_ROLE", "viewer"),
            "tenant": os.getenv("OIDC_DEFAULT_TENANT", auth.DEFAULT_TENANT)}


def _discovery(cfg):
    r = httpx.get(cfg["issuer"] + "/.well-known/openid-configuration", timeout=10)
    r.raise_for_status()
    return r.json()


@router.get("/auth/sso/status")
def sso_status():
    c = _oidc()
    return {"enabled": bool(c), "provider_name": c["name"] if c else "", "issuer": c["issuer"] if c else None}


@router.get("/auth/sso/login")
def sso_login():
    c = _oidc()
    if not c:
        raise HTTPException(503, "SSO is not configured (set OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_REDIRECT_URI)")
    d = _discovery(c)
    state = secrets.token_urlsafe(24)
    _sso_states[state] = time.time()
    q = urllib.parse.urlencode({"response_type": "code", "client_id": c["client_id"], "redirect_uri": c["redirect_uri"], "scope": "openid email profile", "state": state})
    return {"authorization_url": d["authorization_endpoint"] + "?" + q}


@router.get("/auth/sso/callback")
def sso_callback(code: Optional[str] = None, state: Optional[str] = None, error: Optional[str] = None, error_description: Optional[str] = None):
    c = _oidc()
    if not c:
        raise HTTPException(503, "SSO is not configured")
    if error:
        raise HTTPException(400, f"{error}: {error_description or ''}")
    ts = _sso_states.pop(state or "", None)
    if not code or not ts or time.time() - ts > 600:
        raise HTTPException(400, "invalid or expired SSO state")
    d = _discovery(c)
    tok = httpx.post(d["token_endpoint"], data={"grant_type": "authorization_code", "code": code, "redirect_uri": c["redirect_uri"], "client_id": c["client_id"], "client_secret": c["client_secret"]}, timeout=15)
    tok.raise_for_status()
    info = httpx.get(d["userinfo_endpoint"], headers={"Authorization": "Bearer " + tok.json()["access_token"]}, timeout=15)
    info.raise_for_status()
    p = info.json()
    username = (p.get("email") or p.get("preferred_username") or p.get("sub", "")).lower()
    if not username:
        raise HTTPException(400, "identity provider returned no usable identity")
    u = db.get("users", "_global", username)
    if not u:
        u = {"username": username, "password_hash": "!sso", "role": c["role"], "tenant_id": c["tenant"], "created_at": now(), "sso": True}
        db.put("users", "_global", username, u)
    session = auth.issue_token(u)
    session["id_token_hint"] = tok.json().get("id_token")
    audit({"tenant_id": u["tenant_id"], "username": username, "role": u["role"]}, "auth.sso_login")
    return RedirectResponse("/#sso_token=" + session["token"])


@router.post("/auth/sso/logout")
def sso_logout(user: dict = Depends(auth.current_user)):
    auth.revoke(user)
    audit(user, "auth.sso_logout")
    c = _oidc()
    end = None
    if c:
        try:
            end = _discovery(c).get("end_session_endpoint")
        except Exception:
            end = None
    return {"status": "logged_out", "idp_logout_url": end,
            "detail": None if end else "Provider does not advertise RP-initiated logout; only the local session was ended."}


@router.get("/auth/sso/config")
def sso_config(user: dict = Depends(auth.require("admin"))):
    c = _oidc()
    return {"enabled": bool(c), "issuer": c["issuer"] if c else None, "client_id": c["client_id"] if c else None,
            "redirect_uri": c["redirect_uri"] if c else None, "default_role": c["role"] if c else None,
            "client_secret_set": bool(os.getenv("OIDC_CLIENT_SECRET"))}


# ------------------------------------------------------------------ ops
def _tools():
    return {t: bool(shutil.which(t)) for t in ("git",)} | {"builtin_scanner": True}


@router.get("/health")
def health():
    ok = db.ping()
    return {
        "status": "ok" if ok else "degraded", "db": "connected" if ok else "error", "database": "connected" if ok else "error",
        "version": "1.0.0", "scanner": {"tools": _tools(), "available": True},
        "llm": llm.status(), "groq_api_key_configured": llm.status()["configured"],
    }


@router.get("/liveness")
def liveness():
    return {"status": "alive"}


@router.get("/readiness")
def readiness():
    if not db.ping():
        raise HTTPException(503, "database unavailable")
    return {"status": "ready"}


@router.get("/metrics")
def metrics():
    lines = ["# TYPE cgip_documents gauge"]
    for col in ("scans", "findings", "repositories", "users", "runtime_events"):
        n = 0
        for t in [x["id"] for x in db.items("tenants", "_global")]:
            n += db.count(col, t) if col != "users" else 0
        if col == "users":
            n = db.count("users", "_global")
        lines.append(f'cgip_documents{{collection="{col}"}} {n}')
    return PlainTextResponse("\n".join(lines) + "\n")


@router.get("/llm-status")
def llm_status(user: dict = Depends(auth.current_user)):
    return llm.status()


# ------------------------------------------------------------------ scans
def _public_scan(s: dict, full: bool = False) -> dict:
    out = {k: s[k] for k in ("id", "source", "git_url", "repository_id", "repository_name", "status", "created_by", "created_at", "finished_at", "error", "summary", "stages")}
    if full:
        out["controls"] = s.get("controls", [])
    return out


STAGE_LABELS = {"intake": "Intake", "manifest": "Manifest", "discovery": "Discovery", "ai_detection": "AI Detection", "dependency_scan": "Dependency Scan", "security_scan": "Security Scan", "secrets_scan": "Secrets Scan", "pii_phi_scan": "PII/PHI Scan", "policy_evaluation": "Policy Evaluation", "evidence_graph": "Evidence Graph", "documentation": "Documentation",
                "fetch": "Fetch source", "inventory": "Scan files", "controls": "Evaluate controls", "graph": "Build evidence graph", "persist": "Save results"}


def _created(s):
    return {"scan_id": s["id"], "status": s["status"],
            "stages": [{"name": x["name"], "label": STAGE_LABELS.get(x["name"], x["name"]), "status": "queued"} for x in s["stages"]]}


@router.post("/scans")
def create_scan(req: CreateScanRequest, user: dict = Depends(auth.require("admin", "reviewer"))):
    try:
        s = scan_mod.create(user["tenant_id"], user["username"], git_url=req.git_url)
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit(user, "scan.create", s["id"], {"git_url": req.git_url})
    return _created(s)


@router.get("/scans")
def list_scans(user: dict = Depends(auth.current_user)):
    return [_public_scan(s) for s in db.items("scans", user["tenant_id"])]


@router.post("/scans/upload")
async def create_scan_from_zip(file: UploadFile = File(...), user: dict = Depends(auth.require("admin", "reviewer"))):
    data = await file.read()
    if not data[:4] == b"PK\x03\x04":
        raise HTTPException(400, "file must be a .zip archive")
    if len(data) > 200 * 1024 * 1024:
        raise HTTPException(413, "zip larger than 200MB")
    s = scan_mod.create(user["tenant_id"], user["username"], zip_bytes=data, name=file.filename or "upload.zip")
    audit(user, "scan.upload", s["id"], {"filename": file.filename})
    return _created(s)


@router.delete("/scans")
def delete_all_scans(user: dict = Depends(auth.require("admin"))):
    t = user["tenant_id"]
    n = db.count("scans", t)
    for col in ("scans", "findings", "findings_evidence", "graphs", "inventory", "repositories", "triage"):
        db.clear(col, t)
    audit(user, "scan.delete_all", "", {"deleted": n})
    bus.publish(t, "findings", {"type": "findings_updated", "reason": "scan_deleted"})
    return {"status": "deleted", "scans_deleted": n}


@router.get("/scans/{scan_id}/stages")
def scan_stages(scan_id: str, user: dict = Depends(auth.current_user)):
    s = scan_or_404(user, scan_id)
    return {"scan_id": scan_id, "status": s["status"], "stages": s["stages"]}


@router.get("/scans/{scan_id}/events")
async def scan_events(scan_id: str, user: dict = Depends(auth.current_user)):
    scan_or_404(user, scan_id)
    tenant = user["tenant_id"]

    async def gen():
        sent = 0
        idle = 0
        while True:
            s = db.get("scans", tenant, scan_id)
            if not s:
                yield "event: deleted\ndata: {}\n\n"
                return
            ev = s["events"]
            while sent < len(ev):
                e = ev[sent]
                st = {"cancelled": "skipped"}.get(e["status"], e["status"])
                yield f"data: {json.dumps({'type': 'stage_update', 'stage': e['stage'], 'status': st, 'detail': e.get('message') or None, 'at': e.get('ts')})}\n\n"
                sent += 1
                idle = 0
            if s["status"] in ("completed", "failed", "cancelled"):
                if s["status"] == "completed":
                    g = db.get("graphs", tenant, scan_id) or {}
                    types = {}
                    for n in g.get("nodes", []):
                        types[n.get("type", "node")] = types.get(n.get("type", "node"), 0) + 1
                    yield f"data: {json.dumps({'type': 'graph_updated', 'node_count': len(g.get('nodes', [])), 'edge_count': len(g.get('edges', [])), 'node_types': types})}\n\n"
                term = {"completed": "scan_completed", "failed": "scan_failed", "cancelled": "scan_cancelled"}[s["status"]]
                yield f"data: {json.dumps({'type': term, 'scan_id': scan_id, 'status': s['status'], 'error': s.get('error')})}\n\n"
                return
            idle += 1
            if idle % 20 == 0:
                yield ": keepalive\n\n"
            await asyncio.sleep(0.4)
    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.post("/scans/{scan_id}/cancel")
def cancel_scan(scan_id: str, user: dict = Depends(auth.require("admin", "reviewer"))):
    s = scan_or_404(user, scan_id)
    if s["status"] not in ("queued", "running"):
        raise HTTPException(409, f"scan is already {s['status']}")
    scan_mod.CANCELLED.add(scan_id)
    audit(user, "scan.cancel", scan_id)
    return {"scan_id": scan_id, "status": "cancelling"}


@router.get("/scans/{scan_id}")
def get_scan(scan_id: str, user: dict = Depends(auth.current_user)):
    s = scan_or_404(user, scan_id)
    out = _public_scan(s, full=True)
    inv = db.get("inventory", user["tenant_id"], scan_id)
    out["inventory"] = {k: inv[k] for k in ("components", "ai_components", "models", "providers", "hosts", "languages")} if inv else None
    return out


@router.delete("/scans/{scan_id}")
def delete_scan(scan_id: str, user: dict = Depends(auth.require("admin"))):
    s = scan_or_404(user, scan_id)
    if s["status"] in ("queued", "running"):
        raise HTTPException(409, "cancel the scan before deleting it")
    t = user["tenant_id"]
    for col in ("findings", "findings_evidence"):
        for f in db.items(col, t):
            if f["scan_id"] == scan_id:
                db.delete(col, t, f["id"])
    db.delete("graphs", t, scan_id)
    db.delete("inventory", t, scan_id)
    db.delete("scans", t, scan_id)
    repo = db.get("repositories", t, s["repository_id"])
    if repo and repo.get("last_scan_id") == scan_id:
        rest = latest_scans(t, s["repository_id"])
        if rest:
            repo["last_scan_id"] = rest[0]["id"]
            db.put("repositories", t, repo["id"], repo)
        else:
            db.delete("repositories", t, repo["id"])
    audit(user, "scan.delete", scan_id)
    bus.publish(t, "findings", {"type": "findings_updated", "reason": "scan_deleted", "scan_id": scan_id, "repository_id": s["repository_id"]})
    return {"status": "deleted", "scan_id": scan_id}


@router.get("/scans/{scan_id}/compare/{other_scan_id}")
def compare_scans(scan_id: str, other_scan_id: str, user: dict = Depends(auth.current_user)):
    a = scan_or_404(user, scan_id)
    b = scan_or_404(user, other_scan_id)
    t = user["tenant_id"]
    fa = {f["fingerprint"]: f for f in db.items("findings", t) if f["scan_id"] == scan_id}
    fb = {f["fingerprint"]: f for f in db.items("findings", t) if f["scan_id"] == other_scan_id}
    ca = {c["control_id"]: c["status"] for c in a.get("controls", [])}
    cb = {c["control_id"]: c["status"] for c in b.get("controls", [])}
    return {
        "scan_id": scan_id, "other_scan_id": other_scan_id,
        "new_findings": [fa[k] for k in fa if k not in fb],
        "resolved_findings": [fb[k] for k in fb if k not in fa],
        "unchanged_count": len(set(fa) & set(fb)),
        "control_changes": [{"control_id": c, "from": cb.get(c), "to": ca.get(c)} for c in ca if ca.get(c) != cb.get(c)],
    }
