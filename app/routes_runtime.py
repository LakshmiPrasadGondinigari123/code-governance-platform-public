"""Runtime telemetry: apps, credentials, policy, event ingest/stream, integrations (webhooks)."""
import asyncio
import hashlib
import hmac
import json
import secrets
import time
from typing import Any, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from . import auth, db, scans as scan_mod
from .common import audit, now

router = APIRouter()


class RuntimeEventRequest(BaseModel):
    event_id: str
    event_type: str
    application_id: Optional[str] = None
    environment: Optional[str] = None
    trace_id: Optional[str] = None
    span_id: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    provider: Optional[str] = None
    model: Optional[str] = None
    endpoint: Optional[str] = None
    tool_name: Optional[str] = None
    request_metadata: Optional[dict] = None
    response_metadata: Optional[dict] = None
    retrieval_metadata: Optional[dict] = None
    policy_context: Optional[dict] = None
    network_metadata: Optional[dict] = None
    content_preview: Optional[str] = None
    source: Optional[str] = None


class RuntimeApplicationCreateRequest(BaseModel):
    application_id: str
    display_name: Optional[str] = None


class RuntimeApplicationRepositoryRequest(BaseModel):
    repository_id: Optional[str] = None


class RuntimeCredentialCreateRequest(BaseModel):
    name: str
    application_id: Optional[str] = None
    expires_in_days: Optional[int] = None


class RuntimePolicyRequest(BaseModel):
    approved_providers: list = []
    approved_models: list = []
    approved_tools: list = []
    approved_api_hosts: list = []


class CreateWebhookRequest(BaseModel):
    provider: str = "generic"
    name: str


def _hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def _policy(tenant: str) -> dict:
    return db.get("runtime_policy", tenant, "policy") or {"approved_providers": [], "approved_models": [], "approved_tools": [], "approved_api_hosts": []}


def _violations(policy: dict, ev: dict) -> list:
    v = []

    def chk(value, key, code):
        allowed = [a.lower() for a in policy.get(key, [])]
        if value and allowed and value.lower() not in allowed:
            v.append({"code": code, "value": value, "message": f"{value} is not in the approved list"})

    chk(ev.get("provider"), "approved_providers", "unapproved_provider")
    chk(ev.get("model"), "approved_models", "unapproved_model")
    chk(ev.get("tool_name"), "approved_tools", "unapproved_tool")
    host = (ev.get("network_metadata") or {}).get("host") or ""
    chk(host, "approved_api_hosts", "unapproved_api_host")
    return v


def _principal(request: Request, x_runtime_key: Optional[str] = Header(None), authorization: Optional[str] = Header(None)) -> dict:
    if x_runtime_key:
        rec = db.get("runtime_keys", "_global", _hash(x_runtime_key))
        if not rec or rec.get("revoked"):
            raise HTTPException(401, "invalid runtime key")
        if rec.get("expires_at") and rec["expires_at"] < time.time():
            raise HTTPException(401, "runtime key expired")
        return {"tenant_id": rec["tenant_id"], "application_id": rec.get("application_id"), "via": "key", "username": f"runtime:{rec['name']}", "role": "runtime"}
    u = auth.current_user(request, authorization)
    return {**u, "application_id": None, "via": "user"}


# ------------------------------------------------------------------ events
@router.post("/runtime/events")
def ingest_event(ev: RuntimeEventRequest, p: dict = Depends(_principal)):
    if p["via"] == "user" and p["role"] == "viewer":
        raise HTTPException(403, "viewers cannot ingest events")
    t = p["tenant_id"]
    body = ev.model_dump()
    if p.get("application_id"):
        if body.get("application_id") and body["application_id"] != p["application_id"]:
            raise HTTPException(403, "key is bound to a different application")
        body["application_id"] = p["application_id"]
    if body.get("content_preview"):
        body["content_preview"] = body["content_preview"][:500]
    body["received_at"] = now()
    body["violations"] = _violations(_policy(t), body)
    if body.get("application_id") and not db.get("runtime_apps", t, body["application_id"]):
        db.put("runtime_apps", t, body["application_id"], {"application_id": body["application_id"], "display_name": body["application_id"],
                                                          "repository_id": None, "created_at": now(), "auto_discovered": True})
    db.put("runtime_events", t, ev.event_id, body)
    from . import bus
    bus.publish(t, "runtime", {"type": "runtime_activity", "event_id": ev.event_id, "application_id": body.get("application_id"),
                               "event_type": body.get("event_type"), "violations": len(body["violations"])})
    bus.publish(t, "findings", {"type": "runtime_activity", "application_id": body.get("application_id")})
    if body["violations"]:
        bus.publish(t, "findings", {"type": "finding_created", "finding_id": "rf_" + ev.event_id, "application_id": body.get("application_id")})
    return {"status": "accepted", "event_id": ev.event_id, "violations": body["violations"]}


@router.get("/runtime/events")
def list_events(application_id: Optional[str] = None, violations_only: bool = False, limit: int = 100, user: dict = Depends(auth.current_user)):
    rows = db.items("runtime_events", user["tenant_id"])
    if application_id:
        rows = [e for e in rows if e.get("application_id") == application_id]
    if violations_only:
        rows = [e for e in rows if e.get("violations")]
    return rows[: max(1, min(limit, 500))]


@router.delete("/runtime/events")
def delete_events(user: dict = Depends(auth.require("admin"))):
    n = db.clear("runtime_events", user["tenant_id"])
    audit(user, "runtime.events_delete_all", "", {"deleted": n})
    return {"status": "deleted", "deleted": n}


@router.get("/runtime/events/stream")
async def stream_events(user: dict = Depends(auth.current_user)):
    t = user["tenant_id"]
    seen = {e["event_id"] for e in db.items("runtime_events", t)}

    async def gen():
        nonlocal seen
        beat = 0
        while True:
            cur = db.items("runtime_events", t)
            for e in reversed(cur):
                if e["event_id"] not in seen:
                    seen.add(e["event_id"])
                    yield f"event: runtime\ndata: {json.dumps(e)}\n\n"
            beat += 1
            if beat % 15 == 0:
                yield ": keepalive\n\n"
            await asyncio.sleep(1.5)

    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.get("/runtime/status")
def runtime_status(user: dict = Depends(auth.current_user)):
    t = user["tenant_id"]
    ev = db.items("runtime_events", t)
    return {"events_total": len(ev), "applications": db.count("runtime_apps", t),
            "active_credentials": sum(1 for k in db.items("runtime_keys_meta", t) if not k.get("revoked")),
            "last_event_at": ev[0]["received_at"] if ev else None,
            "policy_configured": any(_policy(t).values()), "violations": sum(1 for e in ev if e.get("violations"))}


@router.get("/runtime/usage/summary")
def usage_summary(application_id: Optional[str] = None, user: dict = Depends(auth.current_user)):
    ev = db.items("runtime_events", user["tenant_id"])
    if application_id:
        ev = [e for e in ev if e.get("application_id") == application_id]
    def tally(key):
        out = {}
        for e in ev:
            v = e.get(key) or "unknown"
            out[v] = out.get(v, 0) + 1
        return dict(sorted(out.items(), key=lambda kv: -kv[1]))
    tokens = sum((e.get("response_metadata") or {}).get("total_tokens", 0) or 0 for e in ev if isinstance((e.get("response_metadata") or {}).get("total_tokens", 0), (int, float)))
    return {"events": len(ev), "by_provider": tally("provider"), "by_model": tally("model"), "by_event_type": tally("event_type"),
            "by_application": tally("application_id"), "total_tokens": tokens, "violations": sum(1 for e in ev if e.get("violations"))}


@router.get("/runtime/findings/{finding_id}")
def runtime_finding(finding_id: str, user: dict = Depends(auth.current_user)):
    eid = finding_id.removeprefix("rf_")
    e = db.get("runtime_events", user["tenant_id"], eid)
    if not e or not e.get("violations"):
        raise HTTPException(404, "runtime finding not found")
    return {"id": f"rf_{eid}", "event": e, "violations": e["violations"], "policy": _policy(user["tenant_id"]),
            "application": db.get("runtime_apps", user["tenant_id"], e.get("application_id") or "")}


# ------------------------------------------------------------------ applications
@router.post("/runtime/applications")
def register_app(req: RuntimeApplicationCreateRequest, user: dict = Depends(auth.require("admin", "reviewer"))):
    if db.get("runtime_apps", user["tenant_id"], req.application_id):
        raise HTTPException(409, "application already registered")
    a = {"application_id": req.application_id, "display_name": req.display_name or req.application_id, "repository_id": None, "created_at": now()}
    db.put("runtime_apps", user["tenant_id"], req.application_id, a)
    audit(user, "runtime.app_register", req.application_id)
    return a


@router.get("/runtime/applications")
def list_apps(user: dict = Depends(auth.current_user)):
    ev = db.items("runtime_events", user["tenant_id"])
    out = []
    for a in db.items("runtime_apps", user["tenant_id"]):
        mine = [e for e in ev if e.get("application_id") == a["application_id"]]
        out.append({**a, "events": len(mine), "violations": sum(1 for e in mine if e.get("violations"))})
    return out


@router.put("/runtime/applications/{application_id}/repository")
def link_app_repo(application_id: str, req: RuntimeApplicationRepositoryRequest, user: dict = Depends(auth.require("admin", "reviewer"))):
    a = db.get("runtime_apps", user["tenant_id"], application_id)
    if not a:
        raise HTTPException(404, "application not found")
    if req.repository_id and not db.get("repositories", user["tenant_id"], req.repository_id):
        raise HTTPException(404, "repository not found")
    a["repository_id"] = req.repository_id
    db.put("runtime_apps", user["tenant_id"], application_id, a)
    audit(user, "runtime.app_link", application_id, {"repository_id": req.repository_id})
    return a


# ------------------------------------------------------------------ credentials & policy
@router.post("/runtime/credentials")
def create_credential(req: RuntimeCredentialCreateRequest, user: dict = Depends(auth.require("admin"))):
    key = "rtk_" + secrets.token_urlsafe(32)
    cid = db.new_id("cred_")
    exp = time.time() + req.expires_in_days * 86400 if req.expires_in_days else None
    t = user["tenant_id"]
    db.put("runtime_keys", "_global", _hash(key), {"credential_id": cid, "tenant_id": t, "name": req.name, "application_id": req.application_id,
                                                   "revoked": False, "expires_at": exp})
    meta = {"id": cid, "name": req.name, "application_id": req.application_id, "created_at": now(), "created_by": user["username"],
            "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(exp)) if exp else None, "revoked": False,
            "key_hash": _hash(key), "key_prefix": key[:8]}
    db.put("runtime_keys_meta", t, cid, meta)
    audit(user, "runtime.credential_create", cid)
    return {**{k: v for k, v in meta.items() if k != "key_hash"}, "key": key, "note": "Store this key now; it cannot be shown again."}


@router.get("/runtime/credentials")
def list_credentials(user: dict = Depends(auth.require("admin"))):
    return [{k: v for k, v in m.items() if k != "key_hash"} for m in db.items("runtime_keys_meta", user["tenant_id"])]


@router.post("/runtime/credentials/{credential_id}/revoke")
def revoke_credential(credential_id: str, user: dict = Depends(auth.require("admin"))):
    m = db.get("runtime_keys_meta", user["tenant_id"], credential_id)
    if not m:
        raise HTTPException(404, "credential not found")
    m["revoked"] = True
    db.put("runtime_keys_meta", user["tenant_id"], credential_id, m)
    rec = db.get("runtime_keys", "_global", m["key_hash"])
    if rec:
        rec["revoked"] = True
        db.put("runtime_keys", "_global", m["key_hash"], rec)
    audit(user, "runtime.credential_revoke", credential_id)
    return {"status": "revoked", "id": credential_id}


@router.get("/runtime/policy")
def get_policy(user: dict = Depends(auth.current_user)):
    return _policy(user["tenant_id"])


@router.put("/runtime/policy")
def put_policy(req: RuntimePolicyRequest, user: dict = Depends(auth.require("admin"))):
    p = req.model_dump()
    for k, v in p.items():
        p[k] = sorted({str(x).strip() for x in v if str(x).strip()})
    db.put("runtime_policy", user["tenant_id"], "policy", p)
    # re-evaluate stored events against the new policy
    n = 0
    for e in db.items("runtime_events", user["tenant_id"]):
        v = _violations(p, e)
        if v != e.get("violations"):
            e["violations"] = v
            db.put("runtime_events", user["tenant_id"], e["event_id"], e)
            n += 1
    audit(user, "runtime.policy_update", "", {"events_reevaluated": n})
    return {**p, "events_reevaluated": n}


# ------------------------------------------------------------------ webhook integrations
@router.post("/integrations/webhooks")
def create_webhook(req: CreateWebhookRequest, user: dict = Depends(auth.require("admin"))):
    wid = db.new_id("wh_")
    secret = secrets.token_urlsafe(24)
    doc = {"id": wid, "provider": req.provider, "name": req.name, "tenant_id": user["tenant_id"], "created_at": now(), "secret_hash": _hash(secret), "secret_hmac_key": secret}
    db.put("webhooks", "_global", wid, doc)
    audit(user, "webhook.create", wid)
    return {"id": wid, "provider": req.provider, "name": req.name, "url_path": f"/integrations/webhooks/{wid}", "secret": secret,
            "note": "Send header X-Webhook-Secret: <secret> (or a GitHub X-Hub-Signature-256 HMAC) with a JSON body containing git_url or repository.clone_url. Secret is shown once."}


@router.get("/integrations/webhooks")
def list_webhooks(user: dict = Depends(auth.require("admin"))):
    return [{k: w[k] for k in ("id", "provider", "name", "created_at")} | {"url_path": f"/integrations/webhooks/{w['id']}"}
            for w in db.items("webhooks", "_global") if w["tenant_id"] == user["tenant_id"]]


@router.delete("/integrations/webhooks/{integration_id}")
def delete_webhook(integration_id: str, user: dict = Depends(auth.require("admin"))):
    w = db.get("webhooks", "_global", integration_id)
    if not w or w["tenant_id"] != user["tenant_id"]:
        raise HTTPException(404, "integration not found")
    db.delete("webhooks", "_global", integration_id)
    audit(user, "webhook.delete", integration_id)
    return {"status": "deleted", "id": integration_id}


@router.post("/integrations/webhooks/{integration_id}")
async def receive_webhook(integration_id: str, request: Request, x_webhook_secret: Optional[str] = Header(None),
                          x_hub_signature_256: Optional[str] = Header(None)):
    w = db.get("webhooks", "_global", integration_id)
    raw = await request.body()
    if not w:
        raise HTTPException(404, "integration not found")
    ok = False
    if x_webhook_secret:
        ok = hmac.compare_digest(_hash(x_webhook_secret), w["secret_hash"])
    elif x_hub_signature_256:
        mac = "sha256=" + hmac.new(w["secret_hmac_key"].encode(), raw, hashlib.sha256).hexdigest()
        ok = hmac.compare_digest(mac, x_hub_signature_256)
    if not ok:
        raise HTTPException(401, "invalid webhook secret or signature")
    try:
        payload = json.loads(raw or b"{}")
    except ValueError:
        raise HTTPException(400, "body must be JSON")
    url = payload.get("git_url") or (payload.get("repository") or {}).get("clone_url") or (payload.get("repository") or {}).get("html_url")
    if not url:
        return {"status": "ignored", "detail": "no git_url / repository.clone_url in payload"}
    try:
        s = scan_mod.create(w["tenant_id"], f"webhook:{w['name']}", git_url=url)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"status": "scan_started", "scan_id": s["id"]}
