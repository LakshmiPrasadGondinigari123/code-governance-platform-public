"""Release-gate policy, waivers with owner/expiry, signed evidence packs and push-triggered rescans.

Everything here maps to the blueprint: policy applicability + CI gate decisions (section 2, item 6), exceptions that
"require owner, approver, rationale, compensating controls, expiry and rescan conditions" (section 7), signed artifacts
(phase 3) and "changes in commits ... trigger reassessment" (user journey, step 12).
"""
import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from . import auth, db, scans as scan_mod
from .common import audit

router = APIRouter()
MAX_WAIVER_DAYS = 180

DEFAULT_POLICY = {
    "block_on": {
        "secrets": True,            # any hard-coded credential
        "critical": True,           # any critical finding
        "phi": True,                # health information in code
        "pii": "high",              # personal data at this severity or above ("off" to disable)
        "code_security": "high",    # code-security findings at this severity or above ("off" to disable)
    },
}
_SEV = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _iso(ts=None):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts if ts is not None else time.time()))


def get_policy(tenant: str) -> dict:
    doc = db.get("settings", tenant, "gate_policy")
    base = json.loads(json.dumps(DEFAULT_POLICY))
    if doc:
        base["block_on"].update(doc.get("block_on", {}))
        version = doc.get("version")
    else:
        version = None
    if not version:
        version = "policy-1.1.0"
    base["version"] = version
    return base


def _ts(s):
    try:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
    except Exception:
        return 0


def active_waivers(tenant: str) -> dict:
    out = {}
    now = time.time()
    for w in db.items("waivers", tenant):
        if _ts(w.get("expires_at", "")) > now:
            out[w["fingerprint"]] = w
    return out


def evaluate_gate(tenant: str, scan_id: str) -> dict:
    s = db.get("scans", tenant, scan_id)
    if not s:
        raise HTTPException(404, "scan not found")
    pol = get_policy(tenant)
    if s["status"] != "completed":
        return {"block": None, "reason": "scan_not_completed", "detail": f"Scan is {s['status']}.", "policy_version": pol["version"]}
    waivers = active_waivers(tenant)
    live, waived = [], []
    for f in db.items("findings", tenant):
        if f["scan_id"] != scan_id or f.get("classification", "open") != "open":
            continue
        (waived if f.get("fingerprint") in waivers else live).append(f)
    b = pol["block_on"]
    reasons = []

    def add(rule, label, rows):
        if rows:
            reasons.append({"rule": rule, "label": label, "count": len(rows),
                            "examples": [{"file": r["file"], "line": r["line"], "title": r["title"]} for r in rows[:3]]})

    if b.get("secrets"):
        add("secrets", "Hard-coded credentials in code", [f for f in live if f["category"] == "secret" and f.get("context") != "test"])
    if b.get("critical"):
        add("critical", "Critical findings", [f for f in live if f["severity"] == "critical" and f["category"] != "secret"])
    if b.get("phi"):
        add("phi", "Health information in code", [f for f in live if f["rule_id"].startswith("phi.")])
    thr = b.get("pii")
    if thr and thr != "off":
        add("pii", "Personal data in code", [f for f in live if f["category"] == "pii" and not f["rule_id"].startswith("phi.")
                                              and _SEV.get(f["severity"], 0) >= _SEV.get(thr, 3)])
    thr = b.get("code_security")
    if thr and thr != "off":
        add("code_security", "Code-security findings", [f for f in live if f["category"] == "security" and _SEV.get(f["severity"], 0) >= _SEV.get(thr, 3)])
    block = bool(reasons)
    return {
        "block": block,
        "reason": ",".join(r["rule"] for r in reasons) if block else "clear",
        "reasons": reasons,
        "waived": len(waived),
        "policy_version": pol["version"],
        "secrets": sum(r["count"] for r in reasons if r["rule"] == "secrets"),
        "critical": sum(r["count"] for r in reasons if r["rule"] == "critical"),
        "code_security": sum(r["count"] for r in reasons if r["rule"] == "code_security"),
        "detail": None if block else "No blocking conditions under the active policy.",
    }


# ------------------------------------------------------------------ detection scope
SCOPE_ALL = ("pii", "phi", "secrets", "code_security", "ai_inventory")
DEFAULT_SCOPE = ["pii", "phi", "secrets", "code_security", "ai_inventory"]  # all ten checks are evaluated; only PII/PHI are listed as findings


def get_scope(tenant: str) -> list:
    doc = db.get("settings", tenant, "detection_scope")
    return list(doc["value"]) if doc and doc.get("value") else list(DEFAULT_SCOPE)


class ScopeBody(BaseModel):
    detect: list


@router.get("/scope")
def read_scope(user: dict = Depends(auth.current_user)):
    return {"detect": get_scope(user["tenant_id"]), "available": list(SCOPE_ALL),
            "note": "Applies to scans started after the change. Categories outside the scope are neither detected nor evaluated."}


@router.put("/scope")
def write_scope(body: ScopeBody, user: dict = Depends(auth.require("admin"))):
    bad = [x for x in body.detect if x not in SCOPE_ALL]
    if bad or not body.detect:
        raise HTTPException(400, f"detect must be a non-empty subset of {list(SCOPE_ALL)}")
    db.put("settings", user["tenant_id"], "detection_scope", {"value": sorted(set(body.detect)), "updated_by": user["username"], "updated_at": _iso()})
    audit(user, "scope.update", "detection_scope", body.detect)
    return read_scope(user)

# ------------------------------------------------------------------ policy
class PolicyBody(BaseModel):
    block_on: dict


@router.get("/policy")
def read_policy(user: dict = Depends(auth.current_user)):
    return get_policy(user["tenant_id"])


@router.put("/policy")
def write_policy(body: PolicyBody, user: dict = Depends(auth.require("admin"))):
    allowed = set(DEFAULT_POLICY["block_on"])
    unknown = set(body.block_on) - allowed
    if unknown:
        raise HTTPException(400, f"unknown policy keys: {sorted(unknown)}")
    for k in ("pii", "code_security"):
        if k in body.block_on and body.block_on[k] not in ("off", "low", "medium", "high", "critical"):
            raise HTTPException(400, f"{k} must be one of off|low|medium|high|critical")
    cur = get_policy(user["tenant_id"])["block_on"]
    cur.update(body.block_on)
    version = "policy-" + hashlib.sha256(json.dumps(cur, sort_keys=True).encode()).hexdigest()[:8]
    db.put("settings", user["tenant_id"], "gate_policy", {"block_on": cur, "version": version, "updated_by": user["username"], "updated_at": _iso()})
    audit(user, "policy.update", version, cur)
    return get_policy(user["tenant_id"])


# ------------------------------------------------------------------ waivers
class WaiverBody(BaseModel):
    owner: str
    rationale: str
    expires_at: str                     # ISO date or datetime
    compensating_controls: Optional[str] = None
    rescan_condition: Optional[str] = "Re-evaluate when this file changes or at expiry."


def _parse_expiry(s: str) -> float:
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    raise HTTPException(422, "expires_at must be YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ")


def _find(tenant: str, finding_id: str) -> dict:
    f = db.get("findings", tenant, finding_id)
    if not f:
        raise HTTPException(404, "finding not found")
    return f


@router.post("/findings/{finding_id}/waiver")
def create_waiver(finding_id: str, body: WaiverBody, user: dict = Depends(auth.require("admin", "reviewer"))):
    t = user["tenant_id"]
    f = _find(t, finding_id)
    if len(body.owner.strip()) < 2 or len(body.rationale.strip()) < 10:
        raise HTTPException(422, "owner and a rationale of at least 10 characters are required")
    exp = _parse_expiry(body.expires_at)
    if exp <= time.time():
        raise HTTPException(422, "expiry must be in the future")
    if exp > time.time() + MAX_WAIVER_DAYS * 86400:
        raise HTTPException(422, f"a waiver cannot last longer than {MAX_WAIVER_DAYS} days")
    if f["severity"] == "critical" and f["category"] == "secret":
        raise HTTPException(422, "hard-coded credentials cannot be waived: rotate the key instead")
    doc = {
        "fingerprint": f["fingerprint"], "rule_id": f["rule_id"], "file": f["file"], "line": f["line"], "title": f["title"],
        "severity": f["severity"], "owner": body.owner.strip(), "rationale": body.rationale.strip(),
        "compensating_controls": body.compensating_controls, "rescan_condition": body.rescan_condition,
        "approved_by": user["username"], "created_at": _iso(), "expires_at": _iso(exp),
    }
    db.put("waivers", t, f["fingerprint"], doc)
    audit(user, "waiver.create", finding_id, {"fingerprint": f["fingerprint"], "expires_at": doc["expires_at"]})
    return doc


@router.get("/waivers")
def list_waivers(user: dict = Depends(auth.current_user)):
    now = time.time()
    rows = db.items("waivers", user["tenant_id"])
    for w in rows:
        w["status"] = "active" if _ts(w["expires_at"]) > now else "expired"
    return {"waivers": rows, "active": sum(1 for w in rows if w["status"] == "active")}


@router.delete("/waivers/{fingerprint}")
def delete_waiver(fingerprint: str, user: dict = Depends(auth.require("admin", "reviewer"))):
    if not db.delete("waivers", user["tenant_id"], fingerprint):
        raise HTTPException(404, "waiver not found")
    audit(user, "waiver.revoke", fingerprint)
    return {"status": "revoked"}


# ------------------------------------------------------------------ signed evidence pack
def _signing_key() -> bytes:
    k = os.getenv("EVIDENCE_SIGNING_KEY")
    if k:
        return k.encode()
    doc = db.get("settings", "_global", "evidence_signing_key")
    if not doc:
        import secrets
        doc = db.put("settings", "_global", "evidence_signing_key", {"value": secrets.token_urlsafe(48)})
    return doc["value"].encode()


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _key_id() -> str:
    return hashlib.sha256(_signing_key()).hexdigest()[:12]


@router.get("/scans/{scan_id}/evidence-pack/signed")
def signed_evidence_pack(scan_id: str, user: dict = Depends(auth.current_user)):
    t = user["tenant_id"]
    s = db.get("scans", t, scan_id)
    if not s or s["status"] != "completed":
        raise HTTPException(404, "completed scan not found")
    fs = [f for f in db.items("findings", t) if f["scan_id"] == scan_id]
    gate = evaluate_gate(t, scan_id)
    pack = {
        "schema": "cgp.evidence-pack/1",
        "scan": {"id": s["id"], "repository": s.get("repo_ref") or s.get("repository_name"), "commit_sha": s.get("commit_sha"),
                 "branch": s.get("branch"), "scanned_at": s.get("scanned_at"), "files_scanned": (s.get("summary") or {}).get("files_scanned")},
        "policy_version": gate["policy_version"],
        "gate": {"block": gate["block"], "reasons": gate.get("reasons", []), "waived": gate.get("waived", 0)},
        "controls": [{k: c.get(k) for k in ("id", "name", "status", "detail")} for c in s.get("controls", [])],
        "findings": [{"id": f["id"], "rule_id": f["rule_id"], "severity": f["severity"], "file": f["file"], "line": f["line"],
                      "title": f["title"], "evidence_label": "Detected", "fingerprint": f["fingerprint"],
                      "disposition": f.get("classification", "open")} for f in fs],
        "limits": ["Static analysis is not complete.", "A finding is evidence for review, not a legal conclusion.",
                   "Unknown fields require owner confirmation."],
        "generated_at": _iso(),
    }
    body = _canonical(pack)
    sig = hmac.new(_signing_key(), body, hashlib.sha256).hexdigest()
    audit(user, "evidence_pack.sign", scan_id, {"sha256": hashlib.sha256(body).hexdigest()})
    return {"pack": pack, "sha256": hashlib.sha256(body).hexdigest(), "signature": sig, "algorithm": "HMAC-SHA256", "key_id": _key_id()}


class VerifyBody(BaseModel):
    pack: dict
    signature: str


@router.post("/evidence-pack/verify")
def verify_pack(body: VerifyBody, user: dict = Depends(auth.current_user)):
    calc = hmac.new(_signing_key(), _canonical(body.pack), hashlib.sha256).hexdigest()
    ok = hmac.compare_digest(calc, body.signature)
    return {"valid": ok, "key_id": _key_id(), "detail": "Signature matches." if ok else "The pack was changed or signed with a different key."}


# ------------------------------------------------------------------ push-triggered rescans
_LAST_PUSH = {}


@router.post("/integrations/github/webhook")
async def github_webhook(request: Request):
    secret = os.getenv("GITHUB_WEBHOOK_SECRET")
    if not secret:
        raise HTTPException(503, "GITHUB_WEBHOOK_SECRET is not configured")
    raw = await request.body()
    sig = request.headers.get("X-Hub-Signature-256", "")
    calc = "sha256=" + hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(calc, sig):
        raise HTTPException(401, "invalid signature")
    event = request.headers.get("X-GitHub-Event", "")
    if event == "ping":
        return {"status": "pong"}
    if event != "push":
        return {"status": "ignored", "event": event}
    payload = json.loads(raw or b"{}")
    repo = payload.get("repository") or {}
    url = repo.get("clone_url") or ""
    branch = (payload.get("ref") or "").rsplit("/", 1)[-1]
    if branch != repo.get("default_branch"):
        return {"status": "ignored", "reason": "not the default branch"}
    # only repositories this platform already governs are rescanned (no scanning of arbitrary repos)
    known = None
    for tenant in {u["tenant_id"] for u in [db.get("users", "_global", "admin") or {"tenant_id": "default"}]}:
        for r in db.items("repositories", tenant):
            if (r.get("url") or "").rstrip("/").removesuffix(".git").lower() == url.rstrip("/").removesuffix(".git").lower():
                known = (tenant, r)
    if not known:
        return {"status": "ignored", "reason": "repository is not registered"}
    if time.time() - _LAST_PUSH.get(url, 0) < 60:
        return {"status": "ignored", "reason": "rate limited"}
    _LAST_PUSH[url] = time.time()
    tenant, r = known
    doc = scan_mod.create(tenant, "github-webhook", git_url=r["url"])
    audit({"tenant_id": tenant, "username": "github-webhook", "role": "system"}, "scan.push_triggered", doc["id"], {"commit": (payload.get("after") or "")[:12]})
    return {"status": "scan_queued", "scan_id": doc["id"]}
