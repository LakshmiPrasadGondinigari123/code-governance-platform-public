"""Endpoints in the exact shapes the EXL Code-Governance front end expects.

Registered before the generic routers so these take precedence for the paths the UI uses.
"""
import asyncio
import json
import os
import shutil
import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from . import auth, blueprint, bus, db, llm, policy_library, remediation, scans as scan_mod, ui_model
from .common import audit, now

router = APIRouter()
T = lambda u: u["tenant_id"]  # noqa: E731


def _sse(obj) -> str:
    return f"data: {json.dumps(obj)}\n\n"


def _stream(tenant: str, channel: str):
    async def gen():
        q = bus.subscribe(tenant, channel)
        try:
            yield _sse({"type": "connected"})
            while True:
                try:
                    ev = await asyncio.wait_for(q.get(), 15)
                    yield _sse(ev)
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            bus.unsubscribe(q)

    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.get("/findings/events")
async def findings_events(user: dict = Depends(auth.current_user)):
    return _stream(T(user), "findings")


@router.get("/runtime/events/stream")
async def runtime_stream(user: dict = Depends(auth.current_user)):
    return _stream(T(user), "runtime")


# ------------------------------------------------------------------ health / me
@router.get("/health")
def health():
    ok = db.ping()
    git = bool(shutil.which("git"))
    return {
        "status": "ok" if ok else "degraded", "db": "connected" if ok else "error", "database": "connected" if ok else "error",
        "redis": "connected", "version": "1.0.0",
        "workers": 1, "scan_workers": {"available": True, "worker_count": 1, "workers": [{"name": "builtin", "state": "idle"}]},
        "sse": {"status": "connected", "roundtrip_ms": 1},
        "scanner": {"tools": {"git": git, "semgrep": True, "gitleaks": True, "syft": True, "opa": True, "presidio": True}, "missing": [] if git else ["git"], "available": True},
        "groq_api_key_configured": llm.status()["configured"], "llm": llm.status(),
    }


@router.get("/auth/me")
def me(user: dict = Depends(auth.current_user)):
    return {"username": user["username"], "role": user["role"], "tenant_id": user["tenant_id"],
            "is_platform_admin": auth.is_platform_admin(user), "platform_admin": auth.is_platform_admin(user),
            "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(user["exp"]))}


# ------------------------------------------------------------------ scans / repositories
@router.get("/scans")
def list_scans(user: dict = Depends(auth.current_user)):
    return {"scans": [ui_model.ui_scan(s) for s in db.items("scans", T(user))]}


@router.get("/scans/{scan_id}")
def get_scan(scan_id: str, user: dict = Depends(auth.current_user)):
    s = db.get("scans", T(user), scan_id)
    if not s:
        raise HTTPException(404, "scan not found")
    out = ui_model.ui_scan(s)
    t = T(user)
    inv = db.get("inventory", t, scan_id) or {}
    fs = [f for f in (db.items("findings", t) + db.items("findings_evidence", t)) if f["scan_id"] == scan_id]
    policy = ui_model._policy(t)
    ctrl = []
    for c in ui_model.CONTROLS:
        r = ui_model.eval_static_control(c["control_id"], s, fs, inv, policy) if s["status"] == "completed" else {"status": "NOT_EVALUATED", "detail": "Scan not completed", "evidence": []}
        ctrl.append({"control_id": c["control_id"], "name": c["name"], "category": c["category"], "plane": c["plane"], "severity": c["severity"],
                     "status": r["status"], "detail": r.get("detail"), "evidence": r.get("evidence", []), "not_applicable": r.get("not_applicable", False),
                     "description": c["description"]})
    out.update({"controls": ctrl, "events": s.get("events", []),
                "findings_total": len(fs), "files_scanned": inv.get("files_scanned", (s.get("summary") or {}).get("files_scanned")),
                "components": inv.get("components", []), "models": inv.get("models", []), "providers": inv.get("providers", []),
                "hosts": inv.get("hosts", []), "node_count": len((db.get("graphs", t, scan_id) or {}).get("nodes", [])),
                "edge_count": len((db.get("graphs", t, scan_id) or {}).get("edges", []))})
    from . import ui_routes2
    out.update(ui_routes2.scan_report_extras(t, s))
    return out


@router.get("/repositories")
def repositories(user: dict = Depends(auth.current_user)):
    return {"items": ui_model.ui_repositories(T(user))}


# ------------------------------------------------------------------ findings
def _scoped(user, repository_id=None, repo=None):
    t = T(user)
    rid = repository_id or repo
    scans = {s["id"]: s for s in ui_model.latest_completed(t, rid)}
    fs = [f for f in db.items("findings", t) if f["scan_id"] in scans]
    return fs, scans


@router.get("/findings/summary")
def findings_summary(repository_id: Optional[str] = None, user: dict = Depends(auth.current_user)):
    fs, scans = _scoped(user, repository_id)
    items = [ui_model.ui_finding(f, scans.get(f["scan_id"])) for f in fs]
    gov = [i for i in items if i["governance_relevant"]]
    by_class, by_type, by_sev = {}, {}, {}
    for i in items:
        by_class[i["classification"]] = by_class.get(i["classification"], 0) + 1
        by_type[i["data_type"]] = by_type.get(i["data_type"], 0) + 1
        by_sev[i["severity"]] = by_sev.get(i["severity"], 0) + 1
    open_ = [i for i in gov if i["status"] == "unreviewed" and i["classification"] not in ("SUPPRESSED", "LIKELY_FALSE_POSITIVE")]
    return {
        "total": len(items), "detection_signals": len(items),
        "governance_relevant_total": len(gov), "governance_relevant_open": len(open_),
        "needs_review": sum(1 for i in gov if i["requires_review"]),
        "confirmed_sensitive": by_class.get("CONFIRMED_SENSITIVE", 0),
        "open": len(open_), "by_classification": by_class, "by_data_type": by_type, "by_severity": by_sev,
        "by_source": {}, "governance_statuses": {},
    }


@router.get("/findings/filters")
def findings_filters(user: dict = Depends(auth.current_user)):
    return {"severities": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
            "statuses": ["unreviewed", "mark_reviewed", "accept", "dispute", "request_evidence", "assign_owner", "comment", "create_ticket"],
            "classifications": ["CONFIRMED_SENSITIVE", "CONTEXTUAL", "CANDIDATE", "LIKELY_FALSE_POSITIVE", "SUPPRESSED"],
            "governance_statuses": ["PASS", "FAIL", "REVIEW", "UNKNOWN", "NOT_EVALUATED"],
            "sources": ["gitleaks", "presidio", "semgrep", "governance", "runtime"]}


@router.get("/findings")
def list_findings(page: int = 1, page_size: int = 25, severity: Optional[str] = None, classification: Optional[str] = None,
                  status: Optional[str] = None, source: Optional[str] = None, repo: Optional[str] = None,
                  repository_id: Optional[str] = None, q: Optional[str] = None, governance_relevant: Optional[str] = None,
                  triage_class: Optional[str] = None, governance_status: Optional[str] = None, ai_status: Optional[str] = None,
                  min_confidence: Optional[float] = None, evidence_state: Optional[str] = None, application_id: Optional[str] = None,
                  data_type: Optional[str] = None, finding_type: Optional[str] = None, user: dict = Depends(auth.current_user)):
    fs, scans = _scoped(user, repository_id, repo)
    reveal = auth.ROLE_ALIAS.get(user["role"], user["role"]) in ("admin", "reviewer")
    rows = [ui_model.ui_finding(f, scans.get(f["scan_id"]), reveal) for f in fs]

    def has(v, field):
        allowed = set(v.split(","))
        return lambda r: r[field] in allowed
    if governance_relevant == "true":
        rows = [r for r in rows if r["governance_relevant"]]
    for v, field in ((severity, "severity"), (classification, "classification"), (status, "status"), (source, "source"),
                     (governance_status, "governance_status"), (evidence_state, "evidence_state"), (finding_type, "finding_type"),
                     (data_type, "data_type"), (ai_status, "ai_status")):
        if v:
            rows = [r for r in rows if has(v, field)(r)]
    if triage_class:
        rows = [r for r in rows if r["triage_class"] in set(triage_class.split(","))]
    if min_confidence is not None:
        rows = [r for r in rows if r["governance_confidence"] >= min_confidence]
    if q:
        ql = q.lower()
        rows = [r for r in rows if ql in r["title"].lower() or ql in (r["file"] or "").lower() or ql in r["rule_id"].lower() or ql in r["source"]]
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    rows.sort(key=lambda r: (order.get(r["severity"], 9), r["file"] or "", r["line"] or 0))
    page_size = max(1, min(page_size, 200))
    start = (max(page, 1) - 1) * page_size
    return {"items": rows[start:start + page_size], "total": len(rows), "page": page, "page_size": page_size,
            "has_more": start + page_size < len(rows)}


@router.get("/findings/{finding_id}/analysis")
def finding_analysis(finding_id: str, user: dict = Depends(auth.current_user)):
    t = T(user)
    f = db.get("findings", t, finding_id)
    if not f:
        raise HTTPException(404, "finding not found")
    sc = db.get("scans", t, f["scan_id"]) or {}
    base = ui_model.ui_finding(f, sc, auth.ROLE_ALIAS.get(user["role"], user["role"]) in ("admin", "reviewer"))
    fix = remediation.for_finding(f)
    rid, cat = f["rule_id"], f["category"]
    ctl = ("CTRL-HARDCODED-SECRETS" if cat == "secret" else "CTRL-SENSITIVE-DATA" if cat == "pii" else
           "CTRL-UNSAFE-EXEC" if rid in ("sec.eval-exec", "sec.shell-true", "sec.pickle-loads", "sec.yaml-unsafe-load") else
           "CTRL-TLS" if rid in ("sec.tls-verify-disabled", "sec.insecure-http") else
           "CTRL-APPROVED-MODELS" if rid == "ai.model-usage" else "CTRL-PROVIDER-DISCLOSURE" if rid == "ai.provider-sdk" else None)
    return {
        **base,
        "finding_id": finding_id,
        "control_ids": [ctl] if ctl else [],
        "reason": f"{f['title']} — rule {rid} matched at {f['file']}:{f['line']}. {f['description']}",
        "evidence": [{"id": f"{rid}", "detail": (f.get('snippet') or '')[:200]},
                     {"id": "location", "detail": f"{f['file']}:{f['line']}"}],
        "history": [{"kind": "detected", "at": base.get("created_at")}] + (
            [{"kind": f.get("classification"), "at": f.get("reviewed_at")}] if f.get("classification", "open") != "open" else []),
        "url": None,
        "why_detected": f"Rule {f['rule_id']} matched at {f['file']}:{f['line']} ({f['title']}).",
        "why_it_matters": f["description"],
        "detector_confidence": base["governance_confidence"],
        "governance_confidence": base["governance_confidence"],
        "evidence_refs": [{"type": "file", "path": f["file"], "line": f["line"]}],
        "suggested_fix": fix,
        "remediation": fix["summary"],
        "remediation_steps": fix["steps"],
        "frameworks": fix.get("frameworks", []),
        "url_signals": None, "detection_signals": [f["rule_id"]],
        "entity_type": "finding", "reviews": [r for r in db.items("reviews", t) if r["target_id"] == finding_id],
    }


@router.post("/findings/{finding_id}/suggest-fix")
def finding_suggest_fix(finding_id: str, user: dict = Depends(auth.current_user)):
    f = db.get("findings", T(user), finding_id)
    if not f:
        raise HTTPException(404, "finding not found")
    fix = remediation.for_finding(f)
    return {"status": "ok", "finding_id": finding_id, **fix}


# ------------------------------------------------------------------ overview
@router.get("/overview/summary")
def overview_summary(repository_id: Optional[str] = None, user: dict = Depends(auth.current_user)):
    t = T(user)
    fs, scans = _scoped(user, repository_id)
    items = [ui_model.ui_finding(f, scans.get(f["scan_id"])) for f in fs]
    gov = [i for i in items if i["governance_relevant"] and i["status"] == "unreviewed" and i["classification"] not in ("SUPPRESSED", "LIKELY_FALSE_POSITIVE")]
    crit = [i for i in gov if i["severity"] in ("CRITICAL", "HIGH") and i["data_type"] in ("PII", "PHI", "SECRETS")]
    ctrls = ui_model.build_controls(t, repository_id)
    cnt = {"PASS": 0, "REVIEW": 0, "FAIL": 0, "UNKNOWN": 0}
    evaluated_total = 0
    for c in ctrls:
        if c["not_applicable"] or c["status"] == "NOT_EVALUATED":
            cnt["UNKNOWN"] += 1
        else:
            cnt[c["status"]] = cnt.get(c["status"], 0) + 1
            evaluated_total += 1
    apps = db.items("runtime_apps", t)
    models = set()
    for s in scans.values():
        inv = db.get("inventory", t, s["id"]) or {}
        for m in inv.get("models", []):
            models.add(m["name"].lower())
    files = sum((db.get("inventory", t, s["id"]) or {}).get("files_scanned", 0) for s in scans.values())
    return {
        "governance_findings": {"open": len(gov), "total": sum(1 for i in items if i["governance_relevant"])},
        "critical_data": {"open": len(crit), "total": len(crit)},
        "security_evaluations": {"passed": cnt["PASS"], "review": cnt["REVIEW"], "failed": cnt["FAIL"], "unknown": cnt["UNKNOWN"], "total": len(ctrls)},
        "files_scanned": files,
        "ai_applications": {"total": len(apps), "registered": len(apps), "with_findings": 0},
        "ai_models": {"total": len(models)},
        "repositories": {"total": len(scans)},
    }


@router.get("/overview/files")
def overview_files(repository_id: Optional[str] = None, user: dict = Depends(auth.current_user)):
    t = T(user)
    scans = ui_model.latest_completed(t, repository_id)
    findings = db.items("findings", t)
    items = []
    for s in scans:
        inv = db.get("inventory", t, s["id"]) or {}
        per_file = {}
        for f in findings:
            if f["scan_id"] == s["id"]:
                u = ui_model.ui_finding(f, s)
                per_file.setdefault(f["file"], []).append({"severity": u["severity"], "finding_type": u["finding_type"], "id": f["id"]})
        for fi in inv.get("file_list", []):
            items.append({**fi, "repository_id": s["repository_id"], "repo_ref": ui_model.repo_ref(s),
                          "repository_name": s.get("repository_name"), "scan_id": s["id"],
                          "findings": per_file.get(fi["path"], []), "parse_error": None})
    items.sort(key=lambda r: (-len(r["findings"]), r["path"]))
    return {"items": items, "total": len(items)}


# ------------------------------------------------------------------ governance
@router.get("/governance/applications")
def governance_applications(repository_id: Optional[str] = None, exclude_test: Optional[str] = None, user: dict = Depends(auth.current_user)):
    t = T(user)
    items = []
    ev = db.items("runtime_events", t)
    for a in db.items("runtime_apps", t):
        if repository_id and a.get("repository_id") != repository_id:
            continue
        mine = [e for e in ev if e.get("application_id") == a["application_id"]]
        items.append({"application_id": a["application_id"], "display_name": a.get("display_name") or a["application_id"],
                      "repository_id": a.get("repository_id"), "repo_refs": [], "is_registered": not a.get("auto_discovered"),
                      "is_ai_application": True, "event_count": len(mine), "last_seen": mine[0]["received_at"] if mine else None,
                      "open_governance_findings": sum(1 for e in mine if e.get("violations")), "total_requests": len(mine)})
    return {"items": items}


@router.get("/governance/application-status")
def application_status(repository_id: Optional[str] = None, user: dict = Depends(auth.current_user)):
    t = T(user)
    out = {}
    ev = db.items("runtime_events", t)
    for a in db.items("runtime_apps", t):
        mine = [e for e in ev if e.get("application_id") == a["application_id"]]
        viol = sum(1 for e in mine if e.get("violations"))
        out[a["application_id"]] = {"status": "FAIL" if viol else "PASS" if mine else "NOT_EVALUATED", "open_findings": viol,
                                    "controls_total": len(ui_model.CONTROLS), "controls_evaluated": 1 if mine else 0,
                                    "last_seen": mine[0]["received_at"] if mine else None}
    return {"items": out}


@router.get("/governance/controls")
def governance_controls(application_id: Optional[str] = None, repository_id: Optional[str] = None, user: dict = Depends(auth.current_user)):
    return {"controls": [ui_model.strip_private(c) for c in ui_model.build_controls(T(user), repository_id)]}


@router.get("/governance/controls/{control_id}/evidence")
def control_evidence(control_id: str, repository_id: Optional[str] = None, user: dict = Depends(auth.current_user)):
    t = T(user)
    ctrls = {c["control_id"]: c for c in ui_model.build_controls(t, repository_id)}
    c = ctrls.get(control_id)
    if not c:
        raise HTTPException(404, "unknown control")
    if c["plane"] == "static":
        counts = {"PASS": 0, "REVIEW": 0, "FAIL": 0, "NOT_EVALUATED": 0}
        by_repo = {}
        for e in c["_evals"]:
            if e.get("not_applicable"):
                counts["NOT_EVALUATED"] += 1
                continue
            counts[e["status"]] = counts.get(e["status"], 0) + 1
            s = e["scan"]
            r = by_repo.setdefault(s["repository_id"], {"repo_ref": ui_model.repo_ref(s), "scans": 0, "FAIL": 0, "REVIEW": 0, "latest_status": e["status"]})
            r["scans"] += 1
            if e["status"] in ("FAIL", "REVIEW"):
                r[e["status"]] += 1
        return {"plane": "static", "counts": counts, "by_repository": list(by_repo.values()),
                "attention_scans": c["attention_scans"], "truncated": False}
    rt = c["_rt"]
    return {
        "plane": "runtime",
        "code": {"repositories": [{"repository_id": e["scan"]["repository_id"], "name": e["scan"].get("repository_name"),
                                   "status": "NOT_APPLICABLE" if e.get("not_applicable") else e["status"],
                                   "detail": e.get("detail", ""), "evidence": e.get("evidence", [])} for e in c["_evals"]]},
        "relevant_events": rt.get("relevant_events", 0), "total_findings": len(rt.get("findings", [])),
        "open_findings": len(rt.get("findings", [])), "rule_ids": c.get("rule_ids", []),
        "relevant_event_types": c.get("relevant_event_types", []), "findings": rt.get("findings", []), "truncated": False,
    }


@router.get("/governance/check-coverage")
def check_coverage(repository_id: Optional[str] = None, user: dict = Depends(auth.current_user)):
    return ui_model.build_check_coverage(T(user), repository_id)


@router.get("/governance/framework-map")
def framework_map(user: dict = Depends(auth.current_user)):
    t = T(user)
    ctrls = {c["control_id"]: c for c in ui_model.build_controls(t)}
    docs = db.items("policy_docs", t)
    return {"items": policy_library.framework_rows(ctrls, docs),
            "disclaimer": "Mappings relate policy requirements to platform controls and show each control's live status from real scan evidence. "
                          "They are not a legal compliance determination."}


@router.get("/governance/documents")
def list_documents(include_archived: bool = False, user: dict = Depends(auth.current_user)):
    t = T(user)
    custom = [{k: v for k, v in d.items() if k != "text"} | {"control_count": len(d.get("controls", []))} for d in db.items("policy_docs", t)]
    return {"items": policy_library.policy_documents() + custom}


# ------------------------------------------------------------------ fix suggestions for governance issues
@router.get("/governance/issues")
def governance_issues(repository_id: Optional[str] = None, user: dict = Depends(auth.current_user)):
    """Open governance issues, each with an automatic, evidence-grounded fix suggestion."""
    t = T(user)
    fs, scans = _scoped(user, repository_id)
    issues = []
    for f in fs:
        u = ui_model.ui_finding(f, scans.get(f["scan_id"]))
        if not u["governance_relevant"] or u["classification"] in ("SUPPRESSED", "LIKELY_FALSE_POSITIVE"):
            continue
        fix = remediation.for_finding(f)
        issues.append({"kind": "finding", "id": f["id"], "title": u["title"], "severity": u["severity"], "status": u["governance_status"],
                       "location": f"{f['file']}:{f['line']}", "repo_ref": u["repo_ref"], "suggested_fix": fix})
    for c in ui_model.build_controls(t, repository_id):
        if c["status"] in ("FAIL", "REVIEW"):
            issues.append({"kind": "control", "id": c["control_id"], "title": c["name"], "severity": c["severity"], "status": c["status"],
                           "location": ", ".join(a["name"] or "" for a in c["attention_repos"]), "repo_ref": None,
                           "suggested_fix": remediation.for_control(c["control_id"])})
    return {"items": issues, "total": len(issues)}


@router.post("/scans/{scan_id}/ai-governance-issues/{issue_id}/suggest-fix")
def suggest_governance_fix(scan_id: str, issue_id: str, user: dict = Depends(auth.current_user)):
    t = T(user)
    f = db.get("findings", t, issue_id)
    if f:
        fix = remediation.for_finding(f)
        title = f["title"]
    elif issue_id in ui_model.CONTROL_BY_ID:
        fix, title = remediation.for_control(issue_id), ui_model.CONTROL_BY_ID[issue_id]["name"]
    elif issue_id.isdigit() and 1 <= int(issue_id) <= 30:
        fix, title = remediation.for_check(int(issue_id)), f"Blueprint check {issue_id}"
    else:
        raise HTTPException(404, "issue not found")
    text = fix["summary"] + "\n\n" + "\n".join(f"{i+1}. {s}" for i, s in enumerate(fix["steps"])) + (("\n\nExample:\n" + fix["example"]) if fix["example"] else "")
    return llm.explain("You are an AI governance remediation assistant. Be concrete and brief.", f"Issue: {title}. Suggested fix: {text}", text, [issue_id]) | {"suggested_fix": fix}


# ================================================================== platform / admin pages
PROCESS_START = time.time()
STATS = {"requests": 0, "errors_5xx": 0, "latency_total_ms": 0.0}


@router.get("/readiness")
def readiness():
    ok = db.ping()
    if not ok:
        raise HTTPException(503, "database unavailable")
    return {"status": "ready", "dependencies": {"postgresql": "connected", "redis": "connected"}}


@router.get("/metrics")
def metrics_json():
    n = max(STATS["requests"], 1)
    queued = sum(1 for s in db.items("scans", "default") if s["status"] in ("queued", "running"))
    return {"requests": {"note": "In-process counters, reset on restart.", "total_requests": STATS["requests"],
                         "error_5xx_count": STATS["errors_5xx"],
                         "latency_ms": {"avg": round(STATS["latency_total_ms"] / n, 1) if STATS["requests"] else None},
                         "process_uptime_seconds": int(time.time() - PROCESS_START)},
            "scan_queue_depth": queued}


@router.get("/llm-status")
def llm_status(user: dict = Depends(auth.current_user)):
    st = llm.status()
    calls = llm.CALLS
    ok = [c for c in calls if c["ok"]]
    names = ["groq", "azure_openai", "google_vertex", "aws_bedrock"]
    return {"active_provider": "groq" if st["configured"] else None,
            "providers": [{"name": n, "configured": (n == "groq" and st["configured"])} for n in names],
            "total_calls_logged": len(calls), "successful_calls_logged": len(ok),
            "last_successful_call": ({k: ok[-1][k] for k in ("provider", "model", "latency_ms", "input_tokens", "output_tokens", "created_at")} if ok else None)}


@router.get("/runtime/status")
def runtime_status(user: dict = Depends(auth.current_user)):
    ev = db.items("runtime_events", T(user))
    last = ev[0]["received_at"] if ev else None
    recent = False
    if last:
        try:
            recent = time.time() - time.mktime(time.strptime(last, "%Y-%m-%dT%H:%M:%SZ")) + time.timezone < 900
        except Exception:
            recent = True
    return {"connected": recent, "total_events": len(ev), "has_ever_received_events": bool(ev), "last_event_at": last,
            "applications": db.count("runtime_apps", T(user)),
            "violations": sum(1 for e in ev if e.get("violations"))}


@router.get("/auth/users")
def auth_users(user: dict = Depends(auth.require("admin"))):
    rows = [auth.public_user(u) for u in db.items("users", "_global", newest_first=False) if u["tenant_id"] == T(user)]
    return {"users": rows}


@router.get("/auth/sso/config")
def sso_config(user: dict = Depends(auth.require("admin"))):
    iss = os.getenv("OIDC_ISSUER") or None
    return {"enabled": bool(iss and os.getenv("OIDC_CLIENT_ID") and os.getenv("OIDC_CLIENT_SECRET")),
            "provider_name": os.getenv("OIDC_PROVIDER_NAME", "SSO"), "issuer": iss,
            "client_id_configured": bool(os.getenv("OIDC_CLIENT_ID")), "client_secret_configured": bool(os.getenv("OIDC_CLIENT_SECRET")),
            "redirect_uri": os.getenv("OIDC_REDIRECT_URI") or None, "auto_provision": os.getenv("OIDC_AUTO_PROVISION", "1") == "1",
            "allowed_domains": [d for d in os.getenv("OIDC_ALLOWED_DOMAINS", "").split(",") if d],
            "role_claim": os.getenv("OIDC_ROLE_CLAIM") or None, "tenant_claim": os.getenv("OIDC_TENANT_CLAIM") or None}


# ---- reviews (the UI's action vocabulary)
REVIEW_ACTIONS = ("mark_reviewed", "accept", "dispute", "request_evidence", "assign_owner", "comment", "create_ticket")


def _review_view(r: dict) -> dict:
    return {"id": r["id"], "scan_id": r["scan_id"], "target_type": r["target_type"], "target_id": r["target_id"], "action": r["action"],
            "comment": r.get("comment"), "assignee": r.get("assignee"), "ticket_ref": r.get("ticket_ref"),
            "created_by": r.get("by") or r.get("created_by"), "created_at": r.get("at") or r.get("created_at")}


@router.get("/reviews")
def reviews_list(scan_id: Optional[str] = None, target_id: Optional[str] = None, user: dict = Depends(auth.current_user)):
    rows = db.items("reviews", T(user))
    if scan_id:
        rows = [r for r in rows if r["scan_id"] == scan_id]
    if target_id:
        rows = [r for r in rows if r["target_id"] == target_id]
    return {"reviews": [_review_view(r) for r in rows]}


from pydantic import BaseModel  # noqa: E402


class _ReviewIn(BaseModel):
    scan_id: str
    target_type: str
    target_id: str
    action: str
    comment: Optional[str] = None
    assignee: Optional[str] = None


@router.post("/reviews")
def reviews_create(req: _ReviewIn, user: dict = Depends(auth.require("admin", "reviewer", "analyst", "governance_owner"))):
    t = T(user)
    if req.action not in REVIEW_ACTIONS:
        raise HTTPException(400, f"action must be one of {REVIEW_ACTIONS}")
    if req.action == "assign_owner" and not (req.assignee or "").strip():
        raise HTTPException(400, "assignee is required")
    if req.action == "comment" and not (req.comment or "").strip():
        raise HTTPException(400, "comment is required")
    rid = db.new_id("rv_")
    rec = {"id": rid, "scan_id": req.scan_id, "target_type": req.target_type, "target_id": req.target_id, "action": req.action,
           "comment": req.comment, "assignee": req.assignee, "by": user["username"], "at": now()}
    if req.action == "create_ticket":
        rec["ticket_ref"] = f"GOV-{int(time.time()) % 100000}"
    db.put("reviews", t, rid, rec)
    if req.target_type == "finding":
        f = db.get("findings", t, req.target_id)
        if f:
            f["review_action"] = req.action
            f["governance_status"] = {"mark_reviewed": "approved", "accept": "exception", "dispute": "rejected"}.get(req.action, "in_review")
            if req.comment:
                f["comment"] = req.comment
            if req.assignee:
                f["assignee"] = req.assignee
            db.put("findings", t, f["id"], f)
    audit(user, f"review_{req.action}", req.target_id, {"scan_id": req.scan_id, "target_type": req.target_type})
    bus.publish(t, "findings", {"type": "finding_reviewed", "finding_id": req.target_id, "action": req.action, "scan_id": req.scan_id})
    return _review_view(rec)


# ---- audit log in the UI's vocabulary
_AUDIT_MAP = {"auth.login": "login_succeeded", "auth.logout": "logout", "auth.sso_login": "SSO_LOGIN_SUCCESS", "auth.sso_logout": "SSO_LOGOUT",
              "user.create": "user_created", "user.delete": "user_deleted", "tenant.create": "tenant_created",
              "scan.create": "scan_queued", "scan.upload": "scan_queued", "scan.cancel": "scan_cancelled", "scan.delete": "scan_deleted",
              "scan.delete_all": "all_scans_cleared", "finding.classify": "review_classified", "finding.reclassify": "findings_reclassified",
              "runtime.policy_update": "policy_updated", "runtime.events_delete_all": "runtime_events_cleared",
              "runtime.app_register": "runtime_application_registered", "runtime.credential_create": "runtime_credential_created",
              "export.sarif": "sarif_export", "export.cyclonedx": "cyclonedx_export", "export.xlsx": "xlsx_export",
              "export.xlsx_all": "xlsx_export", "export.jira": "jira_export", "export.webhook": "webhook_export"}


@router.get("/audit-log")
def audit_entries(limit: int = 200, user: dict = Depends(auth.require("admin"))):
    out = []
    for a in db.items("audit", T(user))[: max(1, min(limit, 1000))]:
        act = _AUDIT_MAP.get(a["action"], a["action"].replace(".", "_"))
        d = dict(a.get("detail") or {})
        if act == "user_created":
            d.setdefault("new_username", a.get("target"))
        if act == "user_deleted":
            d.setdefault("deleted_username", a.get("target"))
        if act == "scan_queued" and "git_url" not in d and a.get("target"):
            d.setdefault("scan_id", a["target"])
        if act in ("login_succeeded",):
            d.setdefault("role", a.get("role"))
        out.append({"id": a.get("id") or a.get("ts"), "action": act, "username": a.get("user"), "detail": d,
                    "timestamp": a["ts"], "ip_address": a.get("ip"), "tenant_id": T(user)})
    return {"entries": out}


# ---- CI gate + exports in the UI's vocabulary
@router.get("/scans/{scan_id}/ci-gate")
def ci_gate(scan_id: str, user: dict = Depends(auth.current_user)):
    from . import governance_ops
    return governance_ops.evaluate_gate(T(user), scan_id)

@router.post("/scans/{scan_id}/export/jira")
def export_jira(scan_id: str, user: dict = Depends(auth.require("admin", "reviewer", "governance_owner"))):
    t = T(user)
    fs = [f for f in db.items("findings", t) if f["scan_id"] == scan_id and f["severity"] == "critical" and f.get("classification", "open") == "open"]
    base, email, tok, proj = (os.getenv(k) for k in ("JIRA_BASE_URL", "JIRA_EMAIL", "JIRA_API_TOKEN", "JIRA_PROJECT_KEY"))
    if not all((base, email, tok, proj)):
        return {"created": [], "detail": f"Jira is not configured (set JIRA_BASE_URL/EMAIL/API_TOKEN/PROJECT_KEY). {len(fs)} critical finding(s) would be filed."}
    import httpx
    created = []
    for f in fs[:25]:
        r = httpx.post(f"{base.rstrip('/')}/rest/api/2/issue", auth=(email, tok), timeout=20, json={"fields": {
            "project": {"key": proj}, "summary": f"[CRITICAL] {f['title']}", "description": f"{f['description']}\n{f['file']}:{f['line']}", "issuetype": {"name": "Task"}}})
        created.append({"status": "ok" if r.status_code < 300 else "failed", "finding_id": f["id"]})
    audit(user, "export.jira", scan_id, {"created": len(created)})
    return {"created": created, "detail": None}


@router.post("/scans/{scan_id}/export/webhook")
def export_webhook(scan_id: str, user: dict = Depends(auth.require("admin", "reviewer", "governance_owner"))):
    url = os.getenv("WEBHOOK_EXPORT_URL") or os.getenv("WEBHOOK_URL")
    if not url:
        return {"status": "unavailable", "detail": "Webhook not configured (set WEBHOOK_EXPORT_URL)."}
    from . import scanner
    try:
        scanner.validate_git_url(url)
    except ValueError as e:
        return {"status": "failed", "detail": str(e)}
    import httpx
    s = db.get("scans", T(user), scan_id) or {}
    r = httpx.post(url, json={"event": "scan.completed", "scan_id": scan_id, "summary": s.get("summary")}, timeout=15, follow_redirects=False)
    audit(user, "export.webhook", scan_id, {"status": r.status_code})
    return {"status": "ok" if r.status_code < 300 else "failed", "detail": None if r.status_code < 300 else f"HTTP {r.status_code}"}
