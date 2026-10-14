"""Findings, review workflow, search, overview, LLM explanations."""
import asyncio
import json
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from . import auth, db, frameworks, llm
from .common import (SEVERITIES, audit, findings_for, inventories_for, latest_scans, now, paginate, rule_help,
                     scan_or_404, scope_scans, sev_counts)

router = APIRouter()
CLASSIFICATIONS = ("open", "true_positive", "false_positive", "accepted_risk", "remediated")
GOV_STATUSES = ("unreviewed", "in_review", "approved", "rejected", "exception")


class ClassificationOverrideRequest(BaseModel):
    classification: str
    governance_status: Optional[str] = None
    comment: str = ""


class CreateReviewRequest(BaseModel):
    scan_id: str
    target_type: str
    target_id: str
    action: str
    comment: Optional[str] = None
    assignee: Optional[str] = None


class TriageRunRequest(BaseModel):
    run_ai: bool = False
    force: bool = False


def _finding_or_404(user, finding_id):
    f = db.get("findings", user["tenant_id"], finding_id)
    if not f:
        raise HTTPException(404, "finding not found")
    return f


def _scoped_findings(user, scan_id=None, repository_id=None):
    scans = scope_scans(user, scan_id, repository_id)
    return findings_for(user["tenant_id"], {s["id"] for s in scans})


# ------------------------------------------------------------------ findings
@router.get("/findings")
def list_findings(
    scan_id: Optional[str] = None, repository_id: Optional[str] = None, severity: Optional[str] = None,
    category: Optional[str] = None, classification: Optional[str] = None, rule_id: Optional[str] = None,
    file: Optional[str] = None, q: Optional[str] = None, limit: int = 100, offset: int = 0,
    user: dict = Depends(auth.current_user),
):
    rows = _scoped_findings(user, scan_id, repository_id)
    if severity:
        rows = [f for f in rows if f["severity"] in severity.split(",")]
    if category:
        rows = [f for f in rows if f["category"] in category.split(",")]
    if classification:
        rows = [f for f in rows if f.get("classification") == classification]
    if rule_id:
        rows = [f for f in rows if f["rule_id"] == rule_id]
    if file:
        rows = [f for f in rows if file.lower() in f["file"].lower()]
    if q:
        ql = q.lower()
        rows = [f for f in rows if ql in f["title"].lower() or ql in f["file"].lower() or ql in (f.get("snippet") or "").lower()]
    order = {s: i for i, s in enumerate(SEVERITIES)}
    rows.sort(key=lambda f: (order.get(f["severity"], 9), f["file"], f["line"]))
    return paginate(rows, limit, offset)


@router.get("/findings/summary")
def findings_summary(scan_id: Optional[str] = None, repository_id: Optional[str] = None, user: dict = Depends(auth.current_user)):
    rows = _scoped_findings(user, scan_id, repository_id)
    cats, cls, files = {}, {}, {}
    for f in rows:
        cats[f["category"]] = cats.get(f["category"], 0) + 1
        cls[f.get("classification", "open")] = cls.get(f.get("classification", "open"), 0) + 1
        files[f["file"]] = files.get(f["file"], 0) + 1
    top = sorted(files.items(), key=lambda kv: -kv[1])[:10]
    return {"total": len(rows), "by_severity": sev_counts(rows), "by_category": cats, "by_classification": cls,
            "top_files": [{"file": k, "findings": v} for k, v in top]}


@router.get("/findings/filters")
def findings_filters(scan_id: Optional[str] = None, repository_id: Optional[str] = None, user: dict = Depends(auth.current_user)):
    rows = _scoped_findings(user, scan_id, repository_id)
    return {
        "severities": SEVERITIES, "classifications": list(CLASSIFICATIONS), "governance_statuses": list(GOV_STATUSES),
        "categories": sorted({f["category"] for f in rows}), "rules": sorted({f["rule_id"] for f in rows}),
    }


@router.get("/findings/events")
async def findings_events(user: dict = Depends(auth.current_user)):
    tenant = user["tenant_id"]
    known = {f["id"] for f in db.items("findings", tenant)}

    async def gen():
        nonlocal known
        beat = 0
        while True:
            cur = db.items("findings", tenant)
            ids = {f["id"] for f in cur}
            for f in cur:
                if f["id"] not in known:
                    yield f"event: finding\ndata: {json.dumps(f)}\n\n"
            known = ids
            beat += 1
            if beat % 15 == 0:
                yield ": keepalive\n\n"
            await asyncio.sleep(2)

    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


def _related_controls(f: dict, scan: Optional[dict]):
    out = []
    for c in frameworks.CONTROLS:
        if f["category"] in c.get("categories", []) or f["rule_id"] in c.get("rule_ids", []):
            status = next((x["status"] for x in (scan or {}).get("controls", []) if x["control_id"] == c["id"]), None)
            out.append({"control_id": c["id"], "title": c["title"], "status": status, "refs": c["refs"]})
    return out


@router.get("/findings/{finding_id}/analysis")
def finding_analysis(finding_id: str, user: dict = Depends(auth.current_user)):
    f = _finding_or_404(user, finding_id)
    scan = db.get("scans", user["tenant_id"], f["scan_id"])
    why, fix = rule_help(f["rule_id"], f["category"])
    same_rule = [x for x in db.items("findings", user["tenant_id"]) if x["scan_id"] == f["scan_id"] and x["rule_id"] == f["rule_id"]]
    return {
        "finding": f, "why_it_matters": why, "recommended_fix": fix,
        "related_controls": _related_controls(f, scan),
        "occurrences_in_scan": len(same_rule),
        "evidence_id": f["id"],
        "reviews": [r for r in db.items("reviews", user["tenant_id"]) if r["target_id"] == finding_id],
    }


@router.post("/findings/{finding_id}/classification-override")
def override_classification(finding_id: str, req: ClassificationOverrideRequest, user: dict = Depends(auth.require("admin", "reviewer"))):
    f = _finding_or_404(user, finding_id)
    if req.classification not in CLASSIFICATIONS:
        raise HTTPException(400, f"classification must be one of {CLASSIFICATIONS}")
    if req.governance_status and req.governance_status not in GOV_STATUSES:
        raise HTTPException(400, f"governance_status must be one of {GOV_STATUSES}")
    f["classification"] = req.classification
    if req.governance_status:
        f["governance_status"] = req.governance_status
    f["comment"] = req.comment or f.get("comment")
    f["reviewed_by"], f["reviewed_at"] = user["username"], now()
    db.put("findings", user["tenant_id"], finding_id, f)
    audit(user, "finding.classify", finding_id, {"classification": req.classification})
    return f


KNOWN_HOSTS = [
    ("openai.com", "ai_provider", "OpenAI"), ("anthropic.com", "ai_provider", "Anthropic"), ("groq.com", "ai_provider", "Groq"),
    ("googleapis.com", "ai_provider_or_cloud", "Google"), ("huggingface.co", "ai_provider", "Hugging Face"),
    ("cohere.ai", "ai_provider", "Cohere"), ("cohere.com", "ai_provider", "Cohere"), ("mistral.ai", "ai_provider", "Mistral"),
    ("amazonaws.com", "cloud", "AWS"), ("azure.com", "cloud", "Azure"), ("github.com", "source_hosting", "GitHub"),
    ("pypi.org", "package_registry", "PyPI"), ("npmjs.org", "package_registry", "npm"),
]


def _triage(user, scan_id):
    inv = db.get("inventory", user["tenant_id"], scan_id)
    if not inv:
        raise HTTPException(404, "no inventory for scan (scan not completed?)")
    approved = (db.get("runtime_policy", user["tenant_id"], "policy") or {}).get("approved_api_hosts", [])
    rows = []
    for h in inv["hosts"]:
        kind, vendor = "unknown_external", None
        for suffix, k, v in KNOWN_HOSTS:
            if h == suffix or h.endswith("." + suffix):
                kind, vendor = k, v
                break
        rows.append({"host": h, "kind": kind, "vendor": vendor, "approved": h in approved if approved else None,
                     "needs_review": kind == "unknown_external" and (not approved or h not in approved)})
    doc = {"scan_id": scan_id, "generated_at": now(), "hosts": rows}
    db.put("triage", user["tenant_id"], scan_id, doc)
    return doc


@router.post("/scans/{scan_id}/url-triage")
def run_url_triage(scan_id: str, req: TriageRunRequest = TriageRunRequest(), user: dict = Depends(auth.require("admin", "reviewer"))):
    scan_or_404(user, scan_id)
    if not req.force:
        existing = db.get("triage", user["tenant_id"], scan_id)
        if existing:
            return existing
    return _triage(user, scan_id)


@router.post("/findings/triage/backfill")
def backfill_triage(user: dict = Depends(auth.require("admin", "reviewer"))):
    done = 0
    for s in db.items("scans", user["tenant_id"]):
        if s["status"] == "completed" and not db.get("triage", user["tenant_id"], s["id"]):
            _triage(user, s["id"])
            done += 1
    return {"status": "ok", "scans_triaged": done}


@router.post("/scans/{scan_id}/findings/reclassify")
def reclassify_pii(scan_id: str, user: dict = Depends(auth.require("admin", "reviewer"))):
    """Re-apply PII context rules: matches in docs/tests/fixtures are marked false_positive."""
    scan_or_404(user, scan_id)
    import re
    ctx = re.compile(r"(?i)(?:^|/)(?:docs?|tests?|fixtures?|examples?|samples?)/|\.md$|\.test\.|\.spec\.|test_")
    changed = 0
    for f in db.items("findings", user["tenant_id"]):
        if f["scan_id"] == scan_id and f["category"] == "pii" and f.get("classification") == "open" and ctx.search(f["file"]):
            f["classification"], f["comment"] = "false_positive", "Auto-reclassified: located in docs/tests/examples"
            db.put("findings", user["tenant_id"], f["id"], f)
            changed += 1
    audit(user, "finding.reclassify", scan_id, {"changed": changed})
    return {"status": "ok", "reclassified": changed}


# ------------------------------------------------------------------ reviews
@router.post("/reviews")
def create_review(req: CreateReviewRequest, user: dict = Depends(auth.require("admin", "reviewer"))):
    scan_or_404(user, req.scan_id)
    if req.action not in ("approve", "reject", "comment", "assign", "request_changes", "accept_risk"):
        raise HTTPException(400, "invalid action")
    if req.target_type not in ("finding", "control", "model", "scan"):
        raise HTTPException(400, "target_type must be finding, control, model or scan")
    if req.action == "assign" and not req.assignee:
        raise HTTPException(400, "assignee required for assign")
    review = {"id": db.new_id("rv_"), "scan_id": req.scan_id, "target_type": req.target_type, "target_id": req.target_id,
              "action": req.action, "comment": req.comment, "assignee": req.assignee, "by": user["username"], "at": now()}
    db.put("reviews", user["tenant_id"], review["id"], review)
    if req.target_type == "finding":
        f = db.get("findings", user["tenant_id"], req.target_id)
        if f:
            mapping = {"approve": "approved", "reject": "rejected", "accept_risk": "exception", "request_changes": "in_review", "assign": "in_review"}
            if req.action in mapping:
                f["governance_status"] = mapping[req.action]
                db.put("findings", user["tenant_id"], f["id"], f)
    audit(user, f"review.{req.action}", req.target_id)
    return review


@router.get("/reviews")
def list_reviews(scan_id: Optional[str] = None, target_id: Optional[str] = None, user: dict = Depends(auth.current_user)):
    rows = db.items("reviews", user["tenant_id"])
    if scan_id:
        rows = [r for r in rows if r["scan_id"] == scan_id]
    if target_id:
        rows = [r for r in rows if r["target_id"] == target_id]
    return rows


@router.get("/audit-log")
def audit_log(limit: int = 200, user: dict = Depends(auth.require("admin"))):
    return db.items("audit", user["tenant_id"])[: max(1, min(limit, 1000))]


# ------------------------------------------------------------------ repos / search / overview
@router.get("/repositories")
def list_repositories(user: dict = Depends(auth.current_user)):
    out = []
    for r in db.items("repositories", user["tenant_id"]):
        s = db.get("scans", user["tenant_id"], r.get("last_scan_id", ""))
        out.append({**r, "summary": s["summary"] if s else None})
    return out


@router.get("/search")
def search(q: str = Query(..., min_length=2), user: dict = Depends(auth.current_user)):
    ql, t = q.lower(), user["tenant_id"]
    ids = {s["id"] for s in latest_scans(t)}
    findings = [f for f in findings_for(t, ids) if ql in f["title"].lower() or ql in f["file"].lower() or ql in (f.get("snippet") or "").lower()]
    repos = [r for r in db.items("repositories", t) if ql in r["name"].lower() or ql in (r.get("url") or "").lower()]
    controls = [c for c in frameworks.CONTROLS if ql in c["title"].lower() or ql in c["id"].lower() or ql in c["description"].lower()]
    docs = [{"id": d["id"], "name": d["name"]} for d in db.items("policy_docs", t) if ql in d["name"].lower() or ql in d.get("text", "").lower()]
    return {"query": q, "findings": findings[:25], "repositories": repos[:10],
            "controls": [{"control_id": c["id"], "title": c["title"]} for c in controls], "documents": docs[:10]}


@router.get("/overview/summary")
def overview_summary(user: dict = Depends(auth.current_user)):
    t = user["tenant_id"]
    scans = latest_scans(t)
    ids = {s["id"] for s in scans}
    rows = findings_for(t, ids)
    open_rows = [f for f in rows if f.get("classification", "open") == "open"]
    ctl = {"satisfied": 0, "missing_evidence": 0, "violated": 0}
    fw_cov = {}
    for s in scans:
        for c in s.get("controls", []):
            ctl[c["status"]] = ctl.get(c["status"], 0) + 1
            for r in c["framework_refs"]:
                e = fw_cov.setdefault(r["framework"], {"satisfied": 0, "total": 0})
                e["total"] += 1
                e["satisfied"] += 1 if c["status"] == "satisfied" else 0
    inv = inventories_for(t, ids)
    models = {m["name"].lower() for i in inv for m in i["models"]}
    providers = {p["name"] for i in inv for p in i["providers"]}
    events = db.items("runtime_events", t)
    all_scans = db.items("scans", t)
    return {
        "repositories": db.count("repositories", t),
        "scans": {"total": len(all_scans), "running": sum(1 for s in all_scans if s["status"] in ("queued", "running")),
                  "failed": sum(1 for s in all_scans if s["status"] == "failed")},
        "findings": {"total": len(rows), "open": len(open_rows), "by_severity": sev_counts(open_rows),
                     "by_category": {c: sum(1 for f in rows if f["category"] == c) for c in {f["category"] for f in rows}}},
        "controls": ctl,
        "frameworks": [{"id": fw["id"], "name": fw["name"], **fw_cov.get(fw["id"], {"satisfied": 0, "total": 0})} for fw in frameworks.FRAMEWORKS],
        "ai": {"models": len(models), "providers": len(providers), "components": sum(len(i["ai_components"]) for i in inv)},
        "runtime": {"events": len(events), "violations": sum(1 for e in events if e.get("violations"))},
        "latest_scan": ({k: scans[0][k] for k in ("id", "repository_name", "finished_at", "summary")} if scans else None),
        "documents": db.count("policy_docs", t),
    }


@router.get("/overview/files")
def overview_files(repository_id: Optional[str] = None, user: dict = Depends(auth.current_user)):
    t = user["tenant_id"]
    rows = []
    for s in latest_scans(t, repository_id):
        inv = db.get("inventory", t, s["id"])
        if not inv:
            continue
        for d, st in inv["dir_stats"].items():
            rows.append({"repository": s["repository_name"], "directory": d, "files": st["files"], "findings": st["findings"]})
    rows.sort(key=lambda r: (-r["findings"], -r["files"]))
    return {"items": rows[:200], "total": len(rows)}


# ------------------------------------------------------------------ LLM-assisted
SYSTEM = ("You are an AI governance and application security assistant. Answer concisely and concretely for engineers and "
          "compliance reviewers. Only use the evidence provided; say when evidence is missing. Never ask for or repeat secrets.")


def _ctx_finding(f):
    return f"Rule {f['rule_id']} ({f['severity']}) in {f['file']}:{f['line']} — {f['title']}. Snippet (redacted): {f.get('snippet')}"


@router.post("/scans/{scan_id}/findings/{finding_id}/explain")
def explain_finding(scan_id: str, finding_id: str, user: dict = Depends(auth.current_user)):
    scan_or_404(user, scan_id)
    f = _finding_or_404(user, finding_id)
    why, fix = rule_help(f["rule_id"], f["category"])
    return llm.explain(SYSTEM, f"Explain this finding and its governance impact.\n{_ctx_finding(f)}",
                       f"{f['title']}: {why}\n\nRecommended action: {fix}", [f["id"]])


@router.post("/scans/{scan_id}/findings/{finding_id}/suggest-fix")
def suggest_fix(scan_id: str, finding_id: str, user: dict = Depends(auth.current_user)):
    scan_or_404(user, scan_id)
    f = _finding_or_404(user, finding_id)
    why, fix = rule_help(f["rule_id"], f["category"])
    return llm.explain(SYSTEM, f"Suggest a concrete code-level fix.\n{_ctx_finding(f)}", fix, [f["id"]])


@router.post("/scans/{scan_id}/findings/{finding_id}/apply-fix")
def apply_fix(scan_id: str, finding_id: str, user: dict = Depends(auth.require("admin"))):
    scan_or_404(user, scan_id)
    f = _finding_or_404(user, finding_id)
    _, fix = rule_help(f["rule_id"], f["category"])
    audit(user, "finding.apply_fix_requested", finding_id)
    return {"status": "manual_action_required", "detail": "Automatic commits to source repositories are not enabled. Apply the fix below, then rescan.",
            "explanation": fix, "commit_sha": None, "new_scan_id": None}


@router.post("/scans/{scan_id}/ai-governance-issues/{issue_id}/suggest-fix")
def suggest_governance_fix(scan_id: str, issue_id: str, user: dict = Depends(auth.current_user)):
    s = scan_or_404(user, scan_id)
    c = next((c for c in s.get("controls", []) if c["control_id"] == issue_id), None)
    if not c:
        raise HTTPException(404, "control/issue not found in this scan")
    fallback = (f"Control '{c['title']}' is {c['status'].replace('_', ' ')}. {c['description']} "
                "Add the missing capability or evidence to the repository (code, configuration or documentation) and rescan.")
    return llm.explain(SYSTEM, f"Control {c['control_id']}: {c['title']} is {c['status']}. {c['description']} Suggest a minimal implementation plan.", fallback, [issue_id])


@router.post("/scans/{scan_id}/controls/explain")
def explain_controls(scan_id: str, user: dict = Depends(auth.current_user)):
    s = scan_or_404(user, scan_id)
    cs = s.get("controls", [])
    lines = [f"- {c['control_id']}: {c['status']} ({c['evidence_count']} evidence)" for c in cs]
    ok = sum(1 for c in cs if c["status"] == "satisfied")
    fallback = f"{ok} of {len(cs)} controls are satisfied for {s['repository_name']}.\n" + "\n".join(lines)
    return llm.explain(SYSTEM, "Summarise this control posture and the top three actions:\n" + "\n".join(lines), fallback, [c["control_id"] for c in cs])


@router.post("/scans/{scan_id}/missing-evidence/explain")
def explain_missing(scan_id: str, user: dict = Depends(auth.current_user)):
    s = scan_or_404(user, scan_id)
    miss = [c for c in s.get("controls", []) if c["status"] == "missing_evidence"]
    fallback = ("No evidence is missing." if not miss else
                "Missing evidence:\n" + "\n".join(f"- {c['control_id']} {c['title']}: {c['description']}" for c in miss))
    return llm.explain(SYSTEM, "Explain what evidence is missing and how to produce it:\n" + "\n".join(f"{c['control_id']}: {c['title']}" for c in miss),
                       fallback, [c["control_id"] for c in miss])


@router.post("/scans/{scan_id}/architecture/explain")
def explain_architecture(scan_id: str, user: dict = Depends(auth.current_user)):
    s = scan_or_404(user, scan_id)
    inv = db.get("inventory", user["tenant_id"], scan_id) or {}
    models = [m["name"] for m in inv.get("models", [])]
    provs = [p["name"] for p in inv.get("providers", [])]
    hosts = inv.get("hosts", [])
    fallback = (f"{s['repository_name']} uses {len(models)} model reference(s) ({', '.join(models[:8]) or 'none'}), "
                f"{len(provs)} provider(s) ({', '.join(provs[:8]) or 'none'}) and calls {len(hosts)} external host(s).")
    return llm.explain(SYSTEM, f"Describe the AI architecture. Models: {models}. Providers: {provs}. Hosts: {hosts[:20]}", fallback, [scan_id])
