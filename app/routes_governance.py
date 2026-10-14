"""Governance: controls, frameworks, policy documents, AI inventory, models, architecture, evidence."""
import io
import re
from typing import Optional

from fastapi import APIRouter, Body, Depends, File, Form, HTTPException, Query, UploadFile
from pydantic import BaseModel

from . import auth, db, frameworks, llm
from .common import audit, findings_for, inventories_for, latest_scans, now, scan_or_404, scope_scans
from .routes_findings import SYSTEM

router = APIRouter()
DOC_STATUSES = ("draft", "active", "superseded", "archived")


class PolicyDocumentPatch(BaseModel):
    status: Optional[str] = None
    authoritative: Optional[bool] = None
    version: Optional[str] = None
    effective_date: Optional[str] = None


class PolicyControlPatch(BaseModel):
    mapped_control_ids: Optional[list] = None
    framework_refs: Optional[list] = None
    mapping_status: Optional[str] = None


# ------------------------------------------------------------------ controls & frameworks
def _aggregate_controls(user, scan_id=None, repository_id=None):
    scans = scope_scans(user, scan_id, repository_id)
    agg = {}
    for c in frameworks.CONTROLS:
        agg[c["id"]] = {
            "control_id": c["id"], "title": c["title"], "description": c["description"], "type": c["type"],
            "framework_refs": [{"framework": fw, "refs": r} for fw, r in c["refs"].items()],
            "repositories": [], "counts": {"satisfied": 0, "missing_evidence": 0, "violated": 0},
        }
    for s in scans:
        for c in s.get("controls", []):
            a = agg[c["control_id"]]
            a["counts"][c["status"]] += 1
            a["repositories"].append({"repository_id": s["repository_id"], "repository_name": s["repository_name"],
                                      "scan_id": s["id"], "status": c["status"], "evidence_count": c["evidence_count"]})
    for a in agg.values():
        n = a["counts"]
        a["status"] = ("violated" if n["violated"] else "missing_evidence" if n["missing_evidence"] else
                       "satisfied" if n["satisfied"] else "not_scanned")
    return list(agg.values())


@router.get("/governance/controls")
def governance_controls(scan_id: Optional[str] = None, repository_id: Optional[str] = None, framework: Optional[str] = None,
                        user: dict = Depends(auth.current_user)):
    rows = _aggregate_controls(user, scan_id, repository_id)
    if framework:
        rows = [r for r in rows if any(x["framework"] == framework for x in r["framework_refs"])]
    return rows


@router.get("/governance/controls/{control_id}/evidence")
def control_evidence(control_id: str, scan_id: Optional[str] = None, repository_id: Optional[str] = None, user: dict = Depends(auth.current_user)):
    if not any(c["id"] == control_id for c in frameworks.CONTROLS):
        raise HTTPException(404, "unknown control")
    out = []
    for s in scope_scans(user, scan_id, repository_id):
        c = next((x for x in s.get("controls", []) if x["control_id"] == control_id), None)
        if c:
            out.append({"repository_id": s["repository_id"], "repository_name": s["repository_name"], "scan_id": s["id"],
                        "status": c["status"], "reasons": c["reasons"], "evidence": c["evidence"]})
    docs = [{"id": d["id"], "name": d["name"], "framework": d.get("framework")} for d in db.items("policy_docs", user["tenant_id"])
            if any(control_id in c.get("mapped_control_ids", []) for c in d.get("controls", []))]
    return {"control_id": control_id, "results": out, "policy_documents": docs}


@router.get("/governance/frameworks")
def list_frameworks(user: dict = Depends(auth.current_user)):
    return [{k: fw[k] for k in ("id", "name", "version", "kind")} | {"controls": len(fw["controls"])} for fw in frameworks.catalog()]


@router.get("/governance/framework-catalog")
def framework_catalog(user: dict = Depends(auth.current_user)):
    return frameworks.catalog()


@router.get("/governance/framework-map")
def framework_map(framework: Optional[str] = None, scan_id: Optional[str] = None, repository_id: Optional[str] = None,
                  user: dict = Depends(auth.current_user)):
    ctl = {c["control_id"]: c for c in _aggregate_controls(user, scan_id, repository_id)}
    docs = db.items("policy_docs", user["tenant_id"])
    out = []
    for fw in frameworks.catalog():
        if framework and fw["id"] != framework:
            continue
        rows = []
        for c in fw["controls"]:
            a = ctl.get(c["control_id"], {})
            rows.append({**c, "status": a.get("status", "not_scanned"), "counts": a.get("counts"),
                         "documents": [d["name"] for d in docs if any(c["control_id"] in x.get("mapped_control_ids", []) for x in d.get("controls", []))]})
        sat = sum(1 for r in rows if r["status"] == "satisfied")
        out.append({"id": fw["id"], "name": fw["name"], "version": fw["version"], "satisfied": sat, "total": len(rows),
                    "coverage": round(100 * sat / len(rows), 1) if rows else 0, "controls": rows})
    return out


@router.get("/governance/check-coverage")
def check_coverage(user: dict = Depends(auth.current_user)):
    scans = latest_scans(user["tenant_id"])
    out = []
    for c in frameworks.CONTROLS:
        pats, files = frameworks.compiled_patterns(c)
        out.append({"control_id": c["id"], "title": c["title"], "type": c["type"],
                    "detectors": {"patterns": len(pats), "file_rules": len(files), "dependencies": len(c.get("deps", [])),
                                  "finding_categories": c.get("categories", []), "rule_ids": c.get("rule_ids", [])},
                    "evaluated_in_scans": sum(1 for s in scans if any(x["control_id"] == c["id"] for x in s.get("controls", [])))})
    return out


# ------------------------------------------------------------------ policy documents
def _extract_text(name: str, data: bytes) -> str:
    low = name.lower()
    try:
        if low.endswith(".pdf"):
            from pypdf import PdfReader
            return "\n".join((p.extract_text() or "") for p in PdfReader(io.BytesIO(data)).pages)
        if low.endswith(".docx"):
            import docx
            return "\n".join(p.text for p in docx.Document(io.BytesIO(data)).paragraphs)
    except Exception as exc:
        raise HTTPException(422, f"could not read {name}: {type(exc).__name__}")
    return data.decode("utf-8", errors="ignore")


def _extract_controls(text: str) -> list:
    out = []
    for i, para in enumerate(p.strip() for p in re.split(r"\n\s*\n|\n(?=\s*(?:\d+(?:\.\d+)*[.)]|Art(?:icle)?\.?\s*\d+))", text)):
        if 25 <= len(para) <= 1200 and re.search(r"\b(?:shall|must|should|required|ensure)\b", para, re.I):
            mapped = []
            low = para.lower()
            for c in frameworks.CONTROLS:
                words = {w for w in re.findall(r"[a-z]{5,}", c["title"].lower() + " " + c["description"].lower())}
                if len(words & set(re.findall(r"[a-z]{5,}", low))) >= 2:
                    mapped.append(c["id"])
            out.append({"control_id": f"dc_{len(out)+1}", "text": para[:600], "mapped_control_ids": mapped[:3],
                        "framework_refs": [], "mapping_status": "suggested" if mapped else "unmapped"})
        if len(out) >= 80:
            break
    return out


@router.post("/governance/documents")
async def upload_policy_document(
    file: UploadFile = File(...), name: str = Form(""), version: str = Form("1.0"), source: str = Form("upload"),
    doc_type: str = Form("policy"), framework: str = Form(""), effective_date: str = Form(""), authoritative: bool = Form(False),
    user: dict = Depends(auth.require("admin", "reviewer")),
):
    data = await file.read()
    if len(data) > 25 * 1024 * 1024:
        raise HTTPException(413, "document larger than 25MB")
    text = _extract_text(file.filename or "document.txt", data)
    if not text.strip():
        raise HTTPException(422, "no extractable text in document")
    doc = {
        "id": db.new_id("doc_"), "name": name or file.filename, "filename": file.filename, "version": version, "source": source,
        "doc_type": doc_type, "framework": framework, "effective_date": effective_date, "authoritative": authoritative,
        "status": "active", "uploaded_by": user["username"], "uploaded_at": now(), "size": len(data),
        "text": text[:400_000], "controls": _extract_controls(text),
    }
    db.put("policy_docs", user["tenant_id"], doc["id"], doc)
    audit(user, "document.upload", doc["id"], {"name": doc["name"]})
    return _doc_view(doc, with_text=False)


def _doc_view(d, with_text=True):
    out = {k: v for k, v in d.items() if k != "text"}
    out["control_count"] = len(d.get("controls", []))
    if with_text:
        out["text"] = d.get("text", "")
    return out


@router.get("/governance/documents")
def list_documents(user: dict = Depends(auth.current_user)):
    return [_doc_view(d, False) for d in db.items("policy_docs", user["tenant_id"])]


@router.get("/governance/documents/search")
def search_documents(q: str = Query(..., min_length=2), user: dict = Depends(auth.current_user)):
    terms = [t for t in re.findall(r"\w+", q.lower()) if len(t) > 1]
    hits = []
    for d in db.items("policy_docs", user["tenant_id"]):
        text, low = d.get("text", ""), d.get("text", "").lower()
        score = sum(low.count(t) for t in terms)
        if score:
            i = min((low.find(t) for t in terms if t in low), default=0)
            hits.append({"id": d["id"], "name": d["name"], "score": score, "snippet": text[max(0, i - 80): i + 220].replace("\n", " ")})
    hits.sort(key=lambda h: -h["score"])
    return hits[:25]


@router.get("/governance/documents/{doc_id}")
def get_document(doc_id: str, user: dict = Depends(auth.current_user)):
    d = db.get("policy_docs", user["tenant_id"], doc_id)
    if not d:
        raise HTTPException(404, "document not found")
    return _doc_view(d)


@router.patch("/governance/documents/{doc_id}")
def patch_document(doc_id: str, req: PolicyDocumentPatch, user: dict = Depends(auth.require("admin", "reviewer"))):
    d = db.get("policy_docs", user["tenant_id"], doc_id)
    if not d:
        raise HTTPException(404, "document not found")
    if req.status is not None:
        if req.status not in DOC_STATUSES:
            raise HTTPException(400, f"status must be one of {DOC_STATUSES}")
        d["status"] = req.status
    for k in ("authoritative", "version", "effective_date"):
        v = getattr(req, k)
        if v is not None:
            d[k] = v
    db.put("policy_docs", user["tenant_id"], doc_id, d)
    audit(user, "document.update", doc_id)
    return _doc_view(d, False)


@router.delete("/governance/documents/{doc_id}")
def delete_document(doc_id: str, user: dict = Depends(auth.require("admin"))):
    if not db.delete("policy_docs", user["tenant_id"], doc_id):
        raise HTTPException(404, "document not found")
    audit(user, "document.delete", doc_id)
    return {"status": "deleted", "id": doc_id}


@router.patch("/governance/document-controls/{control_id}")
def map_policy_control(control_id: str, req: PolicyControlPatch, user: dict = Depends(auth.require("admin", "reviewer"))):
    valid = {c["id"] for c in frameworks.CONTROLS}
    for d in db.items("policy_docs", user["tenant_id"]):
        for c in d.get("controls", []):
            if c["control_id"] == control_id:
                if req.mapped_control_ids is not None:
                    bad = [x for x in req.mapped_control_ids if x not in valid]
                    if bad:
                        raise HTTPException(400, f"unknown control ids: {bad}")
                    c["mapped_control_ids"] = req.mapped_control_ids
                    c["mapping_status"] = "confirmed" if req.mapped_control_ids else "unmapped"
                if req.framework_refs is not None:
                    c["framework_refs"] = req.framework_refs
                if req.mapping_status:
                    c["mapping_status"] = req.mapping_status
                db.put("policy_docs", user["tenant_id"], d["id"], d)
                audit(user, "document.map_control", control_id)
                return {"document_id": d["id"], **c}
    raise HTTPException(404, "document control not found")


# ------------------------------------------------------------------ AI inventory & model governance
def _inventory(user, scan_id=None, repository_id=None):
    scans = scope_scans(user, scan_id, repository_id)
    inv = inventories_for(user["tenant_id"], {s["id"] for s in scans})
    names = {s["id"]: s["repository_name"] for s in scans}
    models, providers, comps = {}, {}, {}
    for i in inv:
        repo = names.get(i["scan_id"], "")
        for m in i["models"]:
            e = models.setdefault(m["name"].lower(), {"name": m["name"], "provider": m["provider"], "repositories": [], "files": []})
            e["repositories"].append(repo)
            e["files"] += m["files"]
        for p in i["providers"]:
            e = providers.setdefault(p["name"], {"name": p["name"], "repositories": []})
            e["repositories"].append(repo)
        for c in i["ai_components"]:
            e = comps.setdefault(c["name"], {**{k: c[k] for k in ("name", "category", "provider")}, "version": c.get("version", ""), "repositories": []})
            e["repositories"].append(repo)
    return {"models": list(models.values()), "providers": list(providers.values()), "components": list(comps.values()),
            "hosts": sorted({h for i in inv for h in i["hosts"]}), "repositories": sorted(set(names.values()))}


@router.get("/ai-inventory")
def ai_inventory(scan_id: Optional[str] = None, repository_id: Optional[str] = None, user: dict = Depends(auth.current_user)):
    inv = _inventory(user, scan_id, repository_id)
    inv["counts"] = {k: len(inv[k]) for k in ("models", "providers", "components", "hosts")}
    return inv


@router.get("/ai-inventory/model-card")
def model_card(model: str, user: dict = Depends(auth.current_user)):
    inv = _inventory(user)
    m = next((x for x in inv["models"] if x["name"].lower() == model.lower()), None)
    if not m:
        raise HTTPException(404, "model not found in current inventory")
    pol = db.get("runtime_policy", user["tenant_id"], "policy") or {}
    approved = m["name"] in pol.get("approved_models", [])
    md = (f"# Model card: {m['name']}\n\n- **Provider:** {m['provider']}\n- **Used by:** {', '.join(sorted(set(m['repositories'])))}\n"
          f"- **Referenced in:** {len(set(m['files']))} file(s)\n- **Approval status:** {'approved' if approved else 'not on approved list'}\n\n"
          "## Intended use\n_To be completed by the model owner._\n\n## Known limitations\n_To be completed._\n\n"
          "## Data handling\n_Describe what data is sent to the provider, retention and residency._\n\n"
          f"## Evidence files\n" + "\n".join(f"- `{f}`" for f in sorted(set(m['files']))[:20]))
    return {"model": m["name"], "provider": m["provider"], "approved": approved, "markdown": md, "generated_at": now()}


@router.get("/governance/models")
def governance_models(user: dict = Depends(auth.current_user)):
    return _inventory(user)["models"]


@router.get("/governance/model-governance")
def model_governance_list(user: dict = Depends(auth.current_user)):
    pol = db.get("runtime_policy", user["tenant_id"], "policy") or {}
    approved = {m.lower() for m in pol.get("approved_models", [])}
    reviews = db.items("reviews", user["tenant_id"])
    rows = []
    for m in _inventory(user)["models"]:
        rv = [r for r in reviews if r["target_type"] == "model" and r["target_id"].lower() == m["name"].lower()]
        status = ("approved" if m["name"].lower() in approved or (rv and rv[0]["action"] == "approve")
                  else "rejected" if rv and rv[0]["action"] == "reject" else "unreviewed")
        rows.append({"model": m["name"], "provider": m["provider"], "status": status, "repositories": sorted(set(m["repositories"])),
                     "last_review": rv[0] if rv else None})
    return rows


@router.get("/governance/model-governance/detail")
def model_governance_detail(model: str, user: dict = Depends(auth.current_user)):
    rows = [r for r in model_governance_list(user) if r["model"].lower() == model.lower()]
    if not rows:
        raise HTTPException(404, "model not found")
    t = user["tenant_id"]
    runtime = [e for e in db.items("runtime_events", t) if (e.get("model") or "").lower() == model.lower()]
    return {**rows[0], "reviews": [r for r in db.items("reviews", t) if r["target_type"] == "model" and r["target_id"].lower() == model.lower()],
            "runtime_events": len(runtime), "runtime_violations": sum(1 for e in runtime if e.get("violations"))}


@router.get("/governance/model-changes")
def model_changes(repository_id: str, user: dict = Depends(auth.current_user)):
    t = user["tenant_id"]
    done = [s for s in db.items("scans", t) if s["repository_id"] == repository_id and s["status"] == "completed"]
    if len(done) < 2:
        return {"repository_id": repository_id, "added": [], "removed": [], "detail": "At least two completed scans are needed."}
    cur = {m["name"] for m in (db.get("inventory", t, done[0]["id"]) or {}).get("models", [])}
    old = {m["name"] for m in (db.get("inventory", t, done[1]["id"]) or {}).get("models", [])}
    return {"repository_id": repository_id, "from_scan": done[1]["id"], "to_scan": done[0]["id"],
            "added": sorted(cur - old), "removed": sorted(old - cur)}


@router.get("/governance/applications")
def governance_applications(user: dict = Depends(auth.current_user)):
    t = user["tenant_id"]
    apps = db.items("runtime_apps", t)
    linked = {a.get("repository_id") for a in apps}
    out = [{"type": "runtime", "id": a["application_id"], "name": a.get("display_name") or a["application_id"],
            "repository_id": a.get("repository_id")} for a in apps]
    out += [{"type": "repository", "id": r["id"], "name": r["name"], "repository_id": r["id"]} for r in db.items("repositories", t) if r["id"] not in linked]
    return out


@router.get("/governance/application-status")
def application_status(application_id: Optional[str] = None, repository_id: Optional[str] = None, user: dict = Depends(auth.current_user)):
    t = user["tenant_id"]
    if application_id:
        app = db.get("runtime_apps", t, application_id)
        if not app:
            raise HTTPException(404, "application not found")
        repository_id = app.get("repository_id")
    scans = latest_scans(t, repository_id) if repository_id else []
    s = scans[0] if scans else None
    ev = [e for e in db.items("runtime_events", t) if not application_id or e.get("application_id") == application_id]
    cs = s.get("controls", []) if s else []
    return {"application_id": application_id, "repository_id": repository_id,
            "static": {"scan_id": s["id"] if s else None, "controls_satisfied": sum(1 for c in cs if c["status"] == "satisfied"),
                       "controls_total": len(cs), "findings": (s or {}).get("summary", {}).get("findings_total") if s else None},
            "runtime": {"events": len(ev), "violations": sum(1 for e in ev if e.get("violations"))},
            "status": ("unknown" if not s and not ev else "at_risk" if any(c["status"] == "violated" for c in cs) or any(e.get("violations") for e in ev)
                       else "needs_evidence" if any(c["status"] == "missing_evidence" for c in cs) else "compliant")}


# ------------------------------------------------------------------ evidence
@router.get("/evidence/{evidence_id}")
def get_evidence(evidence_id: str, user: dict = Depends(auth.current_user)):
    t = user["tenant_id"]
    f = db.get("findings", t, evidence_id)
    if f:
        return {"evidence_id": evidence_id, "type": "finding", "finding": f, "scan": _scan_ref(t, f["scan_id"])}
    for s in db.items("scans", t):
        for c in s.get("controls", []):
            if evidence_id == f"{s['id']}:{c['control_id']}":
                return {"evidence_id": evidence_id, "type": "control", "control": c, "scan": _scan_ref(t, s["id"])}
    raise HTTPException(404, "evidence not found")


def _scan_ref(t, scan_id):
    s = db.get("scans", t, scan_id)
    return {"id": scan_id, "repository": s["repository_name"], "finished_at": s["finished_at"]} if s else None


@router.get("/evidence-pack/{evidence_id}")
def evidence_pack(evidence_id: str, user: dict = Depends(auth.current_user)):
    """evidence_id may be a scan id (full pack) or a finding id (finding pack)."""
    t = user["tenant_id"]
    s = db.get("scans", t, evidence_id)
    if s:
        fs = findings_for(t, {s["id"]})
        return {"pack_id": evidence_id, "type": "scan", "generated_at": now(), "repository": s["repository_name"], "git_url": s.get("git_url"),
                "scan": {k: s[k] for k in ("id", "created_at", "finished_at", "status", "summary")}, "controls": s.get("controls", []),
                "findings": fs, "inventory": db.get("inventory", t, s["id"]), "reviews": [r for r in db.items("reviews", t) if r["scan_id"] == s["id"]]}
    f = db.get("findings", t, evidence_id)
    if f:
        sc = db.get("scans", t, f["scan_id"])
        return {"pack_id": evidence_id, "type": "finding", "generated_at": now(), "finding": f,
                "controls": [c for c in (sc or {}).get("controls", []) if c["control_id"] in {x["id"] for x in frameworks.CONTROLS
                             if f["category"] in x.get("categories", []) or f["rule_id"] in x.get("rule_ids", [])}],
                "reviews": [r for r in db.items("reviews", t) if r["target_id"] == evidence_id]}
    raise HTTPException(404, "evidence not found")


@router.get("/repositories/evidence-coverage")
def evidence_coverage(user: dict = Depends(auth.current_user)):
    out = []
    for s in latest_scans(user["tenant_id"]):
        cs = s.get("controls", [])
        n = len(cs) or 1
        out.append({"repository_id": s["repository_id"], "repository": s["repository_name"], "scan_id": s["id"],
                    "satisfied": sum(1 for c in cs if c["status"] == "satisfied"), "missing": sum(1 for c in cs if c["status"] == "missing_evidence"),
                    "violated": sum(1 for c in cs if c["status"] == "violated"), "total": len(cs),
                    "coverage": round(100 * sum(1 for c in cs if c["status"] == "satisfied") / n, 1)})
    return out


@router.get("/evidence-graph/diagram")
def evidence_diagram(scan_id: Optional[str] = None, repository_id: Optional[str] = None, user: dict = Depends(auth.current_user)):
    lines = ["flowchart LR"]
    for s in scope_scans(user, scan_id, repository_id)[:5]:
        rid = "R_" + s["repository_id"]
        lines.append(f'  {rid}["{s["repository_name"]}"]')
        for c in s.get("controls", []):
            cid = f"{rid}_{c['control_id'].replace('-', '_')}"
            style = {"satisfied": "ok", "violated": "bad", "missing_evidence": "gap"}[c["status"]]
            lines.append(f'  {rid} --> {cid}["{c["title"]}"]:::{style}')
            for ev in c["evidence"][:2]:
                if ev.get("file") and ev["file"] != "(dependency)":
                    fid = "F_" + re.sub(r"\W", "_", f"{s['repository_id']}_{ev['file']}")[:40]
                    lines.append(f'  {cid} -.-> {fid}["{ev["file"]}"]')
    lines += ["  classDef ok fill:#d1fae5,stroke:#059669;", "  classDef bad fill:#fee2e2,stroke:#dc2626;", "  classDef gap fill:#fef3c7,stroke:#d97706;"]
    return {"format": "mermaid", "diagram": "\n".join(lines)}


# ------------------------------------------------------------------ architecture
@router.get("/architecture/platform")
def architecture_platform(user: dict = Depends(auth.current_user)):
    return {
        "name": "Code-to-Governance Intelligence Platform",
        "components": [
            {"id": "api", "name": "FastAPI service", "role": "REST API, auth, SSE streams"},
            {"id": "scanner", "name": "Static scanner", "role": "Secrets, PII, unsafe patterns, AI inventory, SBOM, control evidence"},
            {"id": "controls", "name": "Control engine", "role": "Maps evidence to EU AI Act / NIST AI RMF / ISO 42001 / OWASP LLM"},
            {"id": "graph", "name": "Evidence graph", "role": "Repository, package, model, provider, host and finding relationships"},
            {"id": "runtime", "name": "Runtime telemetry", "role": "Ingests LLM call events and enforces approved-provider/model policy"},
            {"id": "store", "name": "Store", "role": "SQLite document store (tenant-scoped)"},
            {"id": "llm", "name": "LLM assistant", "role": "Optional Groq-backed explanations with rule-based fallback"},
        ],
        "flows": [["repository", "scanner"], ["scanner", "controls"], ["scanner", "graph"], ["controls", "api"], ["runtime", "api"], ["api", "store"]],
        "llm": llm.status(),
    }


def _combined_graph(user, repository_id=None):
    nodes, edges = {}, {}
    keep = {"repository", "provider", "model", "host", "control"}
    for s in latest_scans(user["tenant_id"], repository_id):
        g = db.get("graphs", user["tenant_id"], s["id"]) or {"nodes": [], "edges": []}
        for n in g["nodes"]:
            if n["type"] in keep or (n["type"] == "package" and n["props"].get("ecosystem") == "ai"):
                nodes[n["key"]] = n
        for e in g["edges"]:
            if e["src"] in nodes and e["dst"] in nodes:
                edges[e["id"]] = e
    # repo -> provider/model links through files collapsed
    return nodes, edges


@router.get("/architecture/graph")
def architecture_graph(repository_id: Optional[str] = None, user: dict = Depends(auth.current_user)):
    t, nodes, edges = user["tenant_id"], {}, {}
    for s in latest_scans(t, repository_id):
        g = db.get("graphs", t, s["id"]) or {"nodes": [], "edges": []}
        by_key = {n["key"]: n for n in g["nodes"]}
        out_edges = {}
        for e in g["edges"]:
            out_edges.setdefault(e["src"], []).append(e)
        repo = next((n for n in g["nodes"] if n["type"] == "repository"), None)
        if not repo:
            continue
        nodes[repo["key"]] = repo
        for e in out_edges.get(repo["key"], []):
            f = by_key.get(e["dst"])
            if not f or f["type"] != "file":
                if f and f["type"] == "package" and f["props"].get("ecosystem") == "ai":
                    nodes[f["key"]] = f
                    edges[e["id"]] = e
                continue
            for e2 in out_edges.get(f["key"], []):
                n2 = by_key.get(e2["dst"])
                if n2 and n2["type"] in ("model", "host", "package"):
                    if n2["type"] == "package" and n2["props"].get("ecosystem") != "ai":
                        continue
                    nodes[n2["key"]] = n2
                    eid = f"{repo['key']}>{n2['key']}"
                    edges[eid] = {"id": eid, "src": repo["key"], "dst": n2["key"], "type": e2["type"]}
                    for e3 in out_edges.get(n2["key"], []):
                        n3 = by_key.get(e3["dst"])
                        if n3 and n3["type"] == "provider":
                            nodes[n3["key"]] = n3
                            edges[e3["id"]] = e3
    return {"nodes": list(nodes.values()), "edges": list(edges.values())}


@router.get("/architecture/discovery-graph")
def discovery_graph(user: dict = Depends(auth.current_user)):
    g = architecture_graph(None, user)
    t = user["tenant_id"]
    nodes, edges = list(g["nodes"]), list(g["edges"])
    for a in db.items("runtime_apps", t):
        key = f"app:{a['application_id']}"
        nodes.append({"key": key, "type": "runtime_application", "label": a.get("display_name") or a["application_id"], "props": {"observed": True}})
        if a.get("repository_id"):
            edges.append({"id": f"{key}>repo", "src": key, "dst": f"repo:{a['repository_id']}", "type": "deployed_from"})
    seen = {(e.get("provider"), e.get("model")) for e in db.items("runtime_events", t)}
    static_models = {n["label"].lower() for n in g["nodes"] if n["type"] == "model"}
    for prov, model in seen:
        if model and model.lower() not in static_models:
            nodes.append({"key": f"model:{model.lower()}", "type": "model", "label": model, "props": {"runtime_only": True, "provider": prov}})
    return {"nodes": nodes, "edges": edges}


@router.get("/architecture/discovery-graph/explain")
def discovery_explain(user: dict = Depends(auth.current_user)):
    g = discovery_graph(user)
    runtime_only = [n["label"] for n in g["nodes"] if n["props"].get("runtime_only")]
    fallback = (f"Graph has {len(g['nodes'])} nodes and {len(g['edges'])} relationships. "
                + (f"Models seen only at runtime (not in code): {', '.join(runtime_only)}." if runtime_only else "Every runtime model also appears in code."))
    return llm.explain(SYSTEM, f"Explain this AI system graph. Runtime-only models: {runtime_only}. Node types: {sorted({n['type'] for n in g['nodes']})}", fallback)


@router.post("/architecture/narration")
def narrate_architecture(body: dict = Body(default={}), user: dict = Depends(auth.current_user)):
    g = architecture_graph(body.get("repository_id"), user)
    by = {}
    for n in g["nodes"]:
        by.setdefault(n["type"], []).append(n["label"])
    fallback = "Architecture narration: " + "; ".join(f"{k}: {', '.join(v[:6])}" for k, v in by.items()) if by else "No scanned repositories yet."
    return llm.explain(SYSTEM, f"Write a short architecture narration for governance reviewers. Inventory: {by}", fallback)


@router.get("/architecture/repository/{repository_id}")
def repository_architecture(repository_id: str, user: dict = Depends(auth.current_user)):
    t = user["tenant_id"]
    scans = latest_scans(t, repository_id)
    if not scans:
        raise HTTPException(404, "no completed scan for repository")
    s = scans[0]
    inv = db.get("inventory", t, s["id"]) or {}
    return {"repository_id": repository_id, "repository": s["repository_name"], "scan_id": s["id"], "languages": inv.get("languages", {}),
            "components": inv.get("ai_components", []), "models": inv.get("models", []), "providers": inv.get("providers", []),
            "hosts": inv.get("hosts", []), "packages": len(inv.get("components", [])), "controls": s.get("controls", [])}


@router.get("/architecture/repository/{repository_id}/folder-graph")
def folder_graph(repository_id: str, user: dict = Depends(auth.current_user)):
    t = user["tenant_id"]
    scans = latest_scans(t, repository_id)
    if not scans:
        raise HTTPException(404, "no completed scan for repository")
    inv = db.get("inventory", t, scans[0]["id"]) or {"dir_stats": {}}
    nodes, edges = {}, []
    for d, st in inv["dir_stats"].items():
        parts = [] if d == "." else d.split("/")
        for i in range(len(parts) + 1):
            p = "/".join(parts[:i]) or "."
            nodes.setdefault(p, {"key": p, "label": p.split("/")[-1] if p != "." else scans[0]["repository_name"], "files": 0, "findings": 0})
            if i:
                edges.append({"src": "/".join(parts[:i - 1]) or ".", "dst": p})
        nodes[d]["files"] += st["files"]
        nodes[d]["findings"] += st["findings"]
    uniq = {(e["src"], e["dst"]) for e in edges}
    return {"nodes": list(nodes.values()), "edges": [{"src": a, "dst": b} for a, b in sorted(uniq)]}


@router.post("/architecture/repository/{repository_id}/components/{component_key}/explain")
def explain_component(repository_id: str, component_key: str, user: dict = Depends(auth.current_user)):
    arch = repository_architecture(repository_id, user)
    comp = next((c for c in arch["components"] if c["name"].lower() == component_key.lower()), None) \
        or next((m for m in arch["models"] if m["name"].lower() == component_key.lower()), None)
    if not comp:
        raise HTTPException(404, "component not found")
    fallback = f"{comp['name']} is used in {len(comp.get('files', []))} file(s): {', '.join(comp.get('files', [])[:5])}."
    return llm.explain(SYSTEM, f"Explain the role and governance considerations of {comp['name']} in this repository. Files: {comp.get('files', [])[:10]}", fallback)


@router.post("/scans/{scan_id}/documents/{doc_type}")
def generate_document(scan_id: str, doc_type: str, user: dict = Depends(auth.current_user)):
    s = scan_or_404(user, scan_id)
    if s["status"] != "completed":
        raise HTTPException(409, f"scan is {s['status']}")
    if doc_type not in ("evidence-summary", "risk-assessment", "model-card", "compliance-report"):
        raise HTTPException(400, "doc_type must be evidence-summary, risk-assessment, model-card or compliance-report")
    t = user["tenant_id"]
    fs = findings_for(t, {scan_id})
    inv = db.get("inventory", t, scan_id) or {}
    cs = s.get("controls", [])
    md = [f"# {doc_type.replace('-', ' ').title()} — {s['repository_name']}", f"_Generated {now()} from scan `{scan_id}`_", ""]
    md += ["## Summary", f"- Files scanned: {s['summary']['files_scanned']}", f"- Findings: {len(fs)}",
           f"- Controls satisfied: {s['summary']['controls_satisfied']}/{s['summary']['controls_total']}", ""]
    if doc_type in ("model-card", "evidence-summary", "compliance-report"):
        md += ["## AI inventory"] + [f"- **{m['name']}** ({m['provider']}) — {len(m['files'])} file(s)" for m in inv.get("models", [])] or ["- none detected"]
        md += [f"- SDK/framework: {c['name']} ({c['provider']})" for c in inv.get("ai_components", [])] + [""]
    if doc_type in ("risk-assessment", "compliance-report", "evidence-summary"):
        md += ["## Controls"] + [f"- [{c['status']}] **{c['control_id']}** {c['title']}" for c in cs] + [""]
        md += ["## Open high-severity findings"] + [
            f"- ({f['severity']}) {f['title']} — `{f['file']}:{f['line']}`" for f in fs
            if f["severity"] in ("critical", "high") and f.get("classification") == "open"] + [""]
    return {"doc_type": doc_type, "format": "markdown", "scan_id": scan_id, "content": "\n".join(md)}
