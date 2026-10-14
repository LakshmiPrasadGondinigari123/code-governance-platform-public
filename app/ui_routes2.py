"""UI contract, part 2: AI inventory, architecture, runtime usage, evidence graph, scan reports, documents."""
import time
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import BaseModel

from . import auth, bus, db, llm, remediation, ui_model
from .common import audit, now
from .ui_model import repo_ref

router = APIRouter()
T = lambda u: u["tenant_id"]  # noqa: E731

LLM_CATS = ("llm_sdk", "llm_gateway", "framework")


def _is_ai(inv: dict) -> str:
    comps = inv.get("ai_components", [])
    if inv.get("models") or inv.get("providers") or any(c["category"] in LLM_CATS for c in comps):
        return "ai"
    if comps:
        return "artifacts"
    return "none"


def _patterns(inv: dict) -> dict:
    ev = inv.get("blueprint", {}).get("evidence", {})
    return {"prompts": 1 if inv.get("models") or inv.get("providers") else 0, "rag": len(ev.get("11", [])) + len(ev.get("12", [])),
            "tools": len(ev.get("16", [])), "agents": len(ev.get("15", [])), "mcp": 0}


# ------------------------------------------------------------------ AI inventory
@router.get("/ai-inventory")
def ai_inventory(user: dict = Depends(auth.current_user)):
    t = T(user)
    items = []
    live = {}
    for e in db.items("runtime_events", t):
        live[e.get("application_id")] = live.get(e.get("application_id"), 0) + 1
    scanned = {s["repository_id"]: s for s in ui_model.latest_completed(t)}
    for r in ui_model.ui_repositories(t):
        s = scanned.get(r["repository_id"])
        if not s:
            items.append({"repository_id": r["repository_id"], "repo_ref": r["repo_ref"], "name": r["name"], "kind": "unscanned", "level": "unscanned",
                          "providers": [], "models": [], "live_requests": 0, "failing": 0, "review": 0, "scanned_at": None})
            continue
        inv = db.get("inventory", t, s["id"]) or {}
        ctrls = ui_model.build_controls(t, r["repository_id"])
        failing = sum(1 for c in ctrls if c["status"] == "FAIL")
        review = sum(1 for c in ctrls if c["status"] == "REVIEW")
        kind = _is_ai(inv)
        items.append({
            "repository_id": r["repository_id"], "repo_ref": r["repo_ref"], "name": r["name"], "kind": kind,
            "level": "attention" if failing else "review" if review else "clear",
            "providers": sorted({p["name"] for p in inv.get("providers", [])}),
            "models": [{"provider": m["provider"], "model": m["name"], "model_state": "DETECTED"} for m in inv.get("models", [])],
            "live_requests": sum(live.get(a["application_id"], 0) for a in db.items("runtime_apps", t) if a.get("repository_id") == r["repository_id"]),
            "failing": failing, "review": review, "scanned_at": s.get("completed_at"),
        })
    ai = [i for i in items if i["kind"] == "ai"]
    return {"items": items, "summary": {
        "repositories": len(items), "ai_systems": len(ai),
        "models": len({m["model"] for i in items for m in i["models"]}),
        "providers": len({p for i in items for p in i["providers"]}),
        "needs_attention": sum(1 for i in items if i["level"] in ("attention", "review") and i["kind"] in ("ai", "artifacts"))}}


@router.get("/ai-inventory/model-card")
def model_card(repository_id: str, user: dict = Depends(auth.current_user)):
    t = T(user)
    repos = {r["repository_id"]: r for r in ui_model.ui_repositories(t)}
    r = repos.get(repository_id)
    if not r:
        raise HTTPException(404, "repository not found")
    repo = {"repository_id": repository_id, "name": r["name"], "repo_ref": r["repo_ref"]}
    done = ui_model.latest_completed(t, repository_id)
    if not done:
        return {"status": "no_completed_scan", "repository": repo, "scan": None, "application": None, "ai": None, "data": None}
    s = done[0]
    inv = db.get("inventory", t, s["id"]) or {}
    policy = ui_model._policy(t)
    am = [x.lower() for x in policy["approved_models"]]
    langs = [{"name": k.lstrip(".").upper() if len(k) < 5 else k.lstrip(".")} for k in inv.get("languages", {})]
    comps = inv.get("components", [])
    names = {c["name"].lower() for c in comps}
    fw = [n for n in ("fastapi", "flask", "django", "express", "next", "react", "langchain", "streamlit", "spring-boot") if n in names]
    dbs = [n for n in ("sqlalchemy", "psycopg2", "pymongo", "redis", "sqlite3", "mysqlclient", "chromadb", "pinecone-client") if n in names]
    models = []
    for m in inv.get("models", []):
        if not am:
            ap = {"status": "no_policy", "detail": "No approved-model list is defined yet (AI Usage → Policy)."}
        elif m["name"].lower() in am:
            ap = {"status": "approved", "detail": "This model is on the approved list."}
        else:
            ap = {"status": "unapproved", "detail": "This model is not on the approved list."}
        models.append({"provider": m["provider"], "model": m["name"], "model_state": "DETECTED", "approval": ap,
                       "files": m["files"], "runtime": None})
    if inv.get("providers") and not models:
        for p in inv["providers"]:
            models.append({"provider": p["name"], "model": None, "model_state": "UNKNOWN",
                           "approval": {"status": "no_policy", "detail": "No approved-model list is defined."}, "files": p["files"], "runtime": None})
    ev = {c["control_id"]: c for c in ui_model.build_controls(t, repository_id)}
    fs = [f for f in (db.items("findings", t) + db.items("findings_evidence", t)) if f["scan_id"] == s["id"]]
    controls = []
    for c in ui_model.CONTROLS:
        e = ui_model.eval_static_control(c["control_id"], s, fs, inv, policy)
        controls.append({"control_id": c["control_id"], "name": c["name"], "status": e["status"] if not e.get("not_applicable") else "PASS",
                         "detail": e.get("detail", ""), "evidence": e.get("evidence", [])})
    risks = [{"id": f["id"], "title": f["title"], "description": f["description"], "severity": f["severity"].upper(),
              "evidence": [{"file": f["file"], "line": f["line"]}]} for f in fs
             if f["severity"] in ("critical", "high", "medium") and f["category"] != "ai_governance"][:25]
    kind = _is_ai(inv)
    pats = _patterns(inv)
    providers = sorted({p["name"] for p in inv.get("providers", [])})
    headline = (f"{r['name']} is an AI application that calls {', '.join(providers) or 'an AI provider'}"
                f"{' using ' + ', '.join(m['model'] for m in models if m['model']) if any(m['model'] for m in models) else ''}."
                if kind == "ai" else f"{r['name']} shows no AI usage in its latest scan." if kind == "none" else
                f"{r['name']} contains AI-related libraries or files but no direct model calls.")
    needs = [c for c in controls if c["status"] in ("FAIL", "REVIEW")]
    md = [f"# AI system card — {r['name']}", f"_Scan {s['id']} · {s.get('completed_at')}_", "", headline, "", "## Models"]
    md += [f"- {m['provider']} / {m['model'] or 'not named'} — {m['approval']['status']}" for m in models] or ["- none"]
    md += ["", "## What needs attention"] + [f"- [{c['status']}] {c['name']}: {c['detail']}" for c in needs] or ["- nothing"]
    return {
        "status": "ok", "repository": repo, "headline": headline,
        "scan": {"scan_id": s["id"], "commit_sha": s.get("commit_sha"), "branch": s.get("branch"), "scanned_at": s.get("completed_at"),
                 "source": {"kind": "zip_upload" if s["source"] == "zip" else "git"}},
        "application": {"languages": langs, "frameworks": fw, "databases": dbs, "external_services": inv.get("hosts", [])[:12]},
        "ai": {"is_ai_application": kind == "ai", "artifacts": [{"kind": c["category"], "path": c["files"][0]} for c in inv.get("ai_components", []) if c["files"]] if kind == "artifacts" else [],
               "providers": [{"name": p} for p in providers], "frameworks": [{"name": c["name"]} for c in inv.get("ai_components", []) if c["category"] == "framework"],
               "vector_stores": [{"name": c["name"]} for c in inv.get("ai_components", []) if c["category"] == "vector_store"], "patterns": pats},
        "data": {"pii": sum(1 for f in fs if f["category"] == "pii"), "secrets": sum(1 for f in fs if f["category"] == "secret")},
        "models": models, "controls": controls, "risks": risks, "markdown": "\n".join(md),
    }


# ------------------------------------------------------------------ model governance (runtime telemetry)
def _model_rows(t: str, repository_id: Optional[str] = None):
    policy = ui_model._policy(t)
    am = [m.lower() for m in policy["approved_models"]]
    apps = {a["application_id"]: a for a in db.items("runtime_apps", t)}
    rows = {}
    for e in db.items("runtime_events", t):
        if not e.get("model"):
            continue
        a = apps.get(e.get("application_id"))
        if repository_id and (not a or a.get("repository_id") != repository_id):
            continue
        key = f"{e.get('provider') or 'unknown'}::{e['model']}"
        r = rows.setdefault(key, {"model_id": key, "provider": e.get("provider") or "unknown", "model": e["model"], "version": "UNKNOWN",
                                  "environments": set(), "applications": set(), "requests": 0, "total_tokens": 0, "open_findings": 0,
                                  "total_findings": 0, "changes": 0})
        r["requests"] += 1
        r["environments"].add(e.get("environment") or "unknown")
        if e.get("application_id"):
            r["applications"].add(e["application_id"])
        tok = (e.get("response_metadata") or {}).get("total_tokens")
        if isinstance(tok, (int, float)):
            r["total_tokens"] += tok
        if e.get("violations"):
            r["open_findings"] += len(e["violations"])
            r["total_findings"] += len(e["violations"])
    out = []
    for r in rows.values():
        r["environments"], r["applications"] = sorted(r["environments"]), sorted(r["applications"])
        r["governance_status"] = "FAIL" if r["open_findings"] else "PASS" if (r["model"].lower() in am) else "REVIEW" if not am else "FAIL"
        out.append(r)
    return out


@router.get("/governance/model-governance")
def model_governance(repository_id: Optional[str] = None, user: dict = Depends(auth.current_user)):
    return {"items": _model_rows(T(user), repository_id)}


@router.get("/governance/model-changes")
def model_changes(repository_id: Optional[str] = None, user: dict = Depends(auth.current_user)):
    return {"items": []}


@router.get("/governance/models")
def governance_models(repository_id: Optional[str] = None, user: dict = Depends(auth.current_user)):
    return {"items": [{"provider": r["provider"], "model": r["model"], "applications": r["applications"], "requests": r["requests"]}
                      for r in _model_rows(T(user), repository_id)]}


@router.get("/governance/model-governance/detail")
def model_governance_detail(provider: str, model: str, repository_id: Optional[str] = None, user: dict = Depends(auth.current_user)):
    t = T(user)
    row = next((r for r in _model_rows(t, repository_id) if r["provider"] == provider and r["model"] == model), None)
    if not row:
        raise HTTPException(404, "model not found")
    ev = [e for e in db.items("runtime_events", t) if e.get("model") == model and (e.get("provider") or "unknown") == provider]
    return {**row, "controls": [], "findings": [], "changes": [], "recent_events": ev[:20], "applications_detail": [],
            "evidence": {"events_total": len(ev)}}


# ------------------------------------------------------------------ runtime usage ("AI Usage" page)
@router.get("/runtime/usage/summary")
def usage_summary(repository_id: Optional[str] = None, application_id: Optional[str] = None, provider: Optional[str] = None,
                  model: Optional[str] = None, user: dict = Depends(auth.current_user)):
    t = T(user)
    apps = {a["application_id"]: a for a in db.items("runtime_apps", t)}
    ev = db.items("runtime_events", t)
    if repository_id:
        ev = [e for e in ev if apps.get(e.get("application_id"), {}).get("repository_id") == repository_id]
    if application_id:
        ev = [e for e in ev if e.get("application_id") == application_id]
    if provider:
        ev = [e for e in ev if e.get("provider") == provider]
    if model:
        ev = [e for e in ev if e.get("model") == model]

    def tok(e, k):
        v = (e.get("response_metadata") or {}).get(k)
        return v if isinstance(v, (int, float)) else None

    def group(keyfn):
        g = {}
        for e in ev:
            k = keyfn(e)
            r = g.setdefault(k, {"requests": 0, "total_tokens": 0, "input_tokens": 0, "output_tokens": 0, "lat": [], "last_seen": None})
            r["requests"] += 1
            for src, dst in (("total_tokens", "total_tokens"), ("input_tokens", "input_tokens"), ("output_tokens", "output_tokens")):
                v = tok(e, src)
                if v:
                    r[dst] += v
            lat = (e.get("response_metadata") or {}).get("latency_ms")
            if isinstance(lat, (int, float)):
                r["lat"].append(lat)
            r["last_seen"] = r["last_seen"] or e.get("received_at")
        return g

    def fmt(g, key, label):
        return [{label: k, **{x: v[x] for x in ("requests", "total_tokens", "input_tokens", "output_tokens", "last_seen")},
                 "avg_latency_ms": round(sum(v["lat"]) / len(v["lat"]), 1) if v["lat"] else None}
                for k, v in sorted(g.items(), key=lambda kv: -kv[1]["requests"])]
    by_app = fmt(group(lambda e: e.get("application_id") or "unknown"), "application_id", "application_id")
    for r in by_app:
        r["display_name"] = apps.get(r["application_id"], {}).get("display_name", r["application_id"])
    by_model = [{"provider": k.split("::")[0], "model": k.split("::")[1], **{x: v[x] for x in ("requests", "total_tokens")}}
                for k, v in group(lambda e: f"{e.get('provider') or 'unknown'}::{e.get('model') or 'unknown'}").items()]
    by_provider = [{"provider": k, **{x: v[x] for x in ("requests", "total_tokens")}} for k, v in group(lambda e: e.get("provider") or "unknown").items()]
    by_time = [{"bucket": k, "requests": v["requests"], "total_tokens": v["total_tokens"]}
               for k, v in sorted(group(lambda e: (e.get("received_at") or "")[:13] + ":00").items())]
    lats = [x for e in ev for x in [(e.get("response_metadata") or {}).get("latency_ms")] if isinstance(x, (int, float))]
    return {
        "total_requests": len(ev), "total_tokens": sum(tok(e, "total_tokens") or 0 for e in ev) or None,
        "total_input_tokens": sum(tok(e, "input_tokens") or 0 for e in ev), "total_output_tokens": sum(tok(e, "output_tokens") or 0 for e in ev),
        "avg_latency_ms": round(sum(lats) / len(lats), 1) if lats else None,
        "usage_by_application": by_app, "usage_by_model": by_model, "usage_by_provider": by_provider, "usage_by_time": by_time,
        "latest_events": [{"application_id": e.get("application_id"), "provider": e.get("provider"), "model": e.get("model"),
                           "input_tokens": tok(e, "input_tokens"), "output_tokens": tok(e, "output_tokens"),
                           "latency_ms": (e.get("response_metadata") or {}).get("latency_ms"), "received_at": e.get("received_at")} for e in ev[:5]],
        "open_governance_findings": sum(1 for e in ev if e.get("violations")),
    }


@router.get("/runtime/events")
def runtime_events(page: int = 1, page_size: int = 50, application_id: Optional[str] = None, provider: Optional[str] = None,
                   event_type: Optional[str] = None, user: dict = Depends(auth.current_user)):
    rows = db.items("runtime_events", T(user))
    if application_id:
        rows = [e for e in rows if e.get("application_id") == application_id]
    if provider:
        rows = [e for e in rows if e.get("provider") == provider]
    if event_type:
        rows = [e for e in rows if e.get("event_type") == event_type]
    s = (max(page, 1) - 1) * page_size
    return {"items": rows[s:s + page_size], "total": len(rows), "page": page, "page_size": page_size}


@router.delete("/runtime/events")
def delete_runtime_events(user: dict = Depends(auth.require("admin"))):
    t = T(user)
    n = db.clear("runtime_events", t)
    audit(user, "runtime.events_delete_all", "", {"deleted": n})
    bus.publish(t, "findings", {"type": "findings_updated"})
    return {"events_removed": n, "findings_removed": 0}


@router.get("/runtime/applications")
def runtime_applications(user: dict = Depends(auth.current_user)):
    t = T(user)
    ev = db.items("runtime_events", t)
    out = []
    for a in db.items("runtime_apps", t):
        mine = [e for e in ev if e.get("application_id") == a["application_id"]]
        out.append({**a, "repo_ref": None, "events": len(mine), "total_requests": len(mine),
                    "last_seen": mine[0].get("received_at") if mine else None, "violations": sum(1 for e in mine if e.get("violations"))})
    return {"items": out}


@router.get("/runtime/credentials")
def runtime_credentials(user: dict = Depends(auth.require("admin"))):
    out = []
    for m in db.items("runtime_keys_meta", T(user)):
        out.append({"id": m["id"], "name": m["name"], "application_id": m.get("application_id"), "secret_prefix": m.get("key_prefix", ""),
                    "created_at": m.get("created_at"), "expires_at": m.get("expires_at"), "revoked_at": m.get("created_at") if m.get("revoked") else None,
                    "last_used_at": None})
    return {"items": out}


class _Cred(BaseModel):
    name: str
    application_id: Optional[str] = None
    expires_in_days: Optional[int] = None


@router.post("/runtime/credentials")
def runtime_credentials_create(req: _Cred, user: dict = Depends(auth.require("admin"))):
    import hashlib
    import secrets
    t = T(user)
    key = "rtk_" + secrets.token_urlsafe(32)
    cid = db.new_id("cred_")
    exp = time.time() + req.expires_in_days * 86400 if req.expires_in_days else None
    db.put("runtime_keys", "_global", hashlib.sha256(key.encode()).hexdigest(),
           {"credential_id": cid, "tenant_id": t, "name": req.name, "application_id": req.application_id, "revoked": False, "expires_at": exp})
    meta = {"id": cid, "name": req.name, "application_id": req.application_id, "created_at": now(), "created_by": user["username"],
            "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(exp)) if exp else None, "revoked": False,
            "key_hash": hashlib.sha256(key.encode()).hexdigest(), "key_prefix": key[:8]}
    db.put("runtime_keys_meta", t, cid, meta)
    audit(user, "runtime.credential_create", cid)
    return {"id": cid, "name": req.name, "application_id": req.application_id, "secret": key, "key": key, "secret_prefix": key[:8],
            "expires_at": meta["expires_at"], "created_at": meta["created_at"]}


@router.get("/runtime/policy")
def runtime_policy(user: dict = Depends(auth.current_user)):
    return ui_model._policy(T(user))


# ------------------------------------------------------------------ architecture
@router.get("/architecture/platform")
def architecture_platform(user: dict = Depends(auth.current_user)):
    t = T(user)
    ev = db.items("runtime_events", t)
    apps = db.items("runtime_apps", t)
    running = any(s["status"] in ("queued", "running") for s in db.items("scans", t))
    nodes = [{"id": f"app:{a['application_id']}", "live": any(e.get("application_id") == a["application_id"] for e in ev[:50])} for a in apps]
    return {"health": {"database": "connected" if db.ping() else "error", "redis": "connected", "sse": "connected",
                       "worker_available": True, "scan_active": running,
                       "last_runtime_activity": ev[0]["received_at"] if ev else None,
                       "last_activity_at": ev[0]["received_at"] if ev else None},
            "nodes": nodes, "edges": []}


@router.get("/architecture/repository/{repository_id}")
def architecture_repository(repository_id: str, user: dict = Depends(auth.current_user)):
    t = T(user)
    done = ui_model.latest_completed(t, repository_id)
    if not done:
        return {"status": "no_completed_scan", "components": [], "edges": []}
    s = done[0]
    inv = db.get("inventory", t, s["id"]) or {}
    comps = inv.get("components", [])
    names = {c["name"].lower() for c in comps}
    files = inv.get("file_list", [])
    langs = {}
    for f in files:
        if f["language"] not in ("other", "markdown", "text", "json", "yaml", "config"):
            langs[f["language"]] = langs.get(f["language"], 0) + 1
    fws = [n for n in ("fastapi", "flask", "django", "express", "next", "react", "streamlit", "langchain", "pydantic") if n in names]
    routes = inv.get("routes", [])
    services = [f["path"] for f in files if "service" in f["path"].lower()]
    repos_layer = [f["path"] for f in files if any(k in f["path"].lower() for k in ("repository", "/dao", "crud", "models.py"))]
    dbs = [n for n in ("sqlalchemy", "psycopg2", "pymongo", "redis", "chromadb", "pinecone", "sqlite3", "mysqlclient") if any(n in c for c in names)]
    ai_comps = inv.get("ai_components", [])
    providers = sorted({p["name"] for p in inv.get("providers", [])})
    ev = inv.get("blueprint", {}).get("evidence", {})
    components = [
        {"key": "languages", "label": "Languages", "summary": ", ".join(k.title() for k in sorted(langs)) or "No source languages detected",
         "fields": [[k.title(), f"{v} file(s)"] for k, v in sorted(langs.items())]},
        {"key": "frameworks", "label": "Frameworks", "summary": ", ".join(fws) or "None detected", "fields": [["Detected", ", ".join(fws) or "none"]]},
        {"key": "api", "label": "API layer", "summary": f"{len(routes)} route(s)", "fields": [["Routes discovered", len(routes)]]},
        {"key": "services", "label": "Services", "summary": f"{len(services)} service module(s)", "fields": [["Modules", len(services)]]},
        {"key": "repositories_layer", "label": "Data access", "summary": f"{len(repos_layer)} data-access module(s)", "fields": [["Modules", len(repos_layer)]]},
        {"key": "databases", "label": "Databases", "summary": ", ".join(dbs) or "None detected", "fields": [["Detected", ", ".join(dbs) or "none"]]},
        {"key": "ai", "label": "AI usage", "summary": ", ".join(providers) or "No AI provider detected",
         "fields": [["Providers", ", ".join(providers) or "none"],
                    ["AI frameworks", ", ".join(c["name"] for c in ai_comps if c["category"] == "framework") or "none"],
                    ["Models", ", ".join(m["name"] for m in inv.get("models", [])) or "none"],
                    ["RAG signals", len(ev.get("11", [])) + len(ev.get("12", []))],
                    ["Agent / tool signals", len(ev.get("15", [])) + len(ev.get("16", []))]]},
        {"key": "external_services", "label": "External services", "summary": ", ".join(inv.get("hosts", [])[:5]) or "None detected",
         "fields": [["Hosts", ", ".join(inv.get("hosts", [])[:8]) or "none"]]},
    ]
    keys = [c["key"] for c in components]
    edges = [{"from": a, "to": b, "real": (a, b) in (("api", "services"), ("ai", "external_services")) and True, "label": ""}
             for a, b in zip(keys, keys[1:])]
    return {"status": "ok", "components": components, "edges": edges, "scan_id": s["id"]}


@router.post("/architecture/narration")
def narration(body: dict = Body(default={}), user: dict = Depends(auth.current_user)):
    lines = []
    for st in body.get("steps", []):
        facts = st.get("facts") or []
        say = (". ".join(str(f) for f in facts) if isinstance(facts, list) else str(facts)) or f"This is the {st.get('id')} component."
        lines.append({"id": st.get("id"), "say": say[:400]})
    return {"lines": lines, "source": "rules", "provider": None}


@router.get("/architecture/discovery-graph")
def discovery_graph(repository_id: Optional[str] = None, user: dict = Depends(auth.current_user)):
    return {"nodes": [], "edges": []}


@router.get("/architecture/discovery-graph/explain")
def discovery_explain(repository_id: Optional[str] = None, user: dict = Depends(auth.current_user)):
    return llm.explain("You describe AI system architecture briefly.", "Explain the architecture graph.", "No architecture graph data yet; run a scan.")


@router.get("/architecture/repository/{repository_id}/folder-graph")
def folder_graph(repository_id: str, path: str = "", user: dict = Depends(auth.current_user)):
    t = T(user)
    done = ui_model.latest_completed(t, repository_id)
    inv = db.get("inventory", t, done[0]["id"]) if done else {}
    nodes = [{"id": f["path"], "label": f["path"].split("/")[-1], "language": f["language"]} for f in (inv or {}).get("file_list", [])
             if not path or f["path"].startswith(path)][:200]
    return {"nodes": nodes, "edges": []}


# ------------------------------------------------------------------ evidence graph (ER-style diagram)
@router.get("/evidence-graph/diagram")
def evidence_diagram(view: str = "all", repository_id: Optional[str] = None, user: dict = Depends(auth.current_user)):
    t = T(user)
    nodes, edges = [], []

    def col(name, value, key=None, ref=None):
        c = {"name": name, "value": value, "key": key}
        if ref:
            c["references"] = ref
        return c

    scans = ui_model.latest_completed(t, repository_id)
    policy = ui_model._policy(t)
    for s in scans:
        rid = s["repository_id"]
        inv = db.get("inventory", t, s["id"]) or {}
        fs = [f for f in (db.items("findings", t) + db.items("findings_evidence", t)) if f["scan_id"] == s["id"]]
        repo_node = f"repo:{rid}"
        nodes.append({"id": repo_node, "entity_type": "repository", "entity_id": rid, "label": s.get("repository_name"),
                      "subtitle": repo_ref(s), "status": "attention" if any(f["severity"] in ("critical", "high") for f in fs) else "healthy",
                      "severity": None, "evidence_state": "DETECTED", "plane": "static", "repository_id": rid, "repo_ref": repo_ref(s),
                      "repository": {"health": "attention" if fs else "healthy", "progress": None, "last_scan_at": s.get("completed_at"),
                                     "provider": "github" if "github.com" in repo_ref(s) else None},
                      "columns": [col("repository_id", rid, "PK"), col("scan_status", s["status"]), col("commit_sha", s.get("commit_sha")),
                                  col("branch", s.get("branch")), col("last_scan_at", s.get("completed_at")),
                                  col("file_count", inv.get("files_scanned")), col("open_findings", len(fs))]})
        for c in ui_model.build_controls(t, rid):
            cid = f"control:{rid}:{c['control_id']}"
            nodes.append({"id": cid, "entity_type": "control", "entity_id": c["control_id"], "label": c["name"], "subtitle": c["category"],
                          "status": c["status"], "severity": c["severity"], "evidence_state": "DETECTED", "plane": c["plane"],
                          "repository_id": rid, "repo_ref": repo_ref(s),
                          "columns": [col("control_id", c["control_id"], "PK"), col("control_status", c["status"]),
                                      col("repository_id", rid, "FK", {"entity_id": repo_node, "column": "repository_id"})]})
            edges.append({"id": f"e:{repo_node}>{cid}", "kind": "fk", "source": repo_node, "target": cid, "layout_source_id": repo_node,
                          "layout_target_id": cid, "source_column": "repository_id", "target_column": "repository_id", "label": "evaluated"})
        for f in fs[:60]:
            if f["category"] == "ai_governance":
                continue
            u = ui_model.ui_finding(f, s)
            fid = f"finding:{f['id']}"
            nodes.append({"id": fid, "entity_type": "finding", "entity_id": f["id"], "label": f["title"], "subtitle": f"{f['file']}:{f['line']}",
                          "status": u["governance_status"], "severity": u["severity"], "evidence_state": u["evidence_state"], "plane": "static",
                          "repository_id": rid, "repo_ref": repo_ref(s),
                          "columns": [col("finding_id", f["id"], "PK"), col("severity", u["severity"]), col("evidence_state", u["evidence_state"]),
                                      col("repository_id", rid, "FK", {"entity_id": repo_node, "column": "repository_id"})]})
            edges.append({"id": f"e:{repo_node}>{fid}", "kind": "evidence", "source": repo_node, "target": fid, "layout_source_id": repo_node,
                          "layout_target_id": fid, "source_column": "repository_id", "target_column": "repository_id", "label": "has finding"})
        for p in inv.get("providers", []):
            pid = f"provider:{rid}:{p['name']}"
            nodes.append({"id": pid, "entity_type": "ai_provider", "entity_id": p["name"], "label": p["name"], "subtitle": "AI provider (code)",
                          "status": None, "severity": None, "evidence_state": "DETECTED", "plane": "static", "repository_id": rid, "repo_ref": repo_ref(s),
                          "columns": [col("provider", p["name"], "PK"), col("file_count", len(p["files"]))]})
            edges.append({"id": f"e:{repo_node}>{pid}", "kind": "evidence", "source": repo_node, "target": pid, "layout_source_id": repo_node,
                          "layout_target_id": pid, "source_column": "repository_id", "target_column": "provider", "label": "uses"})
        for m in inv.get("models", []):
            mid = f"model:{rid}:{m['name']}"
            nodes.append({"id": mid, "entity_type": "model", "entity_id": m["name"], "label": m["name"], "subtitle": m["provider"],
                          "status": None, "severity": None, "evidence_state": "DETECTED", "plane": "static", "repository_id": rid, "repo_ref": repo_ref(s),
                          "columns": [col("model", m["name"], "PK"), col("provider", m["provider"])]})
            edges.append({"id": f"e:{repo_node}>{mid}", "kind": "evidence", "source": repo_node, "target": mid, "layout_source_id": repo_node,
                          "layout_target_id": mid, "source_column": "repository_id", "target_column": "model", "label": "references"})
        for c in inv.get("components", [])[:25]:
            did = f"dependency:{rid}:{c['name']}"
            nodes.append({"id": did, "entity_type": "dependency", "entity_id": c["name"], "label": c["name"], "subtitle": c.get("version") or "",
                          "status": None, "severity": None, "evidence_state": "DETECTED", "plane": "static", "repository_id": rid, "repo_ref": repo_ref(s),
                          "columns": [col("name", c["name"], "PK"), col("kind", c.get("ecosystem"))]})
            edges.append({"id": f"e:{repo_node}>{did}", "kind": "evidence", "source": repo_node, "target": did, "layout_source_id": repo_node,
                          "layout_target_id": did, "source_column": "repository_id", "target_column": "name", "label": "depends on"})
        for h in inv.get("hosts", [])[:15]:
            xid = f"external_api:{rid}:{h}"
            nodes.append({"id": xid, "entity_type": "external_api", "entity_id": h, "label": h, "subtitle": "External host", "status": None, "severity": None,
                          "evidence_state": "DETECTED", "plane": "static", "repository_id": rid, "repo_ref": repo_ref(s),
                          "columns": [col("host", h, "PK")]})
            edges.append({"id": f"e:{repo_node}>{xid}", "kind": "evidence", "source": repo_node, "target": xid, "layout_source_id": repo_node,
                          "layout_target_id": xid, "source_column": "repository_id", "target_column": "host", "label": "calls"})
    for e in edges:
        e["source_id"], e["target_id"] = e["source"], e["target"]
        e.setdefault("evidence", [])
    return {"nodes": nodes, "edges": edges, "notes": [], "correlations": {"repository_to_application": {"detail": "No runtime applications are linked to a repository yet."}},
            "generated_at": now(), "view": view}


# ------------------------------------------------------------------ scan report detail (adds scanner sections)
def scan_report_extras(t: str, scan: dict) -> dict:
    inv = db.get("inventory", t, scan["id"]) or {}
    fs = [f for f in db.items("findings", t) if f["scan_id"] == scan["id"]]
    ok = scan["status"] == "completed"
    sem = [{"check_id": f["rule_id"], "path": f["file"], "line": f["line"], "severity": f["severity"].upper(), "message": f["description"]}
           for f in fs if f["category"] == "security"]
    leaks = [{"rule": f["rule_id"], "path": f["file"], "line": f["line"], "redacted_snippet": f.get("snippet")} for f in fs if f["category"] == "secret"]
    pres = [{"entity_type": f["rule_id"], "path": f["file"], "line": f["line"], "classification": ui_model._classification(f),
             "confidence": 0.9, "redacted_snippet": f.get("snippet")} for f in fs if f["category"] == "pii"]
    comps = []
    for c in inv.get("components", []):
        eco = "python" if c["ecosystem"] == "pypi" else "javascript"
        v = c.get("version") or ""
        comps.append({"name": c["name"], "version": v, "language": eco, "type": "library",
                      "purl": f"pkg:{'pypi' if c['ecosystem'] == 'pypi' else 'npm'}/{c['name']}" + (f"@{v}" if v else "")})
    return {
        "semgrep": {"status": "ok" if ok else "error", "findings": sem, "counts_by_severity": {}},
        "gitleaks": {"status": "ok" if ok else "error", "findings": leaks, "finding_count": len(leaks)},
        "presidio": {"status": "ok" if ok else "error", "findings": pres},
        "syft": {"status": "ok" if ok else "error", "components": comps, "detail": None if ok else "Scan did not complete."},
        "evidence_pack": {"markdown": _pack_md(scan, fs, inv)} if ok else None,
        "evidence_pack_evidence_id": scan["id"] if ok else None,
    }


def _pack_md(scan, fs, inv) -> str:
    md = [f"# Governance evidence pack — {scan.get('repository_name')}", f"_Scan {scan['id']} · {scan.get('completed_at')}_", "",
          f"- Files scanned: {inv.get('files_scanned')}", f"- Findings: {len(fs)}", f"- Dependencies: {len(inv.get('components', []))}",
          f"- AI providers: {', '.join(p['name'] for p in inv.get('providers', [])) or 'none'}",
          f"- Models: {', '.join(m['name'] for m in inv.get('models', [])) or 'none'}", "", "## Findings"]
    md += [f"- **{f['severity'].upper()}** {f['title']} — `{f['file']}:{f['line']}`" for f in fs[:200]] or ["- none"]
    return "\n".join(md)


DOC_TYPES = ("system_card", "model_card", "risk_register", "remediation_suggestions")


@router.post("/scans/{scan_id}/documents/{doc_type}")
def generate_document(scan_id: str, doc_type: str, user: dict = Depends(auth.current_user)):
    t = T(user)
    s = db.get("scans", t, scan_id)
    if not s:
        raise HTTPException(404, "scan not found")
    if doc_type not in DOC_TYPES + ("evidence-summary", "risk-assessment", "compliance-report"):
        raise HTTPException(400, f"doc_type must be one of {DOC_TYPES}")
    inv = db.get("inventory", t, scan_id) or {}
    fs = [f for f in db.items("findings", t) if f["scan_id"] == scan_id]
    name = s.get("repository_name")
    if doc_type in ("remediation_suggestions",):
        md = [f"# Remediation suggestions — {name}", ""]
        for f in sorted(fs, key=lambda x: -ui_model.STATUS_RANK.get("FAIL", 0) if False else 0):
            if f["category"] == "ai_governance":
                continue
            fx = remediation.for_finding(f)
            md += [f"## {f['title']} ({f['severity'].upper()}) — `{f['file']}:{f['line']}`", fx["summary"], ""]
            md += [f"{i + 1}. {st}" for i, st in enumerate(fx["steps"])]
            if fx.get("example"):
                md += ["", "```", fx["example"], "```"]
            md += [f"_Verify:_ {fx['verify']}", ""]
        content = "\n".join(md) if len(md) > 2 else f"# Remediation suggestions — {name}\n\nNo open findings need remediation."
    elif doc_type == "risk_register":
        rows = ["| Severity | Risk | Location | Status |", "|---|---|---|---|"]
        for f in fs:
            u = ui_model.ui_finding(f, s)
            rows.append(f"| {u['severity']} | {f['title']} | `{f['file']}:{f['line']}` | {u['governance_status']} |")
        content = f"# Risk register — {name}\n\n" + "\n".join(rows)
    elif doc_type == "model_card":
        content = "\n".join([f"# Model card — {name}", ""] + [f"## {m['name']}\n- Provider: {m['provider']}\n- Referenced in: {', '.join(m['files'][:5])}\n- Intended use: _to be completed by the owner_\n"
                                                             for m in inv.get("models", [])] or ["No models referenced in code."])
    else:
        content = _pack_md(s, fs, inv)
    return {"status": "ok", "content": content, "provider": "rules", "model": "deterministic", "latency_ms": 0, "detail": None,
            "evidence_refs": [{"type": "finding", "path": f["file"], "line": f["line"]} for f in fs[:10]], "input_tokens": None, "output_tokens": None}
