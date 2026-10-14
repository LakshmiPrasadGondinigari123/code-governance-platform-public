"""Per-repository architecture map, discovered from each repository's real scan (nothing is hand-drawn).

Layers: entry points -> application modules -> AI layer -> data files -> external services, plus the
infrastructure files found and a summary of repository content. Each node carries the personal / health findings
that sit in its files, and edges that carry data towards an outside AI service are flagged.
"""
import os
import re
from collections import Counter, defaultdict
from typing import Optional

from fastapi import APIRouter, Depends

from . import auth, db
from .common import latest_scans

router = APIRouter()

CODE = {"python", "javascript", "typescript", "java", "go", "ruby", "csharp", "php", "kotlin", "rust", "swift"}
DATA_EXT = {".json", ".csv", ".tsv", ".yaml", ".yml", ".sql", ".xml", ".parquet", ".txt"}
UI_EXT = {".jsx", ".tsx", ".html", ".vue", ".svelte"}
VENDORS = {"openai": ("openai", "azure"), "anthropic": ("anthropic",), "groq": ("groq",), "google": ("google", "gemini", "vertex", "googleapis"),
           "mistral": ("mistral",), "cohere": ("cohere",), "microsoft": ("microsoft", "azure"), "hugging face": ("huggingface", "hf.co"),
           "ollama": ("localhost", "ollama")}


def _kind_of_ai(cat: str) -> str:
    return {"llm_sdk": "AI service SDK", "llm_gateway": "AI gateway", "framework": "AI framework", "vector_store": "Vector store",
            "safety": "Safety / masking", "ml_library": "ML library"}.get(cat, "AI component")


def build(tenant: str, scan: dict) -> dict:
    inv = db.get("inventory", tenant, scan["id"]) or {}
    findings = [f for f in db.items("findings", tenant) if f["scan_id"] == scan["id"] and f.get("category") == "pii"]
    by_file = defaultdict(lambda: {"phi": 0, "pii": 0, "types": Counter()})
    for f in findings:
        d = by_file[f["file"]]
        d["phi" if f["rule_id"].startswith("phi.") else "pii"] += 1
        d["types"][f["title"]] += 1

    files = inv.get("file_list") or []
    paths = [x["path"] for x in files]

    def counts(plist):
        phi = sum(by_file[p]["phi"] for p in plist if p in by_file)
        pii = sum(by_file[p]["pii"] for p in plist if p in by_file)
        return phi, pii

    def node(nid, label, sub, kind, plist=(), **extra):
        phi, pii = counts(plist)
        return {"id": nid, "label": label, "sub": sub, "kind": kind, "files": list(plist)[:12], "file_count": len(list(plist)),
                "phi": phi, "pii": pii, **extra}

    layers = []

    # --- entry points
    entry = []
    route_files = sorted({r["file"] for r in (inv.get("routes") or [])})
    if inv.get("routes"):
        entry.append(node("api", "HTTP API", f"{len(inv['routes'])} route{'s' if len(inv['routes']) != 1 else ''}", "entry", route_files))
    ui_files = [p for p in paths if os.path.splitext(p)[1].lower() in UI_EXT]
    if ui_files:
        entry.append(node("ui", "Web UI", f"{len(ui_files)} page / component file{'s' if len(ui_files) != 1 else ''}", "entry", ui_files))
    if entry:
        layers.append({"id": "entry", "label": "Entry points", "color": "#2563EB", "nodes": entry})

    # --- application modules (grouped by top-level folder)
    groups = defaultdict(list)
    fn_count = defaultdict(int)
    for x in files:
        if x.get("language") in CODE and os.path.splitext(x["path"])[1].lower() not in UI_EXT:
            top = x["path"].split("/")[0] if "/" in x["path"] else "(root)"
            groups[top].append(x["path"])
            fn_count[top] += len(x.get("functions") or [])
    app = []
    for top, plist in sorted(groups.items(), key=lambda kv: -len(kv[1]))[:6]:
        label = "Application code" if top == "(root)" else top
        app.append(node("app:" + top, label, f"{len(plist)} file{'s' if len(plist) != 1 else ''} · {fn_count[top]} functions", "app", plist, group=top))
    if app:
        layers.append({"id": "app", "label": "Application", "color": "#0F766E", "nodes": app})

    # --- AI layer
    ai = []
    for c in (inv.get("ai_components") or [])[:8]:
        ai.append(node("ai:" + c["name"], c["name"], _kind_of_ai(c.get("category")) + (f" · {c['provider']}" if c.get("provider") and c.get("category") == "llm_sdk" else ""),
                       "ai", c.get("files") or [], provider=c.get("provider"), category=c.get("category")))
    for m in (inv.get("models") or [])[:4]:
        ai.append(node("model:" + m["name"], m["name"], f"Model · {m.get('provider') or 'unknown provider'}", "model", m.get("files") or [], provider=m.get("provider")))
    if ai:
        layers.append({"id": "ai", "label": "AI layer", "color": "#7C3AED", "nodes": ai})

    # --- data files
    dnodes = []
    cand = []
    for x in files:
        ext = os.path.splitext(x["path"])[1].lower()
        if ext in DATA_EXT and (x["path"] in by_file or x["path"].split("/")[0] in ("data", "fixtures", "samples")):
            phi, pii = counts([x["path"]])
            cand.append((phi + pii, x))
    for _, x in sorted(cand, key=lambda t: -t[0])[:8]:
        kinds = ", ".join(f"{n}× {t.lower()}" for t, n in by_file[x["path"]]["types"].most_common(3)) if x["path"] in by_file else "no personal data found"
        dnodes.append(node("data:" + x["path"], os.path.basename(x["path"]), kinds, "data", [x["path"]], path=x["path"]))
    comps = " ".join(str(c.get("name", "")).lower() for c in (inv.get("components") or []))
    if re.search(r"psycopg|asyncpg|sqlalchemy|pymongo|mysql|sqlite|redis", comps):
        db_name = "PostgreSQL" if re.search(r"psycopg|asyncpg", comps) else "Database"
        dnodes.append(node("db", db_name, "Declared in dependencies", "data", []))
    if dnodes:
        layers.append({"id": "data", "label": "Data", "color": "#D97706", "nodes": dnodes})

    # --- external services
    ext = []
    seen_hosts = set()
    for h in (inv.get("hosts") or [])[:8]:
        seen_hosts.add(h)
        ext.append(node("host:" + h, h, "Outside service the code calls", "external", [], host=h))
    for p in (inv.get("providers") or [])[:4]:
        nm = p["name"]
        if not any(nm.lower().split()[0] in h.lower() for h in seen_hosts):
            ext.append(node("prov:" + nm, nm, "AI provider (data leaves your boundary)", "external", p.get("files") or [], provider=nm))
    if ext:
        layers.append({"id": "external", "label": "Outside services", "color": "#E11D48", "nodes": ext})

    # --- infrastructure
    infra = []
    def pick(rx):
        return [p for p in paths if re.search(rx, p, re.I)]
    for nid, label, rx, sub in (("docker", "Containers", r"(^|/)(Dockerfile|docker-compose[^/]*\.ya?ml)$", "Dockerfile / compose"),
                                ("k8s", "Kubernetes", r"(^|/)(k8s|kubernetes|helm|charts)/.+\.ya?ml$", "Cluster manifests"),
                                ("tf", "Infrastructure as code", r"\.tf$", "Terraform"),
                                ("ci", "CI pipeline", r"(^|/)\.github/workflows/|(^|/)\.gitlab-ci\.yml$|(^|/)Jenkinsfile$", "Build and release")):
        pl = pick(rx)
        if pl:
            infra.append(node("infra:" + nid, label, f"{sub} · {len(pl)} file{'s' if len(pl) != 1 else ''}", "infra", pl))
    if infra:
        layers.append({"id": "infra", "label": "Infrastructure", "color": "#475569", "nodes": infra})

    # --- repository content (always present, so even configuration-only repositories have a map)
    kinds = defaultdict(list)
    for x in files:
        e = os.path.splitext(x["path"])[1].lower()
        if x.get("language") in CODE:
            kinds["Code"].append(x["path"])
        elif e in (".md", ".rst", ".txt") and e != ".txt" or e in (".md", ".rst"):
            kinds["Documents"].append(x["path"])
        elif e in (".yaml", ".yml", ".toml", ".ini", ".cfg", ".env", ".conf"):
            kinds["Configuration"].append(x["path"])
        elif e in DATA_EXT:
            kinds["Data & text"].append(x["path"])
        else:
            kinds["Other"].append(x["path"])
    content = [node("content:" + k, k, f"{len(v)} file{'s' if len(v) != 1 else ''}", "content", v) for k, v in kinds.items() if v]
    if content:
        layers.insert(0, {"id": "content", "label": "Repository content", "color": "#0891B2", "nodes": content})

    # --- edges (only relationships we can show from evidence)
    edges = []
    nodes = {n["id"]: n for ly in layers for n in ly["nodes"]}
    for e in entry:
        for a in sorted(app, key=lambda n: -n["file_count"])[:3]:
            edges.append({"from": e["id"], "to": a["id"], "label": "calls", "risk": False})
    for a in app:
        pa = set(a["files"]) if a["file_count"] <= 12 else set(groups.get(a.get("group"), []))
        for n in ai:
            if pa & set(n.get("files") or []):
                edges.append({"from": a["id"], "to": n["id"], "label": "uses", "risk": False})
        for d in dnodes:
            top = (d.get("path") or "").split("/")[0] if "/" in (d.get("path") or "") else "(root)"
            if d["id"] != "db" and (top == a.get("group") or (top == "(root)" and a is app[0])):
                edges.append({"from": a["id"], "to": d["id"], "label": "reads", "risk": False})
    for n in ai:
        pv = (n.get("provider") or n["label"]).lower()
        for x in ext:
            tokens = next((v for k, v in VENDORS.items() if k in pv), (pv.split()[0],))
            if any(t in (x.get("host") or x["label"]).lower() for t in tokens):
                risky = (n["phi"] + n["pii"] > 0) or any(by_file.get(p) for p in n.get("files", []))
                edges.append({"from": n["id"], "to": x["id"], "label": "personal data may leave" if risky else "calls", "risk": bool(risky)})
    # a data file read by code that talks to an outside AI service is the path the blueprint cares about
    phi = sum(1 for f in findings if f["rule_id"].startswith("phi."))
    return {
        "repository_id": scan["repository_id"], "name": scan.get("repository_name") or scan.get("repo_ref"),
        "repo_ref": scan.get("repo_ref"), "scan_id": scan["id"], "scanned_at": scan.get("completed_at") or scan.get("finished_at"),
        "files_scanned": inv.get("files_scanned"), "languages": inv.get("languages") or {},
        "findings": {"phi": phi, "pii": len(findings) - phi},
        "layers": layers, "edges": [e for e in edges if e["from"] in nodes and e["to"] in nodes],
    }


TECH = {
    "frontend": [("react", "React"), ("next", "Next.js"), ("vue", "Vue"), ("angular", "Angular"), ("svelte", "Svelte"), ("streamlit", "Streamlit"), ("gradio", "Gradio")],
    "backend": [("fastapi", "FastAPI"), ("flask", "Flask"), ("django", "Django"), ("express", "Express"), ("spring", "Spring"), ("nestjs", "NestJS"), ("uvicorn", "Uvicorn")],
    "queue": [("celery", "Celery"), ("kafka", "Kafka"), ("pika", "RabbitMQ"), ("rabbitmq", "RabbitMQ"), ("redis", "Redis"), ("rq", "RQ"), ("sqs", "Amazon SQS")],
    "db": [("psycopg", "PostgreSQL"), ("asyncpg", "PostgreSQL"), ("pymongo", "MongoDB"), ("mysql", "MySQL"), ("sqlalchemy", "SQL database"), ("sqlite", "SQLite"),
           ("dynamodb", "DynamoDB"), ("elasticsearch", "Elasticsearch"), ("boto3", "Cloud storage")],
}

LANES = [("users", "Users / external"), ("frontend", "Frontend / client"), ("api", "API / gateway"), ("app", "Application / services"),
         ("proc", "Processing / AI"), ("queue", "Messaging / queue"), ("store", "Databases / storage"), ("infra", "Infrastructure / deploy")]


def _tech(names, kind):
    out = []
    for key, label in TECH[kind]:
        if any(key in n for n in names) and label not in out:
            out.append(label)
    return out


def swimlanes(base: dict, inv: dict) -> dict:
    """Re-arrange the discovered map as architecture lanes (users -> frontend -> API -> services -> processing -> queue -> storage)."""
    names = [str(c.get("name", "")).lower() for c in (inv.get("components") or [])]
    lanes = {k: [] for k, _ in LANES}
    byid = {}
    flat = [n for ly in base["layers"] for n in ly["nodes"]]

    def put(lane, n, **ov):
        n = {**n, **ov, "lane": lane}
        lanes[lane].append(n)
        byid[n["id"]] = n
        return n

    def synth(nid, label, sub, kind, **ex):
        return {"id": nid, "label": label, "sub": sub, "kind": kind, "files": [], "file_count": 0, "phi": 0, "pii": 0, **ex}

    has_ui = any(n["id"] == "ui" for n in flat)
    has_api = any(n["id"] == "api" for n in flat)
    ui_tech = _tech(names, "frontend")
    be_tech = _tech(names, "backend")
    q_tech = _tech(names, "queue")
    db_tech = _tech(names, "db")

    put("users", synth("src", "Source repository", f"{base['name']} · {base.get('files_scanned') or 0} files scanned", "source", status="info"))
    if has_ui or has_api:
        put("users", synth("user", "Users / clients", "Browser or calling application", "user"))
    for n in flat:
        k, i = n["kind"], n["id"]
        if i == "ui":
            put("frontend", n, label=(" + ".join(ui_tech[:2]) + " web app") if ui_tech else n["label"])
        elif i == "api":
            put("api", n, label=(be_tech[0] + " API") if be_tech else n["label"], sub=n["sub"] + (" · " + ", ".join(be_tech[:2]) if be_tech else ""))
        elif k == "app":
            put("app", n)
        elif k in ("ai", "model"):
            put("store" if n.get("category") == "vector_store" else "proc", n)
        elif k == "data":
            put("store", n, label=n["label"] if n["id"] != "db" else (db_tech[0] if db_tech else n["label"]))
        elif k == "external":
            if i.startswith("prov:") and not any(v in (n.get("provider") or n["label"]).lower() for v in VENDORS):
                continue  # a library name, not an outside service
            put("users", n)
        elif k == "infra":
            put("infra", n)
    if q_tech:
        put("queue", synth("queue", q_tech[0], "Queue / cache declared in dependencies", "queue"))
    # a database seen only through dependencies
    if db_tech and not any(x["id"] == "db" for x in lanes["store"]):
        put("store", synth("db", db_tech[0], "Declared in dependencies", "data"))

    # small repositories show every component; large ones show the 15 that matter most
    MAX_SHOWN = 15
    total_nodes = len(byid)
    if total_nodes > MAX_SHOWN + 1:
        weight = {"source": 100, "user": 100, "entry": 60, "queue": 45, "ai": 45, "external": 40, "data": 40, "app": 35, "model": 25, "infra": 15}
        def score(n):
            return weight.get(n["kind"], 10) + (30 if (n.get("phi") or n.get("pii")) else 0) + min(n.get("file_count", 0), 20) * 0.5
        keep = {n["id"] for n in sorted(byid.values(), key=score, reverse=True)[:MAX_SHOWN]}
        for k in lanes:
            lanes[k] = [n for n in lanes[k] if n["id"] in keep]
        byid = {i: n for i, n in byid.items() if i in keep}
    edges = []
    def link(a, b, label, risk=False, kind="sync"):
        if a in byid and b in byid and a != b and not any(e["from"] == a and e["to"] == b for e in edges):
            edges.append({"from": a, "to": b, "label": label, "risk": risk, "kind": kind})

    first = lambda lane: lanes[lane][0]["id"] if lanes[lane] else None
    real = [n for n in lanes["app"] if (n.get("group") or "").lower() not in ("tests", "test", "docs", "scripts", "examples")]
    top_app = [n["id"] for n in sorted(real or lanes["app"], key=lambda n: -n["file_count"])[:2]]
    if "user" in byid:
        link("user", first("frontend") or first("api") or (top_app[0] if top_app else None) or "user", "HTTPS")
    if first("frontend") and first("api"):
        link(first("frontend"), first("api"), "REST / JSON")
    gate = first("api") or first("frontend")
    for a in top_app:
        if gate:
            link(gate, a, "requests")
    src_app = top_app[0] if top_app else gate
    if "queue" in byid and src_app:
        link(src_app, "queue", "enqueue", kind="queue")
    for e in base["edges"]:
        if (e["from"] in top_app) or e["from"].startswith("ai:") or e["from"].startswith("model:"):
            link(e["from"], e["to"], e["label"], e.get("risk", False), "data" if e["label"] == "reads" else "sync")
    # AI items that no application folder was matched to still hang off the main application
    for n in lanes["proc"]:
        if src_app and not any(e["to"] == n["id"] for e in edges):
            link(src_app, n["id"], "uses")
    for n in lanes["store"]:
        if n["id"] == "db" and src_app and not any(e["to"] == n["id"] for e in edges):
            link(src_app, "db", "queries", kind="data")
    if "src" in byid and gate:
        link("src", gate, "built from", kind="info")
    return {"lanes": [{"id": k, "label": l, "nodes": lanes[k]} for k, l in LANES if lanes[k]], "edges": edges, "total": total_nodes, "shown": len(byid)}

def _rules_notes(r: dict) -> dict:
    sw = r["swim"]
    nodes = {n["id"]: n for ln in sw["lanes"] for n in ln["nodes"]}
    ai = [n for n in nodes.values() if n["kind"] in ("ai", "model")]
    risky = [e for e in sw["edges"] if e.get("risk")]
    parts = [f"{r['name']} has {r.get('files_scanned') or 0} scanned files."]
    if any(n["kind"] == "entry" for n in nodes.values()):
        parts.append("People or other systems reach it through its web page or API.")
    if ai:
        parts.append("It uses " + ", ".join(sorted({n["label"] for n in ai})[:4]) + " for AI.")
    f = r["findings"]
    parts.append(f"The scan found {f['phi']} health and {f['pii']} personal data items.")
    if risky:
        parts.append("Some of that data sits in code that talks to an outside AI service, shown as red dashed arrows.")
    else:
        parts.append("No path from personal or health data to an outside AI service was found.")
    notes = {i: (n["sub"] + (f" Holds {n['phi']} health and {n['pii']} personal data items." if n["phi"] or n["pii"] else "")) for i, n in nodes.items()}
    flows = [{"from": e["from"], "to": e["to"], "text": f"{nodes[e['from']]['label']} {e['label']} {nodes[e['to']]['label']}" + (" - personal or health data may leave here." if e.get("risk") else ".")}
             for e in sw["edges"] if e["from"] in nodes and e["to"] in nodes]
    return {"summary": " ".join(parts), "nodes": notes, "flows": flows, "source": "rules"}


def agent_notes(tenant: str, scan: dict, r: dict, refresh: bool = False) -> dict:
    """The architecture agent: reads the discovered map and explains it. It may only describe boxes and arrows that exist."""
    cached = None if refresh else db.get("arch_agent2", tenant, scan["id"])
    if cached:
        return cached
    base = _rules_notes(r)
    try:
        import json as _j
        from . import llm
        sw = r["swim"]
        payload = {"repository": r["name"], "findings": r["findings"],
                   "boxes": [{"id": n["id"], "name": n["label"], "kind": n["kind"], "lane": ln["label"], "detail": n["sub"], "phi": n["phi"], "pii": n["pii"]} for ln in sw["lanes"] for n in ln["nodes"]],
                   "arrows": [{"from": e["from"], "to": e["to"], "label": e["label"], "personal_data_may_leave": bool(e.get("risk"))} for e in sw["edges"]]}
        system = ("You are an architecture-explaining agent for a healthcare governance team. You are given the boxes and arrows discovered by scanning one repository. "
                  "Explain them in plain language for non-engineers. Use ONLY the boxes and arrows given; never invent components, ports, products or numbers. "
                  "Reply with JSON only: {\"summary\": \"3-4 short sentences\", \"nodes\": {\"<box id>\": \"one sentence\"}, "
                  "\"flows\": [{\"from\": \"<id>\", \"to\": \"<id>\", \"text\": \"one sentence about what moves and why it matters\"}]}.")
        res = llm.explain(system, _j.dumps(payload)[:12000], fallback="{}", temperature=0.1, max_tokens=3000)
        if res.get("status") == "ok":
            txt = res["content"]
            d = _j.loads(txt[txt.index("{"): txt.rindex("}") + 1])
            ids = {n["id"] for ln in sw["lanes"] for n in ln["nodes"]}
            pairs = {(e["from"], e["to"]) for e in sw["edges"]}
            if isinstance(d.get("summary"), str) and d["summary"].strip():
                base["summary"] = d["summary"].strip()[:900]
            for k, v in (d.get("nodes") or {}).items():
                if k in ids and isinstance(v, str) and v.strip():
                    base["nodes"][k] = v.strip()[:300]
            ft = {}
            for f in d.get("flows") or []:
                if isinstance(f, dict) and (f.get("from"), f.get("to")) in pairs and isinstance(f.get("text"), str):
                    ft[(f["from"], f["to"])] = f["text"].strip()[:300]
            for f in base["flows"]:
                if (f["from"], f["to"]) in ft:
                    f["text"] = ft[(f["from"], f["to"])]
            base["source"] = "ai"
            base["model"] = res.get("model")
    except Exception:
        pass
    db.put("arch_agent2", tenant, scan["id"], base)
    return base

@router.get("/architecture/repo-map")
def repo_map(repository_id: Optional[str] = None, user: dict = Depends(auth.current_user)):
    t = user["tenant_id"]
    scans = [s for s in latest_scans(t, repository_id) if s.get("status") == "completed"]
    out = []
    for s in scans:
        b = build(t, s)
        b["swim"] = swimlanes(b, db.get("inventory", t, s["id"]) or {})
        out.append(b)
    return {"repositories": out}


@router.get("/architecture/repo-map/agent")
def repo_map_agent(repository_id: str, refresh: bool = False, user: dict = Depends(auth.current_user)):
    t = user["tenant_id"]
    s = next((x for x in latest_scans(t, repository_id) if x.get("status") == "completed"), None)
    if not s:
        return {"summary": "No completed scan yet.", "nodes": {}, "flows": [], "source": "rules"}
    b = build(t, s)
    b["swim"] = swimlanes(b, db.get("inventory", t, s["id"]) or {})
    return agent_notes(t, s, b, refresh)
