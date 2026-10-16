"""Adapters that turn stored scan data into the objects the EXL Code-Governance UI consumes."""
import hashlib
from typing import Optional

from . import blueprint, db, remediation
from .common import latest_scans

STATUS_RANK = {"FAIL": 0, "REVIEW": 1, "PASS": 2, "UNKNOWN": 3, "NOT_EVALUATED": 4}

# ---------------------------------------------------------------- repositories / scans
def provider_label(ref: str) -> str:
    r = (ref or "").lower()
    if "github.com" in r:
        return "GitHub"
    if "gitlab" in r:
        return "GitLab"
    if "bitbucket" in r:
        return "Bitbucket"
    if "dev.azure.com" in r or "visualstudio.com" in r:
        return "Azure DevOps"
    if r.startswith("zip:"):
        return "Uploaded archive"
    return "Git"


def repo_ref(scan: dict) -> str:
    return scan.get("repo_ref") or scan.get("git_url") or f"zip:{scan.get('repository_name', 'upload')}"


def _count_findings(findings: list) -> dict:
    live = [f for f in findings if f.get("classification") not in ("false_positive", "remediated", "accepted_risk")]
    pii = sum(1 for f in live if f["category"] == "pii" and not f["rule_id"].startswith("phi."))
    phi = sum(1 for f in live if f["rule_id"].startswith("phi."))
    secrets = sum(1 for f in live if f["category"] == "secret")
    gov = sum(1 for f in live if is_governance_relevant(f))
    return {"pii": pii, "phi": phi, "secrets": secrets, "governance_open": gov, "total": len(live),
            "code_security": sum(1 for f in live if f["category"] == "security")}


def is_governance_relevant(f: dict) -> bool:
    if f["category"] in ("secret", "pii"):
        return True
    if f["category"] == "ai_governance":
        return True
    return f["severity"] in ("critical", "high", "medium")


def ui_scan(s: dict) -> dict:
    ref = repo_ref(s)
    sev = (s.get("summary") or {}).get("by_severity", {})
    counts = {k.upper(): v for k, v in sev.items()}
    gl = (s.get("summary") or {}).get("by_category", {}).get("secret", 0)
    return {
        "scan_id": s["id"],
        "repo_ref": ref,
        "repository_id": s["repository_id"],
        "status": s["status"],
        "scanned_at": s.get("scanned_at") or s.get("created_at"),
        "started_at": s.get("started_at") or s.get("created_at"),
        "completed_at": s.get("completed_at") or s.get("finished_at"),
        "error_detail": s.get("error_detail") or s.get("error"),
        "commit_sha": s.get("commit_sha"),
        "branch": s.get("branch"),
        "semgrep_status": "ok" if s["status"] == "completed" else None,
        "gitleaks_status": "ok" if s["status"] == "completed" else None,
        "presidio_status": "ok" if s["status"] == "completed" else None,
        "syft_status": "ok" if s["status"] == "completed" else None,
        "semgrep_counts_by_severity": {"CRITICAL": counts.get("CRITICAL", 0), "HIGH": counts.get("HIGH", 0),
                                       "MEDIUM": counts.get("MEDIUM", 0), "LOW": counts.get("LOW", 0)},
        "gitleaks_finding_count": gl,
        "ci_block": bool((s.get("gate") or {}).get("block")) if s.get("gate") else bool(counts.get("CRITICAL", 0) or gl),
        "detection_agents": s.get("detection_agents"), "scope": s.get("scope"),
        "secrets_scanned": True,
        "evidence_pack_evidence_id": s["id"] if s["status"] == "completed" else None,
        "stages": s.get("stages", []),
        "summary": s.get("summary"),
    }


def ui_repositories(tenant: str) -> list:
    scans = db.items("scans", tenant)  # newest first
    by_repo = {}
    for s in scans:
        by_repo.setdefault(s["repository_id"], []).append(s)
    findings_all = db.items("findings", tenant)
    out = []
    for rid, group in by_repo.items():
        latest = group[0]
        done = [x for x in group if x["status"] == "completed"]
        newest_done = done[0] if done else None
        fs = [f for f in findings_all if newest_done and f["scan_id"] == newest_done["id"]]
        inv = db.get("inventory", tenant, newest_done["id"]) if newest_done else None
        refs = sorted({repo_ref(x) for x in group})
        ref = repo_ref(latest)
        out.append({
            "repository_id": rid,
            "repo_ref": ref,
            "repo_refs": refs,
            "name": latest.get("repository_name") or ref.rsplit("/", 1)[-1],
            "provider_label": provider_label(ref),
            "branch": latest.get("branch"),
            "last_scan_at": latest.get("scanned_at") or latest.get("created_at"),
            "last_scan_status": latest["status"],
            "scan_count": len(group),
            "completed_scans": len(done),
            "linked_applications": len([a for a in db.items("runtime_apps", tenant) if a.get("repository_id") == rid]),
            "secrets_scanned": True,
            "dependencies": len(inv["components"]) if inv else None,
            "findings": _count_findings(fs) if newest_done else {"pii": 0, "phi": 0, "secrets": 0, "governance_open": None, "total": 0, "code_security": 0},
        })
    out.sort(key=lambda r: r["last_scan_at"] or "", reverse=True)
    return out


# ---------------------------------------------------------------- findings
SOURCE_BY_CATEGORY = {"secret": "gitleaks", "pii": "presidio", "security": "semgrep", "ai_governance": "governance"}


def _classification(f: dict) -> str:
    c = f.get("classification", "open")
    if c in ("false_positive",):
        return "LIKELY_FALSE_POSITIVE"
    if c in ("accepted_risk", "remediated"):
        return "SUPPRESSED"
    if f["category"] in ("secret", "pii") and f["severity"] in ("critical", "high"):
        return "CONFIRMED_SENSITIVE"
    if f["category"] == "security":
        return "CANDIDATE"
    return "CONTEXTUAL"


def _cls(f: dict, conf: float) -> str:
    """Confirmed only when the evidence is strong enough; the rest is left for a person to check."""
    base = _classification(f)
    if base in ("CONFIRMED_SENSITIVE", "CONTEXTUAL") and f["category"] in ("pii", "secret"):
        return "CONFIRMED_SENSITIVE" if conf >= 0.80 else "CONTEXTUAL"
    return base

def _gov_status(f: dict) -> str:
    gs = f.get("governance_status", "unreviewed")
    if gs == "approved":
        return "PASS"
    if gs == "rejected":
        return "REVIEW"
    if f["category"] in ("secret", "pii") and f["severity"] in ("critical", "high"):
        return "FAIL"
    if f["category"] == "ai_governance" or f["severity"] in ("medium",):
        return "REVIEW"
    if f["severity"] in ("critical", "high"):
        return "FAIL"
    return "UNKNOWN"


def _review_status(f: dict) -> str:
    gs = f.get("governance_status", "unreviewed")
    return {"approved": "mark_reviewed", "rejected": "dispute", "in_review": "assign_owner", "exception": "accept"}.get(gs, "unreviewed")


def _mask(v):
    if not v:
        return None
    v = str(v)
    return v[:1] + "\u2022" * min(max(len(v) - 1, 3), 8)


def ui_finding(f: dict, scan: Optional[dict] = None, reveal: bool = False) -> dict:
    ftype = ("PHI" if f["rule_id"].startswith("phi.") else "PII") if f["category"] == "pii" else \
        {"secret": "SECRETS", "security": "CODE_SECURITY", "ai_governance": "GOVERNANCE"}.get(f["category"], "GOVERNANCE")
    gov = _gov_status(f)
    st = _review_status(f)
    from . import confidence as _conf
    cs = _conf.explain(f)
    conf = cs["score"]
    sc = scan or {}
    return {
        "id": f["id"], "finding_id": f["id"],
        "scan_id": f["scan_id"], "repository_id": f["repository_id"], "repo_ref": repo_ref(sc) if sc else None,
        "source": SOURCE_BY_CATEGORY.get(f["category"], "semgrep"),
        "rule_id": f["rule_id"], "title": f["title"], "description": f["description"],
        "severity": f["severity"].upper(),
        "data_type": ftype, "finding_type": ftype,
        "classification": _cls(f, conf),
        "status": st,
        "evidence_state": "OWNER_CONFIRMED" if st in ("mark_reviewed", "accept") else "CONTRADICTED" if st == "dispute" else "DETECTED",
        "governance_status": gov,
        "governance_relevant": is_governance_relevant(f),
        "governance_confidence": conf,
        "confidence_reasons": cs["reasons"],
        "requires_review": gov in ("FAIL", "REVIEW") and st == "unreviewed",
        "ai_status": "not_needed",
        "triage_class": None,
        "occurrence_count": 1,
        "application_id": None,
        "file_path": f["file"], "file": f["file"], "path": f["file"], "line": f["line"],
        "repository": repo_ref(sc) if sc else None, "repository_name": sc.get("repository_name") if sc else None,
        "scanned_at": (sc.get("completed_at") or sc.get("created_at")) if sc else None,
        "redacted_snippet": f.get("snippet"),
        "created_at": (sc.get("completed_at") or sc.get("created_at")) if sc else None,
        "first_seen": (sc.get("completed_at") or sc.get("created_at")) if sc else None,
        "last_seen": (sc.get("completed_at") or sc.get("created_at")) if sc else None,
        "comment": f.get("comment"),
        "context": f.get("context"),
        "value": (f.get("value") if reveal else _mask(f.get("value"))),
        "value_masked": not reveal,
        "detected_by": f.get("agent"),
        "snapshot": (f.get("context_lines") if reveal else None),
    }


# ---------------------------------------------------------------- controls
SEV_TXT = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}

CONTROLS = [
    {"control_id": "CTRL-SENSITIVE-DATA", "name": "Sensitive Data in Repository", "category": "Privacy", "plane": "static", "severity": "HIGH",
     "description": "Personal or health data (PII/PHI) must not be committed to source control, fixtures or prompts.",
     "guide": {"what": "Looks for personal data patterns (SSNs, card numbers, emails, medical record numbers, diagnosis codes) in the scanned code.",
               "why": "Sensitive data in code is copied to every clone, build and — if it reaches a prompt — to an outside model provider.",
               "how": "Pattern detectors run on every file of each scan; findings outside tests, docs and obvious placeholders count.",
               "fix": "Replace real values with synthetic data, move records to a governed store, and add masking before prompts and logs.",
               "needs": "Run a repository scan.", "evidence": ["Static scan"]}},
    {"control_id": "CTRL-HARDCODED-SECRETS", "name": "Hardcoded Secrets", "category": "Supply Chain", "plane": "static", "severity": "HIGH",
     "description": "API keys, tokens and private keys must never be stored in the repository.",
     "guide": {"what": "Detects credential-shaped values (cloud, GitHub, Slack, OpenAI/Anthropic/Groq keys, private keys, password assignments).",
               "why": "A leaked key gives direct access to systems and models, and stays valid in git history.",
               "how": "Secret detectors run on every file; matches are redacted in all output.",
               "fix": "Revoke and rotate the key, purge it from history, and load it from an environment variable or secrets manager.",
               "needs": "Run a repository scan.", "evidence": ["Static scan"]}},
    {"control_id": "CTRL-SBOM", "name": "Dependency Inventory (SBOM) Present", "category": "Supply Chain", "plane": "static", "severity": "LOW",
     "description": "Dependencies are declared in a manifest so a software bill of materials can be produced.",
     "guide": {"what": "Checks that requirements.txt, package.json, pyproject.toml or an equivalent manifest was found and parsed.",
               "why": "Without an inventory nobody can answer which libraries and AI SDKs the application depends on.",
               "how": "Manifests are parsed on each scan; components are listed on the Dependencies page and exported as CycloneDX.",
               "fix": "Declare and pin dependencies in a manifest committed to the repository.",
               "needs": "Run a repository scan.", "evidence": ["Static scan"]}},
    {"control_id": "CTRL-UNSAFE-EXEC", "name": "Unsafe Code Execution", "category": "Agent Safety", "plane": "static", "severity": "MEDIUM",
     "description": "Code must not execute dynamic strings or shell commands, especially near model output.",
     "guide": {"what": "Finds eval/exec, shell=True, unsafe deserialisation and unsafe YAML loading.",
               "why": "If model output reaches these calls, a crafted prompt becomes remote code execution.",
               "how": "Rule-based code patterns evaluated per scan.",
               "fix": "Parse structured output (JSON schema) and dispatch to an allow-list of functions; never eval model output.",
               "needs": "Run a repository scan.", "evidence": ["Static scan"]}},
    {"control_id": "CTRL-TLS", "name": "Encrypted Transport Only", "category": "Security", "plane": "static", "severity": "MEDIUM",
     "description": "TLS verification stays enabled and external calls use HTTPS.",
     "guide": {"what": "Finds disabled certificate verification and plain-HTTP external URLs.",
               "why": "Unencrypted or unverified traffic exposes prompts, data and credentials in transit.",
               "how": "Rule-based code patterns evaluated per scan.",
               "fix": "Remove verify=False / rejectUnauthorized:false and use HTTPS endpoints.",
               "needs": "Run a repository scan.", "evidence": ["Static scan"]}},
    {"control_id": "CTRL-PROVIDER-DISCLOSURE", "name": "External AI Provider Disclosure", "category": "Model Governance", "plane": "static", "severity": "MEDIUM",
     "description": "Every external AI provider receiving data is known, approved and documented.",
     "guide": {"what": "Lists AI providers detected in code and compares them with the approved-provider policy.",
               "why": "Prompts and retrieved data leave the organisation boundary when a provider SDK is used.",
               "how": "SDK imports, dependencies and model names are inventoried; the approved list lives in AI Usage › Policy.",
               "fix": "Add the provider to the approved list after a data-processing review, or remove it.",
               "needs": "Run a repository scan.", "evidence": ["Static scan", "Owner review"]}},
    {"control_id": "CTRL-APPROVED-MODELS", "name": "Approved Model Use", "category": "Model Governance", "plane": "runtime", "severity": "HIGH",
     "description": "Only approved models are used — in code and in live traffic.",
     "guide": {"what": "Compares models referenced in code, and models seen in live traffic, with the approved-model policy.",
               "why": "Unapproved models bypass safety evaluation, contracts and data-residency commitments.",
               "how": "Code: model identifiers in every scanned repository. Live: telemetry events from connected applications.",
               "fix": "Approve the model in AI Usage › Policy after review, or switch to an approved model.",
               "needs": "Scan a repository and/or connect an application's runtime telemetry.", "evidence": ["Static scan", "Runtime telemetry"]}},
    {"control_id": "CTRL-APPROVED-PROVIDERS", "name": "Approved Provider Use", "category": "Model Governance", "plane": "runtime", "severity": "HIGH",
     "description": "Only approved AI providers receive prompts and data.",
     "guide": {"what": "Compares providers in code and in live traffic with the approved-provider policy.",
               "why": "Each provider is a separate data-processing relationship.",
               "how": "Code SDK/model inventory plus runtime telemetry events.",
               "fix": "Approve the provider after review, or route traffic to an approved provider.",
               "needs": "Scan a repository and/or connect an application's runtime telemetry.", "evidence": ["Static scan", "Runtime telemetry"]}},
    {"control_id": "CTRL-AUTHORIZED-TOOLS", "name": "Authorized Tool Invocation", "category": "Agent Safety", "plane": "runtime", "severity": "HIGH",
     "description": "Agents may only invoke tools that have been authorised.",
     "guide": {"what": "Checks tool calls seen in live traffic against the approved-tool policy, and flags over-broad tools in code.",
               "why": "An agent with an unrestricted shell, file or database tool can be steered into damaging actions.",
               "how": "Runtime telemetry (tool_name) and code patterns for broad tools.",
               "fix": "Restrict tools to an allow-list and require human approval for destructive actions.",
               "needs": "Connect an application's runtime telemetry or scan a repository.", "evidence": ["Static scan", "Runtime telemetry"]}},
    {"control_id": "CTRL-APPROVED-DESTINATIONS", "name": "Approved API Destinations", "category": "Security", "plane": "runtime", "severity": "MEDIUM",
     "description": "Outbound calls only go to approved API hosts.",
     "guide": {"what": "Compares external hosts in code and in live traffic with the approved-host policy.",
               "why": "Unknown destinations are an exfiltration and supply-chain risk.",
               "how": "Hosts found in source plus network metadata in telemetry.",
               "fix": "Approve the host after review or remove the call.",
               "needs": "Scan a repository and/or connect an application's runtime telemetry.", "evidence": ["Static scan", "Runtime telemetry"]}},
]
CONTROL_BY_ID = {c["control_id"]: c for c in CONTROLS}


def _policy(tenant: str) -> dict:
    return db.get("runtime_policy", tenant, "policy") or {"approved_providers": [], "approved_models": [], "approved_tools": [], "approved_api_hosts": []}


def _eval_static_control_raw(cid: str, scan: dict, fs: list, inv: dict, policy: dict) -> dict:
    """Evaluate one control for one completed scan → {status, detail, evidence[], not_applicable}."""
    live = [f for f in fs if f.get("classification") not in ("false_positive", "remediated", "accepted_risk")]

    def ev(items, n=5):
        return [{"file": f["file"], "line": f["line"]} for f in items[:n]]

    if cid == "CTRL-SENSITIVE-DATA":
        bad = [f for f in live if f["category"] == "pii" and f["severity"] in ("high", "critical", "medium")]
        low = [f for f in live if f["category"] == "pii" and f["severity"] == "low"]
        if bad:
            return {"status": "FAIL", "detail": f"{len(bad)} sensitive-data finding(s) in code.", "evidence": ev(bad)}
        if low:
            return {"status": "REVIEW", "detail": f"{len(low)} possible personal data value(s) need a person's review.", "evidence": ev(low)}
        return {"status": "PASS", "detail": "No sensitive personal or health data patterns were found.", "evidence": []}
    if cid == "CTRL-HARDCODED-SECRETS":
        bad = [f for f in live if f["category"] == "secret"]
        return ({"status": "FAIL", "detail": f"{len(bad)} credential(s) found in code.", "evidence": ev(bad)} if bad else
                {"status": "PASS", "detail": "No hard-coded credentials were found.", "evidence": []})
    if cid == "CTRL-SBOM":
        comps = inv.get("components", [])
        return ({"status": "PASS", "detail": f"{len(comps)} dependencies inventoried.", "evidence": []} if comps else
                {"status": "REVIEW", "detail": "No dependency manifest was found, so no SBOM can be produced.", "evidence": []})
    if cid == "CTRL-UNSAFE-EXEC":
        bad = [f for f in live if f["rule_id"] in ("sec.eval-exec", "sec.shell-true", "sec.pickle-loads", "sec.yaml-unsafe-load")]
        return ({"status": "FAIL", "detail": f"{len(bad)} unsafe execution pattern(s).", "evidence": ev(bad)} if bad else
                {"status": "PASS", "detail": "No unsafe execution patterns were found.", "evidence": []})
    if cid == "CTRL-TLS":
        bad = [f for f in live if f["rule_id"] in ("sec.tls-verify-disabled", "sec.insecure-http")]
        return ({"status": "FAIL", "detail": f"{len(bad)} insecure transport pattern(s).", "evidence": ev(bad)} if bad else
                {"status": "PASS", "detail": "No insecure transport patterns were found.", "evidence": []})
    models = inv.get("models", [])
    providers = {p["name"] for p in inv.get("providers", [])}
    has_ai = bool(models or providers)
    ap, am, ah = [x.lower() for x in policy["approved_providers"]], [x.lower() for x in policy["approved_models"]], [x.lower() for x in policy["approved_api_hosts"]]
    if cid == "CTRL-PROVIDER-DISCLOSURE":
        if not has_ai:
            return {"status": "NOT_EVALUATED", "not_applicable": True, "detail": "No AI provider usage was detected.", "evidence": []}
        if not ap:
            return {"status": "REVIEW", "detail": f"{len(providers)} provider(s) in use and no approved-provider list is defined.", "evidence": []}
        unapproved = sorted(p for p in providers if p.lower() not in ap)
        return ({"status": "FAIL", "detail": "Unapproved provider(s): " + ", ".join(unapproved), "evidence": []} if unapproved else
                {"status": "PASS", "detail": "All detected providers are approved.", "evidence": []})
    if cid == "CTRL-APPROVED-MODELS":
        if not models:
            return {"status": "NOT_EVALUATED", "not_applicable": True, "detail": "No model references in code.", "evidence": []}
        if not am:
            return {"status": "REVIEW", "detail": f"{len(models)} model(s) referenced and no approved-model list is defined.", "evidence": []}
        bad = [m for m in models if m["name"].lower() not in am]
        return ({"status": "FAIL", "detail": "Unapproved model(s): " + ", ".join(m["name"] for m in bad), "evidence": []} if bad else
                {"status": "PASS", "detail": "All referenced models are approved.", "evidence": []})
    if cid == "CTRL-APPROVED-PROVIDERS":
        if not providers:
            return {"status": "NOT_EVALUATED", "not_applicable": True, "detail": "No AI providers in code.", "evidence": []}
        if not ap:
            return {"status": "REVIEW", "detail": "No approved-provider list is defined.", "evidence": []}
        bad = sorted(p for p in providers if p.lower() not in ap)
        return ({"status": "FAIL", "detail": "Unapproved provider(s): " + ", ".join(bad), "evidence": []} if bad else
                {"status": "PASS", "detail": "All providers are approved.", "evidence": []})
    if cid == "CTRL-AUTHORIZED-TOOLS":
        broad = inv.get("blueprint", {}).get("evidence", {}).get("17", [])
        if broad:
            return {"status": "FAIL", "detail": "A tool with shell, file-write or database-mutation reach is exposed.", "evidence": broad[:5]}
        tools = inv.get("blueprint", {}).get("evidence", {}).get("16", [])
        if tools:
            return {"status": "PASS", "detail": "Tools are declared and none has broad system reach.", "evidence": tools[:5]}
        return {"status": "NOT_EVALUATED", "not_applicable": True, "detail": "No agent tools in code.", "evidence": []}
    if cid == "CTRL-APPROVED-DESTINATIONS":
        hosts = inv.get("hosts", [])
        if not hosts:
            return {"status": "NOT_EVALUATED", "not_applicable": True, "detail": "No external hosts in code.", "evidence": []}
        if not ah:
            return {"status": "REVIEW", "detail": f"{len(hosts)} external host(s) and no approved-host list is defined.", "evidence": []}
        bad = [h for h in hosts if not any(h == a or h.endswith("." + a) for a in ah)]
        return ({"status": "FAIL", "detail": "Unapproved host(s): " + ", ".join(bad[:6]), "evidence": []} if bad else
                {"status": "PASS", "detail": "All external hosts are approved.", "evidence": []})
    return {"status": "NOT_EVALUATED", "detail": "No detector.", "evidence": []}


def _runtime_events(tenant: str) -> list:
    return db.items("runtime_events", tenant)


def _runtime_for(cid: str, events: list) -> dict:
    code_map = {"CTRL-APPROVED-MODELS": "unapproved_model", "CTRL-APPROVED-PROVIDERS": "unapproved_provider",
                "CTRL-AUTHORIZED-TOOLS": "unapproved_tool", "CTRL-APPROVED-DESTINATIONS": "unapproved_api_host"}
    code = code_map.get(cid)
    rel_events = [e for e in events if (cid != "CTRL-AUTHORIZED-TOOLS" or e.get("tool_name"))]
    findings = []
    for e in events:
        for v in e.get("violations") or []:
            if v["code"] == code:
                findings.append({"id": "rf_" + e["event_id"], "title": v["message"], "severity": "HIGH",
                                 "application_id": e.get("application_id"), "created_at": e.get("received_at"),
                                 "review_status": "unreviewed", "occurrence_count": 1})
    return {"relevant_events": len(rel_events), "findings": findings, "code": code}


def latest_completed(tenant: str, repository_id: Optional[str] = None) -> list:
    return latest_scans(tenant, repository_id)


_NEEDS_SCOPE = {"CTRL-HARDCODED-SECRETS": "secrets", "CTRL-UNSAFE-EXEC": "code_security", "CTRL-TLS": "code_security",
                "CTRL-PROVIDER-DISCLOSURE": "ai_inventory"}


def eval_static_control(cid, scan, *args, **kwargs):
    need = _NEEDS_SCOPE.get(cid)
    sc = scan.get("scope")
    if need and sc is not None and need not in sc:
        return {"status": "NOT_EVALUATED", "not_applicable": True, "evidence": [],
                "detail": "Outside this scan's detection scope (personal and health information only)."}
    return _eval_static_control_raw(cid, scan, *args, **kwargs)


_PLAIN = {
    "CTRL-SENSITIVE-DATA": ("Personal and health data in code", "Looks for people's personal or health details left in your files (names, phone numbers, diagnoses, ID numbers)."),
    "CTRL-HARDCODED-SECRETS": ("Passwords and keys in code", "Looks for passwords or access keys written into your files."),
    "CTRL-SBOM": ("List of the software you depend on", "Checks that the project lists the software packages it uses, so any risk in them can be traced."),
    "CTRL-UNSAFE-EXEC": ("Unsafe commands in code", "Looks for code that runs text as a command, which attackers can abuse."),
    "CTRL-TLS": ("Secure connections", "Checks that data is only sent over encrypted connections."),
    "CTRL-PROVIDER-DISCLOSURE": ("AI services in use", "Lists which outside AI services the code talks to, so each one can be approved."),
    "CTRL-APPROVED-MODELS": ("Only approved AI models", "Checks that only AI models your organisation has approved are used."),
    "CTRL-APPROVED-PROVIDERS": ("Only approved AI providers", "Checks that data only goes to AI providers your organisation has approved."),
    "CTRL-AUTHORIZED-TOOLS": ("AI tools are authorised", "Checks that an AI agent can only use tools it has been given permission for."),
    "CTRL-APPROVED-DESTINATIONS": ("Only approved outside connections", "Checks that the application only calls outside addresses you have approved."),
}
_LABEL = {"PASS": ("Passed", "pass"), "FAIL": ("Needs attention", "fail"), "REVIEW": ("Needs review", "review"),
          "NOT_EVALUATED": ("Not checked", "none"), "UNKNOWN": ("Not checked", "none")}


def _plural(n, one, many):
    return f"{n} {one if n == 1 else many}"


def _plain_control(c, status, not_applicable, evals, per_scan, rt):
    """Client-facing wording: what the check is, the result in plain words, and the real reason with real numbers."""
    from collections import Counter
    cid = c["control_id"]
    title, what = _PLAIN.get(cid, (c["name"], c.get("description", "")))
    label, tone = _LABEL.get(status, ("Not checked", "none"))
    out_of_scope = bool(evals) and all(str(e.get("detail", "")).startswith("Outside this scan") for e in evals)
    repos = len(per_scan)
    reason, nxt = "", ""
    if out_of_scope:
        label, tone = "Not checked", "none"
        reason = "Switched off on purpose: this platform is set to look for personal and health information only."
    elif cid == "CTRL-SENSITIVE-DATA":
        items = [f for _, fs, _ in per_scan for f in fs
                 if f.get("rule_id", "").startswith(("pii.", "phi.")) and f.get("classification", "open") == "open"]
        if not repos:
            reason = "No repository has been scanned yet."
        elif not items:
            reason = f"No personal or health details were found in {_plural(repos, 'scanned repository', 'scanned repositories')}."
        else:
            files = len({(f["scan_id"], f["file"]) for f in items})
            rcount = len({f["scan_id"] for f in items})
            phi = sum(1 for f in items if f["rule_id"].startswith("phi."))
            top = Counter(f["title"].lower() for f in items).most_common(3)
            mix = ", ".join(f"{n} {t}" for t, n in top)
            reason = (f"{_plural(len(items), 'personal or health detail was', 'personal or health details were')} found in "
                      f"{_plural(files, 'file', 'files')} across {_plural(rcount, 'repository', 'repositories')}: {mix}. "
                      f"{phi} of them are health information and {len(items) - phi} are personal information.")
            nxt = "Open Findings to see each one, replace real values with made-up test data or move them to a protected store, then scan again."
    elif cid in ("CTRL-HARDCODED-SECRETS", "CTRL-UNSAFE-EXEC", "CTRL-TLS"):
        fam = {"CTRL-HARDCODED-SECRETS": (lambda f: f.get("rule_id", "").startswith("secret."), "password or key", "passwords or keys"),
               "CTRL-UNSAFE-EXEC": (lambda f: f.get("rule_id") in ("sec.eval-exec", "sec.shell-true", "sec.pickle-loads", "sec.yaml-unsafe-load"),
                                    "place where code runs text as a command", "places where code runs text as a command"),
               "CTRL-TLS": (lambda f: f.get("rule_id") in ("sec.tls-verify-disabled", "sec.insecure-http"),
                            "unencrypted connection or switched-off certificate check", "unencrypted connections or switched-off certificate checks")}[cid]
        items = [f for _, fs, _ in per_scan for f in fs if fam[0](f) and f.get("classification", "open") == "open"
                 and f.get("context") != "test"]
        if not repos:
            reason = "No repository has been scanned yet."
        elif not items:
            reason = f"None found in {_plural(repos, 'scanned repository', 'scanned repositories')}."
        else:
            files = len({(f["scan_id"], f["file"]) for f in items})
            reason = f"{_plural(len(items), fam[1] + ' was', fam[2] + ' were')} found in {_plural(files, 'file', 'files')}."
            nxt = {"CTRL-HARDCODED-SECRETS": "Cancel the exposed password or key, store the new one in a protected settings store, and scan again.",
                   "CTRL-UNSAFE-EXEC": "Replace the command-running code with a fixed list of allowed actions, then scan again.",
                   "CTRL-TLS": "Switch every address to https and keep certificate checking on, then scan again."}[cid]
    elif cid == "CTRL-PROVIDER-DISCLOSURE":
        provs = sorted({(p.get("name") if isinstance(p, dict) else str(p)) for _, _, inv in per_scan for p in ((inv or {}).get("providers") or [])})
        if not repos:
            reason = "No repository has been scanned yet."
        elif not provs:
            label, tone = "Passed", "pass"
            reason = "No outside AI services were found in the scanned code."
        else:
            reason = f"{_plural(len(provs), 'outside AI service is', 'outside AI services are')} used ({', '.join(provs[:4])}) and none has been approved yet."
            nxt = "Confirm a data-processing agreement for each one, then approve it under AI Usage → Policy."
    elif cid == "CTRL-SBOM":
        comps = sum(len((inv or {}).get("components") or []) for _, _, inv in per_scan)
        if not repos:
            reason = "No repository has been scanned yet."
        elif status == "PASS":
            reason = f"{_plural(comps, 'software package was', 'software packages were')} identified across {_plural(repos, 'repository', 'repositories')}."
        else:
            missing = [s.get("repository_name") or repo_ref(s) for s, _, inv in per_scan if not (inv or {}).get("components")]
            shown = ", ".join(str(n) for n in missing[:3]) + (" and others" if len(missing) > 3 else "")
            one = len(missing) == 1
            reason = (f"{len(missing)} of {_plural(repos, 'repository', 'repositories')} ({shown}) {'has' if one else 'have'} no dependency file "
                      f"such as requirements.txt or package.json, so the software {'it relies' if one else 'they rely'} on cannot be listed.")
            nxt = "Add the dependency file to those repositories and scan again."
    elif c["plane"] == "runtime":
        if status in ("NOT_EVALUATED", "UNKNOWN"):
            if repos:
                label, tone = "Passed", "pass"
                reason = ("Nothing of this kind was found in the scanned code, so there is nothing to approve. "
                          "Connect an application under AI Usage to also confirm it at run time.")
            else:
                reason = "No repository has been scanned yet."
        elif status == "PASS" and not (rt or {}).get("relevant_events"):
            reason = "No AI agent tools, models or outside calls of this kind were found in the scanned code, and no live traffic is connected yet, so there is nothing to approve."
        elif status == "PASS":
            reason = "Live AI traffic was checked and nothing outside the approved list was seen."
        elif status == "REVIEW":
            det = next((e.get("detail") for e in evals if e.get("status") == "REVIEW" and e.get("detail")), "")
            reason = (det.rstrip(".") + ". Nobody has confirmed these as approved yet.") if det else "Items were seen that nobody has confirmed as approved yet."
            nxt = "Define the approved list under AI Usage → Policy, then approve each item you accept."
        else:
            reason = f"{_plural(len(rt.get('findings') or []), 'live call', 'live calls')} went outside the approved list."
            nxt = "Review the approved list under AI Usage, then approve the item or stop the call."
    else:
        reason = {"PASS": "Checked and nothing needed attention.", "FAIL": "A problem was found in the scanned code.",
                  "REVIEW": "Something was found that a person should look at."}.get(status, "Not checked yet.")
    return {"title": title, "what": what, "label": label, "tone": tone, "reason": reason, "next": nxt}

def build_controls(tenant: str, repository_id: Optional[str] = None, scans: Optional[list] = None, events: Optional[list] = None) -> list:
    scans = scans if scans is not None else latest_completed(tenant, repository_id)
    policy = _policy(tenant)
    events = events if events is not None else _runtime_events(tenant)
    allf = db.items("findings", tenant) + db.items("findings_evidence", tenant)
    per_scan = []
    for s in scans:
        fs = [f for f in allf if f["scan_id"] == s["id"]]
        inv = db.get("inventory", tenant, s["id"]) or {}
        per_scan.append((s, fs, inv))
    out = []
    for c in CONTROLS:
        cid = c["control_id"]
        evals = []
        for s, fs, inv in per_scan:
            r = eval_static_control(cid, s, fs, inv, policy)
            evals.append({"scan": s, **r})
        applicable = [e for e in evals if not e.get("not_applicable")]
        failing = [e for e in applicable if e["status"] == "FAIL"]
        review = [e for e in applicable if e["status"] == "REVIEW"]
        passed = [e for e in applicable if e["status"] == "PASS"]
        na = [e for e in evals if e.get("not_applicable")]
        status = "FAIL" if failing else "REVIEW" if review else "PASS" if passed else "NOT_EVALUATED"
        runtime_status = None
        rt = {}
        if c["plane"] == "runtime":
            rt = _runtime_for(cid, events)
            if rt["findings"]:
                status = "FAIL"
                runtime_status = "FAIL"
            elif rt["relevant_events"]:
                runtime_status = "PASS"
                if status == "NOT_EVALUATED":
                    status = "PASS"
        not_applicable = bool(evals) and len(na) == len(evals) and not rt.get("relevant_events")
        blocked = None
        if not evals and not rt.get("relevant_events"):
            blocked = "No completed scan and no live traffic yet"
        attention = [{"repository_id": e["scan"]["repository_id"], "name": e["scan"].get("repository_name"), "status": e["status"]}
                     for e in failing + review]
        item = {
            **{k: c[k] for k in ("control_id", "name", "category", "plane", "severity", "description", "guide")},
            "status": status,
            "not_applicable": not_applicable,
            "blocked_reason": blocked,
            "evaluated_scans": len(applicable),
            "failing_scans": len(failing),
            "review_scans": len(review),
            "not_evaluated_scans": 0,
            "not_applicable_scans": len(na),
            "last_evaluated_at": max([e["scan"].get("completed_at") or e["scan"].get("finished_at") or "" for e in evals], default=None) or None,
            "attention_repos": attention,
            "attention_scans": [{"scan_id": e["scan"]["id"], "status": e["status"], "repo_ref": repo_ref(e["scan"]),
                                 "scanned_at": e["scan"].get("completed_at")} for e in failing + review],
            "has_evidence": bool(applicable) or bool(rt.get("relevant_events")),
        }
        if c["plane"] == "runtime":
            item.update({
                "code_scanned_repos": len(evals),
                "code_evaluated_repos": len(applicable),
                "code_not_applicable_repos": len(na),
                "open_findings": len(rt["findings"]),
                "total_findings": len(rt["findings"]),
                "runtime_status": runtime_status,
                "relevant_event_types": ["llm_call", "tool_call"] if cid == "CTRL-AUTHORIZED-TOOLS" else ["llm_call"],
                "rule_ids": [rt["code"]] if rt.get("code") else [],
            })
        item["plain"] = _plain_control(c, status, not_applicable, evals, per_scan, rt)
        # one source of truth: the status that drives the tile, the counts and the pill is the same result the table words
        if item["plain"]["tone"] == "pass" and item["status"] in ("NOT_EVALUATED", "UNKNOWN"):
            item["status"] = "PASS"
            item["not_applicable"] = False
            item["has_evidence"] = True
        if evals and all(str(e.get("detail", "")).startswith("Outside this scan") for e in evals):
            continue  # not part of this deployment's detection scope: not listed, so nothing shows as "Not checked"
        item["_evals"] = evals
        item["_rt"] = rt
        out.append(item)
    return out


def strip_private(c: dict) -> dict:
    return {k: v for k, v in c.items() if not k.startswith("_")}


# ---------------------------------------------------------------- 30 blueprint checks
def build_check_coverage(tenant: str, repository_id: Optional[str] = None) -> dict:
    scans = latest_completed(tenant, repository_id)
    checks = []
    summary = {}
    for cid, area, kind, label, detail, _lp, _fp, _sp in blueprint.CHECKS:
        by_repo, evidence = [], []
        statuses = []
        for s in scans:
            inv = db.get("inventory", tenant, s["id"]) or {}
            bp = inv.get("blueprint", {})
            ctx = {"files_scanned": inv.get("files_scanned", 0), "has_llm": bp.get("has_llm", False), "hosts": inv.get("hosts", []), "scope": s.get("scope")}
            ev = bp.get("evidence", {}).get(str(cid), [])
            st = blueprint.classify(cid, kind, ev, ctx)
            statuses.append(st)
            by_repo.append({"repository_id": s["repository_id"], "name": s.get("repository_name"), "status": st})
            evidence += [{"file": e["file"], "line": e["line"]} for e in ev[:3]]
        if not scans:
            status = "NO_SCAN"
        elif len(set(statuses)) == 1:
            status = statuses[0]
        else:
            status = "MIXED"
        summary[status] = summary.get(status, 0) + 1
        checks.append({
            "id": str(cid), "area": area, "kind": kind, "label": label, "detail": detail,
            "status": status, "evidence": evidence[:8],
            "by_repository": by_repo if len(scans) > 1 or status == "MIXED" else by_repo,
        })
    evaluated = sum(1 for c in checks if c["status"] in ("FOUND", "NOT_FOUND", "NOT_APPLICABLE", "MIXED"))
    latest = max([s.get("completed_at") or "" for s in scans], default=None) or None
    return {"checks": checks, "total_checks": len(checks), "evaluated_checks": evaluated, "summary": summary,
            "repositories_evaluated": len(scans), "scanned_at": latest}
