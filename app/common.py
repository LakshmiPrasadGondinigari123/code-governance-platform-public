"""Helpers shared by route modules."""
import time
from typing import Optional

from fastapi import HTTPException

from . import db, scans as scan_mod

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEVERITIES = ["critical", "high", "medium", "low", "info"]


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def audit(user: dict, action: str, target: str = "", detail=None) -> None:
    db.put(
        "audit", user["tenant_id"], db.new_id("a_"),
        {"ts": now(), "user": user["username"], "role": user["role"], "action": action, "target": target, "detail": detail},
    )


def scan_or_404(user: dict, scan_id: str) -> dict:
    s = db.get("scans", user["tenant_id"], scan_id)
    if not s:
        raise HTTPException(404, "scan not found")
    return s


def latest_scans(tenant: str, repository_id: Optional[str] = None) -> list:
    """Newest completed scan per repository (the current governance posture)."""
    seen, out = set(), []
    for s in db.items("scans", tenant):  # newest first
        if s["status"] != "completed" or s["repository_id"] in seen:
            continue
        if repository_id and s["repository_id"] != repository_id:
            continue
        seen.add(s["repository_id"])
        out.append(s)
    return out


def scope_scans(user: dict, scan_id: Optional[str] = None, repository_id: Optional[str] = None) -> list:
    t = user["tenant_id"]
    if scan_id:
        return [scan_or_404(user, scan_id)]
    return latest_scans(t, repository_id)


def findings_for(tenant: str, scan_ids: set) -> list:
    return [f for f in db.items("findings", tenant) if f["scan_id"] in scan_ids]


def inventories_for(tenant: str, scan_ids: set) -> list:
    out = []
    for sid in scan_ids:
        inv = db.get("inventory", tenant, sid)
        if inv:
            out.append(inv)
    return out


def paginate(rows: list, limit: int, offset: int) -> dict:
    limit = max(1, min(limit, 500))
    offset = max(0, offset)
    return {"items": rows[offset: offset + limit], "total": len(rows), "limit": limit, "offset": offset}


def sev_counts(findings: list) -> dict:
    c = {s: 0 for s in SEVERITIES}
    for f in findings:
        c[f["severity"]] = c.get(f["severity"], 0) + 1
    return c


RULE_HELP = {
    "secret": (
        "A credential is committed to source control, so anyone with repository access (or its history) can use it.",
        "Revoke and rotate the credential now, remove it from history, and load it from an environment variable or secrets manager.",
    ),
    "pii": (
        "Personal data in code or fixtures can leak through logs, prompts and model training or retrieval.",
        "Replace with synthetic data, move real data to a governed store, and add PII redaction before prompts and logs.",
    ),
    "sec.eval-exec": (
        "eval/exec on dynamic content allows code injection, especially when the input can originate from model output.",
        "Remove eval/exec; parse structured output (JSON/schema) and dispatch to an allow-list of functions.",
    ),
    "sec.shell-true": (
        "shell=True lets crafted input run arbitrary shell commands.",
        "Pass an argument list without shell=True and validate all inputs.",
    ),
    "sec.pickle-loads": (
        "Unpickling untrusted data executes arbitrary code.",
        "Use JSON or another safe format; only unpickle data you produced and signed.",
    ),
    "sec.yaml-unsafe-load": ("yaml.load can construct arbitrary objects.", "Use yaml.safe_load."),
    "sec.tls-verify-disabled": (
        "Disabled TLS verification allows man-in-the-middle attacks on API and model traffic.",
        "Remove verify=False / rejectUnauthorized:false and install the proper CA bundle instead.",
    ),
    "sec.insecure-http": ("Plain HTTP traffic is readable and modifiable in transit.", "Use HTTPS endpoints."),
    "sec.debug-enabled": ("Debug mode can expose internals and secrets.", "Disable debug in production configuration."),
    "ai.model-usage": (
        "An AI model is referenced in code. Governance needs a record of which models are used and that each is approved.",
        "Add the model to the approved-model policy (Runtime > Policy) or replace it with an approved one; document it in a model card.",
    ),
    "ai.provider-sdk": (
        "An external AI provider receives data from this application.",
        "Confirm a data processing agreement, data-residency and retention terms, and that the provider is in the approved list.",
    ),
}


def rule_help(rule_id: str, category: str):
    return RULE_HELP.get(rule_id) or RULE_HELP.get(category) or ("Review this finding in context.", "Assess and remediate or document an exception.")
