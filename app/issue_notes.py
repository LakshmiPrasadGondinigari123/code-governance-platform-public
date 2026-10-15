"""Plain-language "what the issue is" text for each kind of finding, written from the real facts of the scan.

Facts come from the stored findings and each repository's inventory (which files really use an AI service).
The text is written by the language model when it is available, constrained to those facts, and falls back to
wording built from the same facts. The result is cached until the facts change.
"""
import hashlib
import json
import os
import re
from collections import Counter, defaultdict

from fastapi import APIRouter, Depends

from . import auth, db
from .common import latest_scans

router = APIRouter()
CODE_RX = re.compile(r"\.(py|js|jsx|ts|tsx|java|go|rb|cs|php|kt|rs|swift|sh)$", re.I)
SEV = {"CRITICAL": "Critical", "HIGH": "High", "ERROR": "High", "MEDIUM": "Medium", "WARNING": "Medium", "LOW": "Low", "INFO": "Low"}

RISK = [
    (r"diagnos", "a patient's medical condition", "Anyone who can open the repository can read it."),
    (r"record number|mrn", "the number that opens a patient's chart", "It links straight to a person's full medical record."),
    (r"social security|ssn", "a Social Security number", "With a name it is enough to open accounts in that person's name."),
    (r"birth|dob", "a date of birth", "Combined with a name or postcode it points to one individual."),
    (r"medicat|drug|prescri", "a medication", "It reveals what the patient is being treated for."),
    (r"lab|result", "a lab result", "Test results are among the most sensitive records."),
    (r"card|payment", "a payment card number", "A real card number can be copied and used for fraud."),
    (r"bank|account|iban", "a bank account number", "It can be used for fraud or unwanted withdrawals."),
    (r"email", "an email address", "It ties the record to a real person and invites phishing."),
    (r"phone", "a phone number", "It lets someone contact or trace the person."),
    (r"address|street|zip", "a home address", "It shows where a real person lives."),
    (r"name", "a person's name", "The name makes the other details traceable to one individual."),
    (r"insur|policy|member", "an insurance number", "It can be used to claim benefits in someone else's name."),
    (r"passport|licen|national|id", "a government ID number", "Official IDs are a prime target for identity fraud."),
]


def _risk(title: str):
    t = (title or "").lower()
    for rx, what, why in RISK:
        if re.search(rx, t):
            return what, why
    return None, None


def _facts(tenant: str) -> dict:
    scans = latest_scans(tenant)
    ai_files = {}
    names = {s["repository_id"]: (s.get("repository_name") or str(s.get("repo_ref", "")).rstrip("/").split("/")[-1]) for s in scans}
    for s in scans:
        inv = db.get("inventory", tenant, s["id"]) or {}
        fs = set()
        for c in (inv.get("ai_components") or []):
            if c.get("category") in ("llm_sdk", "llm_gateway", "framework"):
                fs.update(c.get("files") or [])
        for p in (inv.get("providers") or []):
            fs.update(p.get("files") or [])
        for m in (inv.get("models") or []):
            fs.update(m.get("files") or [])
        ai_files[s["repository_id"]] = fs
    groups = {}
    for f in db.items("findings", tenant):
        if f.get("category") != "pii" or f.get("scan_id") not in {s["id"] for s in scans}:
            continue
        sev = SEV.get(str(f.get("severity", "")).upper(), "Low")
        key = f"{f.get('rule_id') or f.get('title')}|{sev}"
        g = groups.setdefault(key, {"key": key, "title": f.get("title"), "class": "PHI" if str(f.get("rule_id", "")).startswith("phi.") else "PII",
                                    "severity": sev, "count": 0, "files": defaultdict(lambda: {"n": 0, "lines": [], "repo": "", "ai": False}),
                                    "repos": set(), "how": Counter(), "fields": Counter()})
        g["count"] += 1
        rp = names.get(f.get("repository_id")) or "repository"
        g["repos"].add(rp)
        d = g["files"][f["file"]]
        d["n"] += 1
        d["repo"] = rp
        d["ai"] = d["ai"] or (f["file"] in ai_files.get(f.get("repository_id"), set()))
        if f.get("line"):
            d["lines"].append(f["line"])
        g["how"][f.get("detected_by") or "scanner"] += 1
    out = {}
    for k, g in groups.items():
        files = sorted(g["files"].items(), key=lambda kv: -kv[1]["n"])
        out[k] = {
            "key": k, "title": g["title"], "class": g["class"], "severity": g["severity"], "count": g["count"],
            "repositories": sorted(g["repos"]),
            "files": [{"path": p, "occurrences": d["n"], "kind": "code" if CODE_RX.search(p) else "data", "repo": d["repo"],
                       "also_calls_an_ai_service": d["ai"]} for p, d in files[:5]],
            "file_count": len(files),
            "ai_linked_files": sum(1 for _, d in files if d["ai"]),
            "found_by": dict(g["how"]),
        }
    return out


def _fallback(f: dict, idx: int) -> str:
    what, why = _risk(f["title"])
    cls = "health data (PHI)" if f["class"] == "PHI" else "personal data (PII)"
    files = f["files"]
    top = files[0]["path"] if files else "the repository"
    more = f["file_count"] - 1
    where = top + (f" and {more} other file{'s' if more > 1 else ''}" if more > 0 else "")
    repos = f["repositories"]
    rp = f"{len(repos)} repositories" if len(repos) > 1 else (repos[0] if repos else "this repository")
    what = what or f["title"].lower()
    why = why or "It should not sit in code that many people and systems can read."
    openers = [
        f"{f['title']} ({cls}) appears {f['count']} time{'s' if f['count'] != 1 else ''} in {where}, in {rp}.",
        f"{where} in {rp} contains {what}, which is {cls}.",
        f"Found {f['count']} place{'s' if f['count'] != 1 else ''} holding {what} ({cls}), starting with {where}.",
    ]
    o = openers[int(hashlib.md5(f["key"].encode()).hexdigest(), 16) % len(openers)]
    tail = " Some of this sits in code that also calls an AI service, so it could be sent to an LLM unmasked." if f["ai_linked_files"] else " Mask it before the repository is shared or used with an AI service."
    return f"{o} {why}{tail}"


def _write_with_llm(facts: list) -> dict:
    try:
        from . import llm
        system = (
            "You write short explanations of data-protection findings for a non-technical healthcare client. "
            "For EACH item write 2 sentences (max 55 words in total): (1) say exactly what kind of data is exposed and where, naming "
            "one or two of the real files and the real counts given; (2) say why that matters for THIS kind of data and that it must be masked. "
            "If a file has also_calls_an_ai_service true, say that data could be passed to an AI model (LLM) unmasked; otherwise do not claim that. "
            "Use ONLY the facts given. Do not invent files, counts or tools. Make every item read differently: vary the opening words and structure, "
            "never start two items the same way, avoid jargon. Reply with JSON only: {\"notes\": {\"<key>\": \"text\"}}."
        )
        res = llm.explain(system, json.dumps(facts)[:14000], fallback="{}", temperature=0.5, max_tokens=3800)
        if res.get("status") != "ok":
            return {}
        txt = res["content"]
        d = json.loads(txt[txt.index("{"): txt.rindex("}") + 1])
        return {k: v.strip() for k, v in (d.get("notes") or {}).items() if isinstance(v, str) and len(v.strip()) > 20}
    except Exception:
        return {}


@router.get("/findings/issue-notes")
def issue_notes(refresh: bool = False, user: dict = Depends(auth.current_user)):
    t = user["tenant_id"]
    facts = _facts(t)
    sig = hashlib.sha1(json.dumps(facts, sort_keys=True, default=list).encode()).hexdigest()
    cached = None if refresh else db.get("issue_notes", t, "current")
    if cached and cached.get("sig") == sig:
        return cached
    items = list(facts.values())
    written = _write_with_llm(items)
    notes = {}
    for i, f in enumerate(items):
        notes[f["key"]] = written.get(f["key"]) or _fallback(f, i)
    doc = {"sig": sig, "notes": notes, "source": "ai" if written else "rules", "count": len(notes)}
    db.put("issue_notes", t, "current", doc)
    return doc
