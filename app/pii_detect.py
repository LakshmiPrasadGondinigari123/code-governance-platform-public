"""Personal (PII) and health (PHI) information detection - a small pipeline of cooperating agents.

Every agent is deterministic and explainable (no model guesses); each finding records which agent produced it.

  1. Structure agent  - reads key/value structure (JSON, YAML, CSV, .env, dict literals) and classifies a field by what
                        its name means *and* whether its value really looks like that kind of data.
  2. Pattern agent    - value patterns anywhere in text: SSN, e-mail, phone, card (Luhn), IP, MRN, ICD-10, labelled names.
  3. Context agent    - decides PHI versus PII: identifiers that sit in a record or file that also carries health
                        information (diagnosis, medication, lab result, insurance, patient id ...) are protected health
                        information; the same identifiers elsewhere are personal information.
  4. Review agent     - removes placeholders, template variables and empty values so nothing is reported for "null",
                        "<name>", "${NAME}", "string" and similar.

The module also exposes POST /detect for instant, per-request detection (no repository scan needed).
"""
import csv
import io
import re
import time

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from . import auth

router = APIRouter()

# --------------------------------------------------------------------------- vocabulary
HEALTH_CONTEXT = re.compile(
    r"(?i)\b(patient|diagnos\w*|medicat\w*|prescri\w*|clinical|clinic|hospital|symptom\w*|treatment|therap\w*|"
    r"lab[_ ]?result\w*|hba1c|icd[-_ ]?10|\bmrn\b|medical|health\w*|insurance|member[_ ]?id|allerg\w*|"
    r"blood|surgery|dosage|physician|nurse)\b")

# (rule suffix, title, severity, key-name regex, value validator name)
FIELDS = [
    ("ssn",        "Social Security number", "high",   r"ssn|social[_ ]?security|national[_ ]?id",                         "ssn"),
    ("passport",   "Passport number",        "high",   r"passport",                                                        "token"),
    ("license",    "Driver's licence number", "high",  r"driver'?s?[_ ]?licen[cs]e|licen[cs]e[_ ]?(no|num)",               "token"),
    ("bank",       "Bank account number",    "high",   r"bank[_ ]?account|account[_ ]?(no|num\w*)|\biban\b|routing[_ ]?n",  "token"),
    ("card",       "Payment card number",    "high",   r"card[_ ]?(number|no|num)|\bpan\b|credit[_ ]?card|card_last\d|last4|last_four", "card"),
    ("dob",        "Date of birth",          "high",   r"\bdob\b|date[_ ]?of[_ ]?birth|birth[_ ]?date|birthday|born",      "date"),
    ("mrn",        "Medical record number",  "high",   r"\bmrn\b|medical[_ ]?record|patient[_ ]?(id|no|num\w*)|chart[_ ]?n", "token"),
    ("insurance",  "Insurance member ID",    "high",   r"insurance|member[_ ]?id|policy[_ ]?(no|num\w*)|subscriber",         "token"),
    ("diagnosis",  "Medical diagnosis",      "high",   r"diagnos|medical[_ ]?condition|health[_ ]?condition|disease|disorder|icd[-_ ]?10|\bicd\b",          "text"),
    ("medication", "Medication",             "high",   r"medicat|prescri|\bdrug\b|\brx\b|dosage",                          "text"),
    ("lab",        "Lab result",             "high",   r"lab[_ ]?result|test[_ ]?result|hba1c|blood[_ ]?(test|pressure|sugar)|cholesterol", "text"),
    ("email",      "Email address",          "medium", r"e-?mail",                                                        "email"),
    ("phone",      "Phone number",           "medium", r"phone|mobile|\btel\b|telephone|fax|contact[_ ]?number",           "phone"),
    ("address",    "Home address",           "medium", r"address|street|postcode|zip[_ ]?code|postal",                    "address"),
    ("person",     "Person's name",          "medium", r"(full|first|last|given|sur|family|patient|customer|person|user|contact)[_ ]?name|^name$", "name"),
    ("customer",   "Customer ID",            "low",    r"customer[_ ]?(id|no|number)|client[_ ]?id|account[_ ]?holder",    "token"),
    ("ip",         "IP address",             "low",    r"ip[_ ]?addr|\bip\b",                                              "ip"),
]
_FIELDS = [(sfx, title, sev, re.compile(k, re.I), v) for sfx, title, sev, k, v in FIELDS]

# identifier rule suffixes that become PHI when the surrounding file/record carries health information
IDENTIFIERS = {"person", "email", "phone", "address", "dob", "ssn", "mrn", "insurance", "customer", "ip", "license", "passport"}
ALWAYS_PHI = {"diagnosis", "medication", "lab", "mrn", "insurance"}

PLACEHOLDER = re.compile(
    r"(?i)^(null|none|n/?a|nil|string|number|todo|tbd|unknown|undefined|redacted|\*+|x+|-+|\?+|false|true|0+)$|"
    r"^\s*$|^<.*>$|^\{\{.*\}\}$|^\$\{.*\}$|^%\(.*\)s$|^\[.*\]$")

EMAIL_RX = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
PHONE_RX = re.compile(r"(?<![\d-])(?:\+?\d{1,3}[\s.\-]?)?(?:\(\d{3}\)|\d{3})[\s.\-]?\d{3}[\s.\-]?\d{4}(?!\d)")
SSN_RX = re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
CARD_RX = re.compile(r"\b(?:\d[ -]?){13,19}\b")
IP_RX = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
DATE_RX = re.compile(r"\b(?:\d{4}[-/.]\d{1,2}[-/.]\d{1,2}|\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4}|[A-Z][a-z]{2,8} \d{1,2},? \d{4})\b")
MRN_RX = re.compile(r"(?i)\b(?:MRN|MR#|patient[_ ]?id)\s*[:#=\-]?\s*([A-Z0-9][A-Z0-9\-]{4,})")
ICD_RX = re.compile(r"\b[A-TV-Z]\d{2}(?:\.\d{1,4})?\b")
NAME_VALUE = re.compile(r"^[A-Z][a-zA-Z'\-]+(?:[ ][A-Z][a-zA-Z'\-]+){0,3}$")
LABELLED_NAME = re.compile(r"(?i)\b(?:patient|customer|client|contact|name|dr\.?|mr\.?|mrs\.?|ms\.?)\s*[:=]\s*([A-Z][a-z]+(?:\s[A-Z][a-z]+){1,2})\b")
ADDRESS_VALUE = re.compile(r"\d+\s+[A-Za-z0-9 .'\-]+\b(?:street|st|avenue|ave|road|rd|lane|ln|drive|dr|blvd|boulevard|way|court|ct|plaza|place)\b|\b\d{5}(?:-\d{4})?\b", re.I)

KV_LINE = re.compile(r"""^\s*(?:-\s+)?["']?([A-Za-z_][\w .\-]{0,60})["']?\s*[:=]\s*(.+?)\s*,?\s*$""")
STRING_VALUE = re.compile(r"""^["'](.*)["']$""")


def luhn(num: str) -> bool:
    d = [int(c) for c in num if c.isdigit()]
    if not 13 <= len(d) <= 19:
        return False
    t = 0
    for i, x in enumerate(reversed(d)):
        if i % 2:
            x *= 2
            if x > 9:
                x -= 9
        t += x
    return t % 10 == 0


def _redact(val: str) -> str:
    v = val.strip()
    if len(v) <= 3:
        return "[redacted]"
    return v[0] + "…[redacted]"


def _unquote(v: str) -> str:
    v = v.strip().rstrip(",").strip()
    m = STRING_VALUE.match(v)
    return m.group(1) if m else v


ORG_WORDS = {"studio", "foundation", "inc", "corp", "corporation", "ltd", "llc", "gmbh", "cloud", "services", "service", "platform",
             "team", "group", "code", "server", "hub", "labs", "lab", "university", "college", "hospital", "clinic", "bank",
             "systems", "system", "technologies", "technology", "software", "solutions", "support", "desk", "center", "centre",
             "department", "office", "institute", "agency", "company", "network", "analytics", "framework", "library", "api",
             "console", "portal", "dashboard", "engine", "model", "assistant", "pipeline", "project", "store", "market"}


def looks_like_org(name: str) -> bool:
    toks = [x.lower().strip(".,") for x in name.split()]
    return bool(toks) and (toks[-1] in ORG_WORDS or toks[0] in ORG_WORDS)


def _valid(kind: str, val: str) -> bool:
    v = val.strip()
    if PLACEHOLDER.match(v):
        return False
    if kind == "email":
        return bool(EMAIL_RX.fullmatch(v))
    if kind == "phone":
        return len(re.sub(r"\D", "", v)) >= 7 and bool(re.search(r"\d", v))
    if kind == "date":
        return bool(DATE_RX.search(v))
    if kind == "ssn":
        return bool(SSN_RX.search(v)) or len(re.sub(r"\D", "", v)) == 9
    if kind == "card":
        digits = re.sub(r"\D", "", v)
        return len(digits) == 4 or luhn(v)          # last-4 columns or a full Luhn-valid number
    if kind == "address":
        return len(v) >= 6 and bool(re.search(r"\d", v)) and " " in v
    if kind == "name":
        return bool(NAME_VALUE.match(v)) and len(v) <= 60 and not looks_like_org(v)
    if kind == "ip":
        return bool(IP_RX.fullmatch(v))
    if kind == "token":
        return len(v) >= 3 and bool(re.search(r"[A-Za-z0-9]", v))
    if kind == "text":
        return len(v) >= 2 and bool(re.search(r"[A-Za-z]", v))
    return True


# --------------------------------------------------------------------------- agents
def _structure_agent(lines, is_csv):
    """Yield (line_no, suffix, title, severity, raw_value, agent) for structured fields."""
    out = []
    if is_csv:
        try:
            rows = list(csv.reader(io.StringIO("\n".join(lines))))
        except csv.Error:
            rows = []
        if len(rows) >= 2:
            header = [h.strip() for h in rows[0]]
            for ri, row in enumerate(rows[1:], start=2):
                for ci, cell in enumerate(row[:len(header)]):
                    for sfx, title, sev, krx, vkind in _FIELDS:
                        if krx.search(header[ci]) and _valid(vkind, cell):
                            out.append((ri, sfx, title, sev, cell, "structure"))
                            break
        return out
    for i, line in enumerate(lines, 1):
        if len(line) > 600:
            continue
        m = KV_LINE.match(line)
        if not m:
            continue
        key, raw = m.group(1).strip(), m.group(2)
        if raw.startswith(("{", "[")) or raw in ("{", "["):
            continue
        val = _unquote(raw)
        for sfx, title, sev, krx, vkind in _FIELDS:
            if krx.search(key) and _valid(vkind, val):
                if sfx == "person" and re.fullmatch(r"(?i)name", key.strip()) and len(val.split()) < 2:
                    continue  # a bare "name" field must hold a full name, not a single word
                out.append((i, sfx, title, sev, val, "structure"))
                break
    return out


def _pattern_agent(lines, covered):
    out = []
    for i, line in enumerate(lines, 1):
        if len(line) > 1500 or i in covered:
            continue
        for m in SSN_RX.finditer(line):
            out.append((i, "ssn", "Social Security number", "high", m.group(0), "pattern"))
        for m in EMAIL_RX.finditer(line):
            out.append((i, "email", "Email address", "medium", m.group(0), "pattern"))
        for m in PHONE_RX.finditer(line):
            digits = re.sub(r"\D", "", m.group(0))
            if 10 <= len(digits) <= 13 and not SSN_RX.search(m.group(0)):
                out.append((i, "phone", "Phone number", "medium", m.group(0), "pattern"))
        for m in CARD_RX.finditer(line):
            if luhn(m.group(0)) and re.sub(r"\D", "", m.group(0)) not in ("4242424242424242", "4111111111111111"):
                out.append((i, "card", "Payment card number", "high", m.group(0), "pattern"))
        for m in MRN_RX.finditer(line):
            out.append((i, "mrn", "Medical record number", "high", m.group(0).strip(), "pattern"))
        for m in LABELLED_NAME.finditer(line):
            if looks_like_org(m.group(1)):
                continue
            out.append((i, "person", "Person's name", "medium", m.group(1), "pattern"))
        if re.search(r"(?i)diagnos|icd", line):
            for m in ICD_RX.finditer(line):
                out.append((i, "diagnosis", "Diagnosis code", "high", m.group(0), "pattern"))
    return out


def analyze(rel: str, text: str, ext: str = "", budget_s: float = 4.0) -> dict:
    """Run the agent pipeline over one file's text. Returns {'items': [...], 'health_context': bool}."""
    t0 = time.time()
    lines = text.splitlines()
    ext = (ext or "").lower()
    is_csv = ext in (".csv", ".tsv")
    s_items = _structure_agent(lines, is_csv)
    covered = {x[0] for x in s_items}
    p_items = _pattern_agent(lines, covered) if time.time() - t0 < budget_s else []
    n_items = _ner_agent(lines, covered | {x[0] for x in p_items}, ext) if time.time() - t0 < budget_s else []
    raw = s_items + p_items + n_items

    # --- review agent: drop empty / placeholder values and de-duplicate
    seen, kept = set(), []
    for ln, sfx, title, sev, val, agent in raw:
        if PLACEHOLDER.match(val.strip()):
            continue
        k = (ln, sfx, val)
        if k in seen:
            continue
        seen.add(k)
        kept.append((ln, sfx, title, sev, val, agent))

    # --- context agent: PHI vs PII
    health = bool(HEALTH_CONTEXT.search(text)) or any(sfx in ALWAYS_PHI for _, sfx, *_ in kept)
    items = []
    for ln, sfx, title, sev, val, agent in kept:
        phi = sfx in ALWAYS_PHI or (health and sfx in IDENTIFIERS)
        items.append({
            "line": ln, "entity": sfx, "title": title, "severity": sev,
            "rule_id": ("phi." if phi else "pii.") + sfx, "class": "PHI" if phi else "PII",
            "value": val, "agent": agent,
            "snippet": (lines[ln - 1].strip()[:200] if 0 < ln <= len(lines) else ""),
        })
    return {"items": items, "health_context": health,
            "agents": [{"name": "structure", "findings": len(s_items)}, {"name": "pattern", "findings": len(p_items)},
                       {"name": "ner", "findings": len(n_items)},
                       {"name": "context", "phi": sum(1 for x in items if x["class"] == "PHI")},
                       {"name": "review", "dropped": len(raw) - len(kept)}]}


def redacted_snippet(item: dict) -> str:
    s = item.get("snippet") or ""
    v = item.get("value") or ""
    return s.replace(v, _redact(v)) if v and v in s else s


# --------------------------------------------------------------------------- language-model agents
_NLP = None
_NLP_ERR = None
_NER_USED = [0]
_CODE_EXT = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".cs", ".php", ".kt", ".rs", ".swift", ".sql"}
_STRING_LIT = re.compile(r"""(["'])((?:(?!\1).){12,300})\1""")
_NOT_PERSON = re.compile(r"(?i)^(open ?ai|anthropic|google|microsoft|amazon|github|gitlab|docker|kubernetes|python|java ?script|"
                         r"type ?script|react|node|linux|windows|mac ?os|chat ?gpt|llama|mistral|hugging ?face|lang ?chain)\b")


def _nlp():
    """Local spaCy NER model (no network, no API key). Loaded once; absent model simply disables the agent."""
    global _NLP, _NLP_ERR
    if _NLP is not None or _NLP_ERR is not None:
        return _NLP
    try:
        import spacy
        _NLP = spacy.load("en_core_web_sm", disable=["parser", "lemmatizer", "tagger", "attribute_ruler"])
    except Exception as exc:  # not installed / model missing
        _NLP_ERR = f"{type(exc).__name__}: {str(exc)[:160]}"
    return _NLP


def _ner_agent(lines, covered, ext):
    """Find people's names inside free text, comments and string literals (where no field name says 'name')."""
    nlp = _nlp()
    if nlp is None:
        return []
    texts = []  # (line_no, text)
    for i, line in enumerate(lines, 1):
        if i in covered or len(line.strip()) < 12 or len(line) > 1500:
            continue
        if ext in _CODE_EXT:
            pieces = [m.group(2) for m in _STRING_LIT.finditer(line)]
            hash_c = re.search(r"(?:#|//)\s*(.{12,})$", line)
            if hash_c:
                pieces.append(hash_c.group(1))
            for pc in pieces:
                if " " in pc:
                    texts.append((i, pc))
        elif not KV_LINE.match(line) or len(line.split()) > 6:
            texts.append((i, line.strip()))
        if len(texts) >= 400:
            break
    if not texts or _NER_USED[0] > 6000:
        return []
    _NER_USED[0] += len(texts)
    out = []
    for (ln, _txt), doc in zip(texts, nlp.pipe([t for _, t in texts], batch_size=64)):
        for ent in doc.ents:
            if ent.label_ != "PERSON":
                continue
            name = ent.text.strip()
            toks = name.split()
            if len(toks) < 2 or len(toks) > 4 or not all(re.fullmatch(r"[A-Z][a-z][A-Za-z'\-]*", x) for x in toks) or _NOT_PERSON.match(name) or looks_like_org(name):
                continue
            out.append((ln, "person", "Person's name", "medium", name, "ner"))
    return out


def llm_review(findings: list) -> dict:
    """Review agent (LLM, optional). It may only REMOVE candidates that are clearly not personal/health data
    (code identifiers, product or company names, placeholders). It can never add a finding or raise a severity,
    and it only sees masked previews and field context - never raw values."""
    import json as _json
    import os

    from . import llm
    info = {"name": "llm-review", "active": bool(os.getenv("GROQ_API_KEY")), "reviewed": 0, "dropped": 0}
    if not info["active"]:
        info["detail"] = "GROQ_API_KEY not configured; review agent idle."
        return info
    # only name candidates are judged: every other entity is format-validated (SSN, phone, card, MRN ...)
    cand = [(i, f) for i, f in enumerate(findings)
            if f.get("category") == "pii" and f.get("agent") in ("ner", "pattern") and f["rule_id"].endswith(".person")][:60]
    if not cand:
        info["detail"] = "No ambiguous candidates."
        return info
    payload = [{"id": i, "entity": f["title"], "file": f["file"], "line": f["line"], "context": f.get("snippet", "")[:160]} for i, f in cand]
    system = ("You review candidate detections of personal (PII) or health (PHI) information in source files. "
              "Reply with JSON only: {\"drop\": [ids], \"reason\": {\"id\": \"short reason\"}}. "
              "Drop an id ONLY if the context clearly shows it is not data about a person (a code identifier, a product, "
              "company or place name, a placeholder or an example of a format). When unsure, keep it.")
    r = llm.explain(system, _json.dumps(payload), fallback="{}", temperature=0.0)
    info["reviewed"] = len(cand)
    if r.get("status") != "ok":
        info["detail"] = r.get("detail")
        return info
    try:
        txt = r["content"]
        data = _json.loads(txt[txt.index("{"): txt.rindex("}") + 1])
        reasons_in = data.get("reason") or {}
        drop = {int(x) for x in data.get("drop", [])} & {i for i, _ in cand}
        drop = {i for i in drop if str(reasons_in.get(str(i), "")).strip()}      # no reason, no removal
        if len(drop) * 2 > len(cand):                                              # never remove more than half
            info["detail"] = "Review agent proposed removing most candidates; nothing changed."
            return info
    except Exception:
        info["detail"] = "Review agent reply could not be parsed; nothing changed."
        return info
    reasons = data.get("reason") or {}
    info["dropped_items"] = [{"file": findings[i]["file"], "line": findings[i]["line"], "rule_id": findings[i]["rule_id"],
                              "reason": str(reasons.get(str(i), ""))[:160]} for i in sorted(drop)]
    for i in sorted(drop, reverse=True):
        findings.pop(i)
    info["dropped"] = len(drop)
    info["model"] = r.get("model")
    return info


def agent_status() -> list:
    import os
    nlp = _nlp()
    return [
        {"name": "structure", "type": "deterministic", "active": True, "role": "Reads field names and values (JSON, YAML, CSV, .env)"},
        {"name": "pattern", "type": "deterministic", "active": True, "role": "SSN, email, phone, card, MRN, ICD-10, labelled names"},
        {"name": "ner", "type": "language model (local)", "active": nlp is not None, "role": "People's names in free text, comments and strings",
         "detail": None if nlp is not None else (_NLP_ERR or "not loaded")},
        {"name": "context", "type": "deterministic", "active": True, "role": "Decides PHI versus PII from the surrounding record"},
        {"name": "review", "type": "deterministic", "active": True, "role": "Drops placeholders and empty values"},
        {"name": "llm-review", "type": "language model (API)", "active": bool(os.getenv("GROQ_API_KEY")),
         "role": "Removes clear false positives only; never adds findings",
         "detail": None if os.getenv("GROQ_API_KEY") else "Set GROQ_API_KEY to enable"},
    ]

# --------------------------------------------------------------------------- real-time API
class DetectBody(BaseModel):
    text: str
    format: str = "auto"      # auto | json | csv | text


@router.get("/detect/agents")
def detect_agents(user: dict = Depends(auth.current_user)):
    return {"agents": agent_status()}


@router.post("/detect")
def detect(body: DetectBody, user: dict = Depends(auth.current_user)):
    """Instant detection for pipelines and applications: send text or a record, get PII/PHI entities back."""
    if len(body.text) > 2_000_000:
        raise HTTPException(413, "text larger than 2 MB")
    ext = {"csv": ".csv", "json": ".json", "text": ".txt"}.get(body.format, "")
    if not ext:
        head = body.text.lstrip()[:1]
        ext = ".json" if head in "{[" else (".csv" if body.text.count(",") > 2 and "\n" in body.text and ":" not in body.text.split("\n")[0] else ".txt")
    res = analyze("input" + ext, body.text, ext)
    return {
        "contains_phi": any(x["class"] == "PHI" for x in res["items"]),
        "contains_pii": any(x["class"] == "PII" for x in res["items"]),
        "entities": [{"line": x["line"], "type": x["title"], "class": x["class"], "severity": x["severity"],
                      "rule_id": x["rule_id"], "preview": _redact(x["value"]), "agent": x["agent"]} for x in res["items"]],
        "agents": res["agents"],
        "limits": "Pattern- and structure-based detection; free-text names without a label or field name are not guessed.",
    }
