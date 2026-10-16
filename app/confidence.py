"""Evidence-based confidence for personal / health data findings.

The score is computed from what the scanner actually saw (how it was found, whether the value passes independent
format checks, what else sits on the same line, where the file lives). Nothing is a fixed number per severity.
"""
import re
from datetime import date

_BASE = {"structure": (0.68, "The field name says what the data is and its value has the right format"),
         "pattern": (0.58, "The value matches a known pattern"),
         "ner": (0.42, "A language model read the text and recognised a person's name")}

_SYNTH = re.compile(r"(?i)\b(example|sample|dummy|fake|placeholder|lorem|test[_ -]?user|john doe|jane roe|noreply)\b")
_PATH = re.compile(r"(?i)(^|/)(tests?|fixtures?|samples?|seed|mocks?|examples?|docs?)(/|_|\.|$)|test_")
_ID_KINDS = (
    ("email", re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")),
    ("phone", re.compile(r"\+?\d[\d\s().-]{8,}\d")),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("mrn", re.compile(r"(?i)\bMRN[- ]?\d{4,}\b")),
    ("date", re.compile(r"\b(19|20)\d{2}-\d{2}-\d{2}\b")),
    ("card", re.compile(r"\b(?:\d[ -]?){13,19}\b")),
)


def _luhn(num: str) -> bool:
    d = [int(c) for c in re.sub(r"\D", "", num)]
    if len(d) < 13:
        return False
    s = 0
    for i, x in enumerate(reversed(d)):
        if i % 2 == 1:
            x *= 2
            if x > 9:
                x -= 9
        s += x
    return s % 10 == 0


def _value_checks(sfx: str, val: str):
    """Independent checks on the value itself: list of (delta, reason)."""
    out = []
    v = (val or "").strip()
    if not v:
        return out
    if sfx == "card":
        if _luhn(v):
            out.append((0.18, "The card number passes the standard card checksum"))
        else:
            out.append((-0.10, "The number does not pass the card checksum"))
    elif sfx == "ssn":
        m = re.fullmatch(r"(\d{3})-(\d{2})-(\d{4})", v)
        if m:
            a, g, s = int(m.group(1)), int(m.group(2)), int(m.group(3))
            if a in (0, 666) or a >= 900 or g == 0 or s == 0:
                out.append((-0.10, "The number is in a range that is never issued, so it is probably test data"))
            else:
                out.append((0.12, "The number is a valid Social Security number format"))
    elif sfx == "email":
        if re.fullmatch(r"[\w.+-]+@[\w-]+(\.[\w-]+)+", v):
            out.append((0.06, "The email address is correctly formed"))
        if re.search(r"(?i)@(example\.|.*\.invalid$|.*\.test$|test\.)|\.invalid$", v):
            out.append((-0.10, "The email uses an example or test domain"))
    elif sfx == "phone":
        digits = re.sub(r"\D", "", v)
        if 10 <= len(digits) <= 13:
            out.append((0.05, "The phone number has a realistic length"))
        if re.search(r"555[- .]?01\d\d", v):
            out.append((-0.10, "The number is in the range reserved for fictional phone numbers"))
    elif sfx == "mrn":
        if re.fullmatch(r"(?i)MRN[- ]?\d{5,}", v):
            out.append((0.10, "It follows the pattern of a medical record number"))
    elif sfx == "diagnosis":
        if re.fullmatch(r"[A-TV-Z]\d{2}(\.\w{1,4})?", v):
            out.append((0.08, "It is a valid diagnosis (ICD-10) code format"))
    elif sfx == "person":
        if len(v.split()) >= 2:
            out.append((0.05, "It looks like a first and last name"))
        else:
            out.append((-0.10, "It is a single word, which is weak evidence of a person's name"))
    elif sfx in ("bank", "account", "iban"):
        if re.search(r"(?i)test|xxxx|0000|1234", v):
            out.append((-0.12, "The account number looks like a placeholder"))
        elif re.fullmatch(r"[A-Za-z0-9-]{8,34}", v):
            out.append((0.12, "The account number has a realistic format"))
    elif sfx in ("dob", "birth"):
        m = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})", v)
        if m and 1900 <= int(m.group(1)) <= date.today().year:
            out.append((0.08, "It is a plausible date of birth"))
    elif sfx == "address":
        if re.search(r"\d", v) and re.search(r"(?i)\b(street|st|avenue|ave|road|rd|lane|ln|drive|dr|court|ct|blvd)\b", v):
            out.append((0.08, "It has a house number and a street, like a real address"))
    return out


def explain(f: dict) -> dict:
    rid = str(f.get("rule_id") or "")
    sfx = rid.split(".", 1)[-1]
    agent = f.get("agent") or "pattern"
    base, why_base = _BASE.get(agent, (0.50, "The scanner matched it"))
    score = base
    parts = [(base, why_base)]
    val = str(f.get("value") or "")
    snippet = str(f.get("snippet") or f.get("context_lines") or "")
    for d, why in _value_checks(sfx, val):
        score += d
        parts.append((d, why))
    # other identifiers on the same line: record-level evidence
    kinds = {k for k, rx in _ID_KINDS if rx.search(snippet)}
    if len(kinds) >= 3:
        score += 0.10
        parts.append((0.10, f"{len(kinds)} different kinds of identifier sit on the same line, which looks like a real record"))
    elif len(kinds) == 2:
        score += 0.05
        parts.append((0.05, "Another identifier sits on the same line"))
    if rid.startswith("phi."):
        score += 0.04
        parts.append((0.04, "The file talks about patients or clinical data"))
    if _SYNTH.search(val + " " + snippet):
        score -= 0.08
        parts.append((-0.08, "It contains words like 'example' or 'sample'"))
    if _PATH.search(str(f.get("file") or "")) or f.get("context") == "test":
        score -= 0.06
        parts.append((-0.06, "The file is in a test, sample or seed folder"))
    if str(f.get("severity", "")).lower() in ("high", "critical"):
        score += 0.03
    score = max(0.30, min(0.99, score))
    parts.sort(key=lambda p: -abs(p[0]))
    return {"score": round(score, 2), "reasons": [{"effect": "up" if d > 0 else ("down" if d < 0 else "base"), "text": t} for d, t in parts[:5]]}
