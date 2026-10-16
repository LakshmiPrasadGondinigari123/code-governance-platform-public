"""Governance agent: turns the real results of the ten checks into a short, plain-language briefing."""
import hashlib
import json
from typing import Optional

from fastapi import APIRouter, Depends

from . import auth, db, ui_model

router = APIRouter()


def _facts(t: str, repository_id: Optional[str]) -> dict:
    ctrls = [c for c in ui_model.build_controls(t, repository_id) if c["plain"]["tone"] != "none"]
    scope = "all repositories"
    if repository_id:
        r = next((x for x in ui_model.ui_repositories(t) if x["repository_id"] == repository_id), None)
        scope = r["name"] if r else repository_id
    return {
        "scope": scope,
        "total": len(ctrls),
        "passed": sum(1 for c in ctrls if c["plain"]["tone"] == "pass"),
        "failing": [{"check": c["plain"]["title"], "why": c["plain"]["reason"], "fix": c["plain"]["next"],
                     "repositories": [a["name"] for a in c.get("attention_repos", []) if a.get("name")][:5]} for c in ctrls if c["plain"]["tone"] == "fail"],
        "to_decide": [{"check": c["plain"]["title"], "why": c["plain"]["reason"]} for c in ctrls if c["plain"]["tone"] == "review"],
    }


def _rules(f: dict) -> dict:
    nf, nr = len(f["failing"]), len(f["to_decide"])
    if not f["total"]:
        summary = f"No check results are available yet for {f['scope']}."
    elif nf:
        summary = (f"{f['scope'].capitalize() if f['scope'] == 'all repositories' else f['scope']} passes {f['passed']} of {f['total']} governance checks. "
                   f"{nf} check{'s' if nf != 1 else ''} need fixing before release and {nr} need a decision.")
    elif nr:
        summary = f"{f['scope']} passes {f['passed']} of {f['total']} checks. {nr} still need a decision from you."
    else:
        summary = f"{f['scope']} passes all {f['total']} governance checks."
    steps = [f"{x['check']}: {x['fix'] or x['why']}" for x in f["failing"][:3]]
    if not steps and f["to_decide"]:
        steps = [f"{x['check']}: {x['why']}" for x in f["to_decide"][:3]]
    return {"summary": summary, "steps": steps[:3], "source": "rules"}


@router.get("/governance/agent")
def governance_agent(repository_id: Optional[str] = None, refresh: bool = False, user: dict = Depends(auth.current_user)):
    t = user["tenant_id"]
    facts = _facts(t, repository_id or None)
    sig = hashlib.sha1(json.dumps(facts, sort_keys=True).encode()).hexdigest()
    key = f"{repository_id or 'all'}"
    cached = None if refresh else db.get("gov_agent", t, key)
    if cached and cached.get("sig") == sig:
        return cached
    out = _rules(facts)
    try:
        from . import llm
        system = ("You brief a non-technical healthcare executive on the results of AI-governance checks. Use ONLY the facts given; never invent numbers, files or tools. "
                  "Reply with JSON only: {\"summary\": \"2-3 short plain sentences with the verdict first\", \"steps\": [\"up to 3 short actions, most important first, each starting with a verb\"]}. No jargon.")
        res = llm.explain(system, json.dumps(facts)[:9000], fallback="{}", temperature=0.2, max_tokens=700)
        if res.get("status") == "ok":
            txt = res["content"]
            d = json.loads(txt[txt.index("{"): txt.rindex("}") + 1])
            if isinstance(d.get("summary"), str) and d["summary"].strip():
                out["summary"] = d["summary"].strip()[:700]
            st = [s.strip()[:220] for s in (d.get("steps") or []) if isinstance(s, str) and s.strip()]
            if st:
                out["steps"] = st[:3]
            out["source"] = "ai"
    except Exception:
        pass
    out["sig"] = sig
    db.put("gov_agent", t, key, out)
    return out
