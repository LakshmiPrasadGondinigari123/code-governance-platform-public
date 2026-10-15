"""AI Inventory agent: explains a repository's AI usage in plain language, from the real scan facts only."""
import hashlib
import json

from fastapi import APIRouter, Depends

from . import auth, db, ui_model
from .ui_routes2 import model_card

router = APIRouter()


def _rules(card: dict) -> dict:
    models = [m for m in card.get("models", []) if m.get("model")]
    provs = sorted({m["provider"] for m in card.get("models", []) if m.get("provider")})
    ctr = card.get("controls", [])
    fail = [c for c in ctr if c["status"] == "FAIL"]
    rev = [c for c in ctr if c["status"] == "REVIEW"]
    data = card.get("data", {})
    name = card["repository"]["name"]
    if not models and not provs:
        summary = f"{name} does not call any AI model in its latest scan."
    else:
        summary = (f"{name} uses {len(models)} AI model{'s' if len(models) != 1 else ''} from {len(provs)} provider{'s' if len(provs) != 1 else ''}. "
                   f"{len(fail)} check{'s' if len(fail) != 1 else ''} need fixing and {len(rev)} need a decision.")
    steps = []
    if data.get("pii"):
        steps.append("Mask personal and health data before it reaches any AI model.")
    for c in fail[:2]:
        steps.append(f"Fix: {c['name']}.")
    if any("approved" in c["name"].lower() for c in rev):
        steps.append("Define the approved AI providers, models and hosts so the review checks can pass.")
    return {"summary": summary, "steps": steps[:3], "models": {}, "source": "rules"}


@router.get("/ai-inventory/agent")
def inventory_agent(repository_id: str, refresh: bool = False, user: dict = Depends(auth.current_user)):
    t = user["tenant_id"]
    card = model_card(repository_id=repository_id, user=user)
    if card.get("status") != "ok":
        return {"summary": "No completed scan yet.", "steps": [], "models": {}, "source": "rules"}
    sid = card["scan"]["scan_id"]
    key = sid
    cached = None if refresh else db.get("inv_agent", t, key)
    if cached:
        return cached
    out = _rules(card)
    try:
        from . import llm
        facts = {
            "repository": card["repository"]["name"],
            "models": [{"model": m["model"], "provider": m["provider"], "files": (m.get("files") or [])[:2]} for m in card.get("models", []) if m.get("model")],
            "providers": [p["name"] for p in card.get("ai", {}).get("providers", [])],
            "personal_or_health_findings": card.get("data", {}).get("pii", 0),
            "checks_failing": [{"name": c["name"], "detail": c["detail"]} for c in card.get("controls", []) if c["status"] == "FAIL"],
            "checks_to_review": [c["name"] for c in card.get("controls", []) if c["status"] == "REVIEW"],
            "outside_services": card.get("application", {}).get("external_services", [])[:5],
        }
        system = ("You explain an AI system's governance position to a non-technical healthcare client. Use ONLY the facts given; never invent models, files or numbers. "
                  "Reply with JSON only: {\"summary\": \"2-3 short plain sentences\", \"steps\": [\"up to 3 short actions, most important first\"], "
                  "\"models\": {\"<model name>\": \"one plain sentence on what it is used for here\"}}. No jargon.")
        res = llm.explain(system, json.dumps(facts)[:9000], fallback="{}", temperature=0.2, max_tokens=900)
        if res.get("status") == "ok":
            txt = res["content"]
            d = json.loads(txt[txt.index("{"): txt.rindex("}") + 1])
            if isinstance(d.get("summary"), str) and d["summary"].strip():
                out["summary"] = d["summary"].strip()[:700]
            st = [s.strip()[:220] for s in (d.get("steps") or []) if isinstance(s, str) and s.strip()]
            if st:
                out["steps"] = st[:3]
            known = {m["model"] for m in card.get("models", []) if m.get("model")}
            out["models"] = {k: v.strip()[:220] for k, v in (d.get("models") or {}).items() if k in known and isinstance(v, str)}
            out["source"] = "ai"
    except Exception:
        pass
    db.put("inv_agent", t, key, out)
    return out