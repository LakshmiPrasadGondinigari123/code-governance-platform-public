"""Two helpers that turn open questions into one-click answers: what you could approve, and how accurate confidence is."""
from fastapi import APIRouter, Depends

from . import auth, db, ui_model

router = APIRouter()


@router.get("/governance/approval-candidates")
def approval_candidates(user: dict = Depends(auth.current_user)):
    """Every AI provider, model and outside host the latest scans actually found, with whether it is approved today."""
    t = user["tenant_id"]
    pol = ui_model._policy(t)
    provs, models, hosts = {}, {}, {}
    for s in ui_model.latest_completed(t):
        inv = db.get("inventory", t, s["id"]) or {}
        name = s.get("repository_name") or s.get("repo_ref") or ""
        for p in inv.get("providers", []):
            provs.setdefault(p["name"], set()).add(name)
        for m in inv.get("models", []):
            models.setdefault(m["name"], set()).add(name)
        for h in inv.get("hosts", []):
            hosts.setdefault(h, set()).add(name)

    def rows(found: dict, key: str):
        ok = {str(x).lower() for x in pol.get(key, [])}
        return [{"name": k, "repositories": sorted(v), "approved": k.lower() in ok} for k, v in sorted(found.items())]

    return {"providers": rows(provs, "approved_providers"), "models": rows(models, "approved_models"),
            "hosts": rows(hosts, "approved_api_hosts"), "policy": pol}


BANDS = [(0.0, 0.60, "Below 60%"), (0.60, 0.80, "60% to 79%"), (0.80, 0.90, "80% to 89%"), (0.90, 1.01, "90% and above")]


@router.get("/findings/calibration")
def calibration(user: dict = Depends(auth.current_user)):
    """How often reviewers confirmed findings, by confidence band. Reviewers' own decisions are the labels."""
    t = user["tenant_id"]
    rows = []
    for f in db.items("findings", t):
        gs = f.get("governance_status", "unreviewed")
        if gs not in ("approved", "rejected"):
            continue
        rows.append((ui_model.ui_finding(f)["governance_confidence"], gs == "approved"))
    bands = []
    for lo, hi, label in BANDS:
        sel = [ok for c, ok in rows if lo <= c < hi]
        bands.append({"label": label, "reviewed": len(sel), "confirmed": sum(sel),
                      "confirmed_pct": round(100 * sum(sel) / len(sel)) if sel else None})
    return {"reviewed": len(rows), "enough": len(rows) >= 30, "needed": 30, "bands": bands}