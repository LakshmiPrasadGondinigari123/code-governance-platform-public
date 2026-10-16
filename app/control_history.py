"""Readiness over time: the ten governance checks evaluated for every completed scan, so progress can be shown honestly.

Earlier scans are evaluated from their own results only (no live traffic, which has no history). The newest scan of each
repository uses exactly what the Governance Controls board shows today.
"""
from typing import Optional

from fastapi import APIRouter, Depends

from . import auth, db, ui_model

router = APIRouter()


def _counts(controls: list) -> dict:
    live = [c for c in controls if c["plain"]["tone"] != "none"]
    passed = sum(1 for c in live if c["plain"]["tone"] == "pass")
    review = sum(1 for c in live if c["plain"]["tone"] == "review")
    fail = sum(1 for c in live if c["plain"]["tone"] == "fail")
    return {"passed": passed, "review": review, "fail": fail, "total": passed + review + fail}


def history(t: str, repository_id: Optional[str] = None) -> list:
    scans = [s for s in db.items("scans", t) if s.get("status") == "completed"]
    policy = ui_model._policy(t)
    sig = str(sorted((policy or {}).get("approved_models", [])) + sorted((policy or {}).get("approved_providers", [])))
    newest = {}
    for s in sorted(scans, key=lambda x: x.get("completed_at") or x.get("created_at") or ""):
        newest[s["repository_id"]] = s["id"]
    pts = []
    for s in scans:
        at = s.get("completed_at") or s.get("finished_at") or s.get("created_at")
        is_newest = newest.get(s["repository_id"]) == s["id"]
        cached = None if is_newest else db.get("control_history", t, s["id"])
        if cached and cached.get("policy_sig") == sig:
            p = cached
        else:
            c = _counts(ui_model.build_controls(t, s["repository_id"], scans=[s], events=None if is_newest else []))
            p = {**c, "scan_id": s["id"], "repository_id": s["repository_id"], "repository_name": s.get("repository_name"), "at": at, "policy_sig": sig}
            if not is_newest:
                db.put("control_history", t, s["id"], p)
        pts.append(p)
    pts.sort(key=lambda p: p.get("at") or "")
    if repository_id:
        return [p for p in pts if p["repository_id"] == repository_id and p["total"]]
    latest, out = {}, []
    for p in pts:
        latest[p["repository_id"]] = p
        tot = sum(x["total"] for x in latest.values())
        if tot:
            out.append({"at": p["at"], "passed": sum(x["passed"] for x in latest.values()), "total": tot,
                        "fail": sum(x["fail"] for x in latest.values()), "review": sum(x["review"] for x in latest.values()),
                        "scan_id": p["scan_id"], "repository_name": p.get("repository_name")})
    return out


@router.get("/governance/trend")
def trend(repository_id: Optional[str] = None, user: dict = Depends(auth.current_user)):
    pts = history(user["tenant_id"], repository_id or None)
    return {"points": [{**p, "pct": round(p["passed"] * 100 / p["total"])} for p in pts]}