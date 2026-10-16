"""One-click self-test: checks that the numbers on every tab agree with each other and with the stored scans."""
import time
from collections import Counter

from fastapi import APIRouter, Depends

from . import arch_map, auth, db, scans as scan_mod, ui_model, ui_routes2
from .common import latest_scans

router = APIRouter()


@router.get("/system/selftest")
def selftest(user: dict = Depends(auth.require("admin"))):
    t = user["tenant_id"]
    t0 = time.time()
    checks = []

    def check(name, fn):
        try:
            ok, detail = fn()
        except Exception as exc:  # a failing check must not stop the others
            ok, detail = False, f"error: {type(exc).__name__}: {exc}"[:240]
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    scans = latest_scans(t)
    sids = {s["id"] for s in scans}
    repos = ui_model.ui_repositories(t)
    findings = [f for f in db.items("findings", t) if f.get("scan_id") in sids]
    scan_by_repo = {s["repository_id"]: s for s in scans}
    scanned = [r for r in repos if r["repository_id"] in scan_by_repo]   # repositories that have a completed scan

    check("Every scanned repository is listed", lambda: ({s["repository_id"] for s in scans} <= {r["repository_id"] for r in repos}, f"{len(scans)} repositories with a completed scan, {len(repos)} listed"))
    check("Repository names are unique", lambda: (len({r['name'] for r in repos}) == len(repos), f"{len(repos)} names"))
    if scan_mod.ONLY_PII_PHI:
        check("Findings list holds only personal (PII) and health (PHI) data",
              lambda: (all(f.get("category") == "pii" for f in findings), f"{len(findings)} findings, categories: {dict(Counter(f.get('category') for f in findings))}"))
    check("No duplicate findings inside a scan",
          lambda: (len({(f['scan_id'], f['rule_id'], f['file'], f['line'], f.get('fingerprint')) for f in findings}) == len(findings), f"{len(findings)} findings checked"))
    check("Finding ids are unique", lambda: (len({f['id'] for f in findings}) == len(findings), f"{len(findings)} ids"))

    def per_repo():
        c = Counter(f["repository_id"] for f in findings)
        return sum(c.values()) == len(findings) and set(c) <= {r["repository_id"] for r in repos}, f"per-repository counts add up to {sum(c.values())} of {len(findings)}"
    check("Per-repository finding counts add up to the total", per_repo)
    check("Every finding has a severity and a file", lambda: (all(f.get("severity") and f.get("file") for f in findings), f"{len(findings)} findings"))
    check("Every latest scan has its inventory stored", lambda: (all(db.get("inventory", t, s["id"]) for s in scans), f"{len(scans)} inventories"))

    def controls():
        bad = []
        for r in scanned:
            sc = scan_by_repo[r["repository_id"]].get("scope")
            expected = sum(1 for c in ui_model.CONTROLS
                           if not (ui_model._NEEDS_SCOPE.get(c["control_id"]) and sc is not None and ui_model._NEEDS_SCOPE[c["control_id"]] not in sc))
            if len(ui_model.build_controls(t, r["repository_id"])) != expected:
                bad.append(r["name"])
        return not bad, f"every check that applies is evaluated for {len(scanned)} repositories" if not bad else f"incomplete for: {bad}"
    check("All governance checks are evaluated for every repository", controls)

    def inventory():
        inv = ui_routes2.ai_inventory(user=user)
        kinds = Counter(i["kind"] for i in inv["items"])
        ok = len(inv["items"]) == len(repos) and inv["summary"]["ai_systems"] == kinds.get("ai", 0)
        return ok, f"{len(inv['items'])} rows, {inv['summary']['ai_systems']} AI systems"
    check("AI Inventory covers every repository and its totals match", inventory)

    def cards():
        bad = [r["name"] for r in scanned if ui_routes2.model_card(repository_id=r["repository_id"], user=user).get("status") != "ok"]
        return not bad, f"{len(scanned)} cards built" if not bad else f"cards failed for: {bad}"
    check("An AI card can be built for every repository", cards)

    def maps():
        bad = []
        for s in scans:
            m = arch_map.build(t, s)
            if not m.get("layers"):
                bad.append(s.get("repository_name"))
        return not bad, f"{len(scans)} architecture maps built" if not bad else f"empty maps: {bad}"
    check("An architecture map can be built for every repository", maps)

    def conf():
        vals = [ui_model.ui_finding(f)["governance_confidence"] for f in findings]
        return all(0 <= v <= 1 for v in vals), f"{len(vals)} confidence scores in range"
    check("Confidence scores are between 0% and 100%", conf)

    def conf_variety():
        vals = {ui_model.ui_finding(f)["governance_confidence"] for f in findings}
        return len(vals) > 1 or len(findings) < 2, f"{len(vals)} different confidence values across {len(findings)} findings"
    check("Confidence scores vary with the evidence (not one fixed number)", conf_variety)

    def gov_agent_facts():
        from . import gov_agent
        f = gov_agent._facts(t, None)
        return f["total"] > 0 and f["passed"] + len(f["failing"]) + len(f["to_decide"]) == f["total"], f"{f['total']} checks: {f['passed']} passed, {len(f['failing'])} failing, {len(f['to_decide'])} to decide"
    check("Governance checks add up (passed + failing + to decide = total)", gov_agent_facts)
    def trend_matches():
        from . import control_history
        bad = []
        for r in scanned:
            hist = control_history.history(t, r["repository_id"])
            board = [c for c in ui_model.build_controls(t, r["repository_id"]) if c["plain"]["tone"] != "none"]
            if not hist or not board:
                continue
            if hist[-1]["passed"] != sum(1 for c in board if c["plain"]["tone"] == "pass"):
                bad.append(f"{r['name']}: trend {hist[-1]['passed']} vs board {sum(1 for c in board if c['plain']['tone'] == 'pass')}")
        return not bad, "latest trend point equals the board for every repository" if not bad else "; ".join(bad)[:240]
    check("Trend matches the board (latest point = today's passed checks)", trend_matches)
    passed = sum(1 for c in checks if c["ok"])
    return {"passed": passed, "failed": len(checks) - passed, "total": len(checks), "seconds": round(time.time() - t0, 2),
            "ran_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "checks": checks}