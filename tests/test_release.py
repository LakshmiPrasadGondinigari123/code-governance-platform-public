"""Release tests for the behaviour clients see: scan stages, PII/PHI-only findings, evidence-based confidence,
governance controls, agents' fallbacks, repository maps, live consistency and the self-test."""
import uuid

from test_platform import PHI_APP, MASKED_APP, admin, client, scan_zip  # noqa: F401  (fixtures and helpers)

STAGES = ["intake", "manifest", "discovery", "ai_detection", "dependency_scan", "security_scan", "secrets_scan", "pii_phi_scan",
          "policy_evaluation", "evidence_graph", "documentation"]


def _scan(client, admin, files, name=None):
    return scan_zip(client, admin, files, name=name or f"{uuid.uuid4().hex[:8]}.zip")


def test_scan_runs_all_eleven_stages_with_real_results(client, admin):
    sid, s = _scan(client, admin, PHI_APP)
    assert s["status"] == "completed"
    names = [x["name"] for x in s["stages"]]
    assert names == STAGES
    assert all(x["status"] == "completed" for x in s["stages"])
    detail = {x["name"]: x["detail"] for x in s["stages"]}
    assert "item" in detail["pii_phi_scan"]            # e.g. "6 items (4 health, 2 personal)"
    assert "package" in detail["manifest"]
    assert detail["ai_detection"] and detail["documentation"]


def test_only_personal_and_health_data_is_listed(client, admin):
    _scan(client, admin, PHI_APP)
    items = client.get("/findings?page_size=500", headers=admin).json()["items"]
    assert items
    assert {f["data_type"] for f in items} <= {"PHI", "PII"}


def test_confidence_comes_from_evidence_not_a_fixed_number(client, admin):
    _scan(client, admin, PHI_APP)
    items = client.get("/findings?page_size=500", headers=admin).json()["items"]
    scores = {f["governance_confidence"] for f in items}
    assert len(scores) > 1, scores
    for f in items:
        assert 0.30 <= f["governance_confidence"] <= 0.99
        assert f["confidence_reasons"], f["title"]
        expected = "CONFIRMED_SENSITIVE" if f["governance_confidence"] >= 0.80 else "CONTEXTUAL"
        assert f["classification"] == expected


def test_confidence_unit_rules():
    from app import confidence
    good = {"rule_id": "pii.card", "agent": "pattern", "value": "4539 1488 0343 6467", "snippet": "card 4539 1488 0343 6467", "file": "app/pay.py", "severity": "high"}
    bad = {**good, "value": "4539 1488 0343 6468"}      # fails the card checksum
    assert confidence.explain(good)["score"] > confidence.explain(bad)["score"]
    test_file = {**good, "file": "tests/fixtures/pay.py"}
    assert confidence.explain(test_file)["score"] < confidence.explain(good)["score"]


def test_counts_add_up_across_repositories(client, admin):
    _scan(client, admin, PHI_APP)
    _scan(client, admin, MASKED_APP)
    repos = client.get("/repositories", headers=admin).json()["items"]
    total = client.get("/findings?page_size=500", headers=admin).json()["total"]
    per = sum(client.get(f"/findings?page_size=500&repository_id={r['repository_id']}", headers=admin).json()["total"] for r in repos)
    assert total == per


def test_governance_controls_agent_trend_and_owner_tracking(client, admin):
    _scan(client, admin, PHI_APP)
    ctl = client.get("/governance/controls", headers=admin).json()["controls"]
    assert ctl and all(c["plain"]["tone"] in ("pass", "fail", "review", "none") for c in ctl)
    ag = client.get("/governance/agent", headers=admin).json()
    assert ag["summary"] and ag["source"] in ("ai", "rules")
    tr = client.get("/governance/trend", headers=admin).json()["points"]
    assert all(0 <= p["pct"] <= 100 for p in tr)
    cid = ctl[0]["control_id"]
    r = client.put(f"/governance/control-actions/{cid}", headers=admin, json={"owner": "Dr. Rao", "status": "in_progress"})
    assert r.status_code == 200
    got = client.get("/governance/control-actions", headers=admin).json()["actions"][cid]
    assert got["owner"] == "Dr. Rao" and got["status"] == "in_progress"
    assert client.put(f"/governance/control-actions/{cid}", headers=admin, json={"status": "bogus"}).status_code == 400


def test_viewer_cannot_assign_owners(client, admin):
    name = "viewer" + uuid.uuid4().hex[:5]
    assert client.post("/auth/users", headers=admin, json={"username": name, "password": "Viewer-Pass-12345", "role": "viewer"}).status_code == 200
    tok = client.post("/auth/login", json={"username": name, "password": "Viewer-Pass-12345"}).json()["token"]
    h = {"Authorization": "Bearer " + tok}
    assert client.put("/governance/control-actions/CTRL-SBOM", headers=h, json={"owner": "x"}).status_code == 403
    assert client.get("/governance/control-actions", headers=h).status_code == 200


def test_ai_inventory_card_and_agent(client, admin):
    sid, s = _scan(client, admin, PHI_APP)
    inv = client.get("/ai-inventory", headers=admin).json()
    row = next(i for i in inv["items"] if i["repository_id"] == s["repository_id"])
    assert row["kind"] == "ai"
    card = client.get(f"/ai-inventory/model-card?repository_id={s['repository_id']}", headers=admin).json()
    assert card["status"] == "ok" and card["models"]
    ag = client.get(f"/ai-inventory/agent?repository_id={s['repository_id']}", headers=admin).json()
    assert ag["summary"]


def test_repository_architecture_map_is_capped_and_real(client, admin):
    _scan(client, admin, PHI_APP)
    maps = client.get("/architecture/repo-map", headers=admin).json()["repositories"]
    assert maps
    for m in maps:
        nodes = [n for ln in m["swim"]["lanes"] for n in ln["nodes"]]
        assert nodes and len(nodes) <= 16
        ids = {n["id"] for n in nodes}
        assert all(e["from"] in ids and e["to"] in ids for e in m["swim"]["edges"])


def test_issue_notes_cover_every_kind_of_finding(client, admin):
    _scan(client, admin, PHI_APP)
    notes = client.get("/findings/issue-notes", headers=admin).json()["notes"]
    assert notes and all(len(v) > 20 for v in notes.values())


def test_deleting_a_scan_removes_its_findings(client, admin):
    sid, s = _scan(client, admin, PHI_APP)
    before = client.get(f"/findings?page_size=500&repository_id={s['repository_id']}", headers=admin).json()["total"]
    assert before > 0
    assert client.delete(f"/scans/{sid}", headers=admin).status_code == 200
    ids = {f["scan_id"] for f in client.get("/findings?page_size=500", headers=admin).json()["items"]}
    assert sid not in ids


def test_pages_are_served(client):
    for path in ("/findings", "/controls", "/ai-inventory", "/selftest"):
        r = client.get(path, headers={"Accept": "text/html"})
        assert r.status_code == 200 and "<html" in r.text.lower(), path
    for js in ("/_next/static/cgp-topbar.js", "/_next/static/cgp-scope.js"):
        assert client.get(js).status_code == 200


def test_platform_selftest_passes(client, admin):
    _scan(client, admin, PHI_APP)
    res = client.get("/system/selftest", headers=admin).json()
    failed = [c for c in res["checks"] if not c["ok"]]
    assert not failed, failed
