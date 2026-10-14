"""End-to-end API tests (FastAPI TestClient, isolated temporary data directory).

Run:  pip install -r requirements-dev.txt && pytest -q
"""
import io
import os
import tempfile
import zipfile

import pytest

_DATA = tempfile.mkdtemp(prefix="cgp-test-")
os.environ["DATA_DIR"] = _DATA
os.environ["DATABASE_PATH"] = os.path.join(_DATA, "app.db")
os.environ["ADMIN_USERNAME"] = "admin"
os.environ["ADMIN_PASSWORD"] = "Test-Admin-Password-1"
os.environ["BACKUP_INTERVAL_HOURS"] = "999"

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session")
def admin(client):
    r = client.post("/auth/login", json={"username": "admin", "password": "Test-Admin-Password-1"})
    assert r.status_code == 200
    return {"Authorization": "Bearer " + r.json()["token"]}


def make_zip(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, body in files.items():
            z.writestr(name, body)
    return buf.getvalue()


def scan_zip(client, headers, files, name="app.zip"):
    r = client.post("/scans/upload", headers=headers, files={"file": (name, make_zip(files), "application/zip")})
    assert r.status_code == 200, r.text
    sid = r.json()["scan_id"]
    import time
    for _ in range(60):
        s = client.get(f"/scans/{sid}", headers=headers).json()
        if s["status"] in ("completed", "failed"):
            return sid, s
        time.sleep(0.5)
    raise AssertionError("scan did not finish")


PHI_APP = {
    "app.py": (
        "from openai import OpenAI\n"
        'client = OpenAI(api_key="sk-TESTONLY00000000000000000000000000000000")\n'
        "def summarize(patient_record):\n"
        "    prompt = f\"Summarize: {patient_record['diagnosis']} for {patient_record['name']}\"\n"
        "    return client.chat.completions.create(model='gpt-4o', messages=[{'role': 'user', 'content': prompt}])\n"
        "def run(cmd):\n    return eval(cmd)\n"
    ),
    "data.json": '{"name": "Jane Roe", "ssn": "123-45-6789", "diagnosis": "Type 2 diabetes (ICD-10 E11.9)", "mrn": "MRN: 4400121"}',
    "requirements.txt": "openai==1.30.0\n",
}
MASKED_APP = {
    "app.py": (
        "def redact_phi(t):\n    return t\n"
        "def go(patient_record):\n"
        "    safe = redact_phi(patient_record['diagnosis'])\n"
        "    return client.chat.completions.create(model='gpt-4o', messages=[{'role': 'user', 'content': safe}])\n"
    )
}


def test_hardening(client):
    assert client.get("/liveness").json()["status"] == "alive"
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404
    h = client.get("/liveness").headers
    assert h["x-content-type-options"] == "nosniff" and h["x-frame-options"] == "DENY"


def test_auth_and_lockout(client):
    assert client.get("/scans").status_code == 401
    assert client.get("/scans", headers={"Authorization": "Bearer garbage"}).status_code == 401
    codes = [client.post("/auth/login", json={"username": "nobody", "password": f"x{i}"}).status_code for i in range(11)]
    assert 429 in codes


def test_only_pii_phi_are_listed_but_all_ten_checks_run(client, admin):
    sid, s = scan_zip(client, admin, PHI_APP)
    assert s["status"] == "completed"
    listed = {f["rule_id"] for f in client.get("/findings?page_size=200", headers=admin).json()["items"] if f["scan_id"] == sid}
    assert any(r.startswith(("pii.", "phi.")) for r in listed)
    assert not any(r.startswith(("secret.", "sec.", "ai.", "flow.")) for r in listed), listed
    ctl = {c["control_id"]: c for c in s["controls"]}
    assert len(ctl) == 10
    # the credential in the sample app is evidence for its check, not a listed finding
    assert ctl["CTRL-HARDCODED-SECRETS"]["status"] in ("FAIL", "REVIEW")
    assert ctl["CTRL-UNSAFE-EXEC"]["status"] in ("FAIL", "REVIEW")
    assert ctl["CTRL-SENSITIVE-DATA"]["status"] in ("FAIL", "REVIEW")

def test_gate_blocks_phi(client, admin):
    sid, _ = scan_zip(client, admin, PHI_APP)
    g = client.get(f"/scans/{sid}/ci-gate", headers=admin).json()
    reasons = {r["rule"] for r in g["reasons"]}
    assert g["block"] is True and reasons <= {"phi", "pii"} and reasons


def test_clean_app_passes_gate(client, admin):
    sid, _ = scan_zip(client, admin, {"main.py": "def add(a, b):\n    return a + b\n"}, "clean.zip")
    assert client.get(f"/scans/{sid}/ci-gate", headers=admin).json()["block"] is False

def test_scope_can_be_narrowed(client, admin):
    r = client.put("/scope", headers=admin, json={"detect": ["pii", "phi"]})
    assert r.status_code == 200
    try:
        sid, _ = scan_zip(client, admin, PHI_APP, "narrow.zip")
        s = client.get(f"/scans/{sid}", headers=admin).json()
        ctl = {c["control_id"]: c for c in s["controls"]}
        assert ctl["CTRL-HARDCODED-SECRETS"]["status"] == "NOT_EVALUATED"
    finally:
        client.put("/scope", headers=admin, json={"detect": ["pii", "phi", "secrets", "code_security", "ai_inventory"]})
    assert client.put("/scope", headers=admin, json={"detect": ["nonsense"]}).status_code == 400



def test_waivers(client, admin):
    sid, _ = scan_zip(client, admin, PHI_APP, "waive.zip")
    items = [f for f in client.get("/findings?page_size=200", headers=admin).json()["items"] if f["scan_id"] == sid]
    flow = next(f for f in items if f["rule_id"].startswith(("pii.", "phi.")))
    body = {"owner": "Alice", "rationale": "Masking is applied upstream by the gateway", "expires_at": "2099-01-01"}
    assert client.post(f"/findings/{flow['id']}/waiver", headers=admin, json=body).status_code == 422  # > 180 days
    from datetime import date, timedelta
    body["expires_at"] = (date.today() + timedelta(days=30)).isoformat()
    assert client.post(f"/findings/{flow['id']}/waiver", headers=admin, json=body).status_code == 200
    g = client.get(f"/scans/{sid}/ci-gate", headers=admin).json()
    assert g["waived"] >= 1
    body2 = dict(body, rationale="short")
    assert client.post(f"/findings/{flow['id']}/waiver", headers=admin, json=body2).status_code == 422


def test_policy_versioning_and_rbac(client, admin):
    p0 = client.get("/policy", headers=admin).json()["version"]
    r = client.put("/policy", headers=admin, json={"block_on": {"pii": "critical"}})
    assert r.status_code == 200 and r.json()["version"] != p0
    client.put("/policy", headers=admin, json={"block_on": {"pii": "high"}})
    client.post("/auth/users", headers=admin, json={"username": "viewer1", "password": "Viewer-Pass-2026", "role": "viewer"})
    v = client.post("/auth/login", json={"username": "viewer1", "password": "Viewer-Pass-2026"}).json()["token"]
    vh = {"Authorization": "Bearer " + v}
    assert client.put("/policy", headers=vh, json={"block_on": {"phi": False}}).status_code == 403
    assert client.delete("/scans", headers=vh).status_code == 403


def test_signed_evidence_pack(client, admin):
    sid, _ = scan_zip(client, admin, PHI_APP, "sign.zip")
    sp = client.get(f"/scans/{sid}/evidence-pack/signed", headers=admin).json()
    ok = client.post("/evidence-pack/verify", headers=admin, json={"pack": sp["pack"], "signature": sp["signature"]}).json()
    assert ok["valid"] is True
    sp["pack"]["gate"]["block"] = not sp["pack"]["gate"]["block"]  # any change must break the signature
    bad = client.post("/evidence-pack/verify", headers=admin, json={"pack": sp["pack"], "signature": sp["signature"]}).json()
    assert bad["valid"] is False


def test_intake_rejects_unsafe_input(client, admin):
    for url in ("file:///etc/passwd", "http://169.254.169.254/", "--upload-pack=x", "ssh://git@github.com/x/y"):
        assert client.post("/scans", headers=admin, json={"git_url": url}).status_code in (400, 422)
    slip = make_zip({"../../evil.txt": "x"})
    r = client.post("/scans/upload", headers=admin, files={"file": ("slip.zip", slip, "application/zip")})
    if r.status_code == 200:
        import time
        sid = r.json()["scan_id"]
        for _ in range(40):
            st = client.get(f"/scans/{sid}", headers=admin).json()["status"]
            if st in ("completed", "failed"):
                break
            time.sleep(0.25)
        assert st == "failed"
    else:
        assert r.status_code in (400, 422)


def test_password_change_and_backup(client, admin):
    r = client.post("/auth/password", headers=admin, json={"current_password": "wrong", "new_password": "New-Admin-Pass-2"})
    assert r.status_code == 401
    b = client.post("/admin/backups", headers=admin)
    assert b.status_code == 200 and b.json()["bytes"] > 0
    assert any(x["name"] == b.json()["created"] for x in client.get("/admin/backups", headers=admin).json()["backups"])
    dl = client.get(f"/admin/backups/{b.json()['created']}", headers=admin)
    assert dl.status_code == 200 and dl.content[:15] == b"SQLite format 3"

def test_realtime_detect_api(client, admin):
    rec = '{"patient_id": "PAT-0001", "name": "Aarav Example", "email": "aarav@example.invalid", "phone": "+1-202-555-0101", "date_of_birth": "1988-04-12", "diagnosis": "Type 2 diabetes"}'
    r = client.post("/detect", headers=admin, json={"text": rec.replace(", ", ",\n  ").replace("{", "{\n  ").replace("}", "\n}")})
    assert r.status_code == 200
    body = r.json()
    types = {e["type"] for e in body["entities"]}
    assert body["contains_phi"] is True
    assert {"Person's name", "Email address", "Phone number", "Date of birth", "Medical diagnosis"} <= types
    # nothing identifiable is echoed back in clear text
    assert "Aarav" not in str(body["entities"])
    clean = client.post("/detect", headers=admin, json={"text": "{\n  \"mode\": \"fast\",\n  \"retries\": 3\n}"}).json()
    assert clean["entities"] == [] and clean["contains_phi"] is False and clean["contains_pii"] is False
    assert client.post("/detect", json={"text": "x"}).status_code == 401


def test_structured_csv_is_pii_not_phi(client, admin):
    csvdata = "customer_id,full_name,email,phone,bank_account\nCUST-1,Noah Example,noah@example.invalid,+1-202-555-0111,ACCT-0001\n"
    sid, s = scan_zip(client, admin, {"transactions.csv": csvdata}, "fin.zip")
    rules = {f["rule_id"] for f in client.get("/findings?page_size=200", headers=admin).json()["items"] if f["scan_id"] == sid}
    assert {"pii.person", "pii.email", "pii.phone", "pii.bank", "pii.customer"} <= rules
    assert not any(r.startswith("phi.") for r in rules)

def test_agents_are_reported(client, admin):
    names = {a["name"]: a for a in client.get("/detect/agents", headers=admin).json()["agents"]}
    assert {"structure", "pattern", "ner", "context", "review", "llm-review"} <= set(names)
    assert names["structure"]["active"] and names["pattern"]["active"] and names["context"]["active"]

def test_controls_have_plain_language(client, admin):
    scan_zip(client, admin, PHI_APP, "plain.zip")
    ctl = {c["control_id"]: c for c in client.get("/governance/controls", headers=admin).json()["controls"]}
    assert len(ctl) == 10
    for c in ctl.values():
        p = c["plain"]
        assert p["title"] and p["what"] and p["reason"] and p["label"] in ("Passed", "Needs attention", "Needs review", "Not checked")
    sec = ctl["CTRL-SENSITIVE-DATA"]["plain"]
    assert sec["label"] in ("Needs attention", "Needs review") and any(ch.isdigit() for ch in sec["reason"]) and sec["next"]
    assert "found in" in ctl["CTRL-HARDCODED-SECRETS"]["plain"]["reason"] or "None found" in ctl["CTRL-HARDCODED-SECRETS"]["plain"]["reason"]


def test_counts_match_table(client, admin):
    """The dashboard tile, the summary line and the table must all describe the same result."""
    sid, s = scan_zip(client, admin, {"main.py": "def add(a, b):\n    return a + b\n", "requirements.txt": "fastapi==0.110.0\n"}, "consistency.zip")
    repo = s["repository_id"]
    ctl = client.get(f"/governance/controls?repository_id={repo}", headers=admin).json()["controls"]
    overview = client.get(f"/overview/summary?repository_id={repo}", headers=admin).json()["security_evaluations"]
    by_label = {}
    for c in ctl:
        by_label[c["plain"]["label"]] = by_label.get(c["plain"]["label"], 0) + 1
    assert overview["total"] == len(ctl)
    assert overview["passed"] == by_label.get("Passed", 0)
    assert overview["review"] == by_label.get("Needs review", 0)
    assert overview["failed"] == by_label.get("Needs attention", 0)
    assert overview["unknown"] == by_label.get("Not checked", 0)
    assert all(c["status"] == "PASS" for c in ctl if c["plain"]["label"] == "Passed")

def test_severity_levels_are_distinct(client, admin):
    files = {"records.json": '{\n  "patient_id": "PAT-1",\n  "name": "Aarav Example",\n  "email": "a@example.invalid",\n  "date_of_birth": "1988-04-12",\n  "diagnosis": "Asthma",\n  "customer_id": "CUST-9"\n}'}
    sid, _ = scan_zip(client, admin, files, "severity.zip")
    rows = [f for f in client.get("/findings?page_size=200", headers=admin).json()["items"] if f["scan_id"] == sid]
    sev = {f["title"]: f["severity"] for f in rows}
    assert sev["Date of birth"] == "HIGH" and sev["Medical diagnosis"] == "HIGH"
    assert sev["Email address"] == "MEDIUM" and sev["Person's name"] == "MEDIUM"
    assert sev["Customer ID"] == "LOW"

def test_values_visible_to_reviewers_only(client, admin):
    files = {"patients.json": '{\n  "name": "Aarav Example",\n  "diagnosis": "Type 2 diabetes",\n  "date_of_birth": "1988-04-12"\n}'}
    sid, _ = scan_zip(client, admin, files, "values.zip")
    rows = [f for f in client.get("/findings?page_size=200", headers=admin).json()["items"] if f["scan_id"] == sid]
    vals = {f["title"]: f["value"] for f in rows}
    assert vals["Medical diagnosis"] == "Type 2 diabetes" and vals["Person's name"] == "Aarav Example"
    assert all(f["value_masked"] is False for f in rows)
    client.post("/auth/users", headers=admin, json={"username": "viewer2", "password": "Viewer-Pass-2026", "role": "viewer"})
    v = client.post("/auth/login", json={"username": "viewer2", "password": "Viewer-Pass-2026"}).json()["token"]
    vrows = [f for f in client.get("/findings?page_size=200", headers={"Authorization": "Bearer " + v}).json()["items"] if f["scan_id"] == sid]
    assert vrows and all(f["value_masked"] is True for f in vrows)
    assert not any("Aarav" in str(f["value"]) or "diabetes" in str(f["value"]) for f in vrows)