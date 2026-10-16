"""Scale, live-connection and decision-support tests."""
import concurrent.futures
import time
import uuid

from test_platform import PHI_APP, admin, client, make_zip, scan_zip  # noqa: F401


def test_a_large_repository_scans_within_budget(client, admin):
    files = {}
    for i in range(2500):
        body = f"def handler_{i}(x):\n    return x + {i}\n"
        if i % 100 == 0:
            body += f'RECORD = "patient_{i}@example.invalid, +1-202-555-01{i % 100:02d}"\n'
        files[f"src/pkg{i // 100}/mod_{i}.py"] = body
    files["requirements.txt"] = "fastapi==0.115.0\n"
    t0 = time.time()
    r = client.post("/scans/upload", headers=admin, files={"file": (f"big-{uuid.uuid4().hex[:6]}.zip", make_zip(files), "application/zip")})
    assert r.status_code == 200, r.text
    sid = r.json()["scan_id"]
    s = {}
    for _ in range(300):
        s = client.get(f"/scans/{sid}", headers=admin).json()
        if s["status"] in ("completed", "failed"):
            break
        time.sleep(0.5)
    assert s["status"] == "completed", s.get("error")
    assert s["summary"]["files_scanned"] >= 2000
    assert time.time() - t0 < 120


def test_parallel_readers_all_get_answers(client, admin):
    paths = ["/findings?page_size=500", "/governance/controls", "/ai-inventory", "/repositories", "/governance/trend"]

    def hit(p):
        return client.get(p, headers=admin).status_code

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        codes = list(ex.map(hit, paths * 4))
    assert set(codes) == {200}


def test_runtime_events_are_checked_against_the_approved_lists(client, admin):
    sid, s = scan_zip(client, admin, PHI_APP, name=f"{uuid.uuid4().hex[:8]}.zip")
    cand = client.get("/governance/approval-candidates", headers=admin).json()
    assert any(m["name"].lower() == "gpt-4o" for m in cand["models"])
    pol = {"approved_providers": [], "approved_models": ["gpt-4o"], "approved_tools": [], "approved_api_hosts": []}
    assert client.put("/runtime/policy", headers=admin, json=pol).status_code == 200
    cand = client.get("/governance/approval-candidates", headers=admin).json()
    assert next(m for m in cand["models"] if m["name"].lower() == "gpt-4o")["approved"] is True
    ok = client.post("/runtime/events", headers=admin, json={"event_id": uuid.uuid4().hex, "event_type": "llm_call", "application_id": "test-app", "provider": "OpenAI", "model": "gpt-4o"})
    bad = client.post("/runtime/events", headers=admin, json={"event_id": uuid.uuid4().hex, "event_type": "llm_call", "application_id": "test-app", "provider": "OpenAI", "model": "some-unapproved-model"})
    assert ok.status_code == 200 and ok.json()["violations"] == []
    assert bad.status_code == 200 and bad.json()["violations"]
    client.put("/runtime/policy", headers=admin, json={"approved_providers": [], "approved_models": [], "approved_tools": [], "approved_api_hosts": []})


def test_confidence_calibration_reports_honestly_when_there_is_too_little_review(client, admin):
    d = client.get("/findings/calibration", headers=admin).json()
    assert [b["label"] for b in d["bands"]] == ["Below 60%", "60% to 79%", "80% to 89%", "90% and above"]
    assert d["enough"] is (d["reviewed"] >= d["needed"])


def test_reporter_script_builds_valid_events():
    import importlib.util
    import pathlib
    spec = importlib.util.spec_from_file_location("ai_usage_reporter", pathlib.Path(__file__).resolve().parent.parent / "scripts" / "ai_usage_reporter.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    sent = []
    rep = mod.AIUsageReporter("http://x.invalid", "key", "app1")
    rep._send = lambda body: sent.append(body) or {"status": "accepted"}
    rep.llm_call("OpenAI", "gpt-4o", prompt_tokens=10, completion_tokens=5, latency_ms=100)
    rep.tool_call("lookup")
    assert sent[0]["event_type"] == "llm_call" and sent[0]["response_metadata"]["total_tokens"] == 15
    assert sent[1]["tool_name"] == "lookup" and sent[1]["application_id"] == "app1"