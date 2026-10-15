"""Background scan pipeline: fetch -> inventory/detect -> controls -> graph -> persist."""
import hashlib
import io
import logging
import os
import shutil
import subprocess
import threading
import time
import zipfile
from collections import Counter

from . import bus, db, frameworks, scanner

log = logging.getLogger("scans")
WORK_DIR = os.path.join(db.DATA_DIR, "work")
CANCELLED = set()
_slots = threading.Semaphore(int(os.getenv("MAX_CONCURRENT_SCANS", "2")))
STAGES = ["fetch", "inventory", "controls", "graph", "persist"]
# only personal (PII) and health (PHI) data is listed as findings; other detections stay evidence for the ten checks. Set LIST_ONLY_PII_PHI=false to list everything.
ONLY_PII_PHI = os.getenv("LIST_ONLY_PII_PHI", "true").lower() in ("1", "true", "yes")
MAX_ZIP_FILES = 20000
MAX_ZIP_BYTES = 300 * 1024 * 1024


def iso(ts=None):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts if ts else time.time()))


def repo_id_for(key: str) -> str:
    return hashlib.sha1(key.strip().lower().rstrip("/").removesuffix(".git").encode()).hexdigest()[:12]


def _event(doc, stage, status, message=""):
    doc["events"].append({"ts": iso(), "stage": stage, "status": status, "message": message})
    for s in doc["stages"]:
        if s["name"] == stage:
            s["status"] = status
            s["detail"] = message
            if status == "running":
                s["started_at"] = iso()
            else:
                s["finished_at"] = iso()


def create(tenant: str, user: str, git_url: str = None, zip_bytes: bytes = None, name: str = None) -> dict:
    if git_url:
        git_url = scanner.validate_git_url(git_url)
        repo_name = git_url.rstrip("/").removesuffix(".git").split("/")[-1] or "repository"
        repo_key = git_url
        source = "git"
    else:
        repo_name = (name or "upload").removesuffix(".zip")
        repo_key = f"zip:{repo_name}"
        source = "zip"
    scan_id = db.new_id("scan_")
    doc = {
        "id": scan_id, "source": source, "git_url": git_url, "repository_id": repo_id_for(repo_key),
        "repository_name": repo_name, "status": "queued", "created_by": user,
        "created_at": iso(), "finished_at": None, "error": None, "summary": None,
        "stages": [{"name": n, "status": "pending", "detail": "", "started_at": None, "finished_at": None} for n in STAGES],
        "events": [], "controls": [],
    }
    doc["repo_ref"] = git_url or f"zip:{repo_name}"
    doc["scanned_at"] = doc["created_at"]
    db.put("scans", tenant, scan_id, doc)
    bus.publish(tenant, "findings", {"type": "scan_queued", "scan_id": scan_id, "repo_ref": doc["repo_ref"], "repository_id": doc["repository_id"]})
    t = threading.Thread(target=_run, args=(tenant, scan_id, git_url, zip_bytes), daemon=True, name=f"scan-{scan_id}")
    t.start()
    return doc


def _cancelled(scan_id):
    return scan_id in CANCELLED


def _save(tenant, doc):
    if db.get("scans", tenant, doc["id"]) is None:
        raise RuntimeError("scan was deleted")
    db.put("scans", tenant, doc["id"], doc)


def _safe_extract(data: bytes, dest: str):
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        infos = z.infolist()
        if len(infos) > MAX_ZIP_FILES or sum(i.file_size for i in infos) > MAX_ZIP_BYTES:
            raise ValueError("zip too large")
        root = os.path.abspath(dest)
        for i in infos:
            name = i.filename.replace("\\", "/")
            parts = [p for p in name.split("/") if p]
            if name.startswith("/") or ".." in parts or (parts and ":" in parts[0]):
                raise ValueError("zip contains unsafe path")
            target = os.path.abspath(os.path.join(root, *parts)) if parts else root
            if os.path.commonpath([root, target]) != root:
                raise ValueError("zip contains unsafe path")
        z.extractall(dest)


def _run(tenant, scan_id, git_url, zip_bytes):
    doc = db.get("scans", tenant, scan_id)
    work = os.path.join(WORK_DIR, scan_id)
    with _slots:
        try:
            doc["status"] = "running"
            doc["started_at"] = iso()
            _event(doc, "fetch", "running", "Fetching source")
            _save(tenant, doc)
            _emit(tenant, doc, "scan_started")
            os.makedirs(work, exist_ok=True)
            if git_url:
                env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
                p = subprocess.run(
                    ["git", "clone", "--depth", "1", "--single-branch", "--no-tags", "--", git_url, os.path.join(work, "src")],
                    capture_output=True, text=True, timeout=180, env=env,
                )
                if p.returncode != 0:
                    raise RuntimeError("git clone failed: " + (p.stderr.strip().splitlines() or ["unknown error"])[-1])
                root = os.path.join(work, "src")
                try:
                    h = subprocess.run(["git", "-C", root, "rev-parse", "HEAD"], capture_output=True, text=True, timeout=20)
                    doc["commit_sha"] = h.stdout.strip() or None
                    b = subprocess.run(["git", "-C", root, "rev-parse", "--abbrev-ref", "HEAD"], capture_output=True, text=True, timeout=20)
                    doc["branch"] = b.stdout.strip() or None
                except Exception:
                    pass
            else:
                root = os.path.join(work, "src")
                os.makedirs(root, exist_ok=True)
                _safe_extract(zip_bytes, root)
            if _cancelled(scan_id):
                raise InterruptedError()
            _event(doc, "fetch", "completed", "Source ready")
            _event(doc, "inventory", "running", "Scanning files")
            _save(tenant, doc)

            _last = [0.0]

            def _progress(done, total):
                if time.time() - _last[0] < 3:
                    return
                _last[0] = time.time()
                for s_ in doc["stages"]:
                    if s_["name"] == "inventory":
                        s_["detail"] = f"Scanning files {done}/{total}"
                try:
                    _save(tenant, doc)
                except Exception:
                    pass

            from . import governance_ops
            scope = governance_ops.get_scope(tenant)
            doc["scope"] = scope
            result = scanner.scan_directory(root, cancelled=lambda: _cancelled(scan_id), progress=_progress, scope=scope)
            if _cancelled(scan_id):
                raise InterruptedError()
            for f in result["findings"]:
                f["id"] = db.new_id("f_")
                f["scan_id"] = scan_id
                f["repository_id"] = doc["repository_id"]
                f["classification"] = "open"
                f["governance_status"] = "unreviewed"
                f["comment"] = None
            # carry review decisions forward from the previous scan of the same repo
            prev = [s for s in db.items("scans", tenant) if s["repository_id"] == doc["repository_id"] and s["id"] != scan_id and s["status"] == "completed"]
            if prev:
                old = {f["fingerprint"]: f for f in db.items("findings", tenant) if f["scan_id"] == prev[0]["id"]}
                for f in result["findings"]:
                    o = old.get(f["fingerprint"])
                    if o and o.get("classification") != "open":
                        f["classification"] = o["classification"]
                        f["governance_status"] = o.get("governance_status", "unreviewed")
                        f["comment"] = o.get("comment")
            _event(doc, "inventory", "completed", f"{result['files_scanned']} files, {len(result['findings'])} findings")
            _event(doc, "controls", "running", "Evaluating governance controls")
            _save(tenant, doc)

            controls = frameworks.evaluate(result["findings"], result["components"], result["evidence"])
            _event(doc, "controls", "completed", f"{sum(1 for c in controls if c['status']=='satisfied')}/{len(controls)} satisfied")
            _event(doc, "graph", "running", "Building evidence graph")
            graph = scanner.build_graph(doc["repository_id"], doc["repository_name"], result, result["findings"], controls)
            _event(doc, "graph", "completed", f"{len(graph['nodes'])} nodes, {len(graph['edges'])} edges")
            _event(doc, "persist", "running", "Saving results")

            for f in result["findings"]:
                # personal/health findings are the issues people review; everything else is evidence for the ten checks only
                db.put("findings" if (f["category"] == "pii" or not ONLY_PII_PHI) else "findings_evidence", tenant, f["id"], f)
            db.put("graphs", tenant, scan_id, graph)
            db.put(
                "inventory", tenant, scan_id,
                {
                    "scan_id": scan_id, "repository_id": doc["repository_id"], "components": result["components"],
                    "ai_components": result["ai_components"], "models": result["models"], "providers": result["providers"],
                    "hosts": result["hosts"], "dir_stats": result["dir_stats"], "languages": result["languages"],
                    "blueprint": result["blueprint"], "files_scanned": result["files_scanned"], "file_list": result["file_list"], "routes": result["routes"],
                },
            )
            visible = [f for f in result["findings"] if f["category"] == "pii" or not ONLY_PII_PHI]
            sev = Counter(f["severity"] for f in visible)
            cat = Counter(f["category"] for f in visible)
            doc["controls"] = controls
            doc["summary"] = {
                "files_scanned": result["files_scanned"], "findings_total": len(visible),
                "by_severity": dict(sev), "by_category": dict(cat),
                "components": len(result["components"]), "models": len(result["models"]),
                "providers": len(result["providers"]), "hosts": len(result["hosts"]),
                "controls_satisfied": sum(1 for c in controls if c["status"] == "satisfied"),
                "controls_total": len(controls),
            }
            doc["detection_agents"] = result.get("agents")
            doc["status"] = "completed"
            doc["finished_at"] = iso()
            doc["completed_at"] = doc["finished_at"]
            doc["scanned_at"] = doc["finished_at"]
            _event(doc, "persist", "completed", "Done")
            _save(tenant, doc)
            try:  # release-gate decision under the active policy, stored with the scan
                from . import governance_ops
                g = governance_ops.evaluate_gate(tenant, scan_id)
                doc["gate"] = {"block": g["block"], "reason": g["reason"], "policy_version": g["policy_version"]}
                _save(tenant, doc)
            except Exception:
                log.exception("gate evaluation failed for %s", scan_id)
            _emit(tenant, doc, "evidence_created")
            _emit(tenant, doc, "findings_updated")
            _emit(tenant, doc, "scan_completed")

            repo = db.get("repositories", tenant, doc["repository_id"]) or {
                "id": doc["repository_id"], "name": doc["repository_name"], "url": git_url, "source": doc["source"],
                "first_seen": iso(), "scans": 0,
            }
            repo["last_scan_id"] = scan_id
            repo["last_scanned_at"] = doc["finished_at"]
            repo["scans"] = repo.get("scans", 0) + 1
            db.put("repositories", tenant, repo["id"], repo)
        except InterruptedError:
            doc["status"] = "cancelled"
            doc["finished_at"] = iso()
            doc["completed_at"] = doc["finished_at"]
            _mark_open_stages(doc, "cancelled")
            _safe_final(tenant, doc)
            _emit(tenant, doc, "scan_cancelled")
        except Exception as exc:
            log.exception("scan %s failed", scan_id)
            doc["status"] = "failed"
            doc["error"] = str(exc)[:500]
            doc["error_detail"] = doc["error"]
            doc["finished_at"] = iso()
            doc["completed_at"] = doc["finished_at"]
            _mark_open_stages(doc, "failed", str(exc)[:200])
            _safe_final(tenant, doc)
            _emit(tenant, doc, "scan_failed")
        finally:
            CANCELLED.discard(scan_id)
            shutil.rmtree(work, ignore_errors=True)


def _emit(tenant, doc, etype):
    bus.publish(tenant, "findings", {"type": etype, "scan_id": doc["id"], "repo_ref": doc.get("repo_ref"),
                                     "repository_id": doc.get("repository_id")})


def _mark_open_stages(doc, status, msg=""):
    for s in doc["stages"]:
        if s["status"] in ("pending", "running"):
            _event(doc, s["name"], status, msg)


def _safe_final(tenant, doc):
    try:
        _save(tenant, doc)
    except Exception:
        pass
