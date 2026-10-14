"""Automatic snapshots of the data store, retention clean-up and an admin backup download.

* Snapshot every BACKUP_INTERVAL_HOURS (default 6) into DATA_DIR/backups using SQLite's online backup API;
  the newest BACKUP_KEEP (default 8) are kept.
* RETENTION_DAYS (default 0 = keep everything): completed scans older than that, with their findings, graphs and
  inventory, are removed once a day.
"""
import logging
import os
import sqlite3
import threading
import time

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse

from . import auth, db
from .common import audit

log = logging.getLogger("ops")
router = APIRouter()
BACKUP_DIR = os.path.join(db.DATA_DIR, "backups")
INTERVAL = float(os.getenv("BACKUP_INTERVAL_HOURS", "6")) * 3600
KEEP = int(os.getenv("BACKUP_KEEP", "8"))
RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", "0"))


def _db_path() -> str:
    return db.DB_PATH


def snapshot() -> str:
    os.makedirs(BACKUP_DIR, exist_ok=True)
    src = sqlite3.connect(_db_path())
    out = os.path.join(BACKUP_DIR, "backup-" + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + ".db")
    dst = sqlite3.connect(out)
    try:
        src.backup(dst)
    finally:
        dst.close()
        src.close()
    files = sorted(f for f in os.listdir(BACKUP_DIR) if f.startswith("backup-"))
    for old in files[:-KEEP]:
        try:
            os.remove(os.path.join(BACKUP_DIR, old))
        except OSError:
            pass
    return out


def purge_old(days: int) -> int:
    cutoff = time.time() - days * 86400
    n = 0
    for tenant in {x["id"] for x in db.items("tenants", "_global")} or {"default"}:
        for s in db.items("scans", tenant):
            ts = s.get("completed_at") or s.get("finished_at")
            if not ts or s.get("status") not in ("completed", "failed", "cancelled"):
                continue
            try:
                when = time.mktime(time.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")) - time.timezone
            except ValueError:
                continue
            if when < cutoff:
                for col in ("findings", "findings_evidence"):
                    for f in db.items(col, tenant):
                        if f.get("scan_id") == s["id"]:
                            db.delete(col, tenant, f["id"])
                for col in ("graphs", "inventory", "scans"):
                    db.delete(col, tenant, s["id"])
                n += 1
    return n


def _loop():
    last_purge = 0.0
    while True:
        try:
            snapshot()
            if RETENTION_DAYS and time.time() - last_purge > 86400:
                log.info("retention: purged %d scans", purge_old(RETENTION_DAYS))
                last_purge = time.time()
        except Exception:
            log.exception("backup/retention cycle failed")
        time.sleep(max(INTERVAL, 300))


def start() -> None:
    threading.Thread(target=_loop, daemon=True, name="ops-loop").start()


@router.get("/admin/backups")
def list_backups(user: dict = Depends(auth.require("admin"))):
    files = sorted(os.listdir(BACKUP_DIR)) if os.path.isdir(BACKUP_DIR) else []
    return {"backups": [{"name": f, "bytes": os.path.getsize(os.path.join(BACKUP_DIR, f))} for f in files if f.startswith("backup-")],
            "interval_hours": INTERVAL / 3600, "keep": KEEP, "retention_days": RETENTION_DAYS}


@router.post("/admin/backups")
def make_backup(user: dict = Depends(auth.require("admin"))):
    path = snapshot()
    audit(user, "backup.create", os.path.basename(path))
    return {"created": os.path.basename(path), "bytes": os.path.getsize(path)}


@router.get("/admin/backups/{name}")
def download_backup(name: str, user: dict = Depends(auth.require("admin"))):
    if "/" in name or "\\" in name or not name.startswith("backup-"):
        raise HTTPException(400, "invalid backup name")
    p = os.path.join(BACKUP_DIR, name)
    if not os.path.isfile(p):
        raise HTTPException(404, "backup not found")
    audit(user, "backup.download", name)
    return FileResponse(p, filename=name, media_type="application/octet-stream")