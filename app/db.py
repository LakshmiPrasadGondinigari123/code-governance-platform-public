"""Tiny tenant-scoped JSON document store on SQLite (stdlib only)."""
import json
import os
import sqlite3
import threading
import time
import uuid

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.getenv("DATA_DIR", os.path.join(BASE_DIR, "data"))
DB_PATH = os.getenv("DATABASE_PATH", os.path.join(DATA_DIR, "app.db"))

_lock = threading.RLock()
_conn = None


def _connect():
    global _conn
    if _conn is None:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        c = sqlite3.connect(DB_PATH, check_same_thread=False)
        c.execute("PRAGMA journal_mode=WAL")
        c.execute(
            "CREATE TABLE IF NOT EXISTS docs ("
            "col TEXT NOT NULL, tenant TEXT NOT NULL, id TEXT NOT NULL, "
            "created REAL NOT NULL, body TEXT NOT NULL, "
            "PRIMARY KEY (col, tenant, id))"
        )
        c.execute("CREATE INDEX IF NOT EXISTS docs_by_col ON docs(col, tenant, created)")
        c.commit()
        _conn = c
    return _conn


def new_id(prefix: str = "") -> str:
    return prefix + uuid.uuid4().hex[:12]


def put(col: str, tenant: str, doc_id: str, body: dict) -> dict:
    with _lock:
        c = _connect()
        row = c.execute(
            "SELECT created FROM docs WHERE col=? AND tenant=? AND id=?", (col, tenant, doc_id)
        ).fetchone()
        created = row[0] if row else time.time()
        c.execute(
            "INSERT OR REPLACE INTO docs (col, tenant, id, created, body) VALUES (?,?,?,?,?)",
            (col, tenant, doc_id, created, json.dumps(body)),
        )
        c.commit()
    return body


def get(col: str, tenant: str, doc_id: str):
    with _lock:
        row = _connect().execute(
            "SELECT body FROM docs WHERE col=? AND tenant=? AND id=?", (col, tenant, doc_id)
        ).fetchone()
    return json.loads(row[0]) if row else None


def items(col: str, tenant: str, newest_first: bool = True) -> list:
    order = "DESC" if newest_first else "ASC"
    with _lock:
        rows = _connect().execute(
            f"SELECT body FROM docs WHERE col=? AND tenant=? ORDER BY created {order}", (col, tenant)
        ).fetchall()
    return [json.loads(r[0]) for r in rows]


def count(col: str, tenant: str) -> int:
    with _lock:
        return _connect().execute(
            "SELECT COUNT(*) FROM docs WHERE col=? AND tenant=?", (col, tenant)
        ).fetchone()[0]


def delete(col: str, tenant: str, doc_id: str) -> bool:
    with _lock:
        c = _connect()
        cur = c.execute("DELETE FROM docs WHERE col=? AND tenant=? AND id=?", (col, tenant, doc_id))
        c.commit()
        return cur.rowcount > 0


def clear(col: str, tenant: str) -> int:
    with _lock:
        c = _connect()
        cur = c.execute("DELETE FROM docs WHERE col=? AND tenant=?", (col, tenant))
        c.commit()
        return cur.rowcount


def ping() -> bool:
    try:
        with _lock:
            _connect().execute("SELECT 1").fetchone()
        return True
    except Exception:
        return False
