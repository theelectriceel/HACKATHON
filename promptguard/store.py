"""Durable local audit, isolated test ledgers, exact-action approval and replay safety."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from .common import ARTIFACTS, canonical, digest, sign, utcnow

ORDERS = [
    {"id": "ord-1001", "customer": "cust-alex", "paid_cents": 12000, "payment": "pay-original-alex", "eligible": 1},
    {"id": "ord-2002", "customer": "cust-jamie", "paid_cents": 45000, "payment": "pay-original-jamie", "eligible": 1},
    {"id": "ord-1003", "customer": "cust-alex", "paid_cents": 15000, "payment": "pay-original-alex", "eligible": 0},
]


class Store:
    def __init__(self, path: Path | str | None = None, key: bytes = b""):
        self.path = str(path or ARTIFACTS / "promptguard.sqlite3")
        self.key = key
        with self.connection() as db:
            db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY, created TEXT, scenario TEXT, mode TEXT, contract TEXT, result TEXT);
            CREATE TABLE IF NOT EXISTS orders(run_id TEXT, id TEXT, customer TEXT, paid_cents INTEGER, payment TEXT, eligible INTEGER, refunded INTEGER DEFAULT 0, version INTEGER DEFAULT 1, PRIMARY KEY(run_id,id));
            CREATE TABLE IF NOT EXISTS refunds(id TEXT PRIMARY KEY, run_id TEXT, order_id TEXT, amount INTEGER, destination TEXT, idempotency TEXT, unauthorized INTEGER, UNIQUE(run_id,idempotency));
            CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT, created TEXT, body TEXT, signature TEXT);
            CREATE TABLE IF NOT EXISTS approvals(id TEXT PRIMARY KEY, run_id TEXT, action_digest TEXT, expires REAL, consumed INTEGER DEFAULT 0, granted INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS verifications(run_id TEXT, order_id TEXT, version INTEGER, PRIMARY KEY(run_id,order_id));
            """)

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        try:
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def create_run(self, scenario: str, mode: str, contract: dict) -> str:
        run_id = uuid.uuid4().hex
        with self.connection() as db:
            db.execute("INSERT INTO runs VALUES(?,?,?,?,?,NULL)", (run_id, utcnow(), scenario, mode, canonical(contract)))
            for order in ORDERS:
                db.execute("INSERT INTO orders(run_id,id,customer,paid_cents,payment,eligible) VALUES(?,?,?,?,?,?)", (run_id, order["id"], order["customer"], order["paid_cents"], order["payment"], order["eligible"]))
        return run_id

    def event(self, run_id: str, kind: str, **fields) -> dict:
        event = {"kind": kind, "time": utcnow(), **fields}
        with self.connection() as db:
            db.execute("INSERT INTO events(run_id,created,body,signature) VALUES(?,?,?,?)", (run_id, event["time"], canonical(event), sign(event, self.key)))
        return event

    def events(self, run_id: str) -> list[dict]:
        with self.connection() as db:
            return [{**json.loads(row["body"]), "signature": row["signature"]} for row in db.execute("SELECT * FROM events WHERE run_id=? ORDER BY seq", (run_id,))]

    def order(self, run_id: str, order_id: str, verify: bool = True) -> dict | None:
        with self.connection() as db:
            row = db.execute("SELECT * FROM orders WHERE run_id=? AND id=?", (run_id, order_id)).fetchone()
            if not row:
                return None
            if verify:
                db.execute("INSERT OR REPLACE INTO verifications VALUES(?,?,?)", (run_id, order_id, row["version"]))
            return {k: row[k] for k in ("id", "customer", "paid_cents", "payment", "eligible", "refunded", "version")}

    def ledger(self, run_id: str) -> list[dict]:
        with self.connection() as db:
            return [dict(r) for r in db.execute("SELECT * FROM refunds WHERE run_id=? ORDER BY rowid", (run_id,))]

    def finish(self, run_id: str, result: dict):
        with self.connection() as db:
            db.execute("UPDATE runs SET result=? WHERE id=?", (canonical(result), run_id))

    def saved(self, run_id: str) -> dict | None:
        with self.connection() as db:
            row = db.execute("SELECT result FROM runs WHERE id=?", (run_id,)).fetchone()
            return json.loads(row[0]) if row and row[0] else None

    def approval(self, run_id: str, action: dict) -> str:
        identifier = uuid.uuid4().hex
        with self.connection() as db:
            db.execute("INSERT INTO approvals(id,run_id,action_digest,expires) VALUES(?,?,?,?)", (identifier, run_id, digest(action), time.time() + 300))
        return identifier

    def grant(self, identifier: str):
        with self.connection() as db:
            result = db.execute("UPDATE approvals SET granted=1 WHERE id=? AND consumed=0 AND expires>?", (identifier, time.time()))
            return bool(result.rowcount)
