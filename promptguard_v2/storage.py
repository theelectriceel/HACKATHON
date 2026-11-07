"""Separate SQLite control plane, versioned publications, authenticated identities."""
from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import secrets
import sqlite3
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from promptguard.common import ARTIFACTS, canonical, digest, utcnow

V2 = ARTIFACTS / "v2"


def credentials():
    V2.mkdir(exist_ok=True)
    path = V2 / "credentials.json"
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return json.loads(path.read_text())
    value = {"admin_token": secrets.token_urlsafe(32), "demo_agent_token": secrets.token_urlsafe(32)}
    with os.fdopen(fd, "w") as handle:
        json.dump(value, handle)
    return value


class Store:
    def __init__(self, path=None):
        V2.mkdir(exist_ok=True)
        self.path = Path(path or V2 / "control.sqlite3")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        key_path = self.path.with_suffix(".signing-key")
        try:
            fd = os.open(key_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            key = key_path.read_bytes()
        else:
            key = Ed25519PrivateKey.generate().private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
            with os.fdopen(fd, "wb") as handle:
                handle.write(key)
        self.signing_key = Ed25519PrivateKey.from_private_bytes(key)
        self.public_key = base64.b64encode(self.signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
        with self.connection() as db:
            db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS agents(agent_id TEXT PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL, profile TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS resources(resource_type TEXT, resource_id TEXT, data TEXT NOT NULL, PRIMARY KEY(resource_type,resource_id));
            CREATE TABLE IF NOT EXISTS policies(policy_id TEXT,version INTEGER,body TEXT NOT NULL,published_at TEXT NOT NULL,PRIMARY KEY(policy_id,version));
            CREATE TABLE IF NOT EXISTS active_policies(policy_id TEXT PRIMARY KEY,version INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT,execution_id TEXT UNIQUE,agent_id TEXT,session_id TEXT,tool_name TEXT,status TEXT,resource TEXT,data TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS session_events ON events(agent_id,session_id,seq);
            CREATE TABLE IF NOT EXISTS sessions(agent_id TEXT,session_id TEXT,inflight TEXT,PRIMARY KEY(agent_id,session_id));
            CREATE TABLE IF NOT EXISTS path_state(agent_id TEXT,session_id TEXT,fingerprint TEXT,resource TEXT,progress INTEGER,PRIMARY KEY(agent_id,session_id,fingerprint,resource));
            CREATE TABLE IF NOT EXISTS approvals(id TEXT PRIMARY KEY,binding TEXT NOT NULL,expires REAL NOT NULL,consumed INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT,timestamp TEXT,action TEXT,subject TEXT,details TEXT);
            CREATE TABLE IF NOT EXISTS inspections(id TEXT PRIMARY KEY,agent_id TEXT,session_id TEXT,result TEXT);
            CREATE TABLE IF NOT EXISTS evaluations(id TEXT PRIMARY KEY,status TEXT,result TEXT);
            CREATE TABLE IF NOT EXISTS universal_versions(id TEXT,version INTEGER,body TEXT,PRIMARY KEY(id,version));
            CREATE TABLE IF NOT EXISTS universal_active(id TEXT PRIMARY KEY,version INTEGER);
            CREATE TABLE IF NOT EXISTS universal_drafts(id TEXT PRIMARY KEY,body TEXT,base_version INTEGER,tested INTEGER DEFAULT 0);
            """)

    @contextlib.contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            yield db
        finally:
            if db.in_transaction:
                db.rollback()
            db.close()

    @contextlib.contextmanager
    def transaction(self):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()

    def agent(self, token):
        with self.connection() as db:
            row = db.execute("SELECT profile FROM agents WHERE token_hash=?", (digest(token),)).fetchone()
        return json.loads(row[0]) if row else None

    def register(self, profile, token=None):
        token = token or secrets.token_urlsafe(32)
        with self.transaction() as db:
            db.execute("INSERT INTO agents VALUES(?,?,?) ON CONFLICT(agent_id) DO UPDATE SET token_hash=excluded.token_hash,profile=excluded.profile", (profile.agent_id, digest(token), profile.model_dump_json()))
            self.audit(db, "agent_registered", profile.agent_id, {})
        return token

    @staticmethod
    def audit(db, action, subject, details):
        db.execute("INSERT INTO audit(timestamp,action,subject,details) VALUES(?,?,?,?)", (utcnow(), action, subject, canonical(details)))

    def envelope(self, policy):
        issued = time.time()
        payload = {"policy": policy, "issued_at": issued, "expires_at": issued + max(1, min(policy["cache_ttl_seconds"], 30))}
        return {"payload": payload, "signature": base64.b64encode(self.signing_key.sign(canonical(payload).encode())).decode(), "scheme": "Ed25519"}

    @staticmethod
    def current(db, policy_id):
        row = db.execute("SELECT p.body FROM policies p JOIN active_policies a USING(policy_id,version) WHERE p.policy_id=?", (policy_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def events(self, agent=None, session=None, limit=500):
        clauses, values = [], []
        if agent:
            clauses.append("agent_id=?"); values.append(agent)
        if session:
            clauses.append("session_id=?"); values.append(session)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self.connection() as db:
            rows = db.execute("SELECT data FROM events" + where + " ORDER BY seq DESC LIMIT ?", (*values, limit)).fetchall()
        return [json.loads(r[0]) for r in reversed(rows)]
