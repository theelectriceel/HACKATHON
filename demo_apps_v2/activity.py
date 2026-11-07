"""Application-owned logs for both RAG modes. Baseline logging never authorizes."""
import json
import sqlite3
from contextlib import contextmanager
from collections import Counter, defaultdict
from pathlib import Path
from promptguard.common import canonical
from promptguard_v2.storage import V2


class Activity:
    def __init__(self, path=None):
        self.path = Path(path or V2 / "rag-activity.sqlite3")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.db() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("CREATE TABLE IF NOT EXISTS calls(seq INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT UNIQUE,run_id TEXT,mode TEXT,data TEXT)")
            db.execute("CREATE INDEX IF NOT EXISTS run_calls ON calls(run_id,seq)")

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.path, timeout=10)
        try:
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def write(self, event):
        with self.db() as db:
            db.execute("INSERT INTO calls(id,run_id,mode,data) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data",
                       (event["id"], event["run_id"], event["mode"], canonical(event)))

    def report(self):
        with self.db() as db:
            rows = [json.loads(r[0]) for r in db.execute("SELECT data FROM calls ORDER BY seq")]
        completed = [r for r in rows if r["execution_status"] != "running"]
        runs = defaultdict(list)
        for event in rows: runs[event["run_id"]].append(event)
        return {"events": rows[-500:], "summary": {"total_calls": len(rows), "runs": len(runs),
                "blocked_calls": sum(r["decision"] in ("DENY", "QUARANTINE", "SERVICE_UNAVAILABLE", "REQUIRE_APPROVAL") for r in rows),
                "by_tool": dict(Counter(r["tool_name"] for r in rows)), "by_mode": dict(Counter(r["mode"] for r in rows)),
                "by_decision": dict(Counter(r["decision"] for r in rows)),
                "average_latency_ms": round(sum(r["latency_ms"] for r in completed)/len(completed), 2) if completed else None},
                "pathways": [{"run_id": key, "mode": values[0]["mode"], "tools": [e["tool_name"] for e in values],
                              "blocked": any(e["decision"] in ("DENY", "QUARANTINE") for e in values)} for key, values in list(runs.items())[-20:]],
                "scope": "All tool calls made by the two RAG demo modes. Latest 500 shown; statistics include all persisted calls."}
