"""Application-independent context firewall. Does not retrieve or answer questions."""
from __future__ import annotations

import time

from .common import digest, receipt


class Firewall:
    def __init__(self, detector, key: bytes):
        self.detector, self.key = detector, key

    def prepare(self, chunks: list[dict]) -> dict:
        started = time.perf_counter()
        identifiers = [c["id"] for c in chunks]
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("Duplicate chunk IDs are not allowed")
        decisions, admitted = [], []
        for chunk in chunks:
            scan = self.detector.scan(chunk["text"])
            decisions.append({"id": chunk["id"], "source": chunk.get("source", "caller-supplied"), "input_digest": digest(chunk["text"]), **scan})
            if scan["action"] == "ALLOW" and scan["complete"]:
                admitted.append({"id": chunk["id"], "text": chunk["text"], "source": chunk.get("source", "caller-supplied")})
        context = "\n\n".join(f"[{c['id']}] {c['text']}" for c in admitted)
        payload = {"context_digest": digest(context), "input_digests": {c["id"]: digest(c["text"]) for c in chunks},
                   "admitted_ids": [c["id"] for c in admitted], "decisions_digest": digest(decisions), "detector": self.detector.identity,
                   "trust": "Source labels are descriptive; this endpoint does not authenticate source ownership or grant action permissions."}
        return {"status": "ready" if admitted else "no_context", "context": context, "admitted": admitted, "decisions": decisions,
                "receipt": receipt(payload, self.key), "latency_ms": round((time.perf_counter()-started)*1000, 2)}
