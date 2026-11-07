"""Actual NeMo input/output flows invoke the existing local Horizon runtime.

No generative LLM, embedding model, API key, or model-as-judge is configured.
These are content checks; tool authorization stays in PROMPTGUARD's engine.
"""
from __future__ import annotations

import asyncio
import contextvars
import importlib.metadata
import os
import time
from pathlib import Path
from promptguard.common import digest


class NeMoHorizon:
    def __init__(self, detector=None):
        os.environ.setdefault("DO_NOT_TRACK", "1")
        from nemoguardrails import LLMRails, RailsConfig
        from nemoguardrails.actions import action
        if detector is None:
            from promptguard.detector import Guard
            detector = Guard()
        self.detector = detector
        self._findings = contextvars.ContextVar("pg_horizon_findings", default=None)
        config = RailsConfig.from_path(str(Path(__file__).parent / "nemo_config"))
        self.rails = LLMRails(config)

        @action(is_system_action=True)
        async def pg_horizon_check(text: str):
            scan = await asyncio.to_thread(self.detector.scan, text)
            findings = self._findings.get()
            if findings is not None:
                findings.append(scan)
            return scan["complete"] and scan["action"] == "ALLOW"
        self.rails.register_action(pg_horizon_check, name="pg_horizon_check")

    async def inspect(self, text, direction="input"):
        from nemoguardrails.rails.llm.options import RailType
        started = time.perf_counter()
        findings = []
        token = self._findings.set(findings)
        try:
            result = await self.rails.check_async([{"role": "user" if direction == "input" else "assistant", "content": text}],
                rail_types=[RailType.INPUT if direction == "input" else RailType.OUTPUT])
            status, rail = result.status.value, result.rail
            allowed = status == "passed" and len(findings) == 1 and findings[0]["complete"] and findings[0]["action"] == "ALLOW"
        except Exception as exc:
            status, rail, allowed = "error", type(exc).__name__, False
        finally:
            self._findings.reset(token)
        elapsed = round((time.perf_counter()-started)*1000, 3)
        detector_ms = sum(f["latency_ms"] for f in findings)
        return {"allowed": allowed, "direction": direction, "content_digest": digest(text), "characters": len(text),
                "nemo": {"version": importlib.metadata.version("nemoguardrails"), "status": status, "rail": rail, "action_executions": len(findings)},
                "detector_findings": findings, "latency_ms": elapsed, "detector_latency_ms": detector_ms,
                "nemo_overhead_ms": round(max(0, elapsed-detector_ms), 3), "generative_model_calls": 0}
