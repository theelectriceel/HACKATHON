"""PROMPTGUARD protection and assessment service. No retrieval or RAG implementation."""
from __future__ import annotations

import json
import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field

from .auditor import DEFAULT_PROFILE, assess, restriction_report, source_inventory
from .common import ARTIFACTS, ROOT, digest, local_key, utcnow, verify_receipt
from .detector import Guard
from .enforcement import execute_refund
from .firewall import Firewall
from .model_client import MODEL, authentication_status
from .policies import POLICIES, Policy, compare_policy
from .planner import test_plan
from .store import Store

KEY = local_key()
SESSION_TOKEN = digest(KEY.hex() + "local-demo-session")
store = Store(key=KEY)
detector = Guard()
firewall = Firewall(detector, KEY)
app = FastAPI(title="PROMPTGUARD", version="0.1.0", description="Local agent protection and evidence-backed assessment API. RAG is a separate demo application.")
app.add_middleware(CORSMiddleware, allow_origins=["http://127.0.0.1:8766", "http://localhost:8766"], allow_methods=["GET", "POST"], allow_headers=["Content-Type", "X-Session-Token"])
pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="promptguard-tests")
jobs: dict[str, dict] = {}
job_lock = threading.Lock()


@app.middleware("http")
async def local_only(request: Request, call_next):
    host = request.headers.get("host", "").split(":")[0]
    if host not in ("127.0.0.1", "localhost", "testserver"):
        from fastapi.responses import JSONResponse
        return JSONResponse({"detail": "This prototype accepts local requests only."}, status_code=403)
    length = request.headers.get("content-length")
    if length and (not length.isdigit() or int(length) > 1_000_000):
        from fastapi.responses import JSONResponse
        return JSONResponse({"detail": "Request too large."}, status_code=413)
    return await call_next(request)


def authorize(x_session_token: str = Header(default="")):
    import hmac
    if not hmac.compare_digest(x_session_token, SESSION_TOKEN):
        raise HTTPException(403, "A local demo session token is required.")


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Chunk(Strict):
    id: str = Field(min_length=1, max_length=120)
    text: str = Field(min_length=1, max_length=100_000)
    source: str = Field(default="caller-supplied", max_length=250)


class ContextRequest(Strict):
    chunks: list[Chunk] = Field(min_length=1, max_length=12)


class Comparison(Strict):
    scenario: str = "cross_customer"
    policies: list[Literal["recommended", "approval", "disabled", "per_call"]] = Field(default=["recommended"], min_length=1, max_length=4)
    include_scanner: bool = True
    include_clean: bool = False
    custom_text: str | None = Field(default=None, max_length=8000)


def saved_runs(limit=30):
    with store.connection() as db:
        return [json.loads(r[0]) for r in db.execute("SELECT result FROM runs WHERE result IS NOT NULL ORDER BY rowid DESC LIMIT ?", (limit,))]


def submit_job(work):
    with job_lock:
        if sum(j["status"] in ("queued", "running") for j in jobs.values()) >= 2:
            raise HTTPException(429, "Two test jobs are already running or queued. Wait for one to finish.")
        identifier = uuid.uuid4().hex
        jobs[identifier] = {"id": identifier, "status": "queued", "created_at": utcnow(), "progress": "Waiting for the test worker", "completed": 0, "total": None}
    def execute():
        jobs[identifier].update(status="running", progress="Starting isolated executions")
        try:
            result = work(jobs[identifier])
            jobs[identifier].update(status="complete", result=result, progress="Complete", finished_at=utcnow())
            (ARTIFACTS / f"job-{identifier}.json").write_text(json.dumps(jobs[identifier], indent=2), encoding="utf-8")
        except Exception as exc:
            jobs[identifier].update(status="error", error=f"Test could not complete ({type(exc).__name__}). No result fabricated.")
    pool.submit(execute)
    return {"job_id": identifier, "status": "queued"}


@app.get("/api/bootstrap")
def bootstrap():
    return {"session_token": SESSION_TOKEN, "service": "PROMPTGUARD", "local_demo": True}


@app.get("/api/status")
def status():
    auth=authentication_status()
    return {"status": "ready", "detector": detector.identity, "answering_model": MODEL, "model_backend": auth, "model_available": auth["available"], "uses_api_key": False,
            "implemented": ["windowed open-source detector", "context enforcement API", "typed business authorization", "durable cumulative budgets", "exact-action approval", "independent ledger verification", "SMT policy comparison", "capability assessment", "bounded test planning", "bounded data preservation", "fresh retests", "signed receipts", "drift checks"],
            "limitations": ["Local prototype, not production authentication or tenant isolation.", "Support tools only change an isolated simulated ledger.", "No production customer activity has been supplied.", "Provenance tracks exposure conservatively, not exact token influence.", "No global optimality or universal prompt-injection guarantee.", "The RAG app is separate and uses the firewall API."],
            "sources": source_inventory()}


@app.post("/api/v1/prepare-context", dependencies=[Depends(authorize)])
def prepare_context(request: ContextRequest):
    try:
        return firewall.prepare([c.model_dump() for c in request.chunks])
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None


@app.post("/api/v1/scan", dependencies=[Depends(authorize)])
def scan(request: Chunk):
    return detector.scan(request.text)


@app.get("/api/catalog")
def catalog():
    from demo_apps.scenarios import SCENARIOS
    return {"scenarios": [{"id": k, **v} for k, v in SCENARIOS.items()], "policies": [p.public() for p in POLICIES.values()]}


@app.post("/api/demo/compare", dependencies=[Depends(authorize)])
def compare(request: Comparison):
    from demo_apps.scenarios import SCENARIOS
    from demo_apps.support_agent import run_agent
    if request.scenario not in SCENARIOS:
        raise HTTPException(422, "Unknown scenario")
    def work(job):
        scenarios = [request.scenario] + (["clean"] if request.include_clean and request.scenario != "clean" else [])
        conditions = [("unprotected", "recommended")] + ([("scanner", "recommended")] if request.include_scanner else []) + [("protected", p) for p in dict.fromkeys(request.policies)]
        job["total"] = len(scenarios)*len(conditions)
        runs = []
        for scenario in scenarios:
            for mode, policy in conditions:
                job["progress"] = f"Testing {scenario}: {policy if mode == 'protected' else mode}"
                result = run_agent(store, detector, scenario, mode, policy, request.custom_text if scenario == request.scenario else None)
                runs.append(result)
                job["completed"] += 1
                job["runs_so_far"] = [{k: r[k] for k in ("run_id", "scenario", "mode", "policy_id", "status", "task_success", "unauthorized_execution")} for r in runs]
        report = restriction_report(runs)
        return {"runs": runs, "restriction_report": report, "assessment": assess(DEFAULT_PROFILE, runs), "execution": "live_model", "scope": "Isolated authored support scenarios; no real refunds."}
    return submit_job(work)


@app.get("/api/jobs/{identifier}")
def job(identifier: str):
    if identifier in jobs:
        return jobs[identifier]
    path = ARTIFACTS / f"job-{identifier}.json"
    if len(identifier) == 32 and all(c in "0123456789abcdef" for c in identifier) and path.exists():
        return {**json.loads(path.read_text(encoding="utf-8")), "execution": "saved_run"}
    raise HTTPException(404, "Test job not found")


@app.get("/api/runs")
def runs():
    return {"runs": [{k: r.get(k) for k in ("run_id", "scenario", "mode", "policy_id", "status", "task_success", "unauthorized_execution", "created_at", "latency_ms")} for r in saved_runs()]}


@app.get("/api/demo/recorded")
def recorded_demo():
    path=ARTIFACTS/"recorded-demo.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {"runs":[],"status":"unavailable"}


@app.get("/api/runs/{run_id}")
def run(run_id: str):
    result = store.saved(run_id)
    if result is None:
        raise HTTPException(404, "Run not found")
    return {**result, "execution": "saved_run"}


@app.get("/api/audit")
def audit():
    return assess(DEFAULT_PROFILE, [r for r in saved_runs() if r["status"] == "completed"])


class Profile(Strict):
    name: str = Field(max_length=120)
    sources: list[dict] = Field(default=[], max_length=20)
    tools: list[dict] = Field(default=[], max_length=30)
    controls: dict = Field(default={})
    permission_evidence: Literal["declared", "unknown"] = "declared"
    activity: list[dict] = Field(default=[], max_length=200)


@app.post("/api/audit/import", dependencies=[Depends(authorize)])
def import_profile(profile: Profile):
    # An uploaded document cannot declare its own permissions "verified".
    for tool in profile.tools:
        if not isinstance(tool.get("name"), str) or tool.get("kind") not in ("read", "financial_write", "external_send", "destructive"):
            raise HTTPException(422, "Each tool needs a name and a supported kind")
    for source in profile.sources:
        if not isinstance(source.get("id"), str):
            raise HTTPException(422, "Each source needs an ID")
    result=assess(profile.model_dump())
    result["test_plan"]=test_plan(profile.model_dump())
    (ARTIFACTS/f"assessment-{result['profile_digest'][:16]}.json").write_text(json.dumps(result,indent=2),encoding="utf-8")
    return result


class Drift(Strict):
    assessed_digest: str
    current_profile: dict


@app.post("/api/audit/drift", dependencies=[Depends(authorize)])
def drift(request: Drift):
    current = digest(request.current_profile)
    return {"changed": current != request.assessed_digest, "status": "retest_required" if current != request.assessed_digest else "same_snapshot", "current_digest": current,
            "meaning": "Snapshot equality does not prove external permissions stayed unchanged."}


@app.get("/api/audit/test-plan")
def planned_tests():
    return test_plan(DEFAULT_PROFILE)


class PolicyComparison(Strict):
    before: Literal["recommended", "approval", "disabled", "per_call"]
    after: Literal["recommended", "approval", "disabled", "per_call"]


@app.post("/api/policies/compare", dependencies=[Depends(authorize)])
def policy_compare(request: PolicyComparison):
    from .symbolic import compare_symbolically
    return {"before": POLICIES[request.before].public(), "after": POLICIES[request.after].public(), **compare_symbolically(POLICIES[request.before], POLICIES[request.after])}


class ReceiptRequest(Strict):
    receipt: dict
    context: str | None = None


@app.post("/api/receipts/verify", dependencies=[Depends(authorize)])
def verify(request: ReceiptRequest):
    return {"valid": verify_receipt(request.receipt, KEY, request.context)}


class Approval(Strict):
    run_id: str
    approval_id: str


@app.post("/api/approvals/grant", dependencies=[Depends(authorize)])
def approve(request: Approval):
    saved = store.saved(request.run_id)
    if not saved or saved.get("policy_id") != "approval":
        raise HTTPException(422, "No approval-bound action in this run")
    step = next((s for s in saved["trace"] if s["result"].get("approval_id") == request.approval_id), None)
    if not step:
        raise HTTPException(422, "Approval does not match this run")
    if not store.grant(request.approval_id):
        raise HTTPException(409, "Approval expired or was consumed")
    result = execute_refund(store, request.run_id, saved["contract"], step["args"], POLICIES["approval"], request.approval_id)
    return {"result": result, "ledger": store.ledger(request.run_id), "note": "Original run remains an immutable historical snapshot; approval is a new event."}


@app.get("/api/benchmark")
def benchmark():
    path = ARTIFACTS / "benchmark.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {"status": "not_run", "message": "No complete benchmark has been saved. Live demo runs are not a benchmark."}


@app.get("/api/research")
def research():
    return {"document": (ROOT / "docs" / "PROMPTGUARD_ADVANCED_DESIGN.md").read_text(encoding="utf-8"), "status": "Design includes roadmap items; see /api/status for implemented capabilities."}
