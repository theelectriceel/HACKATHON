"""Standalone demo workbench and basic RAG target, on port 8766."""
from __future__ import annotations

import json
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from promptguard.common import ARTIFACTS, ROOT, digest, local_key
from .rag_app import RAG_SCENARIOS, RagIndex, compare_rag

app = FastAPI(title="PROMPTGUARD Demo Applications", description="Independent RAG and demonstration interface. Protection lives on port 8765.")
index = RagIndex()
jobs = {}
pool = ThreadPoolExecutor(max_workers=1)


@app.middleware("http")
async def local_only(request: Request, call_next):
    from fastapi.responses import JSONResponse
    if request.headers.get("host", "").split(":")[0] not in ("localhost", "127.0.0.1", "testserver"):
        return JSONResponse({"detail": "Local demo only"}, status_code=403)
    if request.method == "POST":
        import hmac
        if not hmac.compare_digest(request.headers.get("x-session-token", ""), digest(local_key().hex()+"local-demo-session")):
            return JSONResponse({"detail": "Local demo session required"}, status_code=403)
    return await call_next(request)


class Question(BaseModel):
    model_config = ConfigDict(extra="forbid")
    question: str = Field(min_length=3, max_length=1500)
    scenario: str = "override"


class Document(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(min_length=1, max_length=150)
    text: str = Field(min_length=1, max_length=20_000)


@app.get("/api/rag/catalog")
def catalog():
    return {"documents": index.documents(), "scenarios": [{"id": k, **v} for k, v in RAG_SCENARIOS.items()], "protection_service": "http://127.0.0.1:8765", "is_separate_application": True}


@app.post("/api/rag/documents")
def add_document(request: Document):
    if len(index.documents()) >= 100:
        raise HTTPException(409, "Demo document limit reached")
    return {"id": index.add(request.title, request.text), "trust": "Uploaded documents remain untrusted."}


@app.post("/api/rag/compare")
def compare(request: Question):
    if request.scenario not in RAG_SCENARIOS:
        raise HTTPException(422, "Unknown scenario")
    if any(j["status"] in ("queued", "running") for j in jobs.values()):
        raise HTTPException(429, "A RAG comparison is already running")
    identifier = uuid.uuid4().hex
    jobs[identifier] = {"status": "queued", "id": identifier}
    def work():
        jobs[identifier]["status"] = "running"
        try:
            jobs[identifier]["result"] = compare_rag(index, request.question, request.scenario, lambda message: jobs[identifier].update(progress=message))
            jobs[identifier]["status"] = "complete"
        except Exception as exc:
            jobs[identifier].update(status="error", error=f"RAG comparison failed ({type(exc).__name__}); no result fabricated.")
    pool.submit(work)
    return {"job_id": identifier}


@app.get("/api/rag/jobs/{identifier}")
def get_job(identifier: str):
    if identifier not in jobs:
        raise HTTPException(404, "Job not found")
    return jobs[identifier]


@app.get("/api/rag/saved")
def saved():
    paths = sorted(ARTIFACTS.glob("rag-run-*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    return {"runs": [{**json.loads(p.read_text(encoding="utf-8")), "execution": "saved_run"} for p in paths[:8]]}


@app.get("/")
def home():
    return FileResponse(ROOT / "web" / "index.html")


app.mount("/static", StaticFiles(directory=ROOT / "web"), name="static")
