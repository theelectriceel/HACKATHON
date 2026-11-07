"""Separate RAG demo service. Caller must authenticate with local demo token."""
import json
import hmac
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from fastapi import FastAPI, Header, HTTPException, Depends, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from promptguard.common import ROOT
from promptguard_v2.storage import V2, credentials
from .rag import compare, run, SCENARIOS
from .activity import Activity

app = FastAPI(title="Independent RAG test application — PROMPTGUARD V2")
pool, jobs, lock = ThreadPoolExecutor(max_workers=1), {}, threading.Lock()


@app.middleware("http")
async def local_only(request: Request, call_next):
    if request.headers.get("host","").split(":")[0] not in ("127.0.0.1","localhost","testserver"):
        return JSONResponse({"detail":"Local demo only"},status_code=403)
    return await call_next(request)


def authenticated(authorization: str = Header(default="")):
    expected = "Bearer "+credentials()["demo_agent_token"]
    if not hmac.compare_digest(authorization,expected): raise HTTPException(403,"Local demo sign-in required")


class Question(BaseModel):
    model_config = ConfigDict(extra="forbid")
    question: str = Field(min_length=3,max_length=1500)
    scenario: str = "override"


class RunQuestion(Question):
    mode: str


@app.get("/")
def home():
    from fastapi.responses import RedirectResponse
    return RedirectResponse("http://127.0.0.1:8775/#without")


def submit(function):
    with lock:
        if any(j["status"] in ("queued","running") for j in jobs.values()): raise HTTPException(429,"A RAG run is already running")
        identifier = uuid.uuid4().hex
        jobs[identifier] = {"id":identifier,"status":"queued"}
    def work():
        jobs[identifier]["status"] = "running"
        try:
            result = function(lambda p: jobs[identifier].update(progress=p))
            jobs[identifier].update(status="complete",result=result)
        except Exception as exc:
            jobs[identifier].update(status="error",error=type(exc).__name__)
    pool.submit(work)
    return {"job_id":identifier}


@app.post("/run",dependencies=[Depends(authenticated)])
def single(value: RunQuestion):
    if value.scenario not in SCENARIOS or value.mode not in ("unprotected","protected"): raise HTTPException(422,"Unknown mode or scenario")
    return submit(lambda progress: run(value.question,value.scenario,value.mode,progress))


@app.get("/activity",dependencies=[Depends(authenticated)])
def activity(): return Activity().report()


@app.post("/compare",dependencies=[Depends(authenticated)])
def start(value: Question):
    if value.scenario not in SCENARIOS: raise HTTPException(422,"Unknown scenario")
    return submit(lambda progress: compare(value.question,value.scenario,progress))


@app.get("/jobs/{identifier}",dependencies=[Depends(authenticated)])
def job(identifier: str):
    if identifier not in jobs: raise HTTPException(404,"Job not found")
    return jobs[identifier]


@app.get("/saved",dependencies=[Depends(authenticated)])
def saved():
    paths = sorted(V2.glob("rag-*.json"),key=lambda p:p.stat().st_mtime,reverse=True)
    runs = []
    for path in paths[:20]:
        value = json.loads(path.read_text(encoding="utf-8"))
        if "results" in value:
            for item in value["results"]:
                runs.append({**value,**item,"results":None})
        elif "mode" in value: runs.append(value)
    return {"runs":runs}
