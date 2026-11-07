"""V2 modular monolith. Policies and events are independent of demonstration apps."""
from __future__ import annotations

import asyncio
import hmac
import json
import threading
import uuid
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from promptguard.common import ROOT, canonical
from .analytics import summary, pathways
from .engine import Conflict, Engine
from .schema import AgentRegistration, Authorization, Inspection, Outcome, Policy, Resource
from .storage import Store, credentials


def create_app(store=None, admin_token=None, guardrails=None):
    store = store or Store()
    admin_token = admin_token or credentials()["admin_token"]
    engine = Engine(store)
    app = FastAPI(title="PROMPTGUARD V2 — Control the action. Keep the evidence.", version="2.0.0")
    app.state.store, app.state.engine = store, engine
    app.state.guardrails = guardrails
    initialization_lock = threading.Lock()
    evaluation_lock = threading.Lock()

    def get_rails():
        with initialization_lock:
            if app.state.guardrails is None:
                from .guardrails import NeMoHorizon
                app.state.guardrails = NeMoHorizon()
        return app.state.guardrails

    @app.middleware("http")
    async def local_only(request: Request, call_next):
        if request.headers.get("host", "").split(":")[0] not in ("127.0.0.1", "localhost", "testserver"):
            return JSONResponse({"detail": "This development service binds to localhost only"}, status_code=403)
        if len(await request.body()) > 500_000:
            return JSONResponse({"detail": "Request too large"}, status_code=413)
        return await call_next(request)

    def token(authorization):
        if not authorization.startswith("Bearer "):
            raise HTTPException(401, "Bearer authentication required")
        return authorization[7:]

    def admin(authorization: str = Header(default="")):
        if not hmac.compare_digest(token(authorization), admin_token):
            raise HTTPException(403, "Policy administrator credentials required")

    def sdk(authorization: str = Header(default="")):
        identity = store.agent(token(authorization))
        if not identity:
            raise HTTPException(403, "Registered agent credentials required")
        return identity

    @app.exception_handler(Conflict)
    async def conflict(request, exc):
        return JSONResponse({"detail": str(exc)}, status_code=409)

    @app.exception_handler(ValueError)
    async def invalid_value(request, exc):
        return JSONResponse({"detail": "Invalid or non-finite value; execution stopped"}, status_code=422)

    @app.get("/v1/health")
    def health():
        from promptguard.codex_client import MODEL, BACKEND
        return {"status": "ready", "variant": "v2", "public_key": store.public_key, "model": MODEL,
                "model_backend": BACKEND, "inference_uses_api_key": False, "guardrails_loaded": app.state.guardrails is not None}

    @app.post("/v1/agents", dependencies=[Depends(admin)])
    def register(profile: AgentRegistration):
        return {"agent_id": profile.agent_id, "agent_token": store.register(profile), "token_visibility": "Returned once; stored as a hash"}

    @app.get("/v1/agents", dependencies=[Depends(admin)])
    def agents():
        with store.connection() as db:
            return {"agents": [json.loads(r[0]) for r in db.execute("SELECT profile FROM agents")]}

    @app.get("/v1/agents/{agent_id}/tools", dependencies=[Depends(admin)])
    def tools(agent_id: str):
        with store.connection() as db:
            row = db.execute("SELECT profile FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
        if not row: raise HTTPException(404, "Agent not found")
        return {"tools": json.loads(row[0])["tools"]}

    @app.put("/v1/resources", dependencies=[Depends(admin)])
    def resource(value: Resource):
        with store.transaction() as db:
            db.execute("INSERT INTO resources VALUES(?,?,?) ON CONFLICT(resource_type,resource_id) DO UPDATE SET data=excluded.data", (value.resource_type, value.resource_id, value.model_dump_json()))
            store.audit(db, "resource_updated", value.resource_id, {"type": value.resource_type})
        return {"registered": True}

    @app.get("/v1/policies", dependencies=[Depends(admin)])
    def policies():
        with store.connection() as db:
            return {"policies": [json.loads(r[0]) for r in db.execute("SELECT p.body FROM policies p JOIN active_policies a USING(policy_id,version)")]}

    @app.get("/v1/policies/{policy_id}", dependencies=[Depends(admin)])
    def policy(policy_id: str):
        with store.connection() as db:
            current = store.current(db, policy_id)
            history = [dict(r) for r in db.execute("SELECT version,published_at FROM policies WHERE policy_id=? ORDER BY version", (policy_id,))]
        if not current: raise HTTPException(404, "Policy not found")
        return {"policy": current, "history": history, "signed": store.envelope(current)}

    @app.put("/v1/policies/{policy_id}", dependencies=[Depends(admin)])
    def publish(policy_id: str, policy: Policy):
        if policy.policy_id != policy_id: raise HTTPException(422, "Policy identifier mismatch")
        return engine.publish(policy)

    @app.get("/v1/policy-schema", dependencies=[Depends(admin)])
    def policy_schema():
        return Policy.model_json_schema()

    @app.get("/v1/sdk/policy")
    def sdk_policy(identity=Depends(sdk)):
        with store.connection() as db:
            policy = store.current(db, identity["policy_id"])
        if not policy: raise HTTPException(404, "No policy published")
        return store.envelope(policy)

    async def inspect(text, direction):
        rails = await asyncio.to_thread(get_rails)
        return await rails.inspect(text, direction)

    @app.post("/v1/authorize")
    async def authorize(request: Authorization, identity=Depends(sdk)):
        if len(canonical(request.arguments)) > 100_000:
            raise HTTPException(413, "Arguments too large")
        tool = next((t for t in identity["tools"] if t["name"] == request.tool_name), None)
        result = None
        if tool and tool["scan_fields"]:
            checks = []
            for field in tool["scan_fields"]:
                value = request.arguments.get(field)
                if type(value) is not str or not value.strip():
                    checks.append({"allowed": False, "field": field, "reason": "Missing or invalid scan field"})
                else:
                    check = await inspect(value, "input")
                    checks.append({**check, "field": field})
            result = {"allowed": all(c["allowed"] for c in checks), "checks": checks,
                      "scanned_fields": tool["scan_fields"], "detector_latency_ms": sum(c.get("detector_latency_ms",0) for c in checks),
                      "nemo_overhead_ms": sum(c.get("nemo_overhead_ms",0) for c in checks)}
        return engine.authorize(request, identity, result)

    @app.post("/v1/executions/{execution_id}/outcome")
    def outcome(execution_id: str, value: Outcome, identity=Depends(sdk)):
        try: return engine.report(execution_id, value, identity)
        except KeyError: raise HTTPException(404, "Execution not found") from None

    @app.post("/v1/approvals/{execution_id}", dependencies=[Depends(admin)])
    def approve(execution_id: str):
        try: return engine.approve(execution_id)
        except KeyError: raise HTTPException(404, "Execution not found") from None

    @app.post("/v1/inspect")
    async def inspection(value: Inspection, identity=Depends(sdk)):
        result = await inspect(value.text, value.direction)
        identifier = uuid.uuid4().hex
        with store.transaction() as db:
            db.execute("INSERT INTO inspections VALUES(?,?,?,?)", (identifier, identity["agent_id"], value.session_id, canonical(result)))
        return {"inspection_id": identifier, **result}

    @app.get("/v1/events", dependencies=[Depends(admin)])
    def events(agent_id: str | None = None, limit: int = 200):
        if not 1 <= limit <= 5000: raise HTTPException(422, "Limit must be 1–5000")
        return {"events": store.events(agent=agent_id, limit=limit)}

    @app.get("/v1/sessions/{session_id}", dependencies=[Depends(admin)])
    def session(session_id: str, agent_id: str):
        return {"events": store.events(agent=agent_id, session=session_id, limit=5000)}

    @app.get("/v1/analytics/summary", dependencies=[Depends(admin)])
    def analytics_summary(): return summary(store)

    @app.get("/v1/analytics/pathways", dependencies=[Depends(admin)])
    def analytics_pathways(): return pathways(store)

    @app.post("/v1/evaluations/run", dependencies=[Depends(admin)])
    async def evaluation_run():
        if not evaluation_lock.acquire(blocking=False): raise HTTPException(429, "An evaluation is already running")
        identifier = uuid.uuid4().hex
        with store.transaction() as db:
            db.execute("INSERT INTO evaluations VALUES(?,?,NULL)", (identifier, "running"))
        async def work():
            try:
                from .evaluation import evaluate
                result = await asyncio.to_thread(evaluate)
                status = "complete"
            except Exception as exc:
                result, status = {"error": type(exc).__name__, "message": "No results fabricated"}, "error"
            finally:
                evaluation_lock.release()
            with store.transaction() as db:
                db.execute("UPDATE evaluations SET status=?,result=? WHERE id=?", (status, canonical(result), identifier))
        asyncio.create_task(work())
        return {"evaluation_id": identifier}

    @app.get("/v1/evaluations/{identifier}", dependencies=[Depends(admin)])
    def evaluation(identifier: str):
        with store.connection() as db:
            row = db.execute("SELECT status,result FROM evaluations WHERE id=?", (identifier,)).fetchone()
        if not row: raise HTTPException(404, "Evaluation not found")
        return {"id": identifier, "status": row[0], "result": json.loads(row[1]) if row[1] else None}

    @app.post("/v1/demonstrations/run", dependencies=[Depends(admin)])
    async def demonstration_run():
        if not evaluation_lock.acquire(blocking=False): raise HTTPException(429, "A demonstration or evaluation is running")
        identifier = uuid.uuid4().hex
        with store.transaction() as db:
            db.execute("INSERT INTO evaluations VALUES(?,?,NULL)", (identifier,"running"))
        async def work():
            try:
                from scripts.demo_v2 import demonstrate
                # Live demonstration calls this HTTP service; keep its event loop free.
                result = await asyncio.to_thread(lambda: asyncio.run(demonstrate()))
                status = "complete"
            except Exception as exc:
                result, status = {"error":type(exc).__name__,"message":"No results fabricated"}, "error"
            finally:
                evaluation_lock.release()
            with store.transaction() as db:
                db.execute("UPDATE evaluations SET status=?,result=? WHERE id=?", (status,canonical(result),identifier))
        asyncio.create_task(work())
        return {"evaluation_id":identifier}

    @app.get("/v1/reports/latest", dependencies=[Depends(admin)])
    def latest_reports():
        from .storage import V2
        result = {}
        for name,file in [("evaluation","latest-evaluation.json"),("live_demo","live-demo.json")]:
            path = V2 / file
            result[name] = json.loads(path.read_text(encoding="utf-8")) if path.exists() else None
        return result

    @app.get("/v1/demo/rag-link", dependencies=[Depends(admin)])
    def rag_link():
        return {"url":"http://127.0.0.1:8775/#with"}

    @app.get("/")
    def home(): return FileResponse(ROOT / "web_v2" / "index.html")
    from .demo_routes import demo_router
    app.include_router(demo_router(store,engine,admin))
    from .universal import router as universal_router
    app.include_router(universal_router(store,admin,sdk))
    if (ROOT / "web_v2").exists():
        app.mount("/static", StaticFiles(directory=ROOT / "web_v2"), name="static")
    return app


app = create_app()
