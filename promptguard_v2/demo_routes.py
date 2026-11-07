"""Small authenticated interface for the three-part RAG demonstration."""
import uuid
from typing import Literal
import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import Field, field_validator
from .schema import Strict, Policy
from .rag_policy import TOOLS, AGENT
from .storage import credentials


class RagRun(Strict):
    question: str = Field(min_length=3,max_length=1500)
    scenario: Literal["clean","override","quote"] = "override"
    mode: Literal["unprotected","protected"]


class Sequence(Strict):
    tools: list[str] = Field(min_length=2,max_length=8)

    @field_validator("tools")
    @classmethod
    def registered(cls, values):
        if any(v not in TOOLS for v in values): raise ValueError("Choose one of the actual RAG tools")
        return values


class Toggle(Strict):
    enabled: bool


def demo_router(store, engine, admin):
    router = APIRouter(prefix="/v1/demo",dependencies=[Depends(admin)])

    def proxy(path, body=None):
        try:
            with httpx.Client(trust_env=False,timeout=5) as client:
                response = client.request("POST" if body is not None else "GET","http://127.0.0.1:8776"+path,
                    headers={"Authorization":"Bearer "+credentials()["demo_agent_token"]},json=body)
            if response.status_code >= 400:
                raise HTTPException(response.status_code,response.json().get("detail","RAG request failed"))
            return response.json()
        except (httpx.HTTPError,ValueError):
            raise HTTPException(503,"The RAG demo app is unavailable. Start start-v2.ps1.") from None

    @router.post("/rag/run")
    def run(value: RagRun): return proxy("/run",value.model_dump())

    @router.get("/rag/jobs/{identifier}")
    def job(identifier: str):
        if len(identifier) != 32 or not all(c in "0123456789abcdef" for c in identifier): raise HTTPException(422,"Invalid run ID")
        return proxy("/jobs/"+identifier)

    @router.get("/rag/saved")
    def saved(): return proxy("/saved")

    @router.get("/rag/activity")
    def activity(): return proxy("/activity")

    def current():
        with store.connection() as db: body = store.current(db,AGENT)
        if not body: raise HTTPException(503,"RAG policy not initialized; restart start-v2.ps1")
        return body

    @router.get("/sequences")
    def sequences():
        body = current()
        return {"version":body["version"],"tools":[{"id":k,"label":v} for k,v in TOOLS.items()],
            "sequences":[{"id":r["id"],"tools":r["pathway"]["after"]+[r["tool"]],"enabled":r["enabled"]}
                         for r in body["rules"] if r["id"].startswith("rag-sequence-") and r.get("pathway")]}

    @router.post("/sequences")
    def block_sequence(value: Sequence):
        body = current()
        for rule in body["rules"]:
            if rule.get("pathway") and rule["pathway"]["after"]+[rule["tool"]] == value.tools and rule["enabled"]:
                raise HTTPException(409,"This sequence is already blocked")
        identifier = "rag-sequence-"+uuid.uuid4().hex[:12]
        body["rules"].append({"id":identifier,"tool":value.tools[-1],"effect":"DENY","enabled":True,"conditions":[],
            "pathway":{"after":value.tools[:-1],"basis":"completed","same_resource":False},
            "reason":"Blocked sequence: "+" → ".join(TOOLS[t] for t in value.tools)})
        body["version"] += 1
        engine.publish(Policy.model_validate(body))
        return {"id":identifier,"version":body["version"],"enabled":True}

    @router.patch("/sequences/{identifier}")
    def toggle(identifier: str, value: Toggle):
        body = current()
        rule = next((r for r in body["rules"] if r["id"] == identifier and r["id"].startswith("rag-sequence-")),None)
        if not rule: raise HTTPException(404,"Sequence not found")
        rule["enabled"] = value.enabled
        body["version"] += 1
        engine.publish(Policy.model_validate(body))
        return {"id":identifier,"version":body["version"],"enabled":value.enabled}

    return router
