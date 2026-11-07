"""Two concurrent $50 requests across sessions cannot bypass the $75 ledger cap."""
import json
import uuid
from concurrent.futures import ThreadPoolExecutor
import httpx
from promptguard.common import utcnow
from promptguard_v2.examples import profile, policy
from promptguard_v2.sdk import PromptGuard
from promptguard_v2.storage import credentials, V2
from demo_apps_v2.refund_adapter import RefundAdapter, BusinessActionDenied


def demonstrate(endpoint="http://127.0.0.1:8775"):
    auth = credentials()
    with httpx.Client(base_url=endpoint,headers={"Authorization":"Bearer "+auth["admin_token"]},trust_env=False,timeout=10) as admin:
        agent = "ledger-"+uuid.uuid4().hex[:10]
        value = profile(agent,agent)
        value.tools = [t for t in value.tools if t.name == "issue_refund"]
        tool = value.tools[0]
        tool.arguments_schema["properties"]["idempotency_key"] = {"type":"string","minLength":1,"maxLength":100}
        tool.arguments_schema["required"].append("idempotency_key")
        register = admin.post("/v1/agents",json=value.model_dump()); register.raise_for_status()
        body = policy(agent).model_dump()
        response = admin.put("/v1/policies/"+agent,json=body); response.raise_for_status()
        key = admin.get("/v1/health").json()["public_key"]
        pg = PromptGuard(register.json()["agent_token"],endpoint,agent,policy_public_key=key)
        adapter = RefundAdapter(pg)
        issue_refund = pg.protect()(adapter.issue_refund)
        def attempt(i):
            with pg.session():
                try: return {"status":"applied", "result":issue_refund("cust-alex",5000,"request-"+str(i))}
                except BusinessActionDenied as exc: return {"status":"denied_by_authoritative_ledger", "reason":str(exc)}
        with ThreadPoolExecutor(max_workers=2) as pool: outcomes = list(pool.map(attempt,range(2)))
        ledger = adapter.store.ledger(adapter.run_id)
        total = sum(r["amount"] for r in ledger)
        assert total == 5000 and len(ledger) == 1
        report = {"created_at":utcnow(),"agent_id":agent,"run_id":adapter.run_id,"attempts":outcomes,"ledger":ledger,
            "cumulative_cents":total,"configured_limit_cents":body["refund_cumulative_limit_cents"],"concurrent_sessions":2,
            "enforcement_location":"Application's SQLite transaction, reusing existing refund ledger", "limitations":
            "Policy snapshot is checked before the ledger transaction; no distributed atomicity with concurrent remote publication. Frozen task budget remains authoritative. No real funds."}
        (V2 / "ledger-proof.json").write_text(json.dumps(report,indent=2),encoding="utf-8")
        pg.close()
        return report


if __name__ == "__main__": print(json.dumps(demonstrate(),indent=2))
