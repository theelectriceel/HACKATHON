"""The three real RAG tools exposed by the independent demonstration app."""
import hashlib
import hmac
from .schema import AgentRegistration, Policy
from .engine import Engine

TOOLS = {"search_documents": "Search documents", "read_document": "Read a document", "generate_answer": "Generate answer"}
AGENT = "rag-agent"
CAPABILITIES = {"search_documents":"document_search", "read_document":"document_read", "generate_answer":"answer_generation"}


def agent_token(auth):
    return hmac.new(auth["demo_agent_token"].encode(), b"promptguard-rag-tools", hashlib.sha256).hexdigest()


def seed_rag(store, auth):
    properties = {
        "search_documents": {"query": {"type": "string", "minLength": 3, "maxLength": 1500}},
        "read_document": {"document_id": {"type": "string", "minLength": 1, "maxLength": 120}},
        "generate_answer": {"document_count": {"type": "integer", "minimum": 0, "maximum": 3}},
    }
    profile = AgentRegistration(agent_id=AGENT, principal_id="rag-demo-operator", tenant_id="rag-demo", policy_id=AGENT, groups=["rag-agents"],
        tools=[{"name": name, "arguments_schema": {"type": "object", "properties": fields, "required": list(fields), "additionalProperties": False},
                "capabilities":[CAPABILITIES[name]],"integration":"sdk",
                "log_arguments": [key for key in fields if key != "query"]} for name, fields in properties.items()])
    store.register(profile, agent_token(auth))
    with store.connection() as db:
        current = store.current(db, AGENT)
    if not current:
        Engine(store).publish(Policy(policy_id=AGENT, version=1,
            rules=[{"id": "permit-"+name, "tool": name, "effect": "ALLOW", "reason": "RAG tool enabled"} for name in TOOLS]))
