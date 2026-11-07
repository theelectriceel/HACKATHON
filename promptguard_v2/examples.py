"""Small business fixtures. No external mail, payments, or customer systems."""
from .schema import AgentRegistration, Policy, Resource


def object_schema(properties, required=None):
    return {"type": "object", "properties": properties, "required": required or list(properties), "additionalProperties": False}


def profile(agent_id="support-agent", policy_id="support-agent"):
    customer = {"customer_id": {"type": "string", "minLength": 1, "maxLength": 80}}
    tools = []
    for name, properties in [
        ("lookup_customer", customer),
        ("export_customer_data", customer),
        ("send_email", {**customer, "destination": {"type": "string", "enum": ["approved", "external"]}}),
        ("issue_refund", {**customer, "amount_cents": {"type": "integer", "minimum": 1, "maximum": 1000000}}),
        ("process_document", {"text": {"type": "string", "minLength": 1, "maxLength": 20000}}),
    ]:
        tools.append({"name": name, "arguments_schema": object_schema(properties),
            "resource_arg": "customer_id" if name != "process_document" else None,
            "resource_type": "customer" if name != "process_document" else None,
            "identity_bindings": ["tenant_id", "customer_id"] if name != "process_document" else [],
            "log_arguments": ["customer_id", "destination", "amount_cents"], "scan_fields": ["text"] if name == "process_document" else []})
    return AgentRegistration.model_validate({"agent_id": agent_id, "principal_id": "operator-alex", "tenant_id": "acme", "customer_id": "cust-alex", "policy_id": policy_id, "tools": tools})


def policy(policy_id="support-agent", version=1, pathway=True, guardrails=True, revoke=False):
    rules = [{"id": "permit-"+name, "tool": name, "effect": "ALLOW", "reason": "Registered business capability"}
             for name in ("lookup_customer", "export_customer_data", "send_email", "issue_refund", "process_document")]
    rules.append({"id": "refund-approval", "tool": "issue_refund", "effect": "REQUIRE_APPROVAL",
                  "conditions": [{"field": "args.amount_cents", "op": "gt", "value": 7500, "unit": "cents"}],
                  "reason": "A refund above $75 requires approval for this exact action"})
    if pathway:
        rules.append({"id": "external-after-export", "tool": "send_email", "effect": "DENY",
            "pathway": {"after": ["lookup_customer", "export_customer_data"], "basis": "completed", "same_resource": True},
            "conditions": [{"field": "args.destination", "op": "ne", "value": "approved"}],
            "reason": "Customer information was exported in this session; use an approved destination"})
        rules.append({"id": "any-export-external", "tool": "send_email", "effect": "DENY",
            "pathway": {"after": ["export_customer_data"], "basis": "completed", "same_resource": True},
            "conditions": [{"field": "args.destination", "op": "ne", "value": "approved"}],
            "reason": "An export alone is sufficient to restrict subsequent external transmission"})
    if revoke:
        rules.append({"id": "remote-revocation", "tool": "export_customer_data", "effect": "DENY", "reason": "An operator remotely disabled customer exports"})
    return Policy.model_validate({"policy_id": policy_id, "version": version, "rules": rules})


def seed(store, token, agent_id="support-agent", policy_id="support-agent"):
    from .engine import Engine
    value = profile(agent_id, policy_id)
    store.register(value, token)
    with store.transaction() as db:
        for cid, tenant in [("cust-alex", "acme"), ("cust-jamie", "other-company")]:
            resource = Resource(resource_id=cid, resource_type="customer", tenant_id=tenant, customer_id=cid, sensitivity="confidential")
            db.execute("INSERT OR REPLACE INTO resources VALUES(?,?,?)", (resource.resource_type, resource.resource_id, resource.model_dump_json()))
        existing = store.current(db, policy_id)
    if not existing:
        Engine(store).publish(policy(policy_id))


def mcp_server(pg=None):
    from fastmcp import FastMCP
    server = FastMCP("PROMPTGUARD V2 isolated customer tools")
    effects = {"lookup_customer": 0, "export_customer_data": 0, "send_email": 0, "issue_refund": 0, "process_document": 0, "delete_customer": 0}

    @server.tool
    def lookup_customer(customer_id: str):
        effects["lookup_customer"] += 1
        return {"customer_id": customer_id, "record": "Isolated demonstration customer"}

    @server.tool
    def export_customer_data(customer_id: str):
        effects["export_customer_data"] += 1
        return {"customer_id": customer_id, "export": "Mock customer export — no real personal data"}

    @server.tool
    def send_email(customer_id: str, destination: str):
        effects["send_email"] += 1
        return {"delivered_to_mock_outbox": True, "destination": destination}

    @server.tool
    def issue_refund(customer_id: str, amount_cents: int):
        effects["issue_refund"] += 1
        return {"mock_refund_requested": amount_cents, "customer_id": customer_id}

    @server.tool
    def process_document(text: str):
        effects["process_document"] += 1
        return {"delivered_to_test_consumer": True, "characters": len(text)}

    @server.tool
    def delete_customer(customer_id: str):
        # Deliberately available on the server but absent from this agent's permissions.
        effects["delete_customer"] += 1
        return {"deleted_in_isolated_counter_only": customer_id}

    if pg:
        pg.wrap(server)
    return server, effects
