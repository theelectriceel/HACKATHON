"""Authoritative checks and finite-state pathway matching under SQLite transactions."""
from __future__ import annotations

import json
import time
import uuid
from jsonschema import Draft202012Validator
from promptguard.common import canonical, digest, utcnow
from .schema import Policy

RANK = {"ALLOW": 0, "REQUIRE_APPROVAL": 1, "DENY": 2}


class Conflict(ValueError):
    pass


def fingerprint(rule):
    return digest({"id": rule["id"], "pathway": rule["pathway"], "tool": rule["tool"]})


def advance(db, event, basis, policy):
    for rule in policy["rules"]:
        path = rule.get("pathway")
        if not rule["enabled"] or not path or path["basis"] != basis:
            continue
        resource = event["resource_key"] if path["same_resource"] else "*"
        key = (event["agent_id"], event["session_id"], fingerprint(rule), resource)
        row = db.execute("SELECT progress FROM path_state WHERE agent_id=? AND session_id=? AND fingerprint=? AND resource=?", key).fetchone()
        progress = row[0] if row else 0
        sequence = path["after"]
        # Ordered subsequence. A completed prefix remains relevant until session end.
        if progress < len(sequence) and event["tool_name"] == sequence[progress]:
            progress += 1
        db.execute("INSERT INTO path_state VALUES(?,?,?,?,?) ON CONFLICT(agent_id,session_id,fingerprint,resource) DO UPDATE SET progress=excluded.progress", (*key, progress))


def condition_matches(condition, args, resource, identity):
    namespace, key = condition["field"].split(".", 1)
    source = {"args": args, "resource": resource, "identity": identity}[namespace]
    if key not in source:
        raise ValueError("MISSING_POLICY_ATTRIBUTE")
    value, expected, op = source[key], condition["value"], condition["op"]
    if op in ("gt", "gte", "lt", "lte"):
        if type(value) not in (int, float):
            raise ValueError("INVALID_POLICY_ATTRIBUTE_TYPE")
        return {"gt": lambda: value > expected, "gte": lambda: value >= expected, "lt": lambda: value < expected, "lte": lambda: value <= expected}[op]()
    if op in ("eq", "ne"):
        equal = type(value) is type(expected) and value == expected
        return equal if op == "eq" else not equal
    member = any(type(value) is type(v) and value == v for v in expected)
    return member if op == "in" else not member


class Engine:
    def __init__(self, store):
        self.store = store

    def publish(self, policy: Policy):
        body = policy.model_dump()
        with self.store.transaction() as db:
            current = self.store.current(db, policy.policy_id)
            if policy.version != (current["version"] + 1 if current else 1):
                raise Conflict("Publish the next consecutive policy version")
            db.execute("INSERT INTO policies VALUES(?,?,?,?)", (policy.policy_id, policy.version, canonical(body), utcnow()))
            db.execute("INSERT INTO active_policies VALUES(?,?) ON CONFLICT(policy_id) DO UPDATE SET version=excluded.version", (policy.policy_id, policy.version))
            # Publication is rare; replay here keeps hot authorization O(number of rules).
            agents = [r[0] for r in db.execute("SELECT agent_id FROM agents WHERE json_extract(profile,'$.policy_id')=?", (policy.policy_id,))]
            for agent in agents:
                db.execute("DELETE FROM path_state WHERE agent_id=?", (agent,))
                for row in db.execute("SELECT data FROM events WHERE agent_id=? ORDER BY seq", (agent,)).fetchall():
                    event = json.loads(row[0])
                    advance(db, event, "attempted", body)
                    if event["execution_status"] == "completed":
                        advance(db, event, "completed", body)
            self.store.audit(db, "policy_published", policy.policy_id, {"version": policy.version})
        return self.store.envelope(body)

    def authorize(self, request, identity, guardrails=None):
        started = time.perf_counter()
        args = request.arguments
        canonical(args)  # Reject NaN, opaque objects and non-JSON input.
        with self.store.transaction() as db:
            if db.execute("SELECT 1 FROM events WHERE execution_id=?", (request.execution_id,)).fetchone():
                raise Conflict("Execution ID already used; automatic retries are unsafe")
            # Reload identity inside the same transaction to avoid stale registration.
            row = db.execute("SELECT profile FROM agents WHERE agent_id=?", (identity["agent_id"],)).fetchone()
            identity = json.loads(row[0])
            policy = self.store.current(db, identity["policy_id"])
            from .universal import active, evaluate
            universal_policies = active(db)
            tool = next((t for t in identity["tools"] if t["name"] == request.tool_name), None)
            hard, matches, reasons, resource = [], [], [], {}
            if request.agent_id != identity["agent_id"]:
                hard.append("AGENT_IDENTITY_MISMATCH")
            if not tool:
                hard.append("TOOL_NOT_REGISTERED")
            if not policy:
                hard.append("NO_PUBLISHED_POLICY")
            if tool:
                if not Draft202012Validator(tool["arguments_schema"]).is_valid(args):
                    hard.append("ARGUMENT_SCHEMA_VIOLATION")
                if tool["resource_arg"]:
                    rid = args.get(tool["resource_arg"])
                    r = db.execute("SELECT data FROM resources WHERE resource_type=? AND resource_id=?", (tool["resource_type"], rid if type(rid) is str else "")).fetchone()
                    if not r:
                        hard.append("UNKNOWN_RESOURCE")
                    else:
                        resource = json.loads(r[0])
                        for binding in tool["identity_bindings"]:
                            if identity.get(binding) is None or resource.get(binding) != identity[binding]:
                                hard.append("RESOURCE_" + binding.upper() + "_MISMATCH")
            resource_key = digest([resource.get("resource_type"), resource.get("resource_id")]) if resource else "none"
            if tool and policy and not hard:
                if tool["scan_fields"] and (not guardrails or guardrails.get("scanned_fields") != tool["scan_fields"]):
                    hard.append("REQUIRED_GUARDRAILS_NOT_EXECUTED")
                for rule in policy["rules"]:
                    if not rule["enabled"] or rule["tool"] != request.tool_name:
                        continue
                    path = rule.get("pathway")
                    if path:
                        rkey = resource_key if path["same_resource"] else "*"
                        row = db.execute("SELECT progress FROM path_state WHERE agent_id=? AND session_id=? AND fingerprint=? AND resource=?", (identity["agent_id"], request.session_id, fingerprint(rule), rkey)).fetchone()
                        if not row or row[0] < len(path["after"]):
                            continue
                    try:
                        matched = all(condition_matches(c, args, resource, identity) for c in rule["conditions"])
                    except ValueError as exc:
                        hard.append(str(exc)); continue
                    if matched:
                        matches.append(rule); reasons.append(rule["reason"])
            decision = max((r["effect"] for r in matches), key=RANK.get) if matches else (policy["default_effect"] if policy else "DENY")
            universal_matches, universal_errors = evaluate(universal_policies, identity, tool, args, resource) if tool else ([],[])
            hard.extend(universal_errors)
            for matched in universal_matches:
                decision = max((decision,matched['effect']),key=RANK.get)
                reasons.append(matched['reason'])
            if guardrails and not guardrails["allowed"]:
                hard.append("GUARDRAIL_BLOCKED")
            if hard:
                decision = "DENY"
            binding = digest({"agent": identity["agent_id"], "principal": identity["principal_id"], "session": request.session_id, "tool": request.tool_name, "args": args, "policy": policy,"universal_policies":universal_policies})
            approval_used = None
            if decision == "REQUIRE_APPROVAL" and request.approval_id:
                approval = db.execute("SELECT * FROM approvals WHERE id=?", (request.approval_id,)).fetchone()
                if approval and approval["binding"] == binding and approval["expires"] > time.time() and not approval["consumed"]:
                    decision, approval_used = "ALLOW", request.approval_id
                else:
                    reasons.append("Approval missing, stale, consumed or does not match this exact action")
            db.execute("INSERT OR IGNORE INTO sessions VALUES(?,?,NULL)", (identity["agent_id"], request.session_id))
            inflight = db.execute("SELECT inflight FROM sessions WHERE agent_id=? AND session_id=?", (identity["agent_id"], request.session_id)).fetchone()[0]
            if decision == "ALLOW" and inflight:
                decision = "DENY"; hard.append("SESSION_INFLIGHT_UNRESOLVED")
            if decision == "ALLOW":
                db.execute("UPDATE sessions SET inflight=? WHERE agent_id=? AND session_id=?", (request.execution_id, identity["agent_id"], request.session_id))
                if approval_used:
                    db.execute("UPDATE approvals SET consumed=1 WHERE id=?", (approval_used,))
            redacted = {}
            for key, value in args.items():
                # Only explicitly allowlisted small scalar arguments enter analytics.
                safe = tool and key in tool["log_arguments"] and type(value) in (str, int, float, bool) and len(str(value)) <= 120
                sensitive_name = any(x in key.lower() for x in ("key", "secret", "token", "password", "email", "text", "body", "content"))
                redacted[key] = value if safe and not sensitive_name else "[redacted]"
            event = {"event_id": request.execution_id, "timestamp": utcnow(), "agent_id": identity["agent_id"], "session_id": request.session_id,
                     "principal_id": identity["principal_id"], "tool_name": request.tool_name, "redacted_arguments": redacted,
                     "policy_id": identity["policy_id"], "policy_version": policy["version"] if policy else None,
                     "authorization_decision": decision, "matched_rules": [r["id"] for r in matches], "reasons": hard + reasons,
                     "matched_universal_policies":universal_matches,
                     "guardrail_findings": guardrails, "execution_status": "authorized" if decision == "ALLOW" else "not_executed",
                     "execution_latency_ms": None, "authorization_latency_ms": round((time.perf_counter()-started)*1000, 3),
                     "resource_identifiers": {k:resource[k] for k in ("resource_id", "resource_type") if k in resource},
                     "resource_key": resource_key, "approval_binding": binding, "approval_used": approval_used}
            db.execute("INSERT INTO events(execution_id,agent_id,session_id,tool_name,status,resource,data) VALUES(?,?,?,?,?,?,?)", (request.execution_id, identity["agent_id"], request.session_id, request.tool_name, event["execution_status"], resource_key, canonical(event)))
            if policy:
                advance(db, event, "attempted", policy)
        return {"execution_id": request.execution_id, "decision": decision, "reasons": event["reasons"], "matched_rules": event["matched_rules"],
                "agent_id":identity['agent_id'],"tool":request.tool_name,"matched_universal_policies":universal_matches,
                "policy_id": event["policy_id"], "policy_version": event["policy_version"], "authorization_latency_ms": event["authorization_latency_ms"], "guardrails": guardrails}

    def report(self, execution_id, outcome, identity):
        with self.store.transaction() as db:
            row = db.execute("SELECT data FROM events WHERE execution_id=? AND agent_id=?", (execution_id, identity["agent_id"])).fetchone()
            if not row:
                raise KeyError("Execution not found")
            event = json.loads(row[0])
            if event["execution_status"] != "authorized":
                raise Conflict("Only a single outcome for an authorized execution is accepted")
            event.update(execution_status=outcome.execution_status, execution_latency_ms=outcome.execution_latency_ms, error_type=outcome.error_type)
            db.execute("UPDATE events SET status=?,data=? WHERE execution_id=?", (outcome.execution_status, canonical(event), execution_id))
            db.execute("UPDATE sessions SET inflight=NULL WHERE agent_id=? AND session_id=? AND inflight=?", (identity["agent_id"], event["session_id"], execution_id))
            policy = self.store.current(db, identity["policy_id"])
            if policy and outcome.execution_status == "completed":
                advance(db, event, "completed", policy)
        return {"recorded": True, "execution_id": execution_id}

    def approve(self, execution_id):
        with self.store.transaction() as db:
            row = db.execute("SELECT data FROM events WHERE execution_id=?", (execution_id,)).fetchone()
            if not row:
                raise KeyError("Execution not found")
            event = json.loads(row[0])
            if event["authorization_decision"] != "REQUIRE_APPROVAL":
                raise Conflict("Only approval-required actions can be approved")
            identifier = uuid.uuid4().hex
            db.execute("INSERT INTO approvals(id,binding,expires) VALUES(?,?,?)", (identifier, event["approval_binding"], time.time()+120))
            self.store.audit(db, "approval_granted", execution_id, {"approval_id": identifier})
        return {"approval_id": identifier, "expires_in_seconds": 120}
