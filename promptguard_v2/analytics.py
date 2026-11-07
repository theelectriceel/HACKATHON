"""Business recommendations grounded only in persisted control-plane events."""
from collections import Counter, defaultdict
import json
import math


def percentile(values, p=.95):
    return round(sorted(values)[max(0, math.ceil(len(values)*p)-1)], 3) if values else None


def summary(store):
    with store.connection() as db:
        events = [json.loads(r[0]) for r in db.execute("SELECT data FROM events ORDER BY seq")]
        changes = [dict(r) for r in db.execute("SELECT timestamp,action,subject,details FROM audit ORDER BY id DESC LIMIT 50")]
        inspections = [json.loads(r[0]) for r in db.execute("SELECT result FROM inspections")]
    decisions = Counter(e["authorization_decision"] for e in events)
    denied = [e for e in events if e["authorization_decision"] == "DENY"]
    unresolved = [e for e in events if e["execution_status"] == "authorized"]
    findings = []
    if denied:
        tools = Counter(e["tool_name"] for e in denied)
        top, count = tools.most_common(1)[0]
        findings.append({"priority": "Review", "finding": f"{count} restricted {top} calls were stopped before the tool ran.",
            "decision": "Keep this restriction enabled. Review the linked sessions before expanding this agent's access.",
            "why_now": "These requests have already occurred under the current controls.",
            "evidence": [e["event_id"] for e in denied if e["tool_name"] == top][-5:], "claim": "Observed policy violations; malicious intent is not established."})
    if unresolved:
        findings.append({"priority": "Investigate", "finding": f"{len(unresolved)} authorized calls have no confirmed execution outcome.",
            "decision": "Check the application before retrying. These sessions remain closed to further execution.",
            "why_now": "A retry could duplicate a business action.", "evidence": [e["event_id"] for e in unresolved][-5:]})
    all_inspections = inspections + [e["guardrail_findings"] for e in events if e.get("guardrail_findings")]
    latency = [e["authorization_latency_ms"] for e in events]
    return {"total_tool_calls": len(events), "calls_by_agent": dict(Counter(e["agent_id"] for e in events)),
            "calls_by_tool": dict(Counter(e["tool_name"] for e in events)), "decisions": dict(decisions),
            "execution_outcomes": dict(Counter(e["execution_status"] for e in events)), "denied_tools": dict(Counter(e["tool_name"] for e in denied)),
            "policy_matches": dict(Counter(rule for e in events for rule in e["matched_rules"])),
            "violations_by_agent": dict(Counter(e["agent_id"] for e in denied)),
            "denials_by_policy_version": dict(Counter(f'{e["policy_id"]}@{e["policy_version"]}' for e in denied)),
            "authorization_p50_ms": percentile(latency,.5), "authorization_p95_ms": percentile(latency),
            "guardrail_checks": len(all_inspections), "guardrail_blocks": sum(not r["allowed"] for r in all_inspections),
            "detector_p95_ms": percentile([r.get("detector_latency_ms",0) for r in all_inspections]),
            "nemo_overhead_p95_ms": percentile([r.get("nemo_overhead_ms",0) for r in all_inspections]),
            "policy_changes": changes, "recommendations": findings,
            "evidence_scope": "All persisted V2 events. SDK outcomes are application reports, not independent proof of external effects."}


def pathways(store):
    events = store.events(limit=5000)
    sessions = defaultdict(list)
    for event in events:
        sessions[(event["agent_id"],event["session_id"])].append(event)
    counts = Counter(" → ".join(e["tool_name"] for e in values) for values in sessions.values())
    return {"scope": "Most recent 5000 tool events", "pathways": [{"pathway": k, "sessions": v} for k,v in counts.most_common(20)],
            "sessions": [{"agent_id": a, "session_id": s, "tools": [e["tool_name"] for e in values],
                          "denials": sum(e["authorization_decision"] == "DENY" for e in values),
                          "event_ids": [e["event_id"] for e in values]} for (a,s),values in sessions.items()][-50:]}
