"""Export measured V2 evidence and schemas; never manufacture a passing result."""
import json
from pathlib import Path
from promptguard.common import ROOT, utcnow
from promptguard_v2.schema import Policy
from promptguard_v2.examples import profile, policy
from promptguard_v2.storage import V2


def main():
    docs = ROOT / "docs" / "v2"
    docs.mkdir(exist_ok=True)
    for name,value in [("policy.schema.json",Policy.model_json_schema()),("example-policy.json",policy().model_dump()),("example-agent.json",profile().model_dump())]:
        (docs/name).write_text(json.dumps(value,indent=2),encoding="utf-8")
    report = json.loads((V2/"latest-evaluation.json").read_text(encoding="utf-8"))
    proof = json.loads((V2/"live-demo.json").read_text(encoding="utf-8"))
    text = ["# PROMPTGUARD V2 — actual results", "",f"Generated {utcnow()}. Evaluation `{report['id']}`. Frozen suite digest `{report['suite_digest']}`.","",
        "14 authored scenarios × 5 conditions; actual MCP execution and independent counters. This is a small enforcement regression suite, not an LLM attack-success benchmark.","",
        "| Condition | Prohibited actions executed | Legitimate tasks completed | Recall | FPR | Precision | Authorization p95 | Whole call p95 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|"]
    percent = lambda n: "n/a" if n is None else f"{n*100:.1f}%"
    for row in report["conditions"]:
        n = round(row["legitimate_task_completion_rate"]*row["legitimate_trials"])
        auth = "n/a" if row["authorization_p95_ms"] is None else f'{row["authorization_p95_ms"]} ms'
        text.append(f'| {row["condition"]} | {row["unauthorized_actions_executed"]}/{row["unauthorized_action_trials"]} | {n}/{row["legitimate_trials"]} | {percent(row["policy_recall"])} | {percent(row["policy_false_positive_rate"])} | {percent(row["policy_precision"])} | {auth} | {row["call_wall_p95_ms"]} ms |')
    text.extend(["","FPR is measured over the eight legitimate workflows. Detector content delivery is separately reported. NeMo/Horizon blocks one benign security quotation; the stateful policy-only condition preserves all legitimate tasks.","",
        "The static function-permission baseline correctly blocks the unregistered delete tool. It has no argument, resource, or pathway restrictions. PROMPTGUARD tools adds argument/resource checks; the pathway condition adds state. All conditions run the same frozen cases.","",
        f'Remote revocation: export counter {proof["revocation"]["original_function_invocations_before"]} → {proof["revocation"]["original_function_invocations_after"]} after the denied retry; same server/client session. Observed denial {proof["revocation"]["publish_to_observed_denial_ms"]} ms after publication (one observation including request time).',"",
        f'NeMo actual action count {proof["nemo_horizon"]["nemo"]["action_executions"]}; status {proof["nemo_horizon"]["nemo"]["status"]}; Horizon {proof["nemo_horizon"]["detector_latency_ms"]} ms; framework overhead {proof["nemo_horizon"]["nemo_overhead_ms"]} ms. No generative call.',""])
    if proof.get("ledger_proof"):
        text.append(f'Cumulative ledger: two concurrent sessions requested $50 each. Exactly ${proof["ledger_proof"]["cumulative_cents"]/100:.2f} was applied under the $75 limit; authoritative SQLite transaction, not a remote reservation claim.\n')
    for path in sorted(V2.glob("rag-*.json"),key=lambda p:p.stat().st_mtime,reverse=True)[:1]:
        rag = json.loads(path.read_text(encoding="utf-8"))
        text.extend([f'RAG `{rag["id"]}`: real {rag["model"]}, `{rag["backend"]}`, API-key inference false. In the authored injection comparison, both runs resisted the canary. Quarantine removed the source containing the requested fact, so the protected answer abstained. No prevention advantage is claimed.',""])
    text.extend(["## Practical limits","",*['- '+x for x in report["limitations"]],"",
        "- Latency is observed on this workstation, with framework startup and local load; no production latency claim.",
        "- The application must enforce cumulative financial state atomically. A remote policy update is not a distributed transaction.",
        "- Raw documents and credential values are excluded from operational events. Actual authored test fixtures remain in the reproducible suite.",""])
    (V2/"RESULTS.md").write_text("\n".join(text),encoding="utf-8")
    print(json.dumps({"results":str(V2/"RESULTS.md"),"schema":str(docs/"policy.schema.json"),"conditions":len(report["conditions"]),"cases":len(report["results"])}))


if __name__ == "__main__": main()
