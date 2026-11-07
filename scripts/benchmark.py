"""Frozen public detector diagnostics and paired actual-model application evaluation.

python -m scripts.benchmark --detector-only
python -m scripts.benchmark --agent --repeats 2
No threshold/policy optimization occurs in this runner. Every selected case is retained.
"""
from __future__ import annotations

import argparse
import importlib.metadata
import json
import math
import os
import platform
import random
import statistics
import time
import uuid
from collections import defaultdict
from pathlib import Path

from demo_apps.scenarios import SCENARIOS
from demo_apps.support_agent import SYSTEM, run_agent
from promptguard.common import ARTIFACTS, ROOT, canonical, digest, local_key, utcnow
from promptguard.detector import Guard
from promptguard.model_client import MODEL, BACKEND
from promptguard.policies import POLICIES
from promptguard.store import Store


def ratio(a,b):
    return a/b if b else None


def percentile(values, fraction):
    return sorted(values)[max(0, min(len(values)-1, math.ceil(len(values)*fraction)-1))] if values else None


def detector_track(guard, run_id):
    path = ROOT / "data" / "detector_test.jsonl"
    examples = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    groups = defaultdict(list)
    rows = []
    destination = ARTIFACTS / f"detector-cases-{run_id}.jsonl"
    with destination.open("w", encoding="utf-8") as out:
        for i, example in enumerate(examples):
            result = guard.scan(example["text"])
            row = {"id": example["id"], "dataset": example["dataset"], "group_id": example["group_id"], "label": example["label"],
                   "input_digest": digest(example["text"]), "prediction": int(result["action"]=="QUARANTINE") if result["complete"] else None, **result}
            out.write(canonical(row)+"\n")
            groups[example["dataset"]].append(row)
            if (i+1)%100==0:
                out.flush()
                print(f"Detector {i+1}/{len(examples)}", flush=True)
    tracks=[]
    for dataset, cases in groups.items():
        valid=[r for r in cases if r["prediction"] is not None]
        tp=sum(r["label"]==1 and r["prediction"]==1 for r in valid)
        fp=sum(r["label"]==0 and r["prediction"]==1 for r in valid)
        tn=sum(r["label"]==0 and r["prediction"]==0 for r in valid)
        fn=sum(r["label"]==1 and r["prediction"]==0 for r in valid)
        tracks.append({"dataset":dataset,"n":len(cases),"valid":len(valid),"errors":len(cases)-len(valid),"tp":tp,"fp":fp,"tn":tn,"fn":fn,
                       "recall":ratio(tp,tp+fn),"precision":ratio(tp,tp+fp),"false_positive_rate":ratio(fp,fp+tn),
                       "latency_p50_ms":percentile([r["latency_ms"] for r in valid],.5),"latency_p95_ms":percentile([r["latency_ms"] for r in valid],.95)})
    return {"tracks":tracks,"source_sha256":digest(path.read_text(encoding="utf-8")),"case_results":str(destination.relative_to(ROOT)),"threshold":guard.config.threshold,"selection":"All frozen detector_test.jsonl examples; no score-based exclusion or threshold fitting."}


def agent_track(guard, store, run_id, repeats, selected_scenarios):
    conditions=[("unprotected","recommended"),("scanner","recommended"),("protected","recommended"),("protected","approval")]
    plan=[(r,scenario,mode,policy) for r in range(repeats) for scenario in selected_scenarios for mode,policy in conditions]
    random.Random(20261107).shuffle(plan)
    source_digests={name:digest((ROOT/name).read_text(encoding="utf-8")) for name in ("demo_apps/support_agent.py","demo_apps/scenarios.py","promptguard/enforcement.py","promptguard/projection.py","promptguard/policies.py","promptguard/codex_client.py")}
    manifest={"created_at":utcnow(),"source_digests":source_digests,"model":MODEL,"system_digest":digest(SYSTEM),"scenario_digest":digest(SCENARIOS),"policies":{k:p.public() for k,p in POLICIES.items()},"repeats":repeats,"seed":20261107,"plan":plan,
              "disclosure":"Small authored workflow feasibility study. Scenarios were visible during development; this is not an unseen attack-family generalization claim. No policy is selected using these results."}
    (ARTIFACTS / f"agent-plan-{run_id}.json").write_text(json.dumps(manifest,indent=2),encoding="utf-8")
    rows=[]
    destination=ARTIFACTS / f"agent-cases-{run_id}.jsonl"
    with destination.open("w",encoding="utf-8") as out:
        for i,(repeat,scenario,mode,policy) in enumerate(plan):
            result=run_agent(store,guard,scenario,mode,policy)
            row={**result,"repeat":repeat,"condition":policy if mode=="protected" else mode}
            rows.append(row)
            out.write(canonical(row)+"\n");out.flush()
            print(f"Agent {i+1}/{len(plan)} {scenario}/{row['condition']}: status={result['status']} unauthorized={result['unauthorized_execution']} task={result['task_success']}",flush=True)
    groups=defaultdict(list)
    for row in rows:groups[row["condition"]].append(row)
    summaries=[]
    for condition,cases in groups.items():
        valid=[r for r in cases if r["status"]=="completed"]
        attacks=[r for r in valid if SCENARIOS[r["scenario"]]["attack"]]
        clean=[r for r in valid if not SCENARIOS[r["scenario"]]["attack"]]
        summaries.append({"condition":condition,"n":len(cases),"errors":len(cases)-len(valid),"valid_attacks":len(attacks),"attack_successes":sum(r["unauthorized_execution"] for r in attacks),
                          "valid_clean":len(clean),"clean_successes":sum(r["task_success"] is True for r in clean),"attacked_task_successes":sum(r["task_success"] is True for r in attacks),
                          "approval_pending":sum(r["approval_pending"] for r in valid),"latency_p50_ms":percentile([r["latency_ms"] for r in valid],.5),"latency_p95_ms":percentile([r["latency_ms"] for r in valid],.95)})
    original={(r["repeat"],r["scenario"]):r for r in rows if r["condition"]=="unprotected" and r["status"]=="completed" and r["unauthorized_execution"]}
    residual={}
    for condition in ("scanner","recommended","approval"):
        paired=[r for r in rows if r["condition"]==condition and (r["repeat"],r["scenario"]) in original and r["status"]=="completed"]
        residual[condition]={"valid_pairs_originally_successful":len(paired),"residual_successes":sum(r["unauthorized_execution"] for r in paired)}
    return {"conditions":summaries,"conditional_residual":residual,"cases":str(destination.relative_to(ROOT)),"plan":str((ARTIFACTS/f'agent-plan-{run_id}.json').relative_to(ROOT)),"tokens":sum(c.get("usage",{}).get("total_tokens",0) for r in rows for c in r["model_calls"]),"groups":len(selected_scenarios),"selected_scenarios":selected_scenarios,"repeats":repeats,"errors_included":True}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--detector-only",action="store_true")
    parser.add_argument("--agent",action="store_true")
    parser.add_argument("--repeats",type=int,default=2,choices=range(1,4))
    parser.add_argument("--scenarios",default=",".join(SCENARIOS),help="Comma-separated scenario IDs, frozen before running")
    args=parser.parse_args()
    run_id=utcnow()[:10]+"-"+uuid.uuid4().hex[:8]
    guard=Guard();store=Store(key=local_key())
    path=ARTIFACTS/"benchmark.json"
    report=json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    report.update(run_id=run_id,created_at=utcnow(),status="running",model=MODEL,model_backend=BACKEND,hardware={"platform":platform.platform(),"logical_cpus":os.cpu_count()},detector_identity=guard.identity,
                  versions={p:importlib.metadata.version(p) for p in ("onnxruntime","tokenizers","fastapi","httpx")},
                  limitations=["Public model training/evaluation overlap cannot be excluded; public results are diagnostics.","NotInject contains benign prompts, not production business documents.","Support scenarios and orders are authored fixtures; no real refunds or production activity.","Repeated scenarios are dependent; this small study is not a production risk estimate.","Errors are reported separately and excluded from valid-outcome denominators, never counted as protection.","The original and protected model prompt, model snapshot, operator task and initial ledger are identical.","Local inference latency includes current machine load; no production SLA claim."])
    path.write_text(json.dumps(report,indent=2),encoding="utf-8")
    try:
        if args.detector_only or not args.agent:
            report["detector"]=detector_track(guard,run_id)
        if args.agent:
            selected=args.scenarios.split(",")
            if not selected or any(s not in SCENARIOS for s in selected):
                raise ValueError("Unknown scenario selection")
            report["agent"]=agent_track(guard,store,run_id,args.repeats,selected)
        report.update(status="complete",finished_at=utcnow(),summary="Measured detector diagnostics and separate isolated agent outcomes. Inspect counts, false positives and task utility together.")
    except BaseException:
        report["status"]="interrupted"
        raise
    finally:
        path.write_text(json.dumps(report,indent=2),encoding="utf-8")
    print(f"Saved {path}",flush=True)


if __name__=="__main__":main()
