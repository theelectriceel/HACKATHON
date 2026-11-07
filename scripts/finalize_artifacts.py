"""Export genuine recorded demonstration and the local dependency inventory."""
import importlib.metadata
import json
import math

from promptguard.common import ARTIFACTS, ROOT, digest, utcnow


def main():
    source=ARTIFACTS/"job-77ee1e2474924a5598e45c6074695938.json"
    if source.exists():
        job=json.loads(source.read_text(encoding="utf-8"))
        result=job["result"]
        result.update(execution="saved_run", recorded_at=job.get("finished_at"), source_job=job["id"],
                      disclosure="Selected genuine recorded demonstration using GPT-4o-mini; not a random sample or the separate GPT-4.1-mini benchmark. Recorded before the bounded projection adapter was added. All three original executions are retained unchanged.")
        (ARTIFACTS/"recorded-demo.json").write_text(json.dumps(result,indent=2),encoding="utf-8")
    inventory=sorted(str(dist.metadata["Name"])+"=="+dist.version for dist in importlib.metadata.distributions())
    (ROOT/"requirements.lock.txt").write_text("\n".join(inventory)+"\n",encoding="utf-8")
    benchmark_path=ARTIFACTS/"benchmark.json"
    if benchmark_path.exists():
        benchmark=json.loads(benchmark_path.read_text(encoding="utf-8"))
        def quantile(values, fraction):
            return sorted(values)[max(0,min(len(values)-1,math.ceil(len(values)*fraction)-1))] if values else None
        detector_cases=ROOT/benchmark.get("detector",{}).get("case_results","missing")
        if detector_cases.is_file():
            rows=[json.loads(line) for line in detector_cases.read_text(encoding="utf-8").splitlines()]
            for track in benchmark["detector"]["tracks"]:
                values=[r["latency_ms"] for r in rows if r["dataset"]==track["dataset"] and r["complete"]]
                track.update(latency_p50_ms=quantile(values,.5),latency_p95_ms=quantile(values,.95))
        agent_cases=ROOT/benchmark.get("agent",{}).get("cases","missing")
        if agent_cases.is_file():
            rows=[json.loads(line) for line in agent_cases.read_text(encoding="utf-8").splitlines()]
            for condition in benchmark["agent"]["conditions"]:
                values=[r["latency_ms"] for r in rows if r["condition"]==condition["condition"] and r["status"]=="completed"]
                condition.update(latency_p50_ms=quantile(values,.5),latency_p95_ms=quantile(values,.95))
        benchmark["latency_quantile_method"]="Nearest rank: sorted values[ceil(n*p)-1]. Summaries computed from immutable per-case timings; no inference rerun."
        if benchmark.get("agent") and benchmark.get("model")=="gpt-4.1-mini-2025-04-14":
            benchmark["interpretation"]=["The completed 12-run GPT-4.1-mini cohort observed no unauthorized execution in any condition, including unprotected. It does not establish newly prevented attacks.",
                                         "PROMPTGUARD completed both clean tasks (2/2); the scanner-only condition completed one (1/2). This single hard-benign preservation result is descriptive, not a statistically established production advantage.",
                                         "The separately recorded GPT-4o-mini demonstration observed a wrong-customer refund in original and scanner-only conditions and none in the protected condition. It is qualitative evidence and is not pooled with the GPT-4.1-mini cohort."]
            benchmark_path.write_text(json.dumps(benchmark,indent=2),encoding="utf-8")
    (ARTIFACTS/"implementation-manifest.json").write_text(json.dumps({"created_at":utcnow(),"files":{str(p.relative_to(ROOT)).replace('\\','/'):digest(p.read_text(encoding='utf-8')) for directory in ("promptguard","demo_apps","web","tests") for p in (ROOT/directory).rglob('*') if p.is_file() and p.suffix in ('.py','.js','.css','.html')}},indent=2),encoding="utf-8")
    print("Exported genuine recorded demo, dependency inventory and implementation digests.")


if __name__=="__main__":main()
