from promptguard.common import local_key
from promptguard.detector import Guard
from promptguard.store import Store
from demo_apps.support_agent import run_agent

if __name__ == "__main__":
    guard, store = Guard(), Store(key=local_key())
    for scenario in ("clean", "cross_customer", "split_budget", "destination"):
        for mode in ("unprotected", "protected"):
            result = run_agent(store, guard, scenario, mode)
            print({"scenario": scenario, "mode": mode, "status": result["status"], "unauthorized": result["unauthorized_execution"], "task_success": result["task_success"], "answer": result["answer"], "run_id": result["run_id"]}, flush=True)
