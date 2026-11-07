"""V2 launch leaves the existing V1 ports and database untouched."""
import os
import subprocess
import sys
import time
from promptguard.common import ROOT
from promptguard.codex_client import child_environment
from promptguard_v2.storage import Store, V2, credentials
from promptguard_v2.examples import seed


def main():
    auth = credentials()
    seed(Store(), auth["demo_agent_token"])
    from promptguard_v2.rag_policy import seed_rag
    seed_rag(Store(), auth)
    (V2 / "open-control.html").write_text('<!doctype html><meta http-equiv="refresh" content="0;url=http://127.0.0.1:8775/#admin='+auth["admin_token"]+'">', encoding="utf-8")
    processes, handles = [], []
    try:
        for module, port, name in [("promptguard_v2.api:app",8775,"control"),("demo_apps_v2.app:app",8776,"rag")]:
            log = (V2 / f"server-{name}.log").open("a", encoding="utf-8")
            handles.append(log)
            env = child_environment()
            env["DO_NOT_TRACK"] = "1"
            processes.append(subprocess.Popen([sys.executable,"-m","uvicorn",module,"--host","127.0.0.1","--port",str(port),"--log-level","warning"],
                cwd=ROOT, stdout=log, stderr=log, env=env, creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0))
        print("PROMPTGUARD V2: http://127.0.0.1:8775", flush=True)
        print("Open artifacts/v2/open-control.html to sign in locally. Agent and administrator credentials are separate.", flush=True)
        print("Independent RAG test: http://127.0.0.1:8776", flush=True)
        print("Horizon runs locally. RAG inference: GPT-6 Luna through ChatGPT-signed-in Codex CLI, no provider API keys.", flush=True)
        while all(p.poll() is None for p in processes): time.sleep(1)
        raise RuntimeError("A V2 service stopped. Inspect artifacts/v2/server-*.log")
    except KeyboardInterrupt:
        pass
    finally:
        for p in processes:
            if p.poll() is None: p.terminate()
        for p in processes:
            try: p.wait(timeout=5)
            except subprocess.TimeoutExpired: p.kill()
        for log in handles: log.close()


if __name__ == "__main__": main()
