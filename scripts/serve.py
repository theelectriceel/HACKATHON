"""Start the protection service and independent RAG/demo app together."""
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    processes, handles = [], []
    try:
        for module, port, name in [("promptguard.api:app", 8765, "protection"), ("demo_apps.app:app", 8766, "demo")]:
            server_env = os.environ.copy()
            # Force the requested CLI model and remove inherited API credentials.
            from promptguard.codex_client import child_environment
            server_env = child_environment()
            server_env["PROMPTGUARD_MODEL"] = "gpt-6-luna"
            log = (ROOT / "artifacts" / f"server-{name}.log").open("a", encoding="utf-8")
            handles.append(log)
            processes.append(subprocess.Popen([sys.executable, "-m", "uvicorn", module, "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"], cwd=ROOT, stdout=log, stderr=log,
                                              env=server_env, creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0))
        print("PROMPTGUARD: http://127.0.0.1:8765/docs", flush=True)
        print("Demo and independent RAG app: http://127.0.0.1:8766", flush=True)
        print("GPT-6 Luna via Codex CLI / ChatGPT sign-in. No API-key fallback. Uses Codex plan allowance or credits.", flush=True)
        print("Press Ctrl+C to stop both services.", flush=True)
        while all(p.poll() is None for p in processes):
            time.sleep(1)
        raise RuntimeError("A service stopped. Inspect artifacts/server-*.log.")
    except KeyboardInterrupt:
        pass
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for process in processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        for handle in handles:
            handle.close()


if __name__ == "__main__":
    main()
