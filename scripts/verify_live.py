"""Read-only HTTP health checks and optional isolated demo test requests."""
import argparse
import json
import httpx

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--rag", action="store_true")
    args = parser.parse_args()
    token = httpx.get("http://127.0.0.1:8765/api/bootstrap").json()["session_token"]
    if args.rag:
        result = httpx.post("http://127.0.0.1:8766/api/rag/compare", headers={"X-Session-Token": token}, json={"question": "What was Apple's reported revenue in fiscal year 2025?", "scenario": "override"}, timeout=10)
        print(result.text)
    else:
        print({"protection": httpx.get("http://127.0.0.1:8765/api/status").status_code, "demo": httpx.get("http://127.0.0.1:8766").status_code,
               "documents": len(httpx.get("http://127.0.0.1:8766/api/rag/catalog").json()["documents"])})
