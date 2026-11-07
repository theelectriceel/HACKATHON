# PROMPTGUARD

**New: [PROMPTGUARD V2](README_V2.md)** is a separate variant with remote tool policies, Python/MCP interception, stateful pathways, real NeMo/Horizon integration, and its own control console. Start it with `start-v2.ps1`; V1 remains available below.

Agent Risk Intelligence: inspect capabilities, enforce business authorization, compare restrictions, and retain evidence of what happened.

This is a functioning local research prototype. Financial tools operate only on an isolated test ledger. The basic RAG assistant is a **separate test application**, not a PROMPTGUARD feature.

## Run

The local environment and detector are already installed in this workspace.

```powershell
codex login status   # Must say: Logged in using ChatGPT
# If needed, run codex login and choose ChatGPT sign-in.
.\start.ps1
```

Open [the demo workbench](http://127.0.0.1:8766). The independent [PROMPTGUARD API](http://127.0.0.1:8765/docs) runs on port 8765. Stop both using Ctrl+C in the launching terminal.

For a fresh installation, run `setup.ps1`. It creates a local environment and downloads the pinned model artifacts (about 303 MB total). Python 3.12 is recommended. Optional public-data reacquisition uses `pyarrow==23.0.1` and `python -m scripts.fetch_data`; the acquired data and hashes are retained already.

Live inference now uses **GPT-6 Luna through Codex CLI and existing ChatGPT sign-in**. The CLI is forced to `chatgpt` authentication. API-key variables are removed from server and CLI child environments; there is no API-key or direct-HTTP inference fallback. Live calls consume the signed-in Codex/ChatGPT allowance or credits.

The earlier GPT-4o-mini/GPT-4.1 runs and completed GPT-4.1-mini evaluation used an API key inherited from the environment. Those historical results are retained unchanged and are not Luna results. The key's owner and final billing were not established. They are not pooled with new CLI results.

The CLI returns schema-guided business-tool requests to our application executor. It does not execute those business tools itself. Native shell, app/connector, browser, collaboration and plugin features are disabled; execution is read-only. This inference protocol differs from the historical native API tool-calling cohort, so new evaluations must identify the backend.

Codex plan usage limits can stop live calls. The interface explicitly distinguishes errors, live runs and saved genuine outputs. Saved results never masquerade as new inference. The recorded demo remains inspectable without new inference.

## Tech stack

| Component | Choice |
| --- | --- |
| Services | Python + FastAPI + Uvicorn |
| Detector | Pinned Horizon Guard Small, ONNX Runtime on CPU |
| Answering agent | GPT-6 Luna via ChatGPT-authenticated Codex CLI; schema-guided business-tool intents |
| State and audit | SQLite transactions and signed event metadata |
| Policy | Typed Python predicates and a small state machine |
| Policy comparison | Z3 SMT over the supported abstract policy grammar |
| RAG test target | Independent Python app, SQLite full-text search, top three documents |
| Interface | HTML, CSS and plain JavaScript |
| Verification | Pytest, actual-model runs, independent ledger verifier, browser checks |

No vector database, model training or heavyweight agent framework is required.

## What works

- Scan external chunks with complete overlapping token coverage and explicit limits; incomplete/error scans contribute no context.
- Prepare a context and return a byte-bound signed receipt through an application-independent HTTP API.
- Freeze an operator task and enforce scope, customer, order eligibility, original payment method, integer amount, sequence and cumulative budget.
- Keep spending limits durable across restarts and atomic across concurrent calls.
- Bind approvals to the exact action, policy, contract and order state; reject changed, stale and reused approvals.
- Preserve a bounded, unambiguous order/amount candidate from quarantined support prose without promoting that prose into instructions. Candidate fields never grant authority and still pass independent checks.
- Assess imported configurations with declared/observed evidence labels; graph reachability remains a hypothesis.
- Prioritize a bounded set of supported tests, compare restrictions with fresh agent runs, and report utility alongside security.
- Detect profile snapshot changes and require retesting.
- Prove inclusion or produce an expansion witness for the supported abstract refund-policy grammar using Z3.
- Run the separate document assistant with and without the same context firewall.

## Demonstrations

**Support agent:** choose Wrong customer, then run the comparison or load genuine saved runs. Inspect each model's calls and the test ledger. The detector can miss an instruction that looks like an ordinary handling note; customer binding still prevents an unauthorized action. A secure refusal can also fail the legitimate task, which is shown separately.

**RAG test application:** ask about Apple's fiscal 2025 revenue. Select injected instructions. The app freezes the retrieved set, sends it directly to the model in the unprotected condition, and calls PROMPTGUARD over HTTP in the protected condition. Inspect the exact contexts and exclusions. The model may resist an attack on its own; this is shown honestly.

**Assessment:** inspect potential exposure separately from observed test outcomes. Run the restriction comparison to evaluate customer binding, exact-action approval and disabling refunds on the selected attack and a clean case. A recommendation covers only the candidates actually tested.

## Data and attribution

- Six real SEC companyfacts responses, 36 source-resolved annual facts, and exact source hashes/JSON pointers are retained. The RAG app indexes narrative and structured views of each fact; these are correlated representations of the same record, not independent corroboration.
- The detector diagnostic file contains 948 deduplicated publisher-labelled examples: NotInject, deepset/prompt-injections test, and IndirectRAG. Source revisions, transforms and rights caveats are in `data/manifest.json`. Public guard training/evaluation overlap cannot be ruled out.
- Support tickets, orders and attack variants are authored test fixtures, not production business activity.
- An existing Agent Guard example policy is imported as assessment data, with source digest and retained Apache-2.0 license. Its default-allow observation applies to that example configuration. Agent Guard inspired dispatch/audit patterns; its implementation was not renamed or copied as PROMPTGUARD code.
- No confidential production customer logs were supplied. The prototype does not claim a production incident or monetary loss prevented.

## Reproduce verification

```powershell
.\.venv\Scripts\python.exe -m pytest tests -q
.\.venv\Scripts\python.exe -m scripts.benchmark --detector-only
.\.venv\Scripts\python.exe -m scripts.benchmark --agent --repeats 1 --scenarios clean,cross_customer,security_quote
```

The third command now uses real Codex plan allowance/credits with Luna. All runs reset their test ledger. Its plan, model/prompt/code digests, random order and every output are retained. The bounded cohort uses scenarios known during development; it is a feasibility study, not an unseen-family generalization claim. The retained older benchmark describes its original API-backed model; rerunning creates a new backend-specific cohort.

The complete report is `artifacts/benchmark.json`. Per-case files and plans are named in that report. Interrupted larger experiments remain distinct from the completed cohort. Unit-test doubles do not count as measured detector or agent robustness.

## Project layout

`promptguard/` contains the protection, authorization, assessment and policy modules. `demo_apps/` contains the independent support agent and RAG target. `web/` is the demo interface. `scripts/` contains launch, acquisition, evaluation and verification commands. `tests/` contains operational and security invariants. `docs/` contains research and the design history.

## Practical boundaries

This is localhost-only with a local demo session token, not production authentication, tenant isolation or a hardened hosted service. Model actions cannot reach real Gmail or payment services. Source labels supplied to the scan API are descriptive, not authenticated permissions. The runtime checks the isolated ledger; it does not prove a remote transaction committed.

Provenance tracking is conservative context exposure, not exact token-level causation. HMAC receipts bind recorded bytes but cannot prevent a local operator deleting the entire stream. Z3 verifies the encoded policy abstraction only. The prototype does not implement a full CaMeL/Fides planner, distributed consensus, arbitrary shell containment or universal attack prevention.

The [advanced design](docs/PROMPTGUARD_ADVANCED_DESIGN.md) contains future work as well as implemented concepts. The current API status and this README describe what is actually available.
#   H A C K A T H O N  
 