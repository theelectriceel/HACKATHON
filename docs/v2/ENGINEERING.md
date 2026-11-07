# PROMPTGUARD V2

**Control the action. Keep the evidence.**

V2 is a separate working variant: Python SDK, real FastMCP middleware, remotely published policies, stateful tool pathways, NeMo/Horizon content rails, and persisted execution analytics. V1 remains available on its original ports and databases.

## Open the running system

- Control console: http://127.0.0.1:8775
- Local operator sign-in: open `artifacts/v2/open-control.html` in your browser. The file contains a local service credential; keep it private. Alternatively paste `admin_token` from `artifacts/v2/credentials.json` into the console.
- Choose **Run live protection proof**, **Run five-way comparison**, or **Open RAG test app**.
- Separate RAG application: http://127.0.0.1:8776 — open it through the console to pass its separate agent credential.
- API reference: http://127.0.0.1:8775/docs

The console is not anonymously administrative. Agent tokens cannot publish policies or read other agents' activity. These are PROMPTGUARD authentication credentials, **not OpenAI API keys**.

## Start or reproduce

```powershell
.\setup-v2.ps1                 # only if dependencies need installing
codex login                    # choose ChatGPT sign-in
.\start-v2.ps1

# In another terminal, from this repository:
.\.venv\Scripts\python.exe -m scripts.demo_v2
.\.venv\Scripts\python.exe -m promptguard_v2.evaluation
.\.venv\Scripts\python.exe -m pytest tests -q
node scripts/browser_v2.cjs
.\.venv\Scripts\python.exe -m scripts.report_v2
```

Horizon already exists in `models/guard/`; its pinned ONNX artifacts are reused and checked for integrity. No duplicate model or training. The RAG answer model is **GPT-6 Luna via the official Codex CLI and ChatGPT sign-in**. The subprocess strips provider API-key variables, forces ChatGPT authentication, disables native CLI tools, and has no API fallback. It uses your Codex plan allowance or credits. NeMo has `models: []`, invokes a registered local Horizon action, and makes zero generative model calls.

## Stack and boundaries

Python 3.12, FastAPI 0.121, Pydantic, SQLite WAL, HTTPX, FastMCP 2.14.7 / MCP 1.30.0, NeMo Guardrails 0.24.1, ONNX Runtime CPU, and plain HTML/CSS/JavaScript. Exact packages are frozen in `requirements-v2.lock.txt`. Compatible framework versions preserve the original application.

`promptguard_v2/` is the product. `demo_apps_v2/` is a separate test application. Its RAG uses SQLite full-text search over retained real SEC records. It is not a retrieval feature inside PROMPTGUARD. `web_v2/` is a small control interface. V2 state lives under `artifacts/v2/`.

## SDK integration

An administrator registers an agent, its tool schemas and trusted tenant/customer attributes through `POST /v1/agents`, returning an agent token once. The service stores its hash. Register authoritative resource attributes through `PUT /v1/resources` and publish a validated policy through `PUT /v1/policies/{id}`. Examples are in `promptguard_v2/examples.py` and exported to `docs/v2/`.

```python
from promptguard import PromptGuard

pg = PromptGuard(
    api_key=AGENT_TOKEN,
    endpoint="http://127.0.0.1:8775",
    agent_id="support-agent",
)

@pg.protect()
def issue_refund(customer_id: str, amount_cents: int):
    return your_application_refund(customer_id, amount_cents)

# Async functions work too. A trusted application establishes business sessions:
with pg.session(session_id=trusted_session_id):
    issue_refund("cust-alex", 5000)

# Server-wide FastMCP interception, without decorating individual tools:
pg.wrap(mcp)
```

`api_key` above authenticates to PROMPTGUARD only. Inference continues through Codex CLI. A service identity is bound to one agent/principal; per-user deployments should register separate identities or implement a trusted identity bridge. Caller-supplied tool arguments cannot assert a tenant or principal.

FastMCP wrapping protects tool calls routed through its documented `on_call_tool` middleware, including tools registered later. Calling the original Python function directly bypasses MCP; decorate such functions too. An existing non-FastMCP MCP server is rejected rather than silently claimed protected. A trusted `session_resolver(context)` can map transport sessions to application sessions. Do not derive it from model-controlled tool arguments.

## Policy semantics

- The default is deny. Registered tools also need an applicable permission.
- All conditions within one rule are ANDed. Matching rules combine by `DENY > REQUIRE_APPROVAL > ALLOW`; identity/schema/guardrail failures always deny.
- Comparisons are typed; money uses integer cents and numeric conditions declare units. There is no `eval` or arbitrary expression language.
- Resource identity bindings use administrator-registered metadata, not text in a ticket or document.
- Pathways match ordered subsequences of prior attempted calls or successful completed calls. A matched prefix remains relevant for that session; unrelated tools do not erase it. Rules can bind the same registered resource or the whole session.
- Policy publication atomically increments the version, switches the active pointer, records an audit entry, and rebuilds finite pathway state from prior events. Hot authorization reads materialized state instead of replaying entire histories.
- One unresolved authorized call per agent/session prevents overlapping calls from racing successful-call rules. An unreported call leaves that session closed; reconcile the application before starting a replacement session.
- Approval is exact-action, principal/session/arguments/policy bound, expires after 120 seconds, is consumed once, and never overrides a hard denial. `ApprovalRequired` means the original function did not execute. An administrator grants through `POST /v1/approvals/{execution_id}`; retry within the same `pg.session(..., approval_id=grant)`.
- Signed Ed25519 policy snapshots support bounded diagnostic caching with a pinned public key. Authorization decisions are always online, even when a policy snapshot is cached. This preserves immediate next-call revocation and fail-closed behavior.

## Actual demonstrations and evidence

**Remote revocation:** the same unchanged FastMCP server and client session first executes an export. An authenticated HTTP policy update then disables it. The repeated call is denied and an independent invocation counter stays unchanged. The script restores the allowed demonstration policy afterward.

**Forbidden pathway:** lookup → export → external email is denied before the outbox function runs; an approved destination succeeds. A single export also restricts later external sending, so omitting lookup does not bypass this example policy.

**NeMo + Horizon:** the actual Colang input flow runs a registered custom action against the existing local model. The proof saves its score, model revision, action execution count, rail status, and detector versus framework overhead. The same adapter supports output checks. Generic tool authorization stays in PROMPTGUARD; these are configured content rails, not a claim that NeMo's `check_async` intercepts arbitrary MCP tools.

**Cumulative refunds:** two concurrent $50 requests in different sessions reach the existing isolated refund ledger. Exactly one is applied. The other fails the cumulative-budget check, and the ledger totals $50 under its $75 cap. `demo_apps_v2/refund_adapter.py` applies the signed policy's `refund_cumulative_limit_cents` inside the authoritative application's atomic check/write. The task's frozen budget still caps authority. Generic remote middleware does not make external payments transactional.

**RAG:** one actual GPT-6 Luna CLI comparison is saved. Both runs resisted the authored canary attack. The protected run withheld the poisoned source and consequently lacked the required 2023 fact. This is a measured availability cost; no attack-prevention improvement is claimed from that example. The original source records, frozen retrieved set, decisions, and actual CLI responses are retained.

Evidence: `artifacts/v2/live-demo.json`, `ledger-proof.json`, `latest-evaluation.json`, `evaluations/{id}/report.json`, `rag-{id}.json`, and `RESULTS.md`. The control console shows persisted observations and links session traces. Recommendations distinguish configured violations from proof of malicious intent.

## Evaluation interpretation

The frozen suite has 14 authored cases × 5 conditions: unprotected, conventional static per-tool permissions, PROMPTGUARD argument/resource authorization, added pathway enforcement, and added NeMo/Horizon. Five cases request explicitly prohibited business actions, eight are legitimate workflows, and one separately measures delivery of injected content. No model judge or random attack selection. Independent side-effect counters verify whether functions ran.

In the verified suite, prohibited executions are 5/5, 4/5, 2/5, 0/5, and 0/5 respectively. Pathway enforcement completes all 8 legitimate tasks. Adding Horizon blocks the injected document but also one benign security quotation, reducing legitimate completion to 7/8. These are small regression results, not estimates of real-world protection rates. Full precision, recall, false-positive/negative rates, trace completeness and measured latency remain in the report. Baseline traces have no PROMPTGUARD authorization latency; they are shown as unavailable, not zero.

## Limits

This is a working local prototype, not a multi-tenant hosted service. No production identity-provider integration, network TLS deployment, tamper-proof external audit sink, background-task authorization protocol, cross-service transaction coordinator, or semantic intent inference. Session rules do not automatically correlate across new sessions. Trusted application reports can be wrong; demos independently verify counters and the refund ledger. Calls already authorized at publication are not retroactively canceled. Policy snapshot retrieval and an external application's transaction are not atomic with one another. Detector decisions can miss attacks or block benign content; whole-document quarantine can remove useful evidence.

## Official integration references

- [FastMCP middleware](https://gofastmcp.com/docs/servers/middleware): supported tool interception hooks and middleware boundaries.
- [NeMo check API](https://docs.nvidia.com/nemo/guardrails/v0.24.1/run-guardrailed-inference/using-python-apis/check-messages): input/output validation without generation; this API does not itself run tool rails.
- [NeMo custom actions and core classes](https://docs.nvidia.com/nemo/guardrails/run-guardrailed-inference/using-python-apis/core-classes): explicit action registration.
- [NeMo Guardrails paper](https://arxiv.org/abs/2310.10501): programmable rails. PROMPTGUARD's contribution here is the integrated authorization, trusted resource context, materialized pathways and auditable remote policy workflow; it is not a new classifier or a claim of novel guardrail theory.
