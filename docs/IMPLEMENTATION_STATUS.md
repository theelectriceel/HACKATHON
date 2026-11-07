# Implementation status

Current authentication: GPT-6 Luna through Codex CLI using existing ChatGPT sign-in. API-key variables are stripped from server/CLI child environments; forced ChatGPT authentication and no API fallback are enforced. New model calls use Codex plan allowance/credits. The older GPT-4 results below are historical API-backed evidence, not Luna runs. The inference protocol now uses schema-guided business-tool intents; it is a separate evaluation condition.

This is the implementation record for the local PROMPTGUARD prototype. The earlier advanced design includes a roadmap; this file identifies the actual boundaries.

| Capability | Implemented scope |
| --- | --- |
| Open-source detector | Pinned Horizon Small ONNX artifact, default 0.5 threshold, overlapping full coverage, explicit error/size/deadline behavior |
| Enforcement API | Context admission with exact-byte receipt; denied/incomplete chunks omitted |
| Source authority | Caller labels never override scanning; authenticated source ACLs are not inferred |
| Business task contract | Server-created demo principal, customer, tool scope, expiry and budget |
| Typed refund checks | Customer, order, eligibility, original payment, integer cents, per-call and total bounds |
| Stateful controls | Verified-current-order precondition, durable spending, atomic test-ledger transaction and idempotency |
| Human approval | Exact action/policy/contract/state binding, expiry and single-use grant; local demo operator token |
| Data preservation | Deterministic unambiguous order/amount candidate from quarantined support prose; no authority grant; independent verification still required |
| Provenance | Conservative source exposure sets and source digests; no exact token influence claim |
| Capability analysis | Declared/observed graph, potential-exposure findings and separate observed test side effects |
| Test planning | Bounded prioritization for the registered support/refund adapter; unknown tools need adapters |
| Policy comparison | Z3 check over the supported abstract refund-policy grammar, with an expansion witness or inclusion result |
| Restriction testing | Fresh actual-model runs with reset ledgers, utility/pending/error outcomes and finite-candidate selection |
| Audit | Signed events and receipts; local HMAC cannot prove complete logging or prevent operator deletion |
| Drift | Profile snapshot mismatch yields retest-required; remote permission changes need connector evidence |
| Basic RAG | Separate app and process; SQLite top-three search; HTTP call to PROMPTGUARD for context protection |
| Evaluation | 948 frozen public detector examples plus a separate completed 12-run actual-model cohort; per-case artifacts retained |
| Demo | Genuine recorded failure, live controls, source/context inspection, assessment and evaluation views; desktop/mobile browser verification |

No real email, payment or production customer service is connected. The local session token is not production identity or tenant isolation. The solver does not prove arbitrary shell commands, dynamic model behavior or remote transactions correct. There is no full CaMeL/Fides planner, distributed budget service, independently anchored audit archive or general multi-agent taint engine. Those remain separate roadmap work.

The first larger model evaluations were interrupted by the provider request allowance. Their partial case files remain separate. A smaller cohort was frozen and completed on another model snapshot. All conditions inside each comparison use the same model; results from different snapshots are not pooled.
