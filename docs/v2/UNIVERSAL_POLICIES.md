# Universal cross-agent policies

Open Dashboard → **Policy Studio · universal policies**. The original three-part RAG interface remains intact.

Tool capabilities, money-field mappings, integration declarations, roles and agent groups are registered by an authenticated administrator through `POST /v1/agents`. Names never determine capabilities. The SDK decorator can declare expected metadata, but cannot register or confirm its own authority; a mismatch stops execution.

```python
@pg.protect(capability="financial_transaction", amount_field="amount", currency_field="currency")
def issue_refund(amount, currency):
    return application_refund(amount, currency)
```

Policy Studio uses GPT-6 Luna through the signed-in Codex CLI, with no provider API-key fallback. It compiles a typed draft against confirmed capability metadata. Review its coverage, test it, and explicitly choose **Approve & activate reviewed draft**. Draft compilation/testing never changes active policy. Ambiguous or unsupported instructions return an error instead of creating an invented rule.

The centralized runtime reads global, group and agent restrictions inside the same SQLite authorization transaction as existing agent-specific policies and pathway state. DENY overrides approval; approval overrides permission. Universal policies add restrictions and never grant a permission absent from the agent policy. No permissive lower-level exception can override a global denial.

Money limits are **per transaction**, in integer minor units for the explicitly selected currency. No exchange-rate conversion is provided. A mismatched currency or missing financial mapping fails closed. Currency precision is validated. Cumulative financial controls remain the authoritative application's responsibility.

Approval uses existing server-side expiring, one-use grants bound to principal, session, exact arguments and active policy versions. An agent-provided `manager_approved` Boolean has no authority. In this prototype the authenticated policy administrator acts as the manager; there is no separate enterprise manager identity-provider integration.

Coverage lists agent-qualified tool IDs, schemas, explicit capabilities, mappings, integration declarations, observed calls, unknown classifications, and recent actual decisions. An integration declaration is not proof that every possible code path is wrapped. Unregistered agents and direct unwrapped function calls are outside the enforcement boundary.

## Reproduce the real three-process demo

```powershell
.\start-v2.ps1
# Another terminal:
.\.venv\Scripts\python.exe -m scripts.demo_universal
.\.venv\Scripts\python.exe -m pytest tests -q
node scripts/browser_universal.cjs
```

The script registers Support (`issue_refund`), Finance (`send_payment`) and Sales (`apply_discount`), then launches three independent long-running worker processes. Only the first two explicitly map to `financial_transaction`; Sales maps to `discount_adjustment`.

Before activation, the €150 refund and €250 payment execute. One natural-language €100 global policy is compiled and activated. Both operations then return REQUIRE_APPROVAL without changing independent side-effect counters; a €50 refund and Sales discount still execute. A natural-language update to €300 is tested and activated. Both previously restricted transactions execute in the same worker processes, with no source changes or restarts. No real funds are transferred.

Evidence is saved to `artifacts/v2/universal-demo.json`; the browser screenshot is `universal-policy-studio.png`. The browser test creates and tests an additional €200 draft but deliberately leaves the active €300 policy unchanged.

The reusable demo policy has ID `universal-demo-financial-limit`. Rerunning the demo first disables only that fixture policy through the normal reviewed publication APIs; it does not disable other policies. Additional operator restrictions may legitimately prevent a demonstration action.

## API

- `GET /v1/universal/coverage`
- `POST /v1/universal/compile` — natural-language draft; `policy_id` selects a conversational update.
- `POST /v1/universal/drafts` — validated structured draft.
- `POST /v1/universal/drafts/{id}/test` — actual evaluator boundary probes, explicitly distinct from tool execution.
- `POST /v1/universal/drafts/{id}/activate` — administrator approval, tested immutable draft and current-version checks.
- `GET /v1/universal/history/{policy_id}`
- `POST /v1/universal/rollback/{policy_id}/{version}` — prepares a new draft for review, not immediate rollback.

Only SDK metadata lookup accepts an agent token. Policy administration requires the separate administrator credential. Existing authorization events include matched universal policy IDs, versions, scope and effect. NeMo/Horizon content checks remain separate and cannot override an authorization denial.
