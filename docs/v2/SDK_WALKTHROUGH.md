# How the SDK actually works

The SDK is `promptguard_v2/sdk.py`, exported as `from promptguard import PromptGuard`.

```python
pg = PromptGuard(
    api_key=YOUR_PROMPTGUARD_AGENT_TOKEN,
    endpoint="http://127.0.0.1:8775",
    agent_id="rag-agent",
)

@pg.protect(capability="answer_generation")
def generate_answer(document_count: int):
    return call_your_answering_model()
```

The token authenticates the agent to your local PROMPTGUARD service. It is not an OpenAI inference key. This project's answering model still uses the signed-in Codex CLI.

1. `protect()` replaces the function with a wrapper while preserving its signature through `functools.wraps`.
2. The wrapper binds the actual arguments. Optional capability hints must match the administrator-confirmed registry; the decorator cannot give itself permissions.
3. `_authorize()` sends the agent ID, tool name, arguments, session and unique execution ID to `/v1/authorize`, authenticated with the agent token.
4. The service obtains trusted identity and capability metadata from its registry and evaluates agent permissions, universal restrictions, resource constraints and pathway state. An agent's proposed role or `manager_approved` Boolean cannot supply authority.
5. DENY raises `AuthorizationDenied`. REQUIRE_APPROVAL raises `ApprovalRequired`. Neither calls the original function.
6. Only ALLOW executes the original function. `_report()` records completion or failure and duration. Exceptions propagate; unavailable authorization fails closed. Lost outcome reporting raises an explicit executed-but-unconfirmed error instead of retrying a potentially sensitive operation.

In the actual RAG, `demo_apps_v2/rag.py` applies this dynamically:

```python
invoke = self.pg.protect()(execute) if self.pg else execute
result = invoke(**arguments)
```

`execute` preserves the original RAG tool's signature. Part 1 calls it directly; Part 2 authorizes it first. Both report application activity. Questions and retrieved content also undergo separate NeMo/Horizon inspection in the protected mode.

For an existing FastMCP server, `pg.wrap(mcp)` uses its documented `on_call_tool` middleware to authorize before `call_next(context)`. Direct Python calls that bypass MCP need decorators themselves.

## Apple live demonstration

Question: **What was Apple's net income in 2023?** Choose **Original documents**.

1. Run Part 1 and Part 2 before activating the prepared policy. Both can answer from the same SEC records, subject to any other operator restrictions.
2. In Dashboard, review the **Apple RAG live demo** draft. It targets capability `answer_generation` in group `rag-agents`.
3. Click **Test this draft**, then **Approve & activate reviewed draft**.
4. Run Part 2 again: answer generation is denied before Luna is called. The result identifies the universal policy. Part 1 remains unprotected.
5. To restore Part 2, select the active policy in Studio and request: **Disable the Apple RAG live demo policy.** Review, test and activate the new version.

The example uses an Apple question, but the rule blocks **all answer generation in the RAG group**. It is not a semantic Apple-only filter. No claim is made that the Apple prompt itself is malicious.
