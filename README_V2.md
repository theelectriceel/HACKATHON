# PROMPTGUARD — three-part demo

Start with `./start-v2.ps1`. Open **http://127.0.0.1:8775**. Your local sign-in is also available by opening `artifacts/v2/open-control.html`.

The interface has exactly three parts:

1. **RAG without PROMPTGUARD** — ask a question over existing SEC documents. Retrieved content reaches the answering workflow without PROMPTGUARD authorization or inspection. Tool calls are observed for comparison.
2. **RAG with PROMPTGUARD** — the same RAG, documents, question, model and tools, with local Horizon/NeMo content inspection and dashboard-configured sequence restrictions.
3. **Dashboard** — actual tool-call logs from both modes, usage counts, outcomes, durations, recent pathways, and a drag-and-drop interface to block or unblock sequences.

The question and document scenario stay the same when switching between the two RAG modes. Each mode runs independently and has its own answer and tool trace.

## Show sequence enforcement

Run either RAG mode once. In **Dashboard**, drag or click tools to build:

`Search documents → Read a document → Generate answer`

Click **Block this sequence**, then run **RAG with PROMPTGUARD** again. The last tool is denied before the answering model is called. Its blocked call appears in both the run trace and dashboard. The unprotected RAG continues without enforcement. Choose **Unblock sequence** to restore the protected workflow.

This example intentionally blocks a legitimate workflow to demonstrate operator control. It is not presented as a model compromise. Sequence matching uses earlier completed calls in order within the same run; other calls, such as reading more documents, may occur between those steps.

## Show content inspection

Choose **Add a test injection** in either RAG mode. The protected run checks documents through real NeMo flows using the existing local Horizon weights and withholds flagged content. The baseline model may resist the attack itself. The UI shows the actual responses; it does not invent a successful attack. Withholding a document can also remove a useful fact.

## Runtime

- Answering model: **GPT-6 Luna through the signed-in Codex CLI**, using Codex allowance or credits. No provider API-key fallback.
- Detector: existing, pinned local Horizon ONNX weights. No duplicate download or model training.
- Application: Python, FastAPI, SQLite full-text search and SQLite activity logs, plain HTML/CSS/JavaScript.
- PROMPTGUARD and the independent RAG application remain separate backend processes. The demo presents them through one three-part interface.
- Baseline activity is labeled `NOT_ENFORCED`; logging does not authorize its calls. Protected calls use the actual policy service and SDK. Questions are redacted from operational logs.

If dependencies are missing, run `./setup-v2.ps1` first. V1 remains on its original ports.

## Verify

```powershell
.\.venv\Scripts\python.exe -m pytest tests -q
node scripts/browser_v2.cjs
```

The browser check executes both RAG modes through the real CLI, drags a sequence into the dashboard, verifies the protected generation function never runs, and restores prior operator rules. Screenshots and the result are saved in `artifacts/v2/part-*.png` and `three-part-verification.json`.

The broader backend implementation notes are retained in `docs/v2/ENGINEERING.md`; those extra demonstrations are outside the main interface.
