# PROMPTGUARD research decision

Research checked: 7 November 2026. This is a decision record and test plan. Scores below are engineering judgments made before evaluation, not measured results or claims of global novelty.

## Selected contribution

Build a **task-bounded evidence firewall with coverage repair** for financial fact lookup. Freeze the issuer, reporting period, metric and permitted operation before reading retrieved content. Apply an open-source injection detector. Compile accepted information into validated numeric records with source locations. When quarantine leaves required facts missing, retrieve replacement records once from a server-approved corpus. Return an answerability status, a plain-language action and a receipt showing the evidence that actually reached the answering model.

The testable hypothesis is that coverage repair preserves more correct, supported answers under attack than dropping suspicious passages alone, without increasing successful instruction hijacking. It may improve application security even when detector recall is unchanged. A negative result is valid.

## Three candidates ranked

Scores are 1–5, higher is better; all dimensions are equally weighted for this selection. Expected improvement describes an experiment, not a forecast of a numerical gain.

| Rank | Candidate | Differentiation | Measurable improvement | Business impact | Three-hour feasibility | Total |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | Evidence compiler plus bounded recovery after quarantine | 4 | 5 | 5 | 5 | 19 |
| 2 | Task contract plus provenance-aware action authorization | 3 | 5 | 5 | 3 | 16 |
| 3 | Source-event graph for repeated and distributed injection | 3 | 3 | 4 | 3 | 13 |

**1. Evidence compiler and recovery — select.** The underserved failure mode is a defense that stops the attack by removing the only answer-bearing source, leaving the employee unable to complete the task. Combine task alignment, selective information preservation and explicit data/control separation. The distinctive implementation is exact numeric evidence, coverage checking, one permitted recovery round and an auditable context. Test task completion and attack success together, with a compiler-without-recovery ablation. The scope is bounded filing facts; general prose extraction is deliberately outside the claim.

**2. Task contract and provenance-aware action authorization — useful boundary, reject as the main innovation.** Freeze permitted tools, destinations and data flows from authenticated intent, then reject conflicting proposals regardless of detector score. Test unauthorized mock actions and legitimate task completion. This offers high potential security impact but mature research and products already cover much of it. A full interpreter, capability propagation and realistic multi-step agent benchmark would threaten three-hour completion. Implement only the small boundary needed by the chosen workflow.

**3. Source-event graph — defer.** Link document revisions, duplicate families, adjacent chunks and first-seen timestamps; prioritize a source when suspicious instructions recur or propagate across retrieval results. Test distributed-attack recall against a windowed detector, then show which connector or revision to quarantine. This could combine existing operational events into a useful incident decision, but the empty workspace lacks production history. Synthetic timestamps cannot establish temporal effectiveness. Repetition is also common in legitimate templates, creating false-positive risk. Adjacent-window coverage is a sensible baseline feature, not sufficient novelty by itself.

## Published methods and what they change

| Primary source | Established idea | PROMPTGUARD implication |
| --- | --- | --- |
| [Task Shield, ACL 2025](https://aclanthology.org/2025.acl-long.1435/) | Check whether instructions and tool calls advance the user's task. | Freeze a narrow task contract before untrusted data enters. Do not claim to invent task awareness or reproduce the paper's system. |
| [DataFilter, revised February 2026](https://arxiv.org/abs/2510.19207) | A trained, task-conditioned filter removes adversarial instructions while preserving useful data. | Measure utility after filtering. Our numeric parser and replacement search differ from a generative sanitizer; no claim that information-preserving filtering is new. |
| [CaMeL, revised June 2025](https://arxiv.org/abs/2503.18813) | Separate trusted control flow from untrusted data and enforce capabilities at tool boundaries. | Keep source permissions, retrieval destinations and policy outside document control. This prototype is not a CaMeL interpreter and inherits none of its formal guarantees. |
| [Spotlighting, 2024](https://arxiv.org/abs/2403.14720) | Transform untrusted content to provide a continuous provenance signal. | Preserve provenance through context construction, while recognizing that a source label or delimiter is not an authorization boundary. |
| [InjecGuard / NotInject, revised March 2025](https://arxiv.org/abs/2410.22770) | Trigger-word bias causes guard models to overblock benign text. | Include hard benign data and report false positives separately. A security refusal is not automatically a successful business outcome. |
| [Are Firewalls All You Need, revised March 2026](https://arxiv.org/abs/2510.05244) | Tool-input minimization and tool-output sanitization can perform well; weak attacks and flawed success metrics inflate benchmarks. | Neither a firewall nor minimum-context filtering is our novelty. Use held-out cases, inspect failures and distinguish detector labels from application outcomes. |

Published performance numbers belong to the authors' setups and are not PROMPTGUARD results. The rankings above are our inference from these methods and the available time.

## Existing solutions and the narrow gap

| Existing system | What its documentation establishes | What this build must add to be differentiated |
| --- | --- | --- |
| [NVIDIA NeMo Guardrails](https://docs.nvidia.com/nemo/guardrails/latest/about-nemo-guardrails-library/rail-types) | Input, retrieval, execution and output rails; filtering and validating retrieved chunks and tool calls. | An inspectable numeric evidence representation and measured recovery of task coverage after quarantine. An interception API alone is not novel. |
| [Check Point Guard API](https://docs.lakera.ai/docs/api) | Screening of tool responses/descriptions, data leakage, denied tools and actions outside an agent's mandate. | Show the replacement evidence and resulting completed task. Do not claim other products merely scan user prompts or lack action policy. |
| [Promptfoo RAG testing](https://www.promptfoo.dev/docs/red-team/rag/) | Inject adversarial retrieved context and test application behavior, including attribution. | Execute enforcement and evidence repair, then use paired outcomes to substantiate the contribution. A red-team report alone is not the product. |

These pages do not prove that competitors lack all forms of recovery. Global novelty and commercial superiority remain unestablished. The defensible hackathon claim is a specific implemented combination, a clear bounded use case and reproducible evidence of its tradeoff against a credible scanner baseline.

## Detector choice

[Horizon Guard Small's model card](https://huggingface.co/Horizon-Labs/prompt-injection-guard-small/raw/main/README.md) describes an Apache-2.0, 141M-parameter multilingual classifier with ONNX artifacts and an 8k context. It includes a windowing example. Select it only after a local smoke test and pin the exact revision. Its advertised scores are publisher measurements. Its listed training sources include LLMail-Inject, NVIDIA's indirect-injection data and tool-response injections; those are unsuitable for claims of uncontaminated held-out evaluation. NotInject is a disclosed publisher evaluation set.

[ProtectAI DeBERTa v2](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2) is a recognizable Apache-2.0 alternative with Transformers and ONNX support. Its card says the project is archived, supports English injection detection, and warns of false positives on system prompts. If used, apply equivalent long-input coverage rather than silently discarding the tail. A newer model is not automatically a better baseline; local behavior, availability and reproducibility decide.

## Existing data to an actionable decision

[SEC EDGAR APIs](https://www.sec.gov/search-filings/edgar-application-programming-interfaces) expose filing history and XBRL facts without API keys. Their structured facts retain units and periods. Preserve the accession, exact source location and original response digest. Respect issuer-specific fiscal calendars. Two representations from the same filing do not constitute independent corroboration.

The intended transformation is: **existing filing or XBRL record → validated period/unit/value plus suspicious-source finding → exclude the compromised note and recover required facts → tell the employee whether they can use the answer and which source needs review now.** A suitable output is: “Use the reported figure cited below. We excluded a note that tried to change the assistant's instructions and replaced it with the filing record. Review that note before allowing it back into research.” Such wording must be generated from actual decisions, not a canned success state.

This is an operational security recommendation. Reported company numbers are context, not investment advice. The prototype cannot infer a monetary loss from a classifier score.

## Evaluation required for defensible claims

1. Freeze data, model revision, threshold, scanning limits and policy before the final run. Use development fixtures for debugging. Keep document/task families together across development and test; repeated attack variants are dependent observations.
2. Compare unprotected RAG, the same windowed detector with passage removal, compiler without recovery, and full compiler plus recovery. Use the same question, initial retrieval, answering model and generation settings. Record the extra retrieval work available to full PROMPTGUARD. A scanner granted the same recovery corpus is a useful additional control when feasible.
3. Keep public detector diagnostics separate from application evaluation. [NotInject](https://huggingface.co/datasets/leolee99/NotInject) supplies 339 benign trigger-word examples. [IndirectRAG-Bench](https://huggingface.co/datasets/heisenberg-88/indirectrag-bench?duplicate=true) documents 500 deterministic, synthetic, English, single-turn cases. Neither establishes real-world attack prevalence. Public accessibility does not prove absence from pretraining.
4. Report detector recall, false-positive rate, precision, confusion counts and cold/warm latency. Do not relabel policy denial or typed extraction as improved classifier recall. Count errors, incomplete scans and timeouts explicitly.
5. Separately report harmless-canary attack success, correct supported task completion, insufficient evidence, conflicts and recovery rate. Report attack success over all attacks and over originally successful attacks with denominators. A refusal may stop an attack while failing the legitimate task.
6. Publish per-case outcomes and manifests, not just averages. Report uncertainty and sample dependence. Numerical integrity, evidence admission, detector detection and generative instruction following are different outcomes.
7. Use actual runs of the same answering model for the comparative AI workflow. A deterministic renderer is valuable but must be labeled and evaluated separately. A mock that follows attack markers cannot establish real-model vulnerability.

## Failure cases to show judges

Unrecognized or multilingual instruction patterns; malicious content in long or adjacent chunks; benign security discussions that are quarantined; missing recovery evidence; conflicting amendments or units; incorrect source facts that contain no injection; forged caller-supplied trust labels; model timeouts; and attacks the unprotected model already resists. The trusted manifest and numeric registry are assumptions, not solved compromise scenarios.

Keep the contribution if recovery improves supported completion at comparable security. If the difference is small, report it plainly. Reduce issuer/metric breadth before sacrificing real enforcement, a working baseline or reproducible measurement.
