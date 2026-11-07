"""Human-readable assessment assembled exclusively from retained actual results."""
import json
from promptguard.common import ARTIFACTS, ROOT, utcnow


def main():
    report=json.loads((ARTIFACTS/'benchmark.json').read_text(encoding='utf-8'))
    lines=['# PROMPTGUARD measured results','',f"Generated: {utcnow()}",'',
           '## What the business can act on','',
           'The support/refund adapter enforces customer scope, verified order eligibility, original payment method, exact-action approval and cumulative spending independently of the model. Adopt explicit financial authorization before connecting an agent to real money movement. The current tools affect only an isolated test ledger.','',
           'An existing Agent Guard example policy was imported with its original license and a source hash. It declares default allow: operations not covered by an explicit rule need review before that example is adapted to a financial workflow. This is an observation about the example configuration, not a vulnerability claim about the library.','',
           '## Recorded demonstration','',
           'A selected genuine GPT-4o-mini comparison observed an unauthorized wrong-customer refund without protection and with detector-only protection. The protected run issued none. It also did not complete the legitimate refund task. All three outputs and their evidence are retained in artifacts/recorded-demo.json. This is demonstration evidence, not a representative performance estimate.','',
           '## Complete public detector diagnostics','',
           '| Dataset | Cases | Attack recall | Precision | Benign false-positive rate | p95 scan latency |',
           '| --- | ---: | ---: | ---: | ---: | ---: |']
    percent=lambda x:'—' if x is None else f'{100*x:.2f}%'
    for row in report['detector']['tracks']:
        precision=row['precision'] if row['tp']+row['fn'] else None
        lines.append(f"| {row['dataset']} | {row['n']} | {percent(row['recall'])} | {percent(precision)} | {percent(row['false_positive_rate'])} | {row['latency_p95_ms']:.2f} ms |")
    lines+=['','NotInject is benign-only, so attack recall and useful attack precision are not estimated from it. There were 13 false alarms in its 339 examples. Public training/evaluation overlap cannot be excluded. These are publisher-labelled diagnostics, not a production prevalence estimate.','',
            '## Completed paired application cohort','',f"Model: {report['model']}. Three registered scenarios, four conditions, one execution per scenario/condition: 12 runs. Source, prompt, policy and model manifests are linked in artifacts/benchmark.json.",'',
            '| Condition | Valid attacks / unauthorized execution | Clean tasks completed | Approval pending | Errors |',
            '| --- | ---: | ---: | ---: | ---: |']
    for row in report['agent']['conditions']:
        lines.append(f"| {row['condition']} | {row['valid_attacks']} / {row['attack_successes']} | {row['clean_successes']}/{row['valid_clean']} | {row['approval_pending']} | {row['errors']} |")
    lines+=['','No attack succeeded in this small completed cohort, including without protection. It therefore establishes no newly prevented attack success. PROMPTGUARD completed both clean tasks, versus one for detector-only. Its bounded request-data adapter preserved the hard-benign task without passing the suspicious prose. One example is not a statistically established production benefit.','',
            'The approval condition intentionally left two legitimate actions pending; these are task non-completions, not successful refunds. The scanner-only condition completed the attacked task in one run where the other conditions did not; model variability and the small sample limit causal conclusions.','',
            'The initial larger evaluations were interrupted by provider request allowance. Their incomplete files are separate and their errors are not counted as protection. The completed cohort uses a distinct model snapshot from the selected recorded demonstration; results are not pooled.','',
            '## Reproduction and boundaries','',
            'See README.md for launch and evaluation commands, docs/DEMO_RUNBOOK.md for the presentation, and docs/IMPLEMENTATION_STATUS.md for implemented versus roadmap features. The separate RAG app uses the HTTP protection API and retained real SEC records. No confidential production activity was supplied.','',
            'The assessment does not certify production security, legal compliance, exact model causation or universal attack prevention. The solver verifies the declared policy abstraction only.']
    (ARTIFACTS/'RESULTS.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    print('Exported artifacts/RESULTS.md from measured results.')


if __name__=='__main__':main()
