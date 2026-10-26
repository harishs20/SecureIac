# SecureIaC comparison — 12 IaCSecBench cases

Positive class = vulnerable case. Each run contains 6 SAFE and 6 VULN cases.
Checkov is scored only when the mapped target rule appears in failed_checks.

## Individual-run results

| Method | Run | TP | TN | FP | FN | Accuracy | Precision | Recall | Specificity | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Checkov | 1 | 5 | 6 | 0 | 1 | 91.67% | 100.00% | 83.33% | 100.00% | 90.91% |
| Ungrounded LLM | 1 | 6 | 6 | 0 | 0 | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% |
| Ungrounded LLM | 2 | 5 | 6 | 0 | 1 | 91.67% | 100.00% | 83.33% | 100.00% | 90.91% |
| Ungrounded LLM | 3 | 6 | 6 | 0 | 0 | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% |
| Grounded SecureIaC | 1 | 6 | 5 | 1 | 0 | 91.67% | 85.71% | 100.00% | 83.33% | 92.31% |
| Grounded SecureIaC | 2 | 6 | 5 | 1 | 0 | 91.67% | 85.71% | 100.00% | 83.33% | 92.31% |
| Grounded SecureIaC | 3 | 6 | 5 | 1 | 0 | 91.67% | 85.71% | 100.00% | 83.33% | 92.31% |

## Comparison averages

| Method | Runs | Mean TP | Mean TN | Mean FP | Mean FN | Accuracy | Precision | Recall | Specificity | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Checkov | 1 | 5.00 | 6.00 | 0.00 | 1.00 | 91.67% | 100.00% | 83.33% | 100.00% | 90.91% |
| Ungrounded LLM | 3 | 5.67 | 6.00 | 0.00 | 0.33 | 97.22% | 100.00% | 94.44% | 100.00% | 96.97% |
| Grounded SecureIaC | 3 | 6.00 | 5.00 | 1.00 | 0.00 | 91.67% | 85.71% | 100.00% | 83.33% | 92.31% |

## Metric definitions

- TP: vulnerable cases correctly flagged.
- TN: safe cases correctly left unflagged.
- FP: safe cases incorrectly flagged.
- FN: vulnerable cases missed.
- Accuracy = (TP + TN) / all cases.
- Precision = TP / (TP + FP).
- Recall = TP / (TP + FN).
- Specificity = TN / (TN + FP).
- F1 = harmonic mean of precision and recall.

Caution: verify every target Checkov rule ID and its failed_checks behavior before treating its baseline as final. The LLM averages are across three runs of the same 12 cases, not 36 independent benchmark cases.
