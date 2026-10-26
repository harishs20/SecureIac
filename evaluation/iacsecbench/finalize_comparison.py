import csv
import json
from pathlib import Path
from statistics import mean

ROOT = Path(__file__).resolve().parents[2]
CASES = Path(r"D:\SecureIAC\iacsecbench\benchmark\internal\cases")
CHECKOV = ROOT / "results" / "iacsecbench_comparison" / "checkov"
UNGROUNDED = ROOT / "results" / "iacsecbench_comparison" / "ungrounded"
GROUNDED = ROOT / "results" / "iacsecbench_pilot"
OUT = ROOT / "results" / "iacsecbench_comparison" / "comparison_summary"
OUT.mkdir(parents=True, exist_ok=True)

# Score only failed Checkov checks for the benchmark's target control.
TARGET_RULES = {
    "ENC_UNENCRYPTED_VOLUME": {"CKV_AWS_3"},
    "IAM_WILDCARD_ACTION": {"CKV_AWS_63"},
    "NET_UNRESTRICTED_INGRESS": {"CKV_AWS_24"},
    "STO_NO_ACCESS_LOGGING": {"CKV_AWS_18"},
    "STO_PUBLIC_BUCKET": {"CKV2_AWS_6"},
    "STO_PUBLIC_DATABASE": {"CKV_AWS_17"},
}

def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))

def get_findings(result):
    if not isinstance(result, dict):
        raise ValueError("Model result is not a JSON object")
    findings = result.get("findings")
    if not isinstance(findings, list):
        raise ValueError("Model result has no valid findings list")
    return findings

def score(method, run, case_id, expected, predicted):
    return {
        "method": method,
        "run": run,
        "case_id": case_id,
        "expected": int(expected),
        "predicted": int(predicted),
        "correct": int(int(expected) == int(predicted)),
    }

def calculate(rows):
    tp = sum(r["expected"] == 1 and r["predicted"] == 1 for r in rows)
    tn = sum(r["expected"] == 0 and r["predicted"] == 0 for r in rows)
    fp = sum(r["expected"] == 0 and r["predicted"] == 1 for r in rows)
    fn = sum(r["expected"] == 1 and r["predicted"] == 0 for r in rows)

    def ratio(a, b):
        return a / b if b else 0.0

    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    specificity = ratio(tn, tn + fp)
    return {
        "Cases": len(rows), "TP": tp, "TN": tn, "FP": fp, "FN": fn,
        "Accuracy": ratio(tp + tn, len(rows)),
        "Precision": precision,
        "Recall": recall,
        "Specificity": specificity,
        "F1": ratio(2 * precision * recall, precision + recall),
    }

def write_csv(path, rows, columns=None):
    if columns is None:
        columns = list(rows[0].keys()) if rows else []
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)

all_predictions = []

# 1. Checkov: read FAILED checks only.
for case_dir in sorted(CASES.iterdir()):
    metadata_file = case_dir / "metadata.json"
    if not metadata_file.is_file():
        continue
    meta = load_json(metadata_file)
    case_id = meta["id"]
    control = meta["canonical_controls"][0]
    if control not in TARGET_RULES:
        continue

    report_path = CHECKOV / f"{case_id}.json" / "results_json.json"
    if not report_path.is_file():
        raise FileNotFoundError(f"Missing Checkov report: {report_path}")

    report = load_json(report_path)
    failed = report.get("results", {}).get("failed_checks", [])
    failed_ids = {
        item.get("check_id")
        for item in failed
        if isinstance(item, dict)
    }
    predicted = int(bool(failed_ids & TARGET_RULES[control]))
    expected = int(meta["expected_result"] == "FAIL")
    all_predictions.append(
        score("Checkov", 1, case_id, expected, predicted)
    )

# 2. Grounded SecureIaC: reuse the three saved manifests and responses.
for run in range(1, 4):
    manifest_path = GROUNDED / f"repeat_{run}" / "run_manifest.json"
    if not manifest_path.is_file():
        raise FileNotFoundError(f"Missing grounded manifest: {manifest_path}")

    for item in load_json(manifest_path):
        if item.get("result_status") != "success" or not item.get("result_file"):
            raise RuntimeError(f"Grounded result unavailable for {item.get('id')}")
        result = load_json(item["result_file"])
        predicted = int(len(get_findings(result)) > 0)
        expected = int(item["expected_result"] == "FAIL")
        all_predictions.append(
            score("Grounded SecureIaC", run, item["id"], expected, predicted)
        )

# 3. Ungrounded LLM: reuse the three saved repetitions.
for run in range(1, 4):
    for case_dir in sorted(CASES.iterdir()):
        metadata_file = case_dir / "metadata.json"
        if not metadata_file.is_file():
            continue
        meta = load_json(metadata_file)
        case_id = meta["id"]
        if meta["canonical_controls"][0] not in TARGET_RULES:
            continue

        result_path = UNGROUNDED / f"repeat_{run}" / case_id / "result.json"
        if not result_path.is_file():
            raise FileNotFoundError(
                f"Missing ungrounded result: {result_path}. "
                "Do not rerun the full experiment until checking why it is missing."
            )
        result = load_json(result_path)
        predicted = int(len(get_findings(result)) > 0)
        expected = int(meta["expected_result"] == "FAIL")
        all_predictions.append(
            score("Ungrounded LLM", run, case_id, expected, predicted)
        )

# Save every case-level prediction.
write_csv(OUT / "per_case_predictions.csv", all_predictions)

# Metrics for each individual run.
per_run = []
for method in ("Checkov", "Ungrounded LLM", "Grounded SecureIaC"):
    runs = sorted({r["run"] for r in all_predictions if r["method"] == method})
    for run in runs:
        subset = [
            r for r in all_predictions
            if r["method"] == method and r["run"] == run
        ]
        if len(subset) != 12:
            raise ValueError(f"{method} run {run} has {len(subset)} cases, not 12")
        metrics = calculate(subset)
        per_run.append({"Method": method, "Run": run, **metrics})

write_csv(OUT / "per_run_metrics.csv", per_run)

# Mean of run-level metrics, plus average confusion-matrix counts.
summary = []
for method in ("Checkov", "Ungrounded LLM", "Grounded SecureIaC"):
    runs = [r for r in per_run if r["Method"] == method]
    row = {"Method": method, "Runs": len(runs)}
    for key in ("Accuracy", "Precision", "Recall", "Specificity", "F1",
                "TP", "TN", "FP", "FN"):
        row[key] = mean(r[key] for r in runs)
    summary.append(row)

write_csv(OUT / "comparison_metrics.csv", summary)

# Generate a readable report with both individual runs and averages.
def fmt_metric(value):
    return f"{value * 100:.2f}%"

lines = [
    "# SecureIaC comparison — 12 IaCSecBench cases",
    "",
    "Positive class = vulnerable case. Each run contains 6 SAFE and 6 VULN cases.",
    "Checkov is scored only when the mapped target rule appears in failed_checks.",
    "",
    "## Individual-run results",
    "",
    "| Method | Run | TP | TN | FP | FN | Accuracy | Precision | Recall | Specificity | F1 |",
    "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
]
for r in per_run:
    lines.append(
        f"| {r['Method']} | {r['Run']} | {r['TP']} | {r['TN']} | "
        f"{r['FP']} | {r['FN']} | {fmt_metric(r['Accuracy'])} | "
        f"{fmt_metric(r['Precision'])} | {fmt_metric(r['Recall'])} | "
        f"{fmt_metric(r['Specificity'])} | {fmt_metric(r['F1'])} |"
    )

lines += [
    "",
    "## Comparison averages",
    "",
    "| Method | Runs | Mean TP | Mean TN | Mean FP | Mean FN | Accuracy | Precision | Recall | Specificity | F1 |",
    "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
]
for r in summary:
    lines.append(
        f"| {r['Method']} | {r['Runs']} | {r['TP']:.2f} | {r['TN']:.2f} | "
        f"{r['FP']:.2f} | {r['FN']:.2f} | {fmt_metric(r['Accuracy'])} | "
        f"{fmt_metric(r['Precision'])} | {fmt_metric(r['Recall'])} | "
        f"{fmt_metric(r['Specificity'])} | {fmt_metric(r['F1'])} |"
    )

lines += [
    "",
    "## Metric definitions",
    "",
    "- TP: vulnerable cases correctly flagged.",
    "- TN: safe cases correctly left unflagged.",
    "- FP: safe cases incorrectly flagged.",
    "- FN: vulnerable cases missed.",
    "- Accuracy = (TP + TN) / all cases.",
    "- Precision = TP / (TP + FP).",
    "- Recall = TP / (TP + FN).",
    "- Specificity = TN / (TN + FP).",
    "- F1 = harmonic mean of precision and recall.",
    "",
    "Caution: verify every target Checkov rule ID and its failed_checks behavior "
    "before treating its baseline as final. The LLM averages are across three "
    "runs of the same 12 cases, not 36 independent benchmark cases.",
    "",
]
(OUT / "comparison_table.md").write_text("\n".join(lines), encoding="utf-8")

print("\n=== FINAL COMPARISON GENERATED ===")
print(f"Per-case predictions: {OUT / 'per_case_predictions.csv'}")
print(f"Per-run metrics:      {OUT / 'per_run_metrics.csv'}")
print(f"Average metrics:      {OUT / 'comparison_metrics.csv'}")
print(f"Readable tables:      {OUT / 'comparison_table.md'}")
print("\nIndividual run metrics:")
for r in per_run:
    print(
        f"{r['Method']} run {r['Run']}: "
        f"TP={r['TP']} TN={r['TN']} FP={r['FP']} FN={r['FN']} "
        f"Accuracy={fmt_metric(r['Accuracy'])} "
        f"Precision={fmt_metric(r['Precision'])} "
        f"Recall={fmt_metric(r['Recall'])} "
        f"Specificity={fmt_metric(r['Specificity'])} "
        f"F1={fmt_metric(r['F1'])}"
    )
