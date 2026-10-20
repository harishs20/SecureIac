
import csv
import json
import math
import statistics
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
RESULTS_ROOT = PROJECT_ROOT / "results" / "iacsecbench_pilot"
BENCHMARK_ROOT = PROJECT_ROOT.parent / "iacsecbench" / "benchmark" / "internal" / "cases"
OUTPUT_DIR = RESULTS_ROOT / "evaluation_summary"

RUN_IDS = ["repeat_1", "repeat_2", "repeat_3"]


def read_json(path):
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def safe_div(numerator, denominator):
    return numerator / denominator if denominator else float("nan")


def wilson_interval(successes, total, z=1.96):
    """95% Wilson score interval for a binomial proportion."""
    if total == 0:
        return float("nan"), float("nan")

    p = successes / total
    denominator = 1 + z**2 / total
    center = (p + z**2 / (2 * total)) / denominator
    margin = (
        z
        * math.sqrt(
            p * (1 - p) / total
            + z**2 / (4 * total**2)
        )
        / denominator
    )
    return center - margin, center + margin


def calculate_metrics(tp, tn, fp, fn):
    total = tp + tn + fp + fn

    accuracy = safe_div(tp + tn, total)
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    specificity = safe_div(tn, tn + fp)
    f1 = safe_div(2 * precision * recall, precision + recall)

    accuracy_low, accuracy_high = wilson_interval(tp + tn, total)
    precision_low, precision_high = wilson_interval(tp, tp + fp)
    recall_low, recall_high = wilson_interval(tp, tp + fn)
    specificity_low, specificity_high = wilson_interval(tn, tn + fp)

    return {
        "cases": total,
        "TP": tp,
        "TN": tn,
        "FP": fp,
        "FN": fn,
        "accuracy": accuracy,
        "accuracy_ci95_low": accuracy_low,
        "accuracy_ci95_high": accuracy_high,
        "precision": precision,
        "precision_ci95_low": precision_low,
        "precision_ci95_high": precision_high,
        "recall": recall,
        "recall_ci95_low": recall_low,
        "recall_ci95_high": recall_high,
        "specificity": specificity,
        "specificity_ci95_low": specificity_low,
        "specificity_ci95_high": specificity_high,
        "f1": f1,
    }


def evaluate_run(run_id):
    run_dir = RESULTS_ROOT / run_id
    if not run_dir.is_dir():
        raise FileNotFoundError(f"Missing run directory: {run_dir}")

    records = []
    skipped = []

    for case_dir in sorted(path for path in run_dir.iterdir() if path.is_dir()):
        case_id = case_dir.name
        metadata_path = BENCHMARK_ROOT / case_id / "metadata.json"
        status_path = case_dir / "status.json"
        result_path = case_dir / "result.json"

        if not metadata_path.is_file():
            skipped.append((case_id, "missing benchmark metadata"))
            continue
        if not status_path.is_file():
            skipped.append((case_id, "missing status.json"))
            continue

        metadata = read_json(metadata_path)
        status = read_json(status_path)

        if status.get("status") != "success":
            skipped.append((case_id, f"status={status.get('status')}"))
            continue
        if not result_path.is_file():
            skipped.append((case_id, "missing result.json"))
            continue

        result = read_json(result_path)
        findings = result.get("findings")

        if result.get("test_id") != case_id:
            skipped.append((case_id, "result test_id mismatch"))
            continue
        if not isinstance(findings, list):
            skipped.append((case_id, "findings is not a list"))
            continue

        expected_positive = bool(metadata["has_violation"])
        predicted_positive = len(findings) > 0

        records.append({
            "run_id": run_id,
            "case_id": case_id,
            "expected": "VULN" if expected_positive else "SAFE",
            "predicted": "VULN" if predicted_positive else "SAFE",
            "expected_positive": expected_positive,
            "predicted_positive": predicted_positive,
            "finding_count": len(findings),
            "correct": expected_positive == predicted_positive,
        })

    if skipped:
        print(f"\nSkipped cases in {run_id}:")
        for case_id, reason in skipped:
            print(f"  {case_id}: {reason}")

    return records


def write_csv(path, rows):
    if not rows:
        print(f"No rows to write: {path}")
        return

    with path.open("w", newline="", encoding="utf-8-sig") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    all_predictions = []
    run_summaries = []

    for run_id in RUN_IDS:
        records = evaluate_run(run_id)
        all_predictions.extend(records)

        tp = sum(r["expected_positive"] and r["predicted_positive"] for r in records)
        tn = sum(not r["expected_positive"] and not r["predicted_positive"] for r in records)
        fp = sum(not r["expected_positive"] and r["predicted_positive"] for r in records)
        fn = sum(r["expected_positive"] and not r["predicted_positive"] for r in records)

        metrics = calculate_metrics(tp, tn, fp, fn)
        metrics["run_id"] = run_id
        run_summaries.append(metrics)

        print(f"\n{run_id}: {len(records)} valid cases")
        print(f"  TP={tp}, TN={tn}, FP={fp}, FN={fn}")
        for name in ("accuracy", "precision", "recall", "specificity", "f1"):
            value = metrics[name]
            print(f"  {name}: {value:.4f}" if math.isfinite(value)
                  else f"  {name}: undefined")

    write_csv(OUTPUT_DIR / "per_case_predictions.csv", all_predictions)
    write_csv(OUTPUT_DIR / "repeated_run_metrics.csv", run_summaries)

    summary_rows = []
    metric_names = ("accuracy", "precision", "recall", "specificity", "f1")

    for name in metric_names:
        values = [row[name] for row in run_summaries if math.isfinite(row[name])]
        if not values:
            continue

        mean = statistics.mean(values)
        variance = statistics.variance(values) if len(values) >= 2 else float("nan")
        sd = statistics.stdev(values) if len(values) >= 2 else float("nan")

        # Wilson intervals apply to the pooled counts for each ratio,
        # not to the distribution of repeated-run metric values.
        summary_rows.append({
            "metric": name,
            "run_count": len(values),
            "mean": mean,
            "sample_variance": variance,
            "sample_sd": sd,
        })

    write_csv(OUTPUT_DIR / "statistical_summary.csv", summary_rows)

    print("\nAcross-run summary:")
    for row in summary_rows:
        print(
            f"  {row['metric']}: mean={row['mean']:.4f}, "
            f"sample variance={row['sample_variance']:.8f}"
        )

    print(f"\nPer-case predictions: {OUTPUT_DIR / 'per_case_predictions.csv'}")
    print(f"Per-run metrics:      {OUTPUT_DIR / 'repeated_run_metrics.csv'}")
    print(f"Statistical summary:  {OUTPUT_DIR / 'statistical_summary.csv'}")
    print("\nNo API calls were made.")


if __name__ == "__main__":
    main()
