import csv
import json
import os
import sys
import time
from pathlib import Path
from statistics import mean

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv
from groq import Groq

CASES = Path(r"D:\SecureIAC\iacsecbench\benchmark\internal\cases")
RESULTS = ROOT / "results" / "iacsecbench_comparison"
CHECKOV = RESULTS / "checkov"
UNGROUNDED = RESULTS / "ungrounded"
GROUNDED_ROOT = ROOT / "results" / "iacsecbench_pilot"
OUTPUT = RESULTS / "comparison_summary"
MODEL = "openai/gpt-oss-120b"

# Each rule ID is the Checkov control used to evaluate the benchmark target.
# NET target is CKV_AWS_24; if absent, Checkov is scored as not detecting it.
TARGET_RULES = {
    "ENC_UNENCRYPTED_VOLUME": {"CKV_AWS_3"},
    "IAM_WILDCARD_ACTION": {"CKV_AWS_63"},
    "NET_UNRESTRICTED_INGRESS": {"CKV_AWS_24"},
    "STO_NO_ACCESS_LOGGING": {"CKV_AWS_18"},
    "STO_PUBLIC_BUCKET": {"CKV2_AWS_6"},
    "STO_PUBLIC_DATABASE": {"CKV_AWS_17"},
}

def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))

def get_findings(result):
    if not isinstance(result, dict):
        return []
    findings = result.get("findings", [])
    return findings if isinstance(findings, list) else []

def llm_prediction(result):
    return int(bool(get_findings(result)))

def collect_check_ids(obj):
    found = set()
    if isinstance(obj, dict):
        check_id = obj.get("check_id")
        if isinstance(check_id, str):
            found.add(check_id)
        for value in obj.values():
            found.update(collect_check_ids(value))
    elif isinstance(obj, list):
        for value in obj:
            found.update(collect_check_ids(value))
    return found

def metrics(rows):
    tp = sum(r["expected"] == 1 and r["predicted"] == 1 for r in rows)
    tn = sum(r["expected"] == 0 and r["predicted"] == 0 for r in rows)
    fp = sum(r["expected"] == 0 and r["predicted"] == 1 for r in rows)
    fn = sum(r["expected"] == 1 and r["predicted"] == 0 for r in rows)
    div = lambda a, b: a / b if b else 0.0
    precision = div(tp, tp + fp)
    recall = div(tp, tp + fn)
    specificity = div(tn, tn + fp)
    f1 = div(2 * precision * recall, precision + recall)
    accuracy = div(tp + tn, len(rows))
    return {
        "cases": len(rows), "TP": tp, "TN": tn, "FP": fp, "FN": fn,
        "Accuracy": accuracy, "Precision": precision, "Recall": recall,
        "Specificity": specificity, "F1": f1,
    }

def score_case(case_id, expected, predicted, method, run):
    return {
        "method": method, "run": run, "case_id": case_id,
        "expected": expected, "predicted": int(predicted),
        "correct": int(int(expected) == int(predicted)),
    }

def ungrounded_prompt(case_id, terraform):
    control = next(c for c in TARGET_RULES if case_id.startswith(c.replace("_", "-")))
    descriptions = {
        "ENC_UNENCRYPTED_VOLUME": "whether EBS volumes are encrypted",
        "IAM_WILDCARD_ACTION": "whether IAM policies allow wildcard actions",
        "NET_UNRESTRICTED_INGRESS": "whether security-group ingress permits SSH port 22 from 0.0.0.0/0",
        "STO_NO_ACCESS_LOGGING": "whether the target S3 bucket has server access logging configured",
        "STO_PUBLIC_BUCKET": "whether the S3 bucket permits public access",
        "STO_PUBLIC_DATABASE": "whether the RDS database is publicly accessible",
    }
    return f"""You are a cloud infrastructure security analyzer.
Assess only this target control: {descriptions[control]}.
Do not use an external security policy. Do not report unrelated controls.
Use only evidence present in the Terraform. If the target control is not
violated, return an empty findings list. Return only valid JSON:
{{"test_id":"{case_id}","findings":[{{"finding":"short title","resource":"Terraform resource","reason":"explanation","evidence":"specific Terraform evidence","confidence":0.0}}]}}
Terraform case: {case_id}
Terraform configuration:
{terraform}
"""

def run_ungrounded():
    load_dotenv(ROOT / ".env")
    key = os.getenv("GROQ_API_KEY")
    if not key:
        raise RuntimeError("GROQ_API_KEY is missing from project .env")
    client = Groq(api_key=key)
    UNGROUNDED.mkdir(parents=True, exist_ok=True)

    case_ids = sorted(
        p.name for p in CASES.iterdir()
        if p.is_dir() and (p / "metadata.json").is_file()
        and p.name in {f"{prefix}-{variant}"
                       for prefix in [c.replace("_", "-") for c in TARGET_RULES]
                       for variant in ("SAFE", "VULN")}
    )
    if len(case_ids) != 12:
        raise RuntimeError(f"Expected 12 benchmark cases, found {len(case_ids)}")

    rows = []
    for repeat in range(1, 4):
        for index, case_id in enumerate(case_ids, 1):
            outdir = UNGROUNDED / f"repeat_{repeat}" / case_id
            outdir.mkdir(parents=True, exist_ok=True)
            result_path = outdir / "result.json"

            if result_path.exists():
                result = read_json(result_path)
                print(f"[Ungrounded {repeat}/3] Reusing {case_id}")
            else:
                metadata = read_json(CASES / case_id / "metadata.json")
                terraform = (CASES / case_id / "main.tf").read_text(encoding="utf-8")
                lines = terraform.splitlines()
                while lines and (not lines[0].strip() or lines[0].lstrip().startswith("#")):
                    lines.pop(0)
                terraform = "\n".join(lines)
                prompt = ungrounded_prompt(case_id, terraform)
                (outdir / "prompt.txt").write_text(prompt, encoding="utf-8")
                result = None
                raw = None
                error = None
                for attempt in range(1, 4):
                    try:
                        response = client.chat.completions.create(
                            model=MODEL,
                            messages=[{"role": "user", "content": prompt}],
                        )
                        raw = response.choices[0].message.content
                        if not raw:
                            raise ValueError("Empty model response")
                        cleaned = raw.strip()
                        if cleaned.startswith("```json"):
                            cleaned = cleaned[7:]
                        elif cleaned.startswith("```"):
                            cleaned = cleaned[3:]
                        if cleaned.strip().endswith("```"):
                            cleaned = cleaned.strip()[:-3]
                        result = json.loads(cleaned.strip())
                        if not isinstance(result.get("findings"), list):
                            raise ValueError("JSON must contain a findings list")
                        break
                    except Exception as exc:
                        error = str(exc)
                        result = None
                        if attempt < 3:
                            time.sleep(5)
                if result is None:
                    (outdir / "error.txt").write_text(error or "Unknown error", encoding="utf-8")
                    raise RuntimeError(f"Ungrounded request failed for {case_id}: {error}")
                result_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
                (outdir / "raw_output.txt").write_text(raw, encoding="utf-8")
                print(f"[Ungrounded {repeat}/3, {index}/12] Ran {case_id}", flush=True)
                if index < len(case_ids):
                    time.sleep(5)

            metadata = read_json(CASES / case_id / "metadata.json")
            expected = int(metadata["expected_result"] == "FAIL")
            rows.append(score_case(case_id, expected, llm_prediction(result),
                                   "Ungrounded LLM", repeat))
        (UNGROUNDED / f"repeat_{repeat}" / "run_manifest.json").write_text(
            json.dumps([r for r in rows if r["run"] == repeat], indent=2),
            encoding="utf-8",
        )
    return rows

def main():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    all_rows = []

    # Checkov: score only the benchmark's target control, not unrelated findings.
    for case_dir in sorted(CASES.iterdir()):
        meta_path = case_dir / "metadata.json"
        if not meta_path.is_file():
            continue
        meta = read_json(meta_path)
        case_id = meta["id"]
        control = meta["canonical_controls"][0]
        if control not in TARGET_RULES:
            continue
        expected = int(meta["expected_result"] == "FAIL")
        report = CHECKOV / f"{case_id}.json" / "results_json.json"
        if not report.is_file():
            raise FileNotFoundError(f"Missing Checkov report: {report}")
        ids = collect_check_ids(read_json(report))
        predicted = int(bool(ids & TARGET_RULES[control]))
        all_rows.append(score_case(case_id, expected, predicted, "Checkov", 1))

    # Reuse the three existing grounded runs; no grounded API calls are made.
    for repeat in range(1, 4):
        manifest = GROUNDED_ROOT / f"repeat_{repeat}" / "run_manifest.json"
        if not manifest.is_file():
            raise FileNotFoundError(f"Missing grounded manifest: {manifest}")
        for item in read_json(manifest):
            if item.get("result_status") != "success" or not item.get("result_file"):
                raise RuntimeError(f"Grounded result not successful: {item.get('id')}")
            result = read_json(item["result_file"])
            expected = int(item["expected_result"] == "FAIL")
            all_rows.append(score_case(item["id"], expected, llm_prediction(result),
                                       "Grounded SecureIaC", repeat))

    # Run ungrounded three times on the same 12 cases.
    all_rows.extend(run_ungrounded())

    with (OUTPUT / "per_case_predictions.csv").open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=list(all_rows[0].keys()))
        writer.writeheader()
        writer.writerows(all_rows)

    summary = []
    for method in ("Checkov", "Ungrounded LLM", "Grounded SecureIaC"):
        method_rows = [r for r in all_rows if r["method"] == method]
        runs = sorted(set(r["run"] for r in method_rows))
        run_metrics = [metrics([r for r in method_rows if r["run"] == run]) for run in runs]
        item = {"Method": method, "Runs": len(runs)}
        for key in ("Accuracy", "Precision", "Recall", "Specificity", "F1"):
            item[key] = mean(m[key] for m in run_metrics)
        item.update({f"{key}_mean": mean(m[key] for m in run_metrics)
                     for key in ("TP", "TN", "FP", "FN")})
        summary.append(item)

    columns = ["Method", "Runs", "Accuracy", "Precision", "Recall",
               "Specificity", "F1", "TP_mean", "TN_mean", "FP_mean", "FN_mean"]
    with (OUTPUT / "comparison_metrics.csv").open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        for item in summary:
            writer.writerow({k: (round(item[k], 4) if k in
                ("Accuracy", "Precision", "Recall", "Specificity", "F1") else item[k])
                for k in columns})

    md = ["# SecureIaC Comparison on 12 IaCSecBench Cases", "",
          "Checkov is scored only against the mapped target-control rule. "
          "Ungrounded and grounded predictions count a case as vulnerable when "
          "the model returns one or more findings. Existing grounded runs are reused. "
          "Ungrounded runs use the same Terraform inputs without policy context.", "",
          "| Method | Runs | Accuracy | Precision | Recall | Specificity | F1 | Mean TP | Mean TN | Mean FP | Mean FN |",
          "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for s in summary:
        md.append("| " + " | ".join([
            s["Method"], str(s["Runs"]),
            *(f'{s[k]*100:.2f}%' for k in ("Accuracy", "Precision", "Recall", "Specificity", "F1")),
            *(f'{s[k+"_mean"]:.2f}' for k in ("TP", "TN", "FP", "FN")),
        ]) + " |")
    md += ["", "## Interpretation notes", "",
           "- Metrics are computed over 12 cases per run; the three repeated runs are not 36 independent benchmark cases.",
           "- Checkov's target-rule mapping is explicit in the experiment script and should be verified against each rule's meaning.",
           "- Runtime is not compared because existing Checkov and grounded outputs are cached and do not provide directly comparable per-case timings.",
           "- This is a small pilot benchmark; report the results as preliminary.", ""]
    (OUTPUT / "comparison_table.md").write_text("\n".join(md), encoding="utf-8")
    print("\n=== Comparison complete ===")
    print(f"Per-case predictions: {OUTPUT / 'per_case_predictions.csv'}")
    print(f"Metrics CSV:          {OUTPUT / 'comparison_metrics.csv'}")
    print(f"Markdown table:       {OUTPUT / 'comparison_table.md'}")
    print("\n" + "\n".join(md[5:8 + len(summary)]))

if __name__ == "__main__":
    main()
