import csv
import json
from pathlib import Path


# ==================================================
# Paths
# ==================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

GROUND_TRUTH_FILE = (
    PROJECT_ROOT / "baseline" / "test_cases.csv"
)

VERIFIED_RESULTS_DIR = (
    PROJECT_ROOT / "results" / "verified"
)

OUTPUT_DIR = (
    PROJECT_ROOT / "results" / "evaluation"
)

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True
)


# ==================================================
# Load ground truth
# ==================================================

def load_ground_truth():
    """
    Load the frozen SecureIaC test-case ground truth.
    """

    ground_truth = {}

    with open(
        GROUND_TRUTH_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        reader = csv.DictReader(file)

        for row in reader:

            test_id = row["Test_ID"]

            ground_truth[test_id] = {
                "category": row["Category"],
                "intended_vulnerability": (
                    row["Intended_Vulnerability"]
                ),
                "expected_result": row["Expected_Result"]
            }

    return ground_truth


# ==================================================
# Load verified result
# ==================================================

def load_verified_result(test_id):
    """
    Load the verifier output for one test case.
    """

    result_file = (
        VERIFIED_RESULTS_DIR
        / f"{test_id}_verified.json"
    )

    if not result_file.exists():
        return None

    with open(
        result_file,
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


# ==================================================
# Evaluate one test case
# ==================================================

def evaluate_test_case(
    test_id,
    ground_truth,
    verified_result
):
    """
    Evaluate one test case against the frozen
    ground truth.
    """

    expected_result = (
        ground_truth[test_id]["expected_result"]
    )

    findings = []

    if verified_result is not None:
        findings = verified_result.get(
            "findings",
            []
        )


    # --------------------------------------------------
    # Count accepted and rejected findings
    # --------------------------------------------------

    accepted_findings = [
        finding
        for finding in findings
        if finding.get("decision") == "ACCEPT"
    ]

    rejected_findings = [
        finding
        for finding in findings
        if finding.get("decision") == "REJECT"
    ]


    accepted_count = len(
        accepted_findings
    )

    rejected_count = len(
        rejected_findings
    )


    # --------------------------------------------------
    # Vulnerable test cases
    # --------------------------------------------------

    if expected_result == "Vulnerable":

        if accepted_count > 0:

            classification = "TP"

            tp = 1
            fp = 0
            fn = 0

        else:

            classification = "FN"

            tp = 0
            fp = 0
            fn = 1


    # --------------------------------------------------
    # Secure test case
    # --------------------------------------------------

    else:

        if accepted_count > 0:

            classification = "FP"

            tp = 0
            fp = 1
            fn = 0

        else:

            classification = "TN"

            tp = 0
            fp = 0
            fn = 0


    return {
        "test_id": test_id,
        "expected_result": expected_result,
        "ground_truth": ground_truth[test_id][
            "intended_vulnerability"
        ],
        "generated_findings": len(findings),
        "accepted_findings": accepted_count,
        "rejected_findings": rejected_count,
        "classification": classification,
        "TP": tp,
        "FP": fp,
        "FN": fn,
        "unsupported_findings": rejected_count
    }


# ==================================================
# Calculate metrics
# ==================================================

def calculate_metrics(results):
    """
    Calculate aggregate evaluation metrics.
    """

    tp = sum(
        result["TP"]
        for result in results
    )

    fp = sum(
        result["FP"]
        for result in results
    )

    fn = sum(
        result["FN"]
        for result in results
    )

    unsupported = sum(
        result["unsupported_findings"]
        for result in results
    )

    total_generated_findings = sum(
        result["generated_findings"]
        for result in results
    )


    # Precision

    if tp + fp > 0:
        precision = tp / (tp + fp)
    else:
        precision = 0.0


    # Recall

    if tp + fn > 0:
        recall = tp / (tp + fn)
    else:
        recall = 0.0


    # F1

    if precision + recall > 0:
        f1 = (
            2
            * precision
            * recall
            / (precision + recall)
        )
    else:
        f1 = 0.0


    # Unsupported finding rate

    if total_generated_findings > 0:
        unsupported_rate = (
            unsupported
            / total_generated_findings
        )
    else:
        unsupported_rate = 0.0


    return {
        "TP": tp,
        "FP": fp,
        "FN": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "unsupported_findings": unsupported,
        "total_generated_findings": (
            total_generated_findings
        ),
        "unsupported_finding_rate": (
            unsupported_rate
        )
    }


# ==================================================
# Save CSV
# ==================================================

def save_csv(results):
    """
    Save per-test-case evaluation results.
    """

    output_file = (
        OUTPUT_DIR
        / "grounded_evaluation.csv"
    )

    fieldnames = [
        "test_id",
        "expected_result",
        "ground_truth",
        "generated_findings",
        "accepted_findings",
        "rejected_findings",
        "classification",
        "TP",
        "FP",
        "FN",
        "unsupported_findings"
    ]


    with open(
        output_file,
        "w",
        encoding="utf-8",
        newline=""
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()

        writer.writerows(results)


    return output_file


# ==================================================
# Save JSON summary
# ==================================================

def save_json(
    results,
    metrics
):
    """
    Save complete evaluation results.
    """

    output_file = (
        OUTPUT_DIR
        / "grounded_evaluation.json"
    )


    output = {
        "configuration": "Grounded LLM + Policy + Evidence Verification",
        "test_cases": results,
        "metrics": metrics
    }


    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            output,
            file,
            indent=2
        )


    return output_file


# ==================================================
# Main evaluation
# ==================================================

def main():

    print("=" * 60)

    print(
        "SecureIaC - Grounded LLM Evaluation"
    )

    print("=" * 60)


    # --------------------------------------------------
    # Load ground truth
    # --------------------------------------------------

    ground_truth = load_ground_truth()

    print(
        f"\nLoaded {len(ground_truth)} "
        "ground-truth test cases."
    )


    # --------------------------------------------------
    # Evaluate all test cases
    # --------------------------------------------------

    results = []


    for test_id in sorted(
        ground_truth.keys()
    ):

        verified_result = (
            load_verified_result(test_id)
        )


        if verified_result is None:

            print(
                f"\nWARNING: No verified result "
                f"found for {test_id}"
            )

            continue


        result = evaluate_test_case(
            test_id,
            ground_truth,
            verified_result
        )


        results.append(result)


        print(
            f"\n{test_id}: "
            f"{result['classification']} "
            f"(accepted={result['accepted_findings']}, "
            f"rejected={result['rejected_findings']})"
        )


    # --------------------------------------------------
    # Calculate metrics
    # --------------------------------------------------

    metrics = calculate_metrics(
        results
    )


    # --------------------------------------------------
    # Save results
    # --------------------------------------------------

    csv_file = save_csv(
        results
    )

    json_file = save_json(
        results,
        metrics
    )


    # --------------------------------------------------
    # Print summary
    # --------------------------------------------------

    print("\n" + "=" * 60)

    print(
        "Grounded LLM Evaluation Complete"
    )

    print("=" * 60)


    print(
        f"\nTP:  {metrics['TP']}"
    )

    print(
        f"FP:  {metrics['FP']}"
    )

    print(
        f"FN:  {metrics['FN']}"
    )

    print(
        f"\nPrecision: "
        f"{metrics['precision']:.4f}"
    )

    print(
        f"Recall:    "
        f"{metrics['recall']:.4f}"
    )

    print(
        f"F1 Score:  "
        f"{metrics['f1']:.4f}"
    )

    print(
        f"\nUnsupported findings: "
        f"{metrics['unsupported_findings']}"
    )

    print(
        f"Total generated findings: "
        f"{metrics['total_generated_findings']}"
    )

    print(
        f"Unsupported finding rate: "
        f"{metrics['unsupported_finding_rate']:.4f}"
    )


    print(
        f"\nCSV saved to:"
        f"\n{csv_file}"
    )

    print(
        f"\nJSON saved to:"
        f"\n{json_file}"
    )


# ==================================================
# Run
# ==================================================

if __name__ == "__main__":
    main()