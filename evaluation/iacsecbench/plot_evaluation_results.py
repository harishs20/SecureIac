
import csv
import math
from pathlib import Path

import matplotlib.pyplot as plt

# Project paths
PROJECT_ROOT = Path(__file__).resolve().parents[2]
RESULTS_DIR = (
    PROJECT_ROOT
    / "results"
    / "iacsecbench_pilot"
    / "evaluation_summary"
)

METRICS_FILE = RESULTS_DIR / "repeated_run_metrics.csv"
OUTPUT_FILE = RESULTS_DIR / "evaluation_error_bars.png"

# Metrics with valid Wilson confidence intervals in the CSV
METRICS = [
    ("accuracy", "Accuracy"),
    ("precision", "Precision"),
    ("recall", "Recall"),
    ("specificity", "Specificity"),
]


def main():
    if not METRICS_FILE.exists():
        raise FileNotFoundError(
            f"Metrics CSV not found: {METRICS_FILE}"
        )

    with METRICS_FILE.open(
        "r", newline="", encoding="utf-8-sig"
    ) as file:
        runs = list(csv.DictReader(file))

    if not runs:
        raise ValueError("The metrics CSV contains no rows.")

    means = []
    lower_errors = []
    upper_errors = []
    labels = []

    for metric, label in METRICS:
        required_columns = [
            metric,
            f"{metric}_ci95_low",
            f"{metric}_ci95_high",
        ]

        missing = [
            column
            for column in required_columns
            if column not in runs[0]
        ]

        if missing:
            raise ValueError(
                f"Missing CSV columns for {label}: {missing}"
            )

        values = [float(row[metric]) for row in runs]
        mean_value = sum(values) / len(values)

        # Wilson intervals are identical across runs here because
        # the confusion matrix is identical in every repeated run.
        low = float(runs[0][f"{metric}_ci95_low"])
        high = float(runs[0][f"{metric}_ci95_high"])

        if not all(
            math.isfinite(value)
            for value in (mean_value, low, high)
        ):
            raise ValueError(
                f"Non-finite value found for {label}."
            )

        # Clamp error lengths to zero to prevent tiny negative
        # floating-point differences, especially for recall = 1.0.
        lower_error = max(0.0, mean_value - low)
        upper_error = max(0.0, high - mean_value)

        labels.append(label)
        means.append(mean_value)
        lower_errors.append(lower_error)
        upper_errors.append(upper_error)

    positions = list(range(len(labels)))

    fig, ax = plt.subplots(figsize=(9, 5.5))

    ax.errorbar(
        positions,
        means,
        yerr=[lower_errors, upper_errors],
        fmt="o",
        capsize=6,
    )

    ax.set_xticks(positions)
    ax.set_xticklabels(labels)
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Score")
    ax.set_title(
        "SecureIaC Evaluation: 95% Wilson Confidence Intervals"
    )
    ax.grid(axis="y", alpha=0.3)

    fig.text(
        0.5,
        0.01,
        "12 benchmark cases per run; 3 repeated runs. "
        "Intervals describe binomial uncertainty per run, "
        "not variability across runs.",
        ha="center",
        fontsize=8,
    )

    fig.tight_layout(rect=[0, 0.06, 1, 1])
    fig.savefig(
        OUTPUT_FILE,
        dpi=300,
        bbox_inches="tight",
    )
    plt.close(fig)

    print(f"Saved error-bar chart: {OUTPUT_FILE}")
    print("Metrics plotted:", ", ".join(labels))
    print("No API calls were made.")


if __name__ == "__main__":
    main()
