import matplotlib.pyplot as plt


# ============================================================
# Graph 1 — Target Vulnerability Detection
# ============================================================

methods = [
    "Checkov",
    "Ungrounded LLM",
    "Policy-only LLM",
    "Grounded LLM"
]

detection_rate = [
    100,
    100,
    100,
    100
]

plt.figure(figsize=(9, 5))

bars = plt.bar(methods, detection_rate)

plt.ylabel("Target Vulnerability Detection Rate (%)")
plt.title("Review 2: Target Vulnerability Detection")
plt.ylim(0, 110)

for bar, value in zip(bars, detection_rate):
    plt.text(
        bar.get_x() + bar.get_width() / 2,
        value + 2,
        f"{value}%",
        ha="center"
    )

plt.tight_layout()
plt.savefig("review2_detection_rate.png", dpi=300)
plt.show()


# ============================================================
# Graph 2 — Observed Extra / Out-of-Scope Findings
# ============================================================

llm_methods = [
    "Ungrounded LLM",
    "Policy-only LLM",
    "Grounded LLM"
]

extra_findings = [
    1,
    0,
    0
]

plt.figure(figsize=(8, 5))

bars = plt.bar(llm_methods, extra_findings)

plt.ylabel("Number of Extra / Out-of-Scope Findings")
plt.title("Review 2: Effect of Policy Grounding")
plt.ylim(0, 1.5)

for bar, value in zip(bars, extra_findings):
    plt.text(
        bar.get_x() + bar.get_width() / 2,
        value + 0.05,
        str(value),
        ha="center"
    )

plt.tight_layout()
plt.savefig("review2_extra_findings.png", dpi=300)
plt.show()
# ============================================================
# Graph 3 — Contextual Workload Detection
# ============================================================

contextual_cases = [
    "C01 - Cross-file",
    "C02 - Indirect variable/local"
]

checkov_detection = [
    1,
    0
]

secureiac_detection = [
    1,
    1
]

plt.figure(figsize=(9, 5))

x = range(len(contextual_cases))
width = 0.35

plt.bar(
    [i - width / 2 for i in x],
    checkov_detection,
    width=width,
    label="Checkov"
)

plt.bar(
    [i + width / 2 for i in x],
    secureiac_detection,
    width=width,
    label="SecureIaC"
)

plt.ylabel("Detection (1 = Detected, 0 = Not Detected)")
plt.title("Review 2: Contextual Workload Detection")
plt.xticks(x, contextual_cases)
plt.ylim(0, 1.2)

plt.legend()
plt.tight_layout()

plt.savefig("review2_contextual_detection.png", dpi=300)
plt.show()