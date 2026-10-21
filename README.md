# SecureIaC: Policy-Grounded LLM Security Analysis for Terraform Infrastructure-as-Code

> A hybrid IaC security pipeline combining Checkov baseline scanning, policy-grounded LLM analysis, and deterministic evidence verification.

**Harish S** · 24BCE1440 &nbsp;|&nbsp; **Shailesh K S** · 24BCE1417  
Department of Computer Science and Engineering  
Vellore Institute of Technology, Chennai

---

## Overview

SecureIaC is a research prototype that addresses a key gap in Infrastructure-as-Code (IaC) security: existing rule-based scanners (like Checkov) miss context-dependent vulnerabilities, while unconstrained LLMs hallucinate findings without evidence. SecureIaC bridges this by grounding LLM analysis in explicit security policies and verifying every finding deterministically before acceptance.

**Key Results**
- 11/11 findings verified on the frozen testbed (T01–T09 + C01 + C02)
- 91.67% accuracy on IaCSecBench 12-case pilot · 100% recall · 92.31% F1
- Zero cross-run variance across 3 repeated runs
- Single reproducible false positive traced to policy wording ambiguity — not hallucination

---

## Pipeline

```
Terraform Config ──┐
                   ├──► Grounded LLM ──► Evidence Verifier ──► ACCEPT / REJECT
Security Policy ───┘    (gpt-oss-120b       (5 deterministic
  (9 YAML rules)         via Groq API)       checks)
```

### Evidence Verifier — 5 Checks

1. Policy ID exists in the policy store
2. Clause ID matches the cited policy
3. Policy targets this specific test case
4. Semantic keyword consistency between finding and policy clause
5. Terraform source contains the cited evidence string

---

## Repository Structure

```
SecureIaC/
├── policies/                  # 9 YAML security policy rules
│   ├── s3_public_access.yaml
│   ├── s3_encryption.yaml
│   ├── s3_access_logging.yaml
│   ├── network_ssh_ingress.yaml
│   ├── network_http_ingress.yaml
│   ├── iam_wildcard_action.yaml
│   ├── iam_wildcard_resource.yaml
│   ├── ebs_encryption.yaml
│   └── rds_public_access.yaml
├── testbed/                   # 10 frozen Terraform configs (T01–T09 + S01)
│   ├── T01_public_s3/
│   ├── T02_unencrypted_s3/
│   ├── ...
│   └── S01_secure_ebs/
├── pipeline/
│   ├── grounded_llm.py        # Policy-grounded LLM analysis (Groq API)
│   ├── evidence_verifier.py   # Deterministic 5-step verifier
│   └── checkov_baseline.py    # Checkov v3.3.15 baseline runner
├── benchmark/
│   └── iacSecBench_pilot/     # 12-case external benchmark (6 SAFE + 6 VULN)
├── results/
│   ├── ablation_study.json
│   ├── grounded_evaluation.json
│   └── iacSecBench_results.json
├── paper/
│   └── SecureIaC_Research_Paper_IEEE.docx
└── presentation/
    └── SecureIaC_Presentation.pptx
```

---

## Security Policies

9 YAML rules across 5 categories, each with `policy_id`, `clause_id`, `requirement`, and `evidence_source`:

| # | Policy ID | Category | Description |
|---|-----------|----------|-------------|
| 1 | STO-PUBLIC-ACCESS | S3 | Block public bucket ACLs |
| 2 | STO-ENCRYPTION | S3 | Enforce server-side encryption |
| 3 | STO-NO-ACCESS-LOGGING | S3 | Require access logging |
| 4 | NET-SSH-INGRESS | Network | Restrict SSH (port 22) ingress |
| 5 | NET-HTTP-INGRESS | Network | Restrict HTTP (port 80) ingress |
| 6 | IAM-WILDCARD-ACTION | IAM | Prohibit wildcard actions (`*`) |
| 7 | IAM-WILDCARD-RESOURCE | IAM | Prohibit wildcard resources (`*`) |
| 8 | EBS-ENCRYPTION | EBS | Enforce EBS volume encryption |
| 9 | RDS-PUBLIC-ACCESS | RDS | Block publicly accessible RDS |

---

## Testbed

10 frozen Terraform configurations used for all evaluations:

| ID | Config | Type |
|----|--------|------|
| T01 | Public S3 bucket | Vulnerable |
| T02 | Unencrypted S3 | Vulnerable |
| T03 | Unrestricted SSH ingress | Vulnerable |
| T04 | Unrestricted HTTP ingress | Vulnerable |
| T05 | IAM Action `*` on Resource `*` | Vulnerable |
| T06 | EBS encryption disabled | Vulnerable |
| T07 | RDS publicly accessible | Vulnerable |
| T08 | S3 without access logging | Vulnerable |
| T09 | IAM Resource `*` | Vulnerable |
| S01 | Secure EBS (control) | Secure |

Plus two contextual workloads:
- **C01** — Cross-file dependency (resource defined in a separate `.tf` file)
- **C02** — Variable chain: `var.db_public` → `local.rds_public` → `publicly_accessible`

---

## Ablation Study

| Configuration | Target Detection | Extra Findings | Verified |
|---------------|-----------------|----------------|----------|
| Checkov v3.3.15 | 9 / 9 (100%) | 44 total (out-of-scope included) | — (deterministic) |
| Ungrounded LLM | 9 / 9 (100%) | +1 extra (T07: `skip_final_snapshot`) | Not applied |
| Policy-Only LLM | 9 / 9 (100%) | 0 extra | Not applied |
| Grounded LLM | 9 / 9 (100%) | 0 extra | Not applied |
| **Grounded + Verifier** | **11 / 11 (100%)** | **0 extra** | **11 / 11 passed** |

---

## IaCSecBench Pilot Results

Evaluated on 12 cases (6 SAFE + 6 VULN), 3 repeated runs:

| Metric | Score | 95% CI (Wilson) |
|--------|-------|-----------------|
| Accuracy | 91.67% | 64.6% – 98.5% |
| Recall | 100% | 61.0% – 100% |
| Precision | 85.71% | 48.7% – 97.4% |
| Specificity | 83.33% | 43.6% – 97.0% |
| F1-Score | 92.31% | — |

Zero cross-run variance. Single reproducible FP: `STO-NO-ACCESS-LOGGING-SAFE` (policy-scope ambiguity, not hallucination).

---

## Setup

### Prerequisites

- Python 3.9+
- Node.js 18+ (for report generation)
- [Groq API key](https://console.groq.com/) (for LLM analysis)
- Checkov (`pip install checkov`)

### Install

```bash
git clone https://github.com/<your-username>/SecureIaC.git
cd SecureIaC
pip install -r requirements.txt
```

### Run

```bash
# Set your Groq API key
export GROQ_API_KEY=your_key_here

# Run Checkov baseline
python pipeline/checkov_baseline.py --config testbed/T01_public_s3/

# Run full SecureIaC pipeline
python pipeline/grounded_llm.py --config testbed/T01_public_s3/ --policy policies/

# Run evidence verifier on LLM output
python pipeline/evidence_verifier.py --finding output.json --config testbed/T01_public_s3/ --policy policies/
```

---

## LLM Configuration

- **Model:** `openai/gpt-oss-120b` via Groq API
- **Timeout:** 120 seconds
- **Retries:** 3
- **Output schema:** `policy_id`, `clause_id`, `description`, `affected_resource`, `evidence`, `reason`, `confidence`

---

## Citation

If you use SecureIaC in your research, please cite:

```
Harish S and Shailesh K S, "SecureIaC: Policy-Grounded LLM Security Analysis 
for Terraform Infrastructure-as-Code," Department of Computer Science and 
Engineering, Vellore Institute of Technology, Chennai, 2024.
```

---

## License

This project is for academic research purposes. See [LICENSE](LICENSE) for details.
