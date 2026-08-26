# SecureIaC

## AI-Powered Infrastructure-as-Code Security Analyzer

SecureIaC is a proposed hybrid security analysis system for detecting security misconfigurations in Infrastructure-as-Code (IaC).

The project combines **deterministic rule-based security analysis** with **LLM-based contextual reasoning**, **security-policy grounding**, **clause-level evidence citation**, and **automated verification and rejection of unsupported findings**.

---

## 1. Project Overview

Infrastructure-as-Code allows cloud infrastructure to be defined and managed through machine-readable configuration files such as Terraform configurations. While IaC improves reproducibility and automation, security misconfigurations in these files can propagate across environments through automated deployment pipelines.

Traditional IaC security scanners such as Checkov and tfsec are effective at detecting known, pattern-based misconfigurations. However, rule-based approaches have limitations when security issues depend on configuration context or require semantic reasoning.

LLM-based approaches can provide contextual reasoning beyond fixed security rules, but they may produce hallucinated or unsupported security findings.

SecureIaC aims to combine the strengths of both approaches while introducing an additional evidence-verification layer to improve the reliability of LLM-generated security findings.

---

## 2. Research Problem

Existing rule-based IaC security tools provide reliable detection of known-pattern misconfigurations but have limited contextual reasoning capabilities. LLM-based approaches can improve contextual detection but introduce hallucination and false-positive risks.

The reviewed literature does not demonstrate an IaC security pipeline that combines:

* Deterministic IaC security rules
* LLM-based contextual reasoning
* An explicit clause-structured security-policy document
* Clause-level citation for generated findings
* Automated verification of cited evidence
* Automatic rejection of unsupported findings

SecureIaC investigates this combination as a potential approach for improving the reliability of IaC security analysis.

---

## 3. Research Hypothesis

**H1:** SecureIaC will reduce the rate of unsupported security findings by at least **20%** compared with an ungrounded LLM-based IaC analysis when both approaches are evaluated on the same labelled Terraform testbed and security-analysis tasks.

### Null Hypothesis

**H0:** SecureIaC will not reduce the rate of unsupported security findings by at least **20%** compared with the ungrounded LLM-based IaC analysis under the same evaluation conditions.

> The 20% value is a research target/hypothesis and is not an experimental result.

---

## 4. Proposed SecureIaC Architecture

The planned SecureIaC pipeline consists of the following stages:

```text
                 Infrastructure-as-Code
                          │
                          ▼
               ┌─────────────────────┐
               │ Rule-Based Analysis │
               │      Checkov        │
               └──────────┬──────────┘
                          │
                          ▼
               ┌─────────────────────┐
               │   LLM Reasoning     │
               │ Contextual Analysis │
               └──────────┬──────────┘
                          │
                          ▼
               ┌─────────────────────┐
               │ Policy Grounding    │
               │ Security Policy     │
               └──────────┬──────────┘
                          │
                          ▼
               ┌─────────────────────┐
               │ Clause-Level        │
               │ Evidence Citation   │
               └──────────┬──────────┘
                          │
                          ▼
               ┌─────────────────────┐
               │ Evidence Verification│
               └──────────┬──────────┘
                          │
                    ┌─────┴─────┐
                    │           │
                  Valid       Invalid
                    │           │
                    ▼           ▼
                Accepted      Rejected
                Finding       Finding
```

The complete architecture is a planned system and is being developed incrementally.

---

## 5. Project Objectives

The main objectives of SecureIaC are:

1. Detect known IaC security misconfigurations using deterministic security rules.
2. Investigate the use of LLMs for contextual and semantic IaC security analysis.
3. Ground LLM-generated findings using an explicit security-policy document.
4. Require generated findings to identify supporting policy clauses.
5. Automatically verify whether the cited evidence supports the generated finding.
6. Reject findings that cannot be sufficiently supported by the available evidence.
7. Quantitatively evaluate the reduction in unsupported findings.
8. Compare the proposed approach against appropriate rule-based and LLM-based baselines.

---

## 6. Current Technology Stack

### Infrastructure-as-Code

* Terraform

### Security Analysis

* Checkov

### Programming / Development

* Python
* Terraform
* Git

### Version Control

* Git
* GitHub

### Planned Components

* Large Language Model (LLM)
* Security-policy knowledge base
* Evidence verification component
* Evaluation and metrics pipeline

---

## 7. Current Project Status

### Review 1

* [x] Literature review
* [x] Research gap identification
* [x] Problem statement
* [x] Research hypothesis
* [x] Terraform environment setup
* [x] Checkov installation and baseline environment setup
* [x] Initial Terraform testbed
* [x] Successful Checkov scan
* [ ] Final Terraform test-case dataset
* [ ] Baseline evaluation and metrics
* [ ] LLM-based analysis
* [ ] Security-policy document
* [ ] Policy grounding
* [ ] Clause-level evidence citation
* [ ] Automated evidence verification
* [ ] Unsupported-finding rejection
* [ ] Final SecureIaC evaluation

---

## 8. Current Testbed

The initial testbed uses Terraform configurations that can be scanned using Checkov.

Current repository structure:

```text
SecureIaC/
│
├── .gitignore
├── README.md
├── .venv/
│
└── testbed/
    └── main.tf
```

The `.venv` directory is a local Python virtual environment and is not intended to be committed to the repository.

The testbed will be expanded with secure and intentionally vulnerable Terraform configurations for controlled evaluation.

---

## 9. Initial Baseline

Checkov is being used as the initial rule-based baseline because the reviewed literature identifies rule-based IaC security scanners as effective for known, pattern-based misconfigurations.

The current environment successfully runs Checkov against Terraform configurations.

Example command:

```bash
checkov -d ./testbed
```

The initial test produced:

```text
Passed checks: 4
Failed checks: 7
Skipped checks: 0
```

The scan identified several S3-related security checks, including:

* Missing S3 public access block
* Missing access logging
* Missing KMS encryption configuration
* Missing versioning
* Missing lifecycle configuration
* Missing cross-region replication
* Missing event notifications

These initial results demonstrate that the Terraform testbed can be successfully analyzed by the rule-based baseline.

Formal baseline metrics will be calculated after the labelled test-case dataset is finalized.

---

## 10. Planned Evaluation

The evaluation will use labelled Terraform configurations containing known secure and vulnerable cases.

Each test case will have a documented ground truth.

Example:

| Test Case | Configuration              | Expected Result | Vulnerability        |
| --------- | -------------------------- | --------------- | -------------------- |
| T01       | Public S3 configuration    | Vulnerable      | Public access        |
| T02       | Encrypted S3 configuration | Secure          | None                 |
| T03       | Open security group        | Vulnerable      | Unrestricted ingress |
| T04       | Restricted security group  | Secure          | None                 |
| T05       | Excessive IAM permissions  | Vulnerable      | Excessive privileges |

The final dataset will be expanded to cover multiple IaC security categories.

---

## 11. Evaluation Metrics

The project will consider metrics such as:

* True Positives (TP)
* False Positives (FP)
* False Negatives (FN)
* Precision
* Recall
* F1-score
* Unsupported finding rate

The primary research focus will be the reduction of unsupported security findings when policy grounding and evidence verification are introduced.

---

## 12. Planned Baseline Comparisons

The project is expected to compare multiple configurations of the analysis pipeline:

### Baseline 1 — Rule-Based

```text
Terraform
    ↓
Checkov
    ↓
Security Findings
```

### Baseline 2 — Ungrounded LLM

```text
Terraform
    ↓
LLM
    ↓
Security Findings
```

### Baseline 3 — Grounded LLM

```text
Terraform + Security Policy
    ↓
LLM
    ↓
Grounded Findings
```

### Proposed SecureIaC

```text
Terraform
    ↓
Rule-Based Analysis + LLM
    ↓
Policy Grounding
    ↓
Clause-Level Citation
    ↓
Evidence Verification
    ↓
Accepted / Rejected Findings
```

The exact experimental design and final comparison methodology will be finalized during implementation.

---

## 13. Research Gap

The literature review identified that existing research separately demonstrates:

* High precision of rule-based IaC security analysis
* Contextual reasoning capabilities of LLM-based approaches
* Hallucination and false-positive risks in LLM-based analysis
* Benefits of grounding and RAG techniques
* General evidence and claim-verification approaches

However, the reviewed literature does not demonstrate a single IaC security pipeline combining deterministic rules, LLM reasoning, explicit clause-structured policy grounding, clause-level evidence citation, automated evidence verification, and rejection of unsupported findings.

SecureIaC is designed to investigate this gap.

---

## 14. Repository Structure

The repository will evolve as the project progresses.

Planned structure:

```text
SecureIaC/
│
├── testbed/
│   ├── secure/
│   └── vulnerable/
│
├── policy/
│   └── security_policy.md
│
├── baseline/
│   └── checkov/
│
├── src/
│   ├── llm/
│   ├── grounding/
│   ├── verification/
│   └── analysis/
│
├── results/
│
├── .gitignore
├── README.md
└── requirements.txt
```

---

## 15. Development Environment

The current development environment uses:

```text
Operating System: Windows
IaC: Terraform
Security Scanner: Checkov
Programming Language: Python
Version Control: Git / GitHub
```

Current verified versions:

```text
Terraform: 1.15.9
Checkov: 3.3.15
Python: 3.13.3
```

---

## 16. Running the Current Testbed

Activate the project virtual environment:

```powershell
.\.venv\Scripts\Activate.ps1
```

Navigate to the testbed:

```powershell
cd testbed
```

Run Checkov:

```powershell
checkov -d .
```

The command scans the Terraform configurations in the testbed and reports the security checks that pass or fail.

---

## 17. Development Roadmap

### Phase 1 — Research and Baseline

* Literature review
* Research gap identification
* Problem statement and hypothesis
* Terraform testbed
* Checkov baseline
* Ground-truth dataset
* Baseline metrics

### Phase 2 — LLM Analysis

* LLM integration
* Terraform security-analysis prompts
* Ungrounded LLM baseline
* Evaluation of LLM findings

### Phase 3 — Policy Grounding

* Security-policy document
* Policy retrieval / grounding
* Clause-level citation
* Grounded LLM evaluation

### Phase 4 — Evidence Verification

* Evidence verification mechanism
* Support checking
* Automatic rejection of unsupported findings

### Phase 5 — Final Evaluation

* Compare all baselines
* Measure precision, recall and F1
* Measure unsupported finding rate
* Measure reduction in unsupported findings
* Analyze limitations and failure cases

---

## 18. Project Team

**Team Members**

* Harish
* Shailesh KS

---

## 19. Note on Project Status

SecureIaC is currently under development. Components marked as planned or incomplete in this README should not be interpreted as completed functionality.

The repository will be updated as implementation, experimentation, and evaluation progress.
