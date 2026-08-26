# SecureIaC

## AI-Powered Infrastructure-as-Code Security Analyzer

SecureIaC is a proposed hybrid security analysis system for detecting security misconfigurations in Infrastructure-as-Code (IaC).

The project is designed to combine **deterministic rule-based security analysis** with **LLM-based contextual reasoning**, **security-policy grounding**, **clause-level evidence citation**, and **automated verification and rejection of unsupported findings**.

---

## 1. Project Overview

Infrastructure-as-Code allows cloud infrastructure to be defined and managed through machine-readable configuration files such as Terraform configurations. While IaC improves reproducibility and automation, security misconfigurations in these files can propagate across environments through automated deployment pipelines.

Traditional IaC security scanners such as Checkov are effective at detecting known, pattern-based misconfigurations. However, rule-based approaches have limitations when security issues depend on configuration context or require semantic reasoning.

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

The architecture above represents the proposed final SecureIaC system. The Review 1 implementation currently establishes the research foundation and rule-based baseline; the LLM, grounding, citation, and verification components remain future implementation work.

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

* Checkov 3.3.15

### Cloud Simulation

* CloudSim

### Programming / Development

* Python 3.13.3
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

## 7. Review 1 Status

The substantive Review 1 work has been completed. The remaining Review 1 deliverable is the presentation/PPT.

### Completed

* [x] Literature review
* [x] Research gap identification
* [x] Problem statement
* [x] Research hypothesis
* [x] Terraform development environment setup
* [x] Git/GitHub repository setup
* [x] Checkov installation and baseline setup
* [x] Terraform security testbed
* [x] Secure and vulnerable Terraform test cases
* [x] Ground-truth mapping for the baseline test cases
* [x] Checkov baseline scan
* [x] Raw Checkov TXT output
* [x] Raw Checkov JSON output
* [x] Baseline results documentation
* [x] CloudSim component completed by the teammate
* [x] README updated for the Review 1 implementation

### Future SecureIaC Implementation

* [ ] LLM-based analysis
* [ ] Security-policy document
* [ ] Policy grounding
* [ ] Clause-level evidence citation
* [ ] Automated evidence verification
* [ ] Unsupported-finding rejection
* [ ] Final SecureIaC evaluation

---

## 8. Current Testbed

The current Terraform baseline contains **9 intentionally vulnerable test cases (T01–T09)** and **1 secure test case (S01)** used to establish the initial rule-based baseline.

The vulnerable cases cover multiple IaC security categories, including:

* S3 security
* Network/security-group configuration
* IAM permissions
* EBS configuration
* RDS configuration
* Logging and access-control related issues

The secure case provides a positive control for the baseline environment.

The testbed is designed so that the expected security state of each test case is known in advance through the ground-truth mapping.

---

## 9. Checkov Baseline

Checkov is the current deterministic rule-based baseline for SecureIaC.

The verified environment uses:

```text
Checkov: 3.3.15
Terraform: 1.15.9
Python: 3.13.3
```

The baseline was executed against the labelled Terraform testbed and produced raw results in both TXT and JSON formats.

The baseline scan produced:

```text
Failed findings: 44
Target vulnerable cases detected: 9 / 9
Target detection coverage: 100%
```

The **9/9 (100%) figure refers to detection of the nine target vulnerable test cases**. It should not be interpreted as an overall accuracy, precision, or recall score for the complete Checkov output.

The 44 failed findings represent individual Checkov check failures across the testbed. Multiple findings may be reported for the same vulnerable test case.

The baseline establishes the initial rule-based reference point against which later LLM-based and SecureIaC approaches can be evaluated.

---

## 10. Baseline Ground Truth

A ground-truth mapping was created for the Terraform testbed so that the expected security state of each test case is known before comparing analysis approaches.

The baseline currently contains:

| Category | Test Cases | Expected State |
| --- | --- | --- |
| Vulnerable IaC | T01–T09 | Vulnerable |
| Secure IaC | S01 | Secure |

The vulnerable cases cover S3, network, IAM, EBS, RDS, and logging/access-control related security conditions.

The ground truth will be used as the reference for later evaluation of detection quality.

---

## 11. Baseline Outputs

The Checkov baseline includes machine-readable and human-readable outputs.

### TXT Output

The TXT output provides a readable record of the Checkov scan and its failed checks.

### JSON Output

The JSON output provides structured Checkov findings that can be reused by later evaluation scripts or analysis components.

These outputs provide the initial evidence required to compare deterministic rule-based detection with future LLM-based approaches.

---

## 12. Planned Evaluation

The final evaluation will use labelled Terraform configurations containing known secure and vulnerable cases.

Each test case will have a documented ground truth.

Example:

| Test Case | Configuration | Expected Result | Vulnerability |
| --- | --- | --- | --- |
| T01 | Public S3 configuration | Vulnerable | Public access |
| T02 | Encrypted S3 configuration | Vulnerable / Secure according to test definition | S3 security configuration |
| T03 | Open security group | Vulnerable | Unrestricted ingress |
| T04 | Restricted security group | Secure | None |
| T05 | Excessive IAM permissions | Vulnerable | Excessive privileges |

> The example table is illustrative. The authoritative test-case definitions and ground truth are maintained in the project testbed and baseline results.

The final dataset will be expanded or refined as the SecureIaC implementation progresses.

---

## 13. Evaluation Metrics

The project will consider metrics such as:

* True Positives (TP)
* False Positives (FP)
* False Negatives (FN)
* Precision
* Recall
* F1-score
* Unsupported finding rate

The primary research focus will be the reduction of unsupported security findings when policy grounding and evidence verification are introduced.

The current baseline result of **9/9 target vulnerable cases detected** is a baseline detection result, not the final research evaluation.

---

## 14. Planned Baseline Comparisons

The project is expected to compare multiple configurations of the analysis pipeline.

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

## 15. Research Gap

The literature review identified that existing research separately demonstrates:

* High precision of rule-based IaC security analysis
* Contextual reasoning capabilities of LLM-based approaches
* Hallucination and false-positive risks in LLM-based analysis
* Benefits of grounding and RAG techniques
* General evidence and claim-verification approaches

However, the reviewed literature does not demonstrate a single IaC security pipeline combining deterministic rules, LLM reasoning, explicit clause-structured policy grounding, clause-level evidence citation, automated evidence verification, and rejection of unsupported findings.

SecureIaC is designed to investigate this gap.

---

## 16. Repository Structure

The current repository contains the Review 1 baseline work. It will evolve as the SecureIaC implementation progresses.

Current/established structure:

```text
SecureIaC/
│
├── testbed/
│   └── Terraform test cases
│
├── baseline/
│   ├── Checkov results
│   └── Ground-truth information
│
├── .gitignore
├── README.md
└── project files
```

The final implementation is expected to evolve toward:

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

## 17. Development Environment

The verified development environment is:

```text
Operating System: Windows
IaC: Terraform 1.15.9
Security Scanner: Checkov 3.3.15
Programming Language: Python 3.13.3
Cloud Simulation: CloudSim
Version Control: Git / GitHub
```

A local Python virtual environment is used for development and should not be committed to the repository.

---

## 18. Running the Current Checkov Baseline

Activate the project virtual environment:

```powershell
.\.venv\Scripts\Activate.ps1
```

Navigate to the Terraform testbed:

```powershell
cd testbed
```

Run Checkov:

```powershell
checkov -d .
```

The command scans the Terraform configurations in the testbed and reports the security checks that pass or fail.

The raw baseline results should be retained in the project's baseline/results area for reproducibility.

---

## 19. Cloud Simulation

CloudSim has been completed as part of the project work by the teammate.

It forms part of the broader project setup and complements the Terraform/Checkov security-analysis work.

The current README records CloudSim as completed for Review 1; the detailed CloudSim implementation and configuration should be maintained in the corresponding project files.

---

## 20. Development Roadmap

### Phase 1 — Research and Baseline — Completed for Review 1

* Literature review
* Research gap identification
* Problem statement and hypothesis
* Terraform development environment
* Git/GitHub repository setup
* Terraform security testbed
* Secure and vulnerable test cases
* Ground-truth mapping
* Checkov baseline
* Raw TXT and JSON baseline outputs
* Baseline result documentation
* CloudSim component

### Phase 2 — Review 1 Presentation

* Review 1 PPT / presentation

### Phase 3 — LLM Analysis

* LLM integration
* Terraform security-analysis prompts
* Ungrounded LLM baseline
* Evaluation of LLM findings

### Phase 4 — Policy Grounding

* Security-policy document
* Policy retrieval / grounding
* Clause-level citation
* Grounded LLM evaluation

### Phase 5 — Evidence Verification

* Evidence verification mechanism
* Evidence support checking
* Automatic rejection of unsupported findings

### Phase 6 — Final Evaluation

* Compare all baselines
* Measure precision, recall and F1
* Measure unsupported finding rate
* Measure reduction in unsupported findings
* Analyze limitations and failure cases

---

## 21. Project Team

**Team Members**

* Harish
* Shailesh KS

---

## 22. Current Project Status

SecureIaC has completed the substantive technical and research work required for Review 1, with the **Review 1 PPT/presentation remaining as the main outstanding deliverable**.

The completed work currently establishes:

1. The research motivation and gap.
2. The SecureIaC research hypothesis.
3. The Terraform-based IaC testbed.
4. A labelled set of 9 vulnerable test cases and 1 secure test case.
5. Ground-truth mapping for the baseline.
6. A reproducible Checkov 3.3.15 rule-based baseline.
7. Raw TXT and JSON Checkov outputs.
8. A baseline result showing detection of all 9 target vulnerable cases.
9. CloudSim work completed.
10. Repository and documentation updates.

The LLM reasoning, policy grounding, clause-level citation, evidence verification, unsupported-finding rejection, and final comparative evaluation remain the main implementation stages after Review 1.

> **Important:** The current baseline results are preliminary project results and should not be presented as the final SecureIaC evaluation or as proof of the research hypothesis. The 20% improvement remains the research target to be tested experimentally.
