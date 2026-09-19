# SecureIaC

## Policy-Grounded LLM Security Analysis for Terraform Infrastructure-as-Code

SecureIaC is a hybrid Infrastructure-as-Code (IaC) security analysis
system that combines deterministic security scanning with LLM-based
contextual reasoning, explicit security-policy grounding, clause-level
traceability, Terraform evidence, and deterministic evidence
verification.

The project investigates whether policy grounding can constrain
LLM-generated IaC security findings to a defined security scope while
preserving detection of the intended vulnerabilities.

------------------------------------------------------------------------

## 1. Project Overview

Infrastructure-as-Code allows cloud infrastructure to be defined and
managed through machine-readable configuration such as Terraform. While
IaC improves reproducibility and automation, security misconfigurations
can propagate through deployment pipelines.

SecureIaC combines:

-   Checkov-based rule-driven analysis
-   Ungrounded LLM analysis
-   Security-policy grounding
-   Policy and clause-level traceability
-   Terraform evidence extraction
-   Deterministic evidence verification
-   Comparative evaluation
-   Contextual Terraform workloads
-   Ablation analysis

The main SecureIaC flow is:

``` text
Terraform + Security Policy
            |
            v
       Grounded LLM
            |
            v
Finding + Policy ID + Clause ID + Evidence
            |
            v
     Evidence Verifier
        /          \
   ACCEPT          REJECT
```

------------------------------------------------------------------------

## 2. Research Problem

Rule-based IaC security scanners are effective for known security checks
but can be limited when analysis requires contextual or semantic
reasoning.

LLMs can reason over Terraform configurations beyond fixed rules, but
they may also produce findings that are outside the intended security
scope.

SecureIaC therefore investigates a pipeline that combines:

1.  Deterministic IaC security analysis
2.  LLM-based contextual reasoning
3.  An explicit clause-structured security policy
4.  Policy and clause-level citation
5.  Terraform evidence
6.  Automated evidence verification
7.  Rejection of unsupported findings

------------------------------------------------------------------------

## 3. Research Hypothesis

### H1

> SecureIaC will reduce the rate of unsupported security findings by at
> least 20% compared with an ungrounded LLM-based IaC analysis when both
> approaches are evaluated under the same conditions.

### H0

> SecureIaC will not reduce the rate of unsupported security findings by
> at least 20% compared with an ungrounded LLM-based IaC analysis under
> the same evaluation conditions.

The 20% value is a research target/hypothesis and is **not assumed to be
an experimental result**.

------------------------------------------------------------------------

## 4. Project Architecture

The project evaluates multiple configurations:

### Rule-Based Baseline

``` text
Terraform
   |
   v
Checkov
   |
   v
Security Findings
```

### Ungrounded LLM

``` text
Terraform
   |
   v
LLM
   |
   v
Security Findings
```

### Policy-Only LLM

``` text
Terraform + Security Policy
   |
   v
LLM
   |
   v
Security Findings
```

### Grounded SecureIaC

``` text
Terraform + Security Policy
            |
            v
       Grounded LLM
            |
            v
Finding + Policy + Clause + Evidence
            |
            v
     Evidence Verifier
            |
       +----+----+
       |         |
       v         v
    ACCEPT     REJECT
```

------------------------------------------------------------------------

## 5. Repository Structure

The current repository contains the Review 1 baseline and the completed
Review 2 implementation:

``` text
SecureIac/
│
├── baseline/
│   ├── baseline_results.csv
│   ├── baseline_results.json
│   ├── baseline_results.txt
│   ├── test_cases.csv
│   └── ...
│
├── cloudsim/
│
├── evaluation/
│   └── grounded_evaluation.py
│
├── llm/
│   ├── grounded_llm.py
│   └── src/
│       ├── ungrounded_llm.py
│       └── ablation_policy_only.py
│
├── policy/
│   └── security_policy.yaml
│
├── results/
│   ├── ablation_policy_only/
│   ├── grounded/
│   ├── ungrounded/
│   ├── verified/
│   └── evaluation/
│
├── testbed/
│   ├── contextual/
│   │   ├── C01/
│   │   └── C02/
│   ├── secure/
│   │   └── S01_secure_ebs.tf
│   ├── vulnerable/
│   │   ├── T01_public_s3.tf
│   │   ├── T02_unencrypted_s3.tf
│   │   ├── T03_open_ssh.tf
│   │   ├── T04_open_http.tf
│   │   ├── T05_excessive_iam.tf
│   │   ├── T06_unencrypted_ebs.tf
│   │   ├── T07_public_rds.tf
│   │   ├── T08_s3_no_logging.tf
│   │   └── T09_broad_iam_resource.tf
│   └── main.tf
│
├── verifier/
│   └── evidence_verifier.py
│
├── review2_results.md
├── review2_graphs.py
├── review2_contextual_detection.png
├── review2_detection_rate.png
├── review2_extra_findings.png
├── test_gemini.py
├── test_groq.py
├── .gitignore
└── README.md
```

------------------------------------------------------------------------

## 6. Frozen Testbed

The main labelled testbed contains nine intentionally vulnerable
Terraform configurations and one secure configuration.

  ----------------------------------------------------------------------------------
  ID                Category          Intended          Expected Result
                                      Vulnerability     
  ----------------- ----------------- ----------------- ----------------------------
  T01               Storage           Missing S3 Public Vulnerable
                                      Access Block      

  T02               Storage           Missing S3        Vulnerable
                                      Encryption        

  T03               Network           Unrestricted SSH  Vulnerable
                                      Ingress           

  T04               Network           Unrestricted      Vulnerable
                                      Ingress           

  T05               IAM               Excessive         Vulnerable
                                      Permissions       

  T06               Storage           Missing EBS       Vulnerable
                                      Encryption        

  T07               Database          Public            Vulnerable
                                      Accessibility     

  T08               Logging           Missing S3 Access Vulnerable
                                      Logging           

  T09               Access Control    Overly Broad IAM  Vulnerable
                                      Policy            

  S01               Secure            Standard EBS      Secure-for-target-property
                    Configuration     Encryption        
                                      Enabled           
  ----------------------------------------------------------------------------------

The frozen labelled testbed is used for the main LLM comparison.

------------------------------------------------------------------------

## 7. Review 1 Checkov Baseline

Checkov provides the deterministic rule-based baseline.

Verified environment:

``` text
Terraform: 1.15.9
Checkov:   3.3.15
Python:    3.13.3
```

The baseline produced:

``` text
Failed Checkov findings:       44
Target vulnerable cases:       9 / 9
Target detection coverage:     100%
```

The 44 failed findings are individual Checkov check failures and are not
directly equivalent to the LLM "extra finding" count because multiple
Checkov findings can occur for one test case.

The 9/9 figure represents target-case detection coverage, not overall
Checkov accuracy, precision, or recall.

Baseline artefacts are maintained under:

``` text
baseline/
```

------------------------------------------------------------------------

## 8. Security Policy

The policy is stored in:

``` text
policy/security_policy.yaml
```

It contains 9 policy rules covering:

1.  S3 Public Access Block
2.  S3 Server-Side Encryption
3.  Restricted SSH Ingress
4.  Restricted HTTP Ingress
5.  IAM Least Privilege
6.  EBS Volume Encryption
7.  RDS Public Accessibility
8.  S3 Access Logging
9.  IAM Resource Scope

Each rule contains:

-   Stable policy ID
-   Title
-   Requirement
-   Target test case(s)
-   Source
-   Source URL
-   Clause ID
-   Evidence clause

Example:

``` text
POL-NET-001
└── POL-NET-001-C1
```

The policy is supplied to the grounded and policy-only LLM
configurations.

------------------------------------------------------------------------

## 9. Ungrounded LLM

Implementation:

``` text
llm/src/ungrounded_llm.py
```

The ungrounded configuration establishes the LLM baseline without
security-policy grounding.

### Input

``` text
Terraform only
```

The model does not receive:

-   `security_policy.yaml`
-   Policy IDs
-   Clause IDs

### Model

``` text
Groq
openai/gpt-oss-120b
```

The API key is loaded from a local `.env` file and is excluded from Git.

### Output

The LLM produces structured findings containing:

-   Test ID
-   Finding
-   Resource
-   Reason
-   Terraform evidence
-   Confidence

Raw and parsed outputs are stored under:

``` text
results/ungrounded/
```

### Results

The ungrounded LLM processed:

``` text
T01–T09 + S01
```

with:

``` text
Successful cases = 10
Failed cases     = 0
```

It detected:

``` text
Target vulnerabilities = 9/9
Target detection rate  = 100%
```

It also correctly produced no finding for S01.

One additional out-of-scope finding was observed in T07:

``` text
skip_final_snapshot = true
```

The intended T07 target was RDS public accessibility. The additional
finding was outside the target issue defined for the test case.

Therefore:

``` text
Target detection       = 9/9
Observed extra findings = 1
```

------------------------------------------------------------------------

## 10. Policy-Only LLM Ablation

Implementation:

``` text
llm/src/ablation_policy_only.py
```

The policy-only configuration receives:

``` text
Terraform + Security Policy
```

but does not require the LLM to return policy IDs or clause IDs.

Its purpose is to separate the effect of **providing the security
policy** from the additional effect of **explicit policy/clause
traceability**.

### Output

The policy-only configuration returns:

-   Test ID
-   Finding
-   Resource
-   Reason
-   Terraform evidence
-   Confidence

Raw and parsed outputs are stored under:

``` text
results/ablation_policy_only/
```

### Results

``` text
Target vulnerabilities = 9/9
Observed extra findings = 0
```

------------------------------------------------------------------------

## 11. Grounded SecureIaC LLM

Implementation:

``` text
llm/grounded_llm.py
```

The grounded configuration receives:

``` text
Terraform + Security Policy
```

and requires every finding to provide:

-   Finding
-   Resource
-   Reason
-   Policy ID
-   Clause ID
-   Terraform evidence
-   Confidence

### Prompt constraints

The grounded LLM is instructed to:

1.  Use only the supplied Terraform and security policy.
2.  Not invent policy IDs or clause IDs.
3.  Cite a policy rule and clause for every finding.
4.  Provide Terraform evidence supporting the finding.
5.  Report only issues represented by the supplied policy.
6.  Return an empty findings list when no policy-supported violation
    exists.
7.  Return structured JSON.

Raw and parsed outputs are stored under:

``` text
results/grounded/
```

### Results

``` text
Target vulnerabilities = 9/9
Observed extra findings = 0
```

------------------------------------------------------------------------

## 12. Comparative LLM Results

  Configuration       Target Detection   Observed Extra Findings
  ----------------- ------------------ -------------------------
  Ungrounded LLM            9/9 (100%)                         1
  Policy-only LLM           9/9 (100%)                         0
  Grounded LLM              9/9 (100%)                         0

The controlled experiment shows that introducing the security policy
maintained target detection while eliminating the one observed
out-of-scope finding.

The policy-only ablation also shows that the observed reduction cannot
be attributed specifically to clause citation, because policy-only
already produced zero observed extra findings.

------------------------------------------------------------------------

## 13. Evidence Verifier

Implementation:

``` text
verifier/evidence_verifier.py
```

The verifier prevents the system from blindly trusting LLM output.

### Verification flow

``` text
Grounded Finding
      |
      v
Policy Validation
      |
      v
Clause Validation
      |
      v
Test-Case Applicability
      |
      v
Finding-Policy Consistency
      |
      v
Terraform Evidence Check
      |
   +--+--+
   |     |
   v     v
ACCEPT REJECT
```

### Checks performed

The verifier checks:

1.  Whether the policy exists
2.  Whether the clause exists
3.  Whether the clause belongs to the cited policy
4.  Whether the policy applies to the test case
5.  Whether the finding matches the cited policy
6.  Whether the Terraform evidence supports the finding

Terraform whitespace is normalized before deterministic checks so
formatting differences do not create false rejections.

The verifier is currently designed around the evaluated policies and
controlled test cases. It is not claimed to be a general-purpose
semantic verifier.

------------------------------------------------------------------------

## 14. Verification Results

The verifier was evaluated on:

``` text
S01
T01–T09
C01
C02
```

Generated findings:

``` text
T01–T09 = 9
C01      = 1
C02      = 1
S01      = 0
```

Total:

``` text
11 findings
```

Verification:

``` text
Accepted = 11
Rejected = 0
```

------------------------------------------------------------------------

## 15. C01 --- Cross-File Contextual Workload

C01 evaluates cross-file Terraform reasoning.

The workload separates the relevant configuration across:

``` text
main.tf
security.tf
```

The EC2 instance in `main.tf` references a security group that is
defined in `security.tf`.

The security group allows unrestricted SSH:

``` text
TCP port 22
0.0.0.0/0
```

Reasoning chain:

``` text
main.tf
   ↓
EC2 references aws_security_group.web
   ↓
security.tf
   ↓
Security group
   ↓
TCP 22 from 0.0.0.0/0
   ↓
Unrestricted SSH
```

SecureIaC detected the vulnerability and mapped it to:

``` text
Policy: POL-NET-001
Clause: POL-NET-001-C1
```

The evidence verifier accepted the finding.

Checkov also detected C01. Therefore, C01 demonstrates the ability to
reason across Terraform files rather than establishing general
superiority over Checkov.

------------------------------------------------------------------------

## 16. C02 --- Indirect Terraform Reasoning

C02 evaluates reasoning through Terraform variables, conditions, locals,
and resource properties.

The tested relationship is:

``` text
environment = development
        ↓
development != production
        ↓
allow_public_access = true
        ↓
publicly_accessible = true
        ↓
RDS is publicly accessible
```

The final value is not directly written as:

``` hcl
publicly_accessible = true
```

Instead, it is derived through the Terraform expressions.

For the tested indirect configuration:

``` text
Checkov   = 0
SecureIaC = 1
```

SecureIaC detected the intended RDS public-access vulnerability and
mapped it to:

``` text
Policy: POL-RDS-001
Clause: POL-RDS-001-C1
```

The evidence verifier accepted the finding.

This result is specific to the tested configuration and should not be
generalized to all Terraform configurations or all Checkov analyses.

------------------------------------------------------------------------

## 17. Ablation Study

The ablation compares three LLM configurations:

### Configuration 1 --- Ungrounded

``` text
Terraform → LLM → Finding
```

Result:

``` text
Target detection = 9/9
Extra findings  = 1
```

### Configuration 2 --- Policy-only

``` text
Terraform + Policy → LLM → Finding
```

Result:

``` text
Target detection = 9/9
Extra findings  = 0
```

### Configuration 3 --- Grounded

``` text
Terraform + Policy
        ↓
LLM
        ↓
Finding + Policy ID + Clause ID + Evidence
        ↓
Verifier
```

Result:

``` text
Target detection = 9/9
Extra findings  = 0
```

### Interpretation

The preliminary ablation indicates that policy grounding maintained
target detection while eliminating the one observed out-of-scope
finding.

It does **not** isolate policy/clause citation as the cause of the
reduction because the policy-only configuration already produced zero
observed extra findings.

The main additional contribution of the grounded configuration is
explicit policy/clause-level traceability, which enables deterministic
evidence verification.

------------------------------------------------------------------------

## 18. Evaluation Pipeline

The grounded evaluation script is:

``` text
evaluation/grounded_evaluation.py
```

It loads:

``` text
baseline/test_cases.csv
```

as the frozen ground truth and reads:

``` text
results/verified/
```

for verified findings.

The evaluator computes:

-   TP
-   FP
-   FN
-   Precision
-   Recall
-   F1
-   Unsupported finding count
-   Unsupported finding rate
-   Total generated findings

Outputs:

``` text
results/evaluation/grounded_evaluation.csv
results/evaluation/grounded_evaluation.json
```

### Grounded main-testbed evaluation

For S01 + T01--T09:

``` text
TP = 9
FP = 0
FN = 0
TN = 1

Precision = 1.0000
Recall    = 1.0000
F1        = 1.0000

Unsupported findings = 0
Total generated findings = 9
Unsupported finding rate = 0.0000
```

These values apply to the controlled frozen testbed and current
evaluation methodology. They should not be presented as general-world
accuracy.

------------------------------------------------------------------------

## 19. Review 2 Results Summary

The repository also contains:

``` text
review2_results.md
```

The current comparative summary is:

  Method                  Target Detection   Extra Findings   Verification
  --------------------- ------------------ ---------------- --------------
  Checkov                              9/9       44 total\*            ---
  Ungrounded LLM                       9/9                1            ---
  Policy-only LLM                      9/9                0            ---
  Grounded LLM                         9/9                0            ---
  Grounded + Verifier        9/9 + C01/C02       0 rejected          11/11

\* Checkov's 44 findings include checks outside the nine predefined
target vulnerabilities and are therefore not directly equivalent to the
LLM extra-finding count.

------------------------------------------------------------------------

## 20. Review 2 Visual Results

The repository includes generated Review 2 graphs:

``` text
review2_detection_rate.png
review2_extra_findings.png
review2_contextual_detection.png
```

The graph-generation script is:

``` text
review2_graphs.py
```

These visuals are intended for Review 2 presentation and result
documentation.

------------------------------------------------------------------------

## 21. API and Environment Setup

### Requirements

Recommended environment:

``` text
Python 3.13+
Terraform
Checkov 3.3.15
Git
Groq API access
```

Python dependencies used by the implementation include:

``` text
PyYAML
python-dotenv
groq
```

### Virtual environment

Create:

``` bash
python3 -m venv .venv
```

Activate on macOS/Linux:

``` bash
source .venv/bin/activate
```

Activate on Windows PowerShell:

``` powershell
.\.venv\Scripts\Activate.ps1
```

### Install dependencies

``` bash
pip install pyyaml python-dotenv groq
```

### API key

Create a local `.env` file:

``` env
GROQ_API_KEY=your_api_key_here
```

Never commit the API key.

------------------------------------------------------------------------

## 22. Running the LLM Experiments

### Ungrounded LLM

``` bash
python3 llm/src/ungrounded_llm.py
```

Outputs:

``` text
results/ungrounded/
```

### Policy-only ablation

``` bash
python3 llm/src/ablation_policy_only.py
```

Outputs:

``` text
results/ablation_policy_only/
```

### Grounded LLM

``` bash
python3 llm/grounded_llm.py
```

Outputs:

``` text
results/grounded/
```

------------------------------------------------------------------------

## 23. Running Verification

Run:

``` bash
python3 verifier/evidence_verifier.py
```

Verified results:

``` text
results/verified/
```

------------------------------------------------------------------------

## 24. Running Evaluation

Run:

``` bash
python3 evaluation/grounded_evaluation.py
```

Results:

``` text
results/evaluation/
```

------------------------------------------------------------------------

## 25. Security / Git Hygiene

API keys must not be committed to GitHub.

Before pushing:

``` bash
git status
git check-ignore .env
```

The project should ignore:

``` text
.env
.venv/
__pycache__/
```

Raw LLM outputs and evaluation artefacts may be committed when they
contain no secrets.

------------------------------------------------------------------------

## 26. Threats to Validity

### 1. Small and Controlled Testbed

The evaluation uses a limited number of predefined Terraform
configurations and does not represent the full range of real-world IaC.

### 2. Limited Contextual Workloads

Only C01 and C02 were evaluated as contextual workloads.

They demonstrate:

-   Cross-file reasoning
-   Indirect variable/local reasoning

More complex multi-resource and multi-file workloads are required to
establish broader generalization.

### 3. Policy Dependence

The grounded approach depends on the security policies supplied to the
LLM.

The current evaluation does not establish behavior when policies are
incomplete, ambiguous, or incorrectly specified.

### 4. Deterministic Verifier Scope

The verifier is currently implemented around the policies and Terraform
patterns evaluated in this testbed.

Successful verification therefore does not establish arbitrary Terraform
verification capability.

### 5. Preliminary Evaluation

The current experiments are controlled and do not establish statistical
generalization across multiple independent runs or large real-world
workloads.

### 6. Checkov Comparison

The C02 Checkov difference is specific to the tested configuration and
should not be generalized to all Terraform configurations or Checkov
analyses.

------------------------------------------------------------------------

## 27. Project Status

### Review 1

``` text
Literature Review          ✓
Research Gap               ✓
Problem Statement          ✓
Research Hypothesis        ✓
Terraform Testbed          ✓
Ground Truth               ✓
Checkov Baseline           ✓
CloudSim                   ✓
```

### Review 2

``` text
Ungrounded LLM             ✓
Security Policy            ✓
Grounded LLM               ✓
Policy/Clause Traceability ✓
Evidence Verifier          ✓
Comparative Evaluation     ✓
C01 Contextual Workload    ✓
C02 Contextual Workload    ✓
Policy-only Ablation       ✓
Review 2 Graphs            ✓
Threats to Validity        ✓
```

------------------------------------------------------------------------

## 28. Team Work

The implementation was developed collaboratively.

### Grounded SecureIaC work

-   Security policy creation
-   Policy grounding
-   Grounded LLM pipeline
-   Policy/clause traceability
-   Evidence verifier
-   Grounded evaluation
-   C01/C02 contextual workloads
-   Policy-only ablation

### Ungrounded baseline work

-   Ungrounded LLM implementation
-   Ungrounded LLM execution
-   Evaluation of the ungrounded configuration
-   Identification of the observed T07 extra finding

### Shared work

-   Frozen Terraform testbed
-   Ground-truth definitions
-   Experimental methodology
-   Review 2 result comparison
-   Repository and documentation
-   Review 2 graphs

------------------------------------------------------------------------

## 29. Important Interpretation Notes

The following distinctions are important when presenting the results:

### 9/9 detection

The 9/9 result means all nine predefined target vulnerabilities were
detected.

It does not mean:

``` text
100% general accuracy
```

### 44 Checkov findings vs 1 LLM extra finding

The 44 Checkov failures are individual check failures and may include
multiple findings for one test case.

The LLM "extra finding" count refers to findings outside the predefined
target issue scope.

These counts should therefore not be directly treated as equivalent
metrics.

### Grounded + verifier

The verifier result of 11 accepted and 0 rejected applies to the
evaluated S01, T01--T09, C01 and C02 cases.

It does not prove general-purpose semantic verification accuracy.

### Research hypothesis

The 20% unsupported-finding reduction is the research hypothesis target.

The current preliminary comparison shows one observed extra finding for
the ungrounded configuration and zero for policy-only/grounded
configurations, but the project should avoid presenting this controlled
observation as universal performance.

------------------------------------------------------------------------

## 30. Conclusion

SecureIaC now provides a working policy-grounded LLM security-analysis
pipeline for the evaluated Terraform workloads.

The implementation progresses from:

``` text
Ungrounded LLM
      ↓
Security Policy Grounding
      ↓
Policy + Clause Traceability
      ↓
Terraform Evidence
      ↓
Deterministic Evidence Verification
```

On the controlled Review 2 testbed:

-   Ungrounded LLM detected 9/9 target vulnerabilities and produced one
    observed out-of-scope finding.
-   Policy-only LLM detected 9/9 and produced zero observed extra
    findings.
-   Grounded LLM detected 9/9 and produced zero observed extra findings.
-   Grounded findings were mapped to explicit policy and clause
    identifiers.
-   The verifier accepted all 11 findings evaluated across T01--T09, C01
    and C02.
-   C01 demonstrated cross-file Terraform reasoning.
-   C02 demonstrated indirect variable/local Terraform reasoning.
-   The ablation showed that policy grounding maintained target
    detection while removing the observed extra finding.
-   Clause-level citation provides traceability and enables the
    deterministic verification stage.

The current results demonstrate the feasibility of the proposed
SecureIaC approach on the controlled testbed while acknowledging the
stated threats to validity and limitations.
