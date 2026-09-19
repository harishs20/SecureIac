# SecureIaC — Review 2 Preliminary Results

## Comparative Evaluation

| Method | Target Detection | Extra Findings | Verification |
|---|---:|---:|---:|
| Checkov | 9/9 (100%) | 44 total* | — |
| Ungrounded LLM | 9/9 (100%) | 1 | — |
| Policy-only LLM | 9/9 (100%) | 0 | — |
| Grounded LLM | 9/9 (100%) | 0 | — |
| Grounded + Verifier | 9/9 + C01/C02 | 0 rejected | 11/11 |

\* Checkov's 44 findings include checks outside the nine predefined
target vulnerabilities, so they are not directly equivalent to the
LLM's "extra findings" count.

---

## Interpretation

### Checkov Baseline

Checkov detected all nine predefined target vulnerabilities in the
initial Terraform testbed.

Target detection:

**9/9 = 100%**

This provides the baseline for comparison with the LLM-based approaches.

### Ungrounded LLM

The ungrounded LLM received Terraform configurations without the
security policy.

It detected:

**9/9 target vulnerabilities**

However, it also produced one additional out-of-scope finding in T07.

### Policy-only LLM

The policy-only version received both the Terraform configuration and
the security policy, but did not require policy/clause identifiers.

It detected:

**9/9 target vulnerabilities**

No additional out-of-scope finding was observed.

### Grounded LLM

The grounded LLM received the Terraform configuration together with
the security policy and was required to provide:

- Policy ID
- Clause ID
- Evidence
- Finding
- Reason
- Confidence

It detected:

**9/9 target vulnerabilities**

No additional out-of-scope finding was observed.

### Grounded LLM + Evidence Verifier

The deterministic verifier independently checked the generated findings
against the security policy and Terraform evidence.

The evaluation contained:

- T01–T09: 9 findings
- C01: 1 finding
- C02: 1 finding

Total:

**11 findings**

Verification result:

**11 accepted**
**0 rejected**

---

## Contextual Workloads

### C01 — Cross-file reasoning

C01 separates the relevant Terraform configuration across two files.

`main.tf` references a security group, while `security.tf` defines the
security group and its unrestricted SSH ingress rule.

SecureIaC identified the unrestricted SSH access and associated it with:

- Policy: POL-NET-001
- Clause: POL-NET-001-C1

The deterministic verifier accepted the finding.

### C02 — Indirect configuration reasoning

C02 uses a variable and local expression to determine whether an RDS
instance is publicly accessible.

The configuration evaluates as:

development environment
→ environment is not production
→ allow_public_access = true
→ publicly_accessible = true

SecureIaC identified the RDS public-access violation and associated it
with:

- Policy: POL-RDS-001
- Clause: POL-RDS-001-C1

The deterministic verifier accepted the finding.

---

## Preliminary Observation

The ungrounded LLM detected all nine target vulnerabilities but produced
one additional out-of-scope finding.

After introducing policy grounding, the target detection remained 9/9
while the observed extra finding was reduced to zero.

The policy-only ablation shows that this observed reduction occurred
after adding policy grounding. The current experiment does not isolate
policy/clause citation as the cause of that reduction.

The contextual cases further demonstrate that the grounded pipeline can
handle the evaluated cross-file and indirect variable/local
configurations.

---

## Important Limitation

The current results are preliminary and come from a controlled testbed.
They do not establish general superiority over Checkov or other IaC
security analysis approaches.

The deterministic verifier is also currently implemented for the
evaluated policies and test cases.

## Ablation Study

### Purpose

The ablation study was performed to determine whether security-policy
grounding changes the behavior of the LLM-based IaC analyzer.

Three configurations were compared:

1. Ungrounded LLM
2. Policy-only LLM
3. Grounded LLM

### Configuration 1 — Ungrounded LLM

The LLM receives only the Terraform configuration and is asked to
identify security issues.

Result:

- Target vulnerabilities detected: 9/9
- Observed extra/out-of-scope findings: 1

This establishes the behavior of the LLM without policy grounding.

### Configuration 2 — Policy-only LLM

The LLM receives both the Terraform configuration and the security
policy.

However, it is not required to provide policy IDs or clause IDs.

Result:

- Target vulnerabilities detected: 9/9
- Observed extra/out-of-scope findings: 0

Compared with the ungrounded configuration, the target detection rate
remained unchanged while the observed extra finding was eliminated.

### Configuration 3 — Grounded LLM

The LLM receives the Terraform configuration and security policy and is
required to provide policy and clause references together with the
finding and Terraform evidence.

Result:

- Target vulnerabilities detected: 9/9
- Observed extra/out-of-scope findings: 0

This configuration provides explicit traceability from the finding to
the security policy and its specific clause.

### Ablation Observation

The preliminary results show that introducing the security policy
maintained target detection at 9/9 while reducing the observed
out-of-scope findings from 1 to 0.

Therefore, in the evaluated testbed, policy grounding appears to
constrain the LLM's findings to the defined security scope.

The experiment does not isolate policy/clause citation as the cause of
the reduction, because the policy-only configuration already produced
zero observed extra findings.

The main additional contribution of the grounded configuration is
therefore explicit policy/clause-level traceability, which enables the
subsequent deterministic evidence-verification stage.

## Threats to Validity

The current evaluation has several limitations that should be considered
when interpreting the results.

### 1. Small and Controlled Testbed

The evaluation uses a limited set of predefined Terraform configurations.
The nine vulnerable cases and two contextual cases do not represent the
full range of real-world Infrastructure-as-Code configurations.

### 2. Limited Contextual Workloads

Only two contextual cases, C01 and C02, were evaluated. These demonstrate
cross-file reasoning and indirect variable/local reasoning, but more
complex multi-resource and multi-file workloads are required to determine
whether the observed behavior generalizes.

### 3. Policy Dependence

The grounded approach depends on the security policies supplied to the
LLM. The current evaluation uses a predefined policy set, so it does not
yet establish how the system behaves when policies are incomplete,
ambiguous, or incorrectly specified.

### 4. Deterministic Verifier Scope

The evidence verifier is currently implemented for the policies and
Terraform patterns evaluated in this testbed. Therefore, its successful
verification does not establish that it can automatically verify
arbitrary Terraform security findings.

### 5. Preliminary Evaluation

The current Review 2 results are preliminary. The experiments do not yet
include multiple independent runs, large workloads, or statistical
analysis. These aspects are planned for the more extensive evaluation.

### 6. Checkov Comparison

The Checkov comparison is based on the specific configurations and
checks evaluated in this study. The observed C02 difference should not
be generalized to all Terraform configurations or all Checkov analyses.

### Overall Limitation

Therefore, the current results demonstrate the feasibility of the
proposed policy-grounded and evidence-verified approach on the evaluated
testbed, but they do not establish general superiority over existing
IaC
security analysis tools.