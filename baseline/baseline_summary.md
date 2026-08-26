# Checkov Baseline Summary

## Dataset

- Vulnerable Terraform test cases: 9
- Secure-target test cases: 1
- Scanner: Checkov 3.3.15

## Results

Across the 9 vulnerable test cases:

- Total intended vulnerabilities: 9
- Intended vulnerabilities detected: 9
- Target detection rate: 100%
- Total Checkov failed findings: 44

## Secure Target Case

S01 tests standard EBS encryption.

- Target policy CKV_AWS_3: PASS
- Additional policy CKV_AWS_189: FAIL

Therefore, S01 is considered secure with respect to the target property, but not fully compliant with every Checkov policy.

## Interpretation

The baseline demonstrates that Checkov detected all intentionally introduced target vulnerabilities in the initial test set.

The 44 failed findings should not be interpreted as 44 independent vulnerabilities because a single Terraform misconfiguration can trigger multiple Checkov policies.

The 100% target detection rate therefore represents detection of the predefined target vulnerabilities in this test set, not overall scanner accuracy.