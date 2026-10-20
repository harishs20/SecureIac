# False Positive Analysis: STO-NO-ACCESS-LOGGING-SAFE

## 1. Observation

Across three repeated runs, SecureIaC classified `STO-NO-ACCESS-LOGGING-SAFE` as vulnerable, although the benchmark labels it compliant.

- **Expected result:** PASS
- **Predicted result:** VULN
- **Policy:** POL-S3-003
- **Clause:** POL-S3-003-C1
- **Reported confidence:** 1.0
- **Reproducibility:** The same classification occurred in all three runs.

## 2. Evidence

The benchmark Terraform configuration defines two S3 buckets:

- `aws_s3_bucket.target`: the bucket whose access requests are logged.
- `aws_s3_bucket.logs`: the dedicated destination bucket for access logs.

The `aws_s3_bucket_logging.target` resource directs logs from the target bucket to the dedicated logging bucket, using the prefix `access/`.

The benchmark's `expected.json` specifies `PASS`, severity `NONE`, and an empty violations list.

However, the model reports that `aws_s3_bucket.logs` lacks server access logging because no separate logging resource targets that bucket.

## 3. Analysis

The observed false positive is consistent with an overly broad interpretation of the logging requirement. The model treats the absence of a separate logging configuration on the destination bucket as a violation, even though the benchmark intends that bucket to serve as the destination for the target bucket's access logs.

The policy wording states that S3 buckets should have server access logging enabled, but it does not explicitly define how dedicated logging destination buckets should be treated. Therefore, the result highlights both a resource-scope reasoning limitation and a potential ambiguity in policy interpretation.

## 4. Impact on Evaluation

Each run produced TP = 6, TN = 5, FP = 1, and FN = 0. This case accounts for the single false positive in each run and contributes to the measured specificity of 83.33%.

The consistent error across repeated runs demonstrates repeatability, but repeatability does not establish correctness.

## 5. Potential Improvement

Clarify the intended policy scope for dedicated logging destination buckets and add explicit policy guidance or contextual checks for source-to-destination logging relationships. Re-evaluate the change against both compliant and vulnerable benchmark cases to ensure that reducing this false positive does not introduce false negatives.

## 6. Limitation

This analysis follows the benchmark's expected annotation. The policy's general wording does not explicitly exempt destination buckets, so the result should be described as a mismatch with the benchmark's intended interpretation rather than proof that every possible interpretation of the policy requires the model to ignore destination buckets.