import json
from pathlib import Path

import yaml


# ==================================================
# Paths
# ==================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

POLICY_FILE = PROJECT_ROOT / "policy" / "security_policy.yaml"

GROUNDED_RESULTS_DIR = (
    PROJECT_ROOT / "results" / "grounded"
)

VERIFIED_RESULTS_DIR = (
    PROJECT_ROOT / "results" / "verified"
)

TESTBED_DIR = PROJECT_ROOT / "testbed"


# Create output directory
VERIFIED_RESULTS_DIR.mkdir(
    parents=True,
    exist_ok=True
)


# ==================================================
# Load security policy
# ==================================================

with open(
    POLICY_FILE,
    "r",
    encoding="utf-8"
) as file:
    policy = yaml.safe_load(file)


policy_rules = {
    rule["id"]: rule
    for rule in policy["policy_rules"]
}


print(f"Loaded {len(policy_rules)} policy rules.")

for policy_id, rule in policy_rules.items():
    print(f"{policy_id}: {rule['title']}")


# ==================================================
# Load Terraform configuration
# ==================================================

def load_terraform_for_test_case(test_id):
    """
    Load the Terraform configuration corresponding
    to the supplied test case ID.
    """

    vulnerable_dir = TESTBED_DIR / "vulnerable"
    secure_dir = TESTBED_DIR / "secure"

    # Search vulnerable cases
    for terraform_file in vulnerable_dir.glob(
        f"{test_id}_*.tf"
    ):
        with open(
            terraform_file,
            "r",
            encoding="utf-8"
        ) as file:
            return file.read()

    # Search secure cases
    for terraform_file in secure_dir.glob(
        f"{test_id}_*.tf"
    ):
        with open(
            terraform_file,
            "r",
            encoding="utf-8"
        ) as file:
            return file.read()

    return None


# ==================================================
# Normalize text
# ==================================================

def normalize_text(text):
    """
    Normalize natural-language text for
    deterministic comparison.
    """

    if not text:
        return ""

    return (
        text
        .lower()
        .replace("-", " ")
        .replace("_", " ")
        .replace("/", " ")
    )


# ==================================================
# Normalize Terraform
# ==================================================

def normalize_terraform(terraform_code):
    """
    Normalize Terraform whitespace so deterministic
    checks do not depend on formatting.
    """

    if not terraform_code:
        return ""

    return " ".join(terraform_code.split())


# ==================================================
# Check policy applicability
# ==================================================

def verify_test_case_policy(
    test_id,
    policy_id
):
    """
    Check whether the cited policy rule is
    intended for the current test case.
    """

    if policy_id not in policy_rules:
        return False

    target_test_cases = (
        policy_rules[policy_id]
        .get("target_test_cases", [])
    )

    return test_id in target_test_cases


# ==================================================
# Verify finding-policy consistency
# ==================================================

def verify_finding_policy_match(
    finding,
    policy_id
):
    """
    Check whether the LLM finding is consistent
    with the cited policy.
    """

    finding_text = normalize_text(
        finding.get("finding", "")
    )

    reason_text = normalize_text(
        finding.get("reason", "")
    )

    evidence_text = normalize_text(
        finding.get("evidence", "")
    )

    combined_text = (
        finding_text
        + " "
        + reason_text
        + " "
        + evidence_text
    )

    # --------------------------------------------------
    # T01 - S3 Public Access Block
    # --------------------------------------------------

    if policy_id == "POL-S3-001":

        expected_terms = [
            "public access",
            "block public access",
            "public access block",
            "publicly accessible"
        ]

        if any(
            term in combined_text
            for term in expected_terms
        ):
            return {
                "supported": True,
                "reason": (
                    "Finding is consistent with "
                    "the S3 Public Access Block policy."
                )
            }

        return {
            "supported": False,
            "reason": (
                "Finding does not describe an "
                "S3 Public Access Block issue."
            )
        }

    # --------------------------------------------------
    # T02 - S3 Encryption
    # --------------------------------------------------

    if policy_id == "POL-S3-002":

        expected_terms = [
            "encryption",
            "encrypted",
            "server side encryption",
            "server side"
        ]

        if any(
            term in combined_text
            for term in expected_terms
        ):
            return {
                "supported": True,
                "reason": (
                    "Finding is consistent with "
                    "the S3 Server-Side Encryption policy."
                )
            }

        return {
            "supported": False,
            "reason": (
                "Finding does not describe an "
                "S3 encryption issue."
            )
        }

    # --------------------------------------------------
    # T03 - SSH
    # --------------------------------------------------

    if policy_id == "POL-NET-001":

        expected_terms = [
            "ssh",
            "port 22",
            "port 22 ingress",
            "remote administration"
        ]

        if any(
            term in combined_text
            for term in expected_terms
        ):
            return {
                "supported": True,
                "reason": (
                    "Finding is consistent with "
                    "the Restricted SSH Ingress policy."
                )
            }

        return {
            "supported": False,
            "reason": (
                "Finding does not describe an "
                "unrestricted SSH ingress issue."
            )
        }

    # --------------------------------------------------
    # T04 - HTTP
    # --------------------------------------------------

    if policy_id == "POL-NET-002":

        expected_terms = [
            "http",
            "port 80",
            "port 80 ingress"
        ]

        if any(
            term in combined_text
            for term in expected_terms
        ):
            return {
                "supported": True,
                "reason": (
                    "Finding is consistent with "
                    "the Restricted HTTP Ingress policy."
                )
            }

        return {
            "supported": False,
            "reason": (
                "Finding does not describe an "
                "unrestricted HTTP ingress issue."
            )
        }

    # --------------------------------------------------
    # T05 - IAM Least Privilege
    # --------------------------------------------------

    if policy_id == "POL-IAM-001":

        expected_terms = [
            "least privilege",
            "excessive permission",
            "excessive permissions",
            "unrestricted action",
            "action *",
            "action wildcard",
            "wildcard action"
        ]

        if any(
            term in combined_text
            for term in expected_terms
        ):
            return {
                "supported": True,
                "reason": (
                    "Finding is consistent with "
                    "the IAM Least Privilege policy."
                )
            }

        return {
            "supported": False,
            "reason": (
                "Finding does not describe an "
                "IAM least-privilege issue."
            )
        }

    # --------------------------------------------------
    # T06 - EBS Encryption
    # --------------------------------------------------

    if policy_id == "POL-EBS-001":

        expected_terms = [
            "ebs encryption",
            "ebs encrypted",
            "volume encryption",
            "volume is not encrypted",
            "encryption is disabled"
        ]

        if any(
            term in combined_text
            for term in expected_terms
        ):
            return {
                "supported": True,
                "reason": (
                    "Finding is consistent with "
                    "the EBS Volume Encryption policy."
                )
            }

        return {
            "supported": False,
            "reason": (
                "Finding does not describe an "
                "EBS encryption issue."
            )
        }

    # --------------------------------------------------
    # T07 - RDS Public Accessibility
    # --------------------------------------------------

    if policy_id == "POL-RDS-001":

        expected_terms = [
            "rds",
            "publicly accessible",
            "public accessibility",
            "public access",
            "internet"
        ]

        if any(
            term in combined_text
            for term in expected_terms
        ):
            return {
                "supported": True,
                "reason": (
                    "Finding is consistent with "
                    "the RDS Public Accessibility policy."
                )
            }

        return {
            "supported": False,
            "reason": (
                "Finding does not describe an "
                "RDS public accessibility issue."
            )
        }

    # --------------------------------------------------
    # T08 - S3 Access Logging
    # --------------------------------------------------

    if policy_id == "POL-S3-003":

        expected_terms = [
            "access logging",
            "server access logging",
            "logging",
            "log"
        ]

        if any(
            term in combined_text
            for term in expected_terms
        ):
            return {
                "supported": True,
                "reason": (
                    "Finding is consistent with "
                    "the S3 Access Logging policy."
                )
            }

        return {
            "supported": False,
            "reason": (
                "Finding does not describe an "
                "S3 access logging issue."
            )
        }

    # --------------------------------------------------
    # T09 - IAM Resource Scope
    # --------------------------------------------------

    if policy_id == "POL-IAM-002":

        expected_terms = [
            "resource scope",
            "resource *",
            "resource wildcard",
            "wildcard resource",
            "broad resource",
            "broad resource scope"
        ]

        if any(
            term in combined_text
            for term in expected_terms
        ):
            return {
                "supported": True,
                "reason": (
                    "Finding is consistent with "
                    "the IAM Resource Scope policy."
                )
            }

        return {
            "supported": False,
            "reason": (
                "Finding does not describe an "
                "IAM resource-scope issue."
            )
        }

    # --------------------------------------------------
    # Unknown policy
    # --------------------------------------------------

    return {
        "supported": False,
        "reason": (
            f"No deterministic finding-policy "
            f"mapping exists for '{policy_id}'."
        )
    }


# ==================================================
# Verify Terraform evidence
# ==================================================

def verify_terraform_evidence(
    test_id,
    policy_id
):
    """
    Verify whether the actual Terraform configuration
    supports the security issue represented by the
    policy rule.

    Terraform whitespace is normalized so that
    formatting differences do not affect verification.
    """

    terraform_code = load_terraform_for_test_case(
        test_id
    )

    if terraform_code is None:
        return {
            "supported": False,
            "reason": (
                f"Terraform configuration for "
                f"'{test_id}' could not be found."
            )
        }

    terraform_normalized = normalize_terraform(
        terraform_code
    )

    # --------------------------------------------------
    # T01 - S3 Public Access Block
    # --------------------------------------------------

    if (
        test_id == "T01"
        and policy_id == "POL-S3-001"
    ):

        has_public_access_block = any(
            term in terraform_normalized
            for term in [
                "aws_s3_bucket_public_access_block",
                "block_public_acls",
                "block_public_policy",
                "ignore_public_acls",
                "restrict_public_buckets"
            ]
        )

        if has_public_access_block:
            return {
                "supported": False,
                "reason": (
                    "Terraform contains S3 Block "
                    "Public Access configuration."
                )
            }

        return {
            "supported": True,
            "reason": (
                "Terraform does not contain S3 "
                "Block Public Access controls."
            )
        }

    # --------------------------------------------------
    # T02 - S3 Server-Side Encryption
    # --------------------------------------------------

    if (
        test_id == "T02"
        and policy_id == "POL-S3-002"
    ):

        has_encryption = any(
            term in terraform_normalized
            for term in [
                "server_side_encryption_configuration",
                "sse_algorithm",
                "aws_s3_bucket_server_side_encryption_configuration"
            ]
        )

        if has_encryption:
            return {
                "supported": False,
                "reason": (
                    "Terraform contains S3 "
                    "server-side encryption configuration."
                )
            }

        return {
            "supported": True,
            "reason": (
                "Terraform does not contain S3 "
                "server-side encryption."
            )
        }

    # --------------------------------------------------
    # T03 - Restricted SSH Ingress
    # --------------------------------------------------

    if (
        test_id == "T03"
        and policy_id == "POL-NET-001"
    ):

        unrestricted_ssh = (
            "from_port = 22" in terraform_normalized
            and "to_port = 22" in terraform_normalized
            and 'cidr_blocks = ["0.0.0.0/0"]'
            in terraform_normalized
        )

        if unrestricted_ssh:
            return {
                "supported": True,
                "reason": (
                    "Terraform contains unrestricted "
                    "SSH ingress on port 22."
                )
            }

        return {
            "supported": False,
            "reason": (
                "Terraform does not contain "
                "unrestricted SSH ingress."
            )
        }

    # --------------------------------------------------
    # T04 - Restricted HTTP Ingress
    # --------------------------------------------------

    if (
        test_id == "T04"
        and policy_id == "POL-NET-002"
    ):

        unrestricted_http = (
            "from_port = 80" in terraform_normalized
            and "to_port = 80" in terraform_normalized
            and 'cidr_blocks = ["0.0.0.0/0"]'
            in terraform_normalized
        )

        if unrestricted_http:
            return {
                "supported": True,
                "reason": (
                    "Terraform contains unrestricted "
                    "HTTP ingress on port 80."
                )
            }

        return {
            "supported": False,
            "reason": (
                "Terraform does not contain "
                "unrestricted HTTP ingress."
            )
        }

    # --------------------------------------------------
    # T05 - IAM Least Privilege
    # --------------------------------------------------

    if (
        test_id == "T05"
        and policy_id == "POL-IAM-001"
    ):

        unrestricted_actions = (
            'Action = "*"' in terraform_normalized
            or '"Action": "*"' in terraform_normalized
        )

        unrestricted_resource = (
            'Resource = "*"' in terraform_normalized
            or '"Resource": "*"' in terraform_normalized
        )

        if (
            unrestricted_actions
            and unrestricted_resource
        ):
            return {
                "supported": True,
                "reason": (
                    "Terraform IAM policy grants "
                    "Action '*' on Resource '*'."
                )
            }

        return {
            "supported": False,
            "reason": (
                "Terraform does not contain the "
                "expected unrestricted IAM permissions."
            )
        }

    # --------------------------------------------------
    # T06 - EBS Volume Encryption
    # --------------------------------------------------

    if (
        test_id == "T06"
        and policy_id == "POL-EBS-001"
    ):

        encrypted_false = (
            "encrypted = false"
            in terraform_normalized
        )

        if encrypted_false:
            return {
                "supported": True,
                "reason": (
                    "Terraform explicitly disables "
                    "EBS encryption."
                )
            }

        return {
            "supported": False,
            "reason": (
                "Terraform does not explicitly disable "
                "EBS encryption."
            )
        }

    # --------------------------------------------------
    # T07 - RDS Public Accessibility
    # --------------------------------------------------

    if (
        test_id == "T07"
        and policy_id == "POL-RDS-001"
    ):

        publicly_accessible = (
            "publicly_accessible = true"
            in terraform_normalized
        )

        if publicly_accessible:
            return {
                "supported": True,
                "reason": (
                    "Terraform explicitly makes the "
                    "RDS instance publicly accessible."
                )
            }

        return {
            "supported": False,
            "reason": (
                "Terraform does not explicitly make "
                "the RDS instance publicly accessible."
            )
        }

    # --------------------------------------------------
    # T08 - S3 Access Logging
    # --------------------------------------------------

    if (
        test_id == "T08"
        and policy_id == "POL-S3-003"
    ):

        has_logging = any(
            term in terraform_normalized
            for term in [
                "aws_s3_bucket_logging",
                "target_bucket",
                "target_prefix"
            ]
        )

        if has_logging:
            return {
                "supported": False,
                "reason": (
                    "Terraform contains S3 access "
                    "logging configuration."
                )
            }

        return {
            "supported": True,
            "reason": (
                "Terraform does not contain S3 "
                "access logging configuration."
            )
        }

    # --------------------------------------------------
    # T09 - IAM Resource Scope
    # --------------------------------------------------

    if (
        test_id == "T09"
        and policy_id == "POL-IAM-002"
    ):

        wildcard_resource = (
            'Resource = "*"' in terraform_normalized
            or '"Resource": "*"' in terraform_normalized
        )

        if wildcard_resource:
            return {
                "supported": True,
                "reason": (
                    "Terraform IAM policy uses "
                    "Resource '*'."
                )
            }

        return {
            "supported": False,
            "reason": (
                "Terraform does not contain the "
                "expected broad Resource '*' scope."
            )
        }

    # --------------------------------------------------
    # S01 - Secure EBS
    # --------------------------------------------------

    if test_id == "S01":

        encrypted_true = (
            "encrypted = true"
            in terraform_normalized
        )

        if encrypted_true:
            return {
                "supported": False,
                "reason": (
                    "Terraform explicitly enables "
                    "EBS encryption; no missing-encryption "
                    "violation is present."
                )
            }

    # --------------------------------------------------
    # Unknown combination
    # --------------------------------------------------

    return {
        "supported": False,
        "reason": (
            f"No Terraform evidence rule exists "
            f"for '{test_id}' + '{policy_id}'."
        )
    }


# ==================================================
# Verify individual finding
# ==================================================

def verify_finding(
    finding,
    test_id
):
    """
    Perform all deterministic verification checks
    on a single LLM-generated finding.
    """

    policy_id = finding.get("policy_id")
    clause_id = finding.get("clause_id")

    # --------------------------------------------------
    # Check 1: Policy exists
    # --------------------------------------------------

    if policy_id not in policy_rules:
        return {
            "decision": "REJECT",
            "reason": (
                f"Policy ID '{policy_id}' "
                "does not exist."
            )
        }

    # --------------------------------------------------
    # Check 2: Clause belongs to policy
    # --------------------------------------------------

    rule = policy_rules[policy_id]

    expected_clause_id = (
        rule
        .get("evidence", {})
        .get("clause_id")
    )

    if clause_id != expected_clause_id:
        return {
            "decision": "REJECT",
            "reason": (
                f"Clause ID '{clause_id}' does not "
                f"match the clause defined for "
                f"policy '{policy_id}'."
            )
        }

    # --------------------------------------------------
    # Check 3: Policy applies to test case
    # --------------------------------------------------

    if not verify_test_case_policy(
        test_id,
        policy_id
    ):
        return {
            "decision": "REJECT",
            "reason": (
                f"Policy '{policy_id}' is not "
                f"targeted at test case '{test_id}'."
            )
        }

    # --------------------------------------------------
    # Check 4: Finding matches policy
    # --------------------------------------------------

    policy_match = verify_finding_policy_match(
        finding,
        policy_id
    )

    if not policy_match["supported"]:
        return {
            "decision": "REJECT",
            "reason": policy_match["reason"]
        }

    # --------------------------------------------------
    # Check 5: Terraform supports the issue
    # --------------------------------------------------

    terraform_match = verify_terraform_evidence(
        test_id,
        policy_id
    )

    if not terraform_match["supported"]:
        return {
            "decision": "REJECT",
            "reason": terraform_match["reason"]
        }

    # --------------------------------------------------
    # ACCEPT
    # --------------------------------------------------

    return {
        "decision": "ACCEPT",
        "reason": (
            "Policy rule, cited clause, test-case "
            "mapping, finding-policy consistency, "
            "and Terraform evidence are all consistent."
        )
    }


# ==================================================
# Verify one grounded result
# ==================================================

def verify_result_file(result_file):
    """
    Verify all findings contained in one grounded
    LLM result file.
    """

    with open(
        result_file,
        "r",
        encoding="utf-8"
    ) as file:
        grounded_result = json.load(file)

    test_id = grounded_result.get("test_id")

    findings = grounded_result.get(
        "findings",
        []
    )

    verified_findings = []

    accepted_count = 0
    rejected_count = 0

    for finding in findings:

        verification = verify_finding(
            finding,
            test_id
        )

        verified_finding = {
            "finding": finding.get("finding"),
            "resource": finding.get("resource"),
            "reason": finding.get("reason"),
            "policy_id": finding.get("policy_id"),
            "clause_id": finding.get("clause_id"),
            "evidence": finding.get("evidence"),
            "confidence": finding.get("confidence"),
            "decision": verification["decision"],
            "verification_reason": verification["reason"]
        }

        verified_findings.append(
            verified_finding
        )

        if verification["decision"] == "ACCEPT":
            accepted_count += 1
        else:
            rejected_count += 1

    return {
        "test_id": test_id,
        "source_file": result_file.name,
        "total_findings": len(findings),
        "accepted_findings": accepted_count,
        "rejected_findings": rejected_count,
        "findings": verified_findings
    }


# ==================================================
# Batch verification
# ==================================================

def run_batch_verification():
    """
    Verify every grounded result in results/grounded/.
    """

    result_files = sorted(
        GROUNDED_RESULTS_DIR.glob(
            "*_grounded.json"
        )
    )

    print("\n" + "=" * 60)
    print(
        "SecureIaC - Batch Evidence Verification"
    )
    print("=" * 60)

    print(
        f"\nFound {len(result_files)} grounded result files."
    )

    total_findings = 0
    total_accepted = 0
    total_rejected = 0

    for index, result_file in enumerate(
        result_files,
        start=1
    ):

        print("\n" + "-" * 60)

        print(
            f"[{index}/{len(result_files)}] "
            f"Verifying {result_file.name}"
        )

        print("-" * 60)

        try:

            verified_result = verify_result_file(
                result_file
            )

            test_id = verified_result["test_id"]

            accepted = (
                verified_result["accepted_findings"]
            )

            rejected = (
                verified_result["rejected_findings"]
            )

            findings = (
                verified_result["total_findings"]
            )

            output_file = (
                VERIFIED_RESULTS_DIR
                / f"{test_id}_verified.json"
            )

            with open(
                output_file,
                "w",
                encoding="utf-8"
            ) as file:

                json.dump(
                    verified_result,
                    file,
                    indent=2
                )

            print(
                f"Test case: {test_id}"
            )

            print(
                f"Findings: {findings}"
            )

            print(
                f"Accepted: {accepted}"
            )

            print(
                f"Rejected: {rejected}"
            )

            print(
                f"Saved: {output_file}"
            )

            total_findings += findings
            total_accepted += accepted
            total_rejected += rejected

        except Exception as error:

            print(
                f"ERROR processing "
                f"{result_file.name}: {error}"
            )

    # --------------------------------------------------
    # Final summary
    # --------------------------------------------------

    print("\n" + "=" * 60)
    print(
        "Batch verification complete"
    )
    print("=" * 60)

    print(
        f"Total findings:  {total_findings}"
    )

    print(
        f"Accepted:        {total_accepted}"
    )

    print(
        f"Rejected:        {total_rejected}"
    )

    print(
        f"Output directory: "
        f"{VERIFIED_RESULTS_DIR}"
    )


# ==================================================
# Main
# ==================================================

if __name__ == "__main__":

    run_batch_verification()