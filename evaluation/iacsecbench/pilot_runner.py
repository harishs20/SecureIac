import argparse
import json
import sys
import yaml
from pathlib import Path



PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
BENCHMARK_ROOT = Path(r"D:\SecureIAC\iacsecbench\benchmark\internal\cases")
POLICY_FILE = PROJECT_ROOT / "policy" / "security_policy.yaml"
OUTPUT_DIR = PROJECT_ROOT / "results" / "iacsecbench_pilot"
PROMPT_DIR = OUTPUT_DIR / "prompts"

CASE_POLICIES = {
    "STO_PUBLIC_BUCKET": {
        "policy_id": "POL-S3-001",
        "clause_id": "POL-S3-001-C1",
        "mapping": "direct",
    },
    "ENC_UNENCRYPTED_VOLUME": {
        "policy_id": "POL-EBS-001",
        "clause_id": "POL-EBS-001-C1",
        "mapping": "direct",
    },
    "STO_NO_ACCESS_LOGGING": {
        "policy_id": "POL-S3-003",
        "clause_id": "POL-S3-003-C1",
        "mapping": "direct",
    },
    "STO_PUBLIC_DATABASE": {
        "policy_id": "POL-RDS-001",
        "clause_id": "POL-RDS-001-C1",
        "mapping": "direct",
    },
    "NET_UNRESTRICTED_INGRESS": {
        "policy_id": "POL-NET-001",
        "clause_id": "POL-NET-001-C1",
        "mapping": "direct_for_ssh_port_22",
    },
    "IAM_WILDCARD_ACTION": {
        "policy_id": "POL-IAM-001",
        "clause_id": "POL-IAM-001-C1",
        "mapping": "partial_combined_action_and_resource_wildcard",
    },
}

CASE_IDS = [
    f"{pair.replace('_', '-')}-{variant}"
    for pair in CASE_POLICIES
    for variant in ("SAFE", "VULN")
]


def get_filtered_policy(policy_document, policy_id):
    """Select one rule without modifying the original policy file."""
    matching = [
        rule for rule in policy_document.get("policy_rules", [])
        if rule.get("id") == policy_id
    ]
    if len(matching) != 1:
        raise ValueError(
            f"Expected exactly one rule for {policy_id}, found {len(matching)}"
        )

    selected_rule = dict(matching[0])
    # Original target IDs refer to the project's testbed, not this benchmark.
    # Remove only that routing metadata; preserve the security requirement
    # and evidence clause unchanged.
    selected_rule.pop("target_test_cases", None)

    return {
        key: value
        for key, value in policy_document.items()
        if key != "policy_rules"
    } | {"policy_rules": [selected_rule]}


def build_preview_prompt(case_id, terraform_code, filtered_policy):
    policy_text = yaml.safe_dump(
        filtered_policy, sort_keys=False, allow_unicode=True
    )

    return f"""You are a cloud infrastructure security analysis system.

Analyze the supplied Terraform configuration using ONLY
the supplied security policy.

IMPORTANT RULES:

1. Use ONLY the supplied Terraform configuration and security policy.
2. Do not use external security rules or assumptions.
3. Do not invent policy IDs or clause IDs.
4. Every security finding MUST cite a policy rule ID and clause ID.
5. The cited clause must directly support the finding.
6. If there is no supported security finding, return an empty findings list.
7. Do not report a vulnerability merely because a configuration is unusual.
8. Focus only on security requirements represented in the supplied policy.
9. Return ONLY valid JSON.
10. Do not include Markdown code fences.

TEST CASE:

{case_id}

TERRAFORM CONFIGURATION:

{terraform_code}

SECURITY POLICY:

{policy_text}

Return JSON with this structure:
{{
  "test_id": "{case_id}",
  "findings": [
    {{
      "finding": "Short finding title",
      "resource": "Terraform resource address or type",
      "reason": "Evidence-based explanation",
      "policy_id": "Exact supplied policy ID",
      "clause_id": "Exact supplied clause ID",
      "evidence": "Relevant Terraform evidence",
      "confidence": 0.0
    }}
  ]
}}
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run-llm', action='store_true', help='Send pilot prompts to Groq')
    parser.add_argument('--run-id', default='run_1')
    parser.add_argument(
        '--case-ids',
        nargs='+',
        choices=CASE_IDS,
        help='Process only the specified benchmark case IDs.',
    )
    args = parser.parse_args()
    selected_case_ids = args.case_ids if args.case_ids else CASE_IDS

    if not POLICY_FILE.is_file():
        raise FileNotFoundError(f"Missing policy file: {POLICY_FILE}")

    policy_document = yaml.safe_load(POLICY_FILE.read_text(encoding="utf-8"))
    rows = []
    prompts_written = 0
    if not args.run_id.strip():
        raise ValueError("Run ID cannot be empty.")
    run_dir = OUTPUT_DIR / args.run_id
    
    if args.run_llm and run_dir.exists():
        raise FileExistsError(
            f"Run directory already exists: {run_dir}. "
            "Choose a new --run-id to avoid overwriting results."
        )
    if args.run_llm:
        run_dir.mkdir(parents=True, exist_ok=True)
        print("LIVE LLM MODE: Groq API requests are enabled.")
    else:
        print("DRY RUN MODE: no model/API calls will be made.")

    PROMPT_DIR.mkdir(parents=True, exist_ok=True)

    for case_index, case_id in enumerate(selected_case_ids, start=1):
        print(f"Processing case {case_index}/{len(selected_case_ids)}: {case_id}", flush=True)
        case_dir = BENCHMARK_ROOT / case_id
        metadata_path = case_dir / "metadata.json"
        terraform_path = case_dir / "main.tf"

        if not metadata_path.is_file():
            raise FileNotFoundError(f"Missing metadata: {metadata_path}")
        if not terraform_path.is_file():
            raise FileNotFoundError(f"Missing Terraform file: {terraform_path}")

        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        terraform_code = terraform_path.read_text(encoding="utf-8")
        # Remove leading generated benchmark comments from model input.
        lines = terraform_code.splitlines()
        while lines and (not lines[0].strip() or lines[0].lstrip().startswith("#")):
            lines.pop(0)
        terraform_code = "\n".join(lines)
        control = metadata["canonical_controls"][0]

        if metadata.get("id") != case_id:
            raise ValueError(f"Metadata ID mismatch: {case_id}")
        if metadata.get("expected_result") not in {"PASS", "FAIL"}:
            raise ValueError(f"Invalid expected_result: {case_id}")
        if control not in CASE_POLICIES:
            raise ValueError(f"No policy mapping for control: {control}")
        if metadata.get("has_violation") != (
            metadata["expected_result"] == "FAIL"
        ):
            raise ValueError(f"Ground-truth fields conflict: {case_id}")

        mapping = CASE_POLICIES[control]
        filtered_policy = get_filtered_policy(
            policy_document, mapping["policy_id"]
        )

        selected_rule = filtered_policy["policy_rules"][0]
        actual_clause = selected_rule.get("evidence", {}).get("clause_id")
        if actual_clause != mapping["clause_id"]:
            raise ValueError(
                f"Clause mismatch for {case_id}: {actual_clause}"
            )

        if control == "NET_UNRESTRICTED_INGRESS" and metadata["has_violation"]:
            required_evidence = ["22", "0.0.0.0/0"]
            if not all(term in terraform_code for term in required_evidence):
                raise ValueError(f"SSH mapping not confirmed: {case_id}")

        prompt = build_preview_prompt(
            case_id, terraform_code, filtered_policy
        )
        prompt_file = PROMPT_DIR / f"{case_id}_prompt.txt"
        prompt_file.write_text(prompt, encoding="utf-8")
        prompts_written += 1

        result_status = "not_run"
        result_file = None
        raw_file = None

        if args.run_llm:
            # Import only in live mode; this initializes the existing Groq client.
            from llm.grounded_llm import (
                analyze_test_case,
                MODEL_NAME,
                DELAY_BETWEEN_CASES,
            )
            import time

            result, raw_output = analyze_test_case(
                case_id, terraform_code, filtered_policy
            )

            case_output_dir = run_dir / case_id
            case_output_dir.mkdir(parents=True, exist_ok=True)

            result_status = "request_failed"
            validation_errors = []

            if result is not None and raw_output is not None:
                if not isinstance(result, dict):
                    validation_errors.append("Response must be a JSON object.")
                else:
                    if result.get("test_id") != case_id:
                        validation_errors.append("test_id does not match case ID.")

                    findings = result.get("findings")
                    if not isinstance(findings, list):
                        validation_errors.append("'findings' must be a list.")
                    else:
                        allowed_policy_ids = {
                            rule["id"] for rule in filtered_policy["policy_rules"]
                        }
                        allowed_clause_ids = {
                            rule.get("evidence", {}).get("clause_id")
                            for rule in filtered_policy["policy_rules"]
                        }
                        required_fields = {
                            "finding", "resource", "reason",
                            "policy_id", "clause_id", "evidence", "confidence",
                        }

                        for index, finding in enumerate(findings):
                            if not isinstance(finding, dict):
                                validation_errors.append(
                                    f"Finding {index} must be an object."
                                )
                                continue

                            missing = required_fields - finding.keys()
                            if missing:
                                validation_errors.append(
                                    f"Finding {index} missing fields: "
                                    f"{', '.join(sorted(missing))}."
                                )

                            if finding.get("policy_id") not in allowed_policy_ids:
                                validation_errors.append(
                                    f"Finding {index} cites an unsupported policy ID."
                                )

                            if finding.get("clause_id") not in allowed_clause_ids:
                                validation_errors.append(
                                    f"Finding {index} cites an unsupported clause ID."
                                )

                            confidence = finding.get("confidence")
                            if (
                                not isinstance(confidence, (int, float))
                                or isinstance(confidence, bool)
                                or not 0.0 <= confidence <= 1.0
                            ):
                                validation_errors.append(
                                    f"Finding {index} confidence must be between 0 and 1."
                                )

                raw_path = case_output_dir / "raw_output.txt"
                raw_path.write_text(raw_output, encoding="utf-8")
                raw_file = str(raw_path)

                if validation_errors:
                    result_status = "invalid_response"
                    validation_path = case_output_dir / "validation_errors.json"
                    validation_path.write_text(
                        json.dumps(validation_errors, indent=2),
                        encoding="utf-8",
                    )
                else:
                    result_status = "success"
                    json_path = case_output_dir / "result.json"
                    json_path.write_text(
                        json.dumps(result, indent=2),
                        encoding="utf-8",
                    )
                    result_file = str(json_path)

            (case_output_dir / "status.json").write_text(
                json.dumps({
                    "case_id": case_id,
                    "status": result_status,
                    "validation_errors": validation_errors,
                    "model": MODEL_NAME,
                    "policy_id": mapping["policy_id"],
                    "clause_id": mapping["clause_id"],
                }, indent=2),
                encoding="utf-8",
            )

            # Respect the existing pacing between cases.
            if case_id != CASE_IDS[-1]:
                time.sleep(DELAY_BETWEEN_CASES)
        rows.append({
            "id": case_id,
            "expected_result": metadata["expected_result"],
            "has_violation": metadata["has_violation"],
            "canonical_control": control,
            "pair_id": metadata["pair_id"],
            "policy_id": mapping["policy_id"],
            "clause_id": mapping["clause_id"],
            "mapping_quality": mapping["mapping"],
            "terraform_characters": len(terraform_code),
            "prompt_file": str(prompt_file),
            "result_status": result_status,
            "result_file": result_file,
            "raw_file": raw_file,
        })

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output_file = OUTPUT_DIR / "pilot_manifest.json"
    output_file.write_text(json.dumps(rows, indent=2), encoding="utf-8")

    print(f"Validated {len(rows)} benchmark cases and policy mappings.")
    print(f"PASS labels: {sum(r['expected_result'] == 'PASS' for r in rows)}")
    print(f"FAIL labels: {sum(r['expected_result'] == 'FAIL' for r in rows)}")
    print(f"Prompt previews written: {prompts_written}")
    print(f"Manifest: {output_file}")
    print(f"Prompts: {PROMPT_DIR}")
    if args.run_llm:
        run_manifest = run_dir / "run_manifest.json"
        run_manifest.write_text(json.dumps(rows, indent=2), encoding="utf-8")
        print(f"Live run manifest: {run_manifest}")
        print(f"Results directory: {run_dir}")
        print(f"Successful responses: {sum(r['result_status'] == 'success' for r in rows)}")
        print(f"Failed requests: {sum(r['result_status'] == 'request_failed' for r in rows)}")
        print(f"Invalid responses: {sum(r['result_status'] == 'invalid_response' for r in rows)}")
    else:
        print("DRY RUN ONLY: no model/API calls were made.")


if __name__ == "__main__":
    main()


