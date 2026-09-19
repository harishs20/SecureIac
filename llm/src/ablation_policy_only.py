import json
import os
import time
from pathlib import Path

import yaml
from dotenv import load_dotenv
from groq import Groq


# --------------------------------------------------
# Project paths
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

POLICY_FILE = PROJECT_ROOT / "policy" / "security_policy.yaml"

VULNERABLE_DIR = PROJECT_ROOT / "testbed" / "vulnerable"
SECURE_DIR = PROJECT_ROOT / "testbed" / "secure"

RESULTS_DIR = PROJECT_ROOT / "results" / "ablation_policy_only"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


# --------------------------------------------------
# Groq setup
# --------------------------------------------------

load_dotenv(PROJECT_ROOT / ".env")

api_key = os.getenv("GROQ_API_KEY")

if not api_key:
    raise RuntimeError("GROQ_API_KEY not found in .env")

client = Groq(api_key=api_key)

MODEL_NAME = "openai/gpt-oss-120b"


# --------------------------------------------------
# Experiment settings
# --------------------------------------------------

DELAY_BETWEEN_CASES = 5
MAX_RETRIES = 3
RETRY_DELAY = 10


# --------------------------------------------------
# Load security policy
# --------------------------------------------------

def load_policy():

    with open(POLICY_FILE, "r", encoding="utf-8") as file:
        return yaml.safe_load(file)


# --------------------------------------------------
# Find test cases
# --------------------------------------------------

def find_test_cases():

    test_cases = []

    for terraform_file in VULNERABLE_DIR.glob("*.tf"):
        test_cases.append(terraform_file)

    for terraform_file in SECURE_DIR.glob("*.tf"):
        test_cases.append(terraform_file)

    test_cases.sort(key=lambda path: path.name)

    return test_cases


# --------------------------------------------------
# Load Terraform
# --------------------------------------------------

def load_terraform(terraform_file):

    with open(terraform_file, "r", encoding="utf-8") as file:
        return file.read()


# --------------------------------------------------
# Extract test ID
# --------------------------------------------------

def get_test_id(terraform_file):

    return terraform_file.stem.split("_")[0]


# --------------------------------------------------
# Build POLICY-ONLY prompt
# --------------------------------------------------

def build_prompt(test_id, terraform_code, policy):

    policy_text = yaml.dump(
        policy,
        sort_keys=False,
        allow_unicode=True
    )

    return f"""
You are a cloud infrastructure security analysis system.

Analyze the supplied Terraform configuration using the
supplied security policy.

IMPORTANT RULES:

1. Use the supplied Terraform configuration and security policy.
2. Do not use external security policies.
3. Do not invent security requirements that are not represented
   in the supplied policy.
4. Identify security issues that violate requirements in the
   supplied policy.
5. If there is no supported security finding, return an empty
   findings list.
6. Do not report a vulnerability merely because a configuration
   is unusual.
7. Do NOT provide policy IDs or clause IDs.
8. Return ONLY valid JSON.
9. Do not include Markdown code fences.

TEST CASE:

{test_id}

TERRAFORM CONFIGURATION:

{terraform_code}

SECURITY POLICY:

{policy_text}

Return JSON using exactly this structure:

{{
  "test_id": "{test_id}",
  "findings": [
    {{
      "finding": "Short description of the security issue",
      "resource": "Terraform resource involved",
      "reason": "Why the Terraform configuration violates the supplied policy",
      "evidence": "Specific Terraform evidence supporting the finding",
      "confidence": 0.0
    }}
  ]
}}

Return ONLY JSON.
"""


# --------------------------------------------------
# Clean JSON output
# --------------------------------------------------

def clean_json_output(raw_output):

    raw_output = raw_output.strip()

    if raw_output.startswith("```json"):
        raw_output = raw_output[7:]

    elif raw_output.startswith("```"):
        raw_output = raw_output[3:]

    if raw_output.endswith("```"):
        raw_output = raw_output[:-3]

    return raw_output.strip()


# --------------------------------------------------
# Analyze one test case
# --------------------------------------------------

def analyze_test_case(test_id, terraform_code, policy):

    prompt = build_prompt(
        test_id,
        terraform_code,
        policy
    )

    for attempt in range(1, MAX_RETRIES + 1):

        try:

            print(
                f"  Sending request "
                f"(attempt {attempt}/{MAX_RETRIES})..."
            )

            response = client.chat.completions.create(
                model=MODEL_NAME,
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            )

            raw_output = response.choices[0].message.content

            if not raw_output:
                raise ValueError("Groq returned an empty response.")

            raw_output = clean_json_output(raw_output)

            result = json.loads(raw_output)

            return result, raw_output

        except Exception as error:

            print(f"  Request failed: {error}")

            if attempt < MAX_RETRIES:

                print(
                    f"  Waiting {RETRY_DELAY} seconds "
                    f"before retry..."
                )

                time.sleep(RETRY_DELAY)

            else:

                print(
                    f"  Failed after {MAX_RETRIES} attempts."
                )

                return None, None


# --------------------------------------------------
# Save result
# --------------------------------------------------

def save_result(test_id, result, raw_output):

    raw_file = RESULTS_DIR / f"{test_id}_raw.txt"

    json_file = RESULTS_DIR / f"{test_id}_policy_only.json"

    with open(raw_file, "w", encoding="utf-8") as file:
        file.write(raw_output)

    with open(json_file, "w", encoding="utf-8") as file:
        json.dump(result, file, indent=2)

    print(f"  Raw output:    {raw_file}")
    print(f"  JSON result:   {json_file}")


# --------------------------------------------------
# Main
# --------------------------------------------------

if __name__ == "__main__":

    print("=" * 60)
    print("SecureIaC - Ablation: Policy Only")
    print("=" * 60)

    print(f"Model: {MODEL_NAME}")
    print(f"Delay between cases: {DELAY_BETWEEN_CASES}s")
    print(f"Maximum retries: {MAX_RETRIES}")

    policy = load_policy()

    test_cases = find_test_cases()

    print(f"\nFound {len(test_cases)} Terraform test cases:")

    for terraform_file in test_cases:
        print(f"  - {get_test_id(terraform_file)}")

    print("\nStarting analysis...\n")

    successful = 0
    failed = 0

    for index, terraform_file in enumerate(test_cases):

        test_id = get_test_id(terraform_file)

        print("-" * 60)
        print(
            f"[{index + 1}/{len(test_cases)}] "
            f"Analyzing {test_id}"
        )
        print("-" * 60)

        terraform_code = load_terraform(terraform_file)

        result, raw_output = analyze_test_case(
            test_id,
            terraform_code,
            policy
        )

        if result is not None:

            save_result(
                test_id,
                result,
                raw_output
            )

            successful += 1

        else:

            failed += 1

        if index < len(test_cases) - 1:

            print(
                f"\nWaiting {DELAY_BETWEEN_CASES} seconds "
                f"before next test case..."
            )

            time.sleep(DELAY_BETWEEN_CASES)

    print("\n" + "=" * 60)
    print("Policy-only ablation complete")
    print("=" * 60)

    print(f"Successful: {successful}")
    print(f"Failed:     {failed}")
    print(f"Total:      {len(test_cases)}") 