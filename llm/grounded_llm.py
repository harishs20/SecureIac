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

PROJECT_ROOT = Path(__file__).resolve().parent.parent

POLICY_FILE = PROJECT_ROOT / "policy" / "security_policy.yaml"

VULNERABLE_DIR = PROJECT_ROOT / "testbed" / "vulnerable"
SECURE_DIR = PROJECT_ROOT / "testbed" / "secure"

RESULTS_DIR = PROJECT_ROOT / "results" / "grounded"

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

# Delay between successful API requests.
# This helps avoid sending requests too quickly.
DELAY_BETWEEN_CASES = 5

# Number of times to retry a failed API request.
MAX_RETRIES = 3

# Delay before each retry.
RETRY_DELAY = 10


# --------------------------------------------------
# Load security policy
# --------------------------------------------------

def load_policy():
    with open(POLICY_FILE, "r", encoding="utf-8") as file:
        return yaml.safe_load(file)


# --------------------------------------------------
# Find all Terraform test cases
# --------------------------------------------------

def find_test_cases():

    test_cases = []

    for terraform_file in VULNERABLE_DIR.glob("*.tf"):
        test_cases.append(terraform_file)

    for terraform_file in SECURE_DIR.glob("*.tf"):
        test_cases.append(terraform_file)

    # Sort so T01, T02, ..., T09, S01 appear consistently
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
# Build grounded prompt
# --------------------------------------------------

def build_prompt(test_id, terraform_code, policy):

    policy_text = yaml.dump(
        policy,
        sort_keys=False,
        allow_unicode=True
    )

    return f"""
You are a cloud infrastructure security analysis system.

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
      "reason": "Why the Terraform configuration violates the policy",
      "policy_id": "Exact policy rule ID",
      "clause_id": "Exact clause ID from the supplied policy",
      "evidence": "Specific Terraform evidence supporting the finding",
      "confidence": 0.0
    }}
  ]
}}

Return ONLY JSON.
"""


# --------------------------------------------------
# Clean Gemini/Groq Markdown fences
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

    json_file = RESULTS_DIR / f"{test_id}_grounded.json"

    with open(raw_file, "w", encoding="utf-8") as file:
        file.write(raw_output)

    with open(json_file, "w", encoding="utf-8") as file:
        json.dump(result, file, indent=2)

    print(f"  Raw output:    {raw_file}")
    print(f"  JSON result:   {json_file}")


# --------------------------------------------------
# Main batch execution
# --------------------------------------------------

if __name__ == "__main__":

    print("=" * 60)
    print("SecureIaC - Grounded LLM Analysis")
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

        # Wait before moving to the next test case
        if index < len(test_cases) - 1:

            print(
                f"\nWaiting {DELAY_BETWEEN_CASES} seconds "
                f"before next test case..."
            )

            time.sleep(DELAY_BETWEEN_CASES)

    print("\n" + "=" * 60)
    print("Grounded LLM analysis complete")
    print("=" * 60)

    print(f"Successful: {successful}")
    print(f"Failed:     {failed}")
    print(f"Total:      {len(test_cases)}")