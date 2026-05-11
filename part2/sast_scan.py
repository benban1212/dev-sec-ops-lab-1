#!/usr/bin/env python3
"""
DevSecOps Lab - Session 2
SAST (Static Analysis) Runner using Bandit
Run: python sast_scan.py
"""

import subprocess
import json
import sys
import os

TARGET_FILE = "../part1/app_vulnerable.py"
SECURE_FILE = "../part1/app_secure.py"
BANDIT_CONFIG = ".bandit.yaml"

def run_bandit(filepath: str, label: str) -> dict:
    """Run Bandit SAST on a file and return parsed results."""
    print(f"\n{'='*60}")
    print(f"Running Bandit SAST on: {label}")
    print(f"File: {filepath}")
    print("="*60)

    result = subprocess.run(
        ["bandit", "-r", filepath, "-f", "json", "-ll"],
        capture_output=True, text=True
    )

    try:
        data = json.loads(result.stdout)
        return data
    except json.JSONDecodeError:
        print("Error: Could not parse Bandit output.")
        print(result.stderr)
        return {}


def print_summary(data: dict, label: str):
    """Print a human-readable summary of Bandit findings."""
    metrics = data.get("metrics", {})
    results = data.get("results", [])

    print(f"\n📊 Summary for {label}:")
    print(f"  Total issues found: {len(results)}")

    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in results:
        sev = r.get("issue_severity", "LOW")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    print(f"  HIGH:   {severity_counts['HIGH']}")
    print(f"  MEDIUM: {severity_counts['MEDIUM']}")
    print(f"  LOW:    {severity_counts['LOW']}")

    print("\n📋 Findings:")
    for i, issue in enumerate(results, 1):
        print(f"\n  [{i}] {issue['issue_text']}")
        print(f"      Severity: {issue['issue_severity']} | CWE: {issue.get('issue_cwe', {}).get('id', 'N/A')}")
        print(f"      File: {issue['filename']}:{issue['line_number']}")
        print(f"      Code: {issue['code'].strip()[:100]}")
        print(f"      Test ID: {issue['test_id']} - {issue['test_name']}")


def run_safety_check():
    """Check dependencies for known CVEs using safety."""
    print(f"\n{'='*60}")
    print("Running Safety dependency check...")
    print("="*60)
    result = subprocess.run(
        ["safety", "check", "-r", "../part1/requirements.txt", "--json"],
        capture_output=True, text=True
    )
    try:
        vulns = json.loads(result.stdout)
        if vulns:
            print(f"⚠️  Found {len(vulns)} vulnerable dependencies:")
            for v in vulns:
                print(f"  - {v[0]} {v[2]}: {v[3][:80]}")
        else:
            print("✅ No known vulnerable dependencies found.")
    except Exception:
        print("Safety output:", result.stdout[:500])


def generate_report(vulnerable_data: dict, secure_data: dict):
    """Generate a comparison report."""
    vuln_count = len(vulnerable_data.get("results", []))
    sec_count = len(secure_data.get("results", []))

    print(f"\n{'='*60}")
    print("📈 COMPARISON REPORT")
    print("="*60)
    print(f"  Vulnerable app issues:  {vuln_count}")
    print(f"  Secure app issues:      {sec_count}")
    reduction = ((vuln_count - sec_count) / max(vuln_count, 1)) * 100
    print(f"  Issue reduction:        {reduction:.0f}%")
    print("\n✅ Remediation summary:")
    print("  - SQL injection → parameterized queries")
    print("  - Pickle deserialization → JSON with validation")
    print("  - Command injection → subprocess list + whitelist")
    print("  - Hardcoded secrets → environment variables")
    print("  - Insecure debug mode → debug=False")


if __name__ == "__main__":
    print("🔍 DevSecOps Lab - Session 2: SAST Scanning")

    if not os.path.exists(TARGET_FILE):
        print(f"Error: {TARGET_FILE} not found. Run from session2/ directory.")
        sys.exit(1)

    vuln_data = run_bandit(TARGET_FILE, "Vulnerable App")
    print_summary(vuln_data, "Vulnerable App")

    sec_data = run_bandit(SECURE_FILE, "Secure App")
    print_summary(sec_data, "Secure App")

    run_safety_check()
    generate_report(vuln_data, sec_data)

    # Save JSON reports
    with open("sast_report_vulnerable.json", "w") as f:
        json.dump(vuln_data, f, indent=2)
    with open("sast_report_secure.json", "w") as f:
        json.dump(sec_data, f, indent=2)

    print("\n💾 Reports saved: sast_report_vulnerable.json, sast_report_secure.json")
