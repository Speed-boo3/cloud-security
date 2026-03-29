"""
Demo mode for cloud-security scanners.
Generates realistic mock AWS findings so anyone can run the tool without an AWS account.
Run: python aws/demo_mode.py
"""

import json
import random
from datetime import datetime


DEMO_FINDINGS = {
    "s3": [
        {
            "bucket": "company-backups-prod",
            "issue": "public_access_block_disabled",
            "level": "Critical",
            "score": 25,
            "finding": "Block Public Access is not fully enabled",
            "risk": "Anyone on the internet can read or download files from this bucket",
            "fix": "Enable all four Block Public Access settings on the bucket immediately",
        },
        {
            "bucket": "app-user-uploads",
            "issue": "encryption_disabled",
            "level": "High",
            "score": 12,
            "finding": "Default server-side encryption is not configured",
            "risk": "Objects stored in this bucket are not encrypted at rest",
            "fix": "Enable AES-256 or AWS KMS encryption on the bucket",
        },
        {
            "bucket": "dev-logs-2024",
            "issue": "logging_disabled",
            "level": "Medium",
            "score": 6,
            "finding": "Server access logging is not enabled",
            "risk": "No audit trail of who accessed or modified objects in this bucket",
            "fix": "Enable server access logging and point it to a dedicated logging bucket",
        },
    ],
    "iam": [
        {
            "user": "developer1",
            "level": "High",
            "score": 16,
            "finding": "User has AdministratorAccess policy attached",
            "risk": "Full account takeover if credentials are ever compromised or leaked",
            "fix": "Replace AdministratorAccess with a scoped policy for this user's actual role",
        },
        {
            "user": "ci-pipeline",
            "level": "High",
            "score": 12,
            "finding": "MFA is not enabled on this user",
            "risk": "Account can be taken over with username and password alone",
            "fix": "Enable MFA. For service accounts consider using IAM roles instead of users",
        },
        {
            "user": "backup-service",
            "level": "Medium",
            "score": 9,
            "finding": "Access key is 143 days old (threshold: 90 days)",
            "risk": "Old keys increase the window of exposure if they have been leaked",
            "fix": "Rotate this access key and establish a 90-day rotation policy",
        },
    ],
    "security_groups": [
        {
            "sg_id": "sg-0a1b2c3d4e",
            "sg_name": "web-server-sg",
            "level": "Critical",
            "score": 25,
            "finding": "Port 22 (SSH) is open to 0.0.0.0/0 (the entire internet)",
            "risk": "SSH is exposed to every IP address. Constant brute force target with multiple known CVEs",
            "fix": "Restrict SSH to your office IP or VPN CIDR. Never expose SSH publicly",
        },
        {
            "sg_id": "sg-5f6g7h8i9j",
            "sg_name": "database-sg",
            "level": "Critical",
            "score": 25,
            "finding": "Port 3306 (MySQL) is open to 0.0.0.0/0",
            "risk": "Database directly accessible from the internet. Databases must never be public-facing",
            "fix": "Remove the public inbound rule. Allow only from application server security group",
        },
    ],
    "cloudtrail": [
        {
            "trail": "management-trail",
            "level": "Medium",
            "score": 9,
            "finding": "Trail is not configured for multi-region logging",
            "risk": "API activity in other regions is not captured. Incidents in those regions leave no trail",
            "fix": "Enable multi-region logging on the trail to capture all account activity",
        },
    ],
}


def print_banner():
    print("\n" + "=" * 62)
    print("  AWS CLOUD SECURITY SCAN — DEMO MODE")
    print("  Simulated findings. No AWS credentials required.")
    print("=" * 62)


def print_section(title, issues, id_key):
    print(f"\n[{'1234'.index(title[0]) + 1 if title[0] in '1234' else 0}/4] {title}")
    print("-" * 62)
    if not issues:
        print("  No issues found.")
        return
    for i in issues:
        label = i.get("bucket") or i.get("user") or i.get("sg_name") or i.get("trail", "account")
        print(f"\n  [{i['level'].upper()}] {label}")
        print(f"  Finding : {i['finding']}")
        print(f"  Risk    : {i['risk']}")
        print(f"  Fix     : {i['fix']}")


def run_demo():
    print_banner()

    all_issues = []

    print(f"\n[1/4] Scanning S3 buckets...")
    print_section("S3", DEMO_FINDINGS["s3"], "bucket")
    all_issues.extend(DEMO_FINDINGS["s3"])

    print(f"\n[2/4] Analysing IAM users...")
    print_section("IAM", DEMO_FINDINGS["iam"], "user")
    all_issues.extend(DEMO_FINDINGS["iam"])

    print(f"\n[3/4] Scanning security groups...")
    print_section("SG", DEMO_FINDINGS["security_groups"], "sg_name")
    all_issues.extend(DEMO_FINDINGS["security_groups"])

    print(f"\n[4/4] Checking CloudTrail...")
    print_section("CT", DEMO_FINDINGS["cloudtrail"], "trail")
    all_issues.extend(DEMO_FINDINGS["cloudtrail"])

    critical = [i for i in all_issues if i.get("level") == "Critical"]
    high = [i for i in all_issues if i.get("level") == "High"]
    medium = [i for i in all_issues if i.get("level") == "Medium"]

    print("\n" + "=" * 62)
    print("  SUMMARY")
    print("=" * 62)
    print(f"  Total issues : {len(all_issues)}")
    print(f"  Critical     : {len(critical)}")
    print(f"  High         : {len(high)}")
    print(f"  Medium       : {len(medium)}")
    print("=" * 62)
    print("\n  This is demo output. To scan a real AWS account:")
    print("  1. Install: pip install boto3 awscli")
    print("  2. Configure: aws configure")
    print("  3. Run: python aws/run_all.py --region eu-west-1")
    print()

    with open("demo_results.json", "w") as f:
        json.dump(all_issues, f, indent=2)
    print(f"  Demo results saved to demo_results.json\n")


if __name__ == "__main__":
    run_demo()
