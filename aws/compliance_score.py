#!/usr/bin/env python3
"""
CIS AWS Foundations Benchmark Level 1 — Compliance Score Calculator

Reads scan results and calculates a percentage score against
the most critical CIS Level 1 controls. Outputs a colour-coded
report that shows exactly what is passing, failing and what to
fix first.

Usage:
    python aws/compliance_score.py --results results.json
    python aws/compliance_score.py --demo
"""

import json
import argparse
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))
from utils.colors import C

CIS_CONTROLS = [
    {
        "id": "1.1",
        "title": "MFA enabled on root account",
        "category": "Identity and Access Management",
        "level": "Critical",
        "check": lambda issues: not any("root" in str(i).lower() and "mfa" in str(i).lower() for i in issues),
    },
    {
        "id": "1.2",
        "title": "No access keys on root account",
        "category": "Identity and Access Management",
        "level": "Critical",
        "check": lambda issues: not any("root" in str(i).lower() and "key" in str(i).lower() for i in issues),
    },
    {
        "id": "1.3",
        "title": "MFA enabled for all IAM console users",
        "category": "Identity and Access Management",
        "level": "High",
        "check": lambda issues: not any("mfa" in str(i).lower() for i in issues),
    },
    {
        "id": "1.4",
        "title": "Access keys rotated within 90 days",
        "category": "Identity and Access Management",
        "level": "Medium",
        "check": lambda issues: not any("days old" in str(i).lower() for i in issues),
    },
    {
        "id": "1.5",
        "title": "No overly permissive IAM policies",
        "category": "Identity and Access Management",
        "level": "High",
        "check": lambda issues: not any("administratoraccess" in str(i).lower() or "fullaccess" in str(i).lower() for i in issues),
    },
    {
        "id": "2.1",
        "title": "CloudTrail enabled in all regions",
        "category": "Logging",
        "level": "Critical",
        "check": lambda issues: not any("cloudtrail" in str(i).lower() and ("disabled" in str(i).lower() or "not" in str(i).lower()) for i in issues),
    },
    {
        "id": "2.2",
        "title": "CloudTrail log file validation enabled",
        "category": "Logging",
        "level": "Medium",
        "check": lambda issues: not any("validation" in str(i).lower() for i in issues),
    },
    {
        "id": "2.3",
        "title": "CloudTrail multi-region enabled",
        "category": "Logging",
        "level": "Medium",
        "check": lambda issues: not any("multi-region" in str(i).lower() for i in issues),
    },
    {
        "id": "3.1",
        "title": "S3 Block Public Access enabled",
        "category": "Storage",
        "level": "Critical",
        "check": lambda issues: not any("block public access" in str(i).lower() for i in issues),
    },
    {
        "id": "3.2",
        "title": "S3 buckets encrypted at rest",
        "category": "Storage",
        "level": "High",
        "check": lambda issues: not any("encryption" in str(i).lower() and "not" in str(i).lower() for i in issues),
    },
    {
        "id": "3.3",
        "title": "S3 access logging enabled",
        "category": "Storage",
        "level": "Medium",
        "check": lambda issues: not any("logging" in str(i).lower() and "not enabled" in str(i).lower() for i in issues),
    },
    {
        "id": "4.1",
        "title": "SSH (port 22) not open to 0.0.0.0/0",
        "category": "Networking",
        "level": "Critical",
        "check": lambda issues: not any("22" in str(i) and "0.0.0.0" in str(i) for i in issues),
    },
    {
        "id": "4.2",
        "title": "RDP (port 3389) not open to 0.0.0.0/0",
        "category": "Networking",
        "level": "Critical",
        "check": lambda issues: not any("3389" in str(i) and "0.0.0.0" in str(i) for i in issues),
    },
    {
        "id": "4.3",
        "title": "Databases not publicly accessible",
        "category": "Networking",
        "level": "Critical",
        "check": lambda issues: not any(port in str(i) and "0.0.0.0" in str(i) for port in ["3306","5432","27017","6379"] for i in issues),
    },
]

DEMO_ISSUES = [
    {"level": "Critical", "finding": "Block Public Access is not fully enabled", "bucket": "company-backups"},
    {"level": "High", "finding": "AdministratorAccess policy attached", "user": "developer1"},
    {"level": "High", "finding": "MFA is not enabled", "user": "ci-pipeline"},
    {"level": "Critical", "finding": "Port 22 (SSH) is open to 0.0.0.0/0", "sg": "web-sg"},
    {"level": "Medium", "finding": "Trail is not multi-region", "trail": "mgmt-trail"},
    {"level": "Medium", "finding": "Access key is 143 days old", "user": "backup-service"},
]


def calculate(issues):
    results = []
    for ctrl in CIS_CONTROLS:
        passing = ctrl["check"](issues)
        results.append({**ctrl, "passing": passing})
    return results


def print_report(results, issues):
    passing = [r for r in results if r["passing"]]
    failing = [r for r in results if not r["passing"]]
    score = round(len(passing) / len(results) * 100)

    # Score colour
    if score >= 80:
        sc = C.GREEN
    elif score >= 60:
        sc = C.YELLOW
    else:
        sc = C.RED

    print(f"\n{C.GREY}{'═'*64}{C.RESET}")
    print(f"  {C.BOLD}{C.WHITE}CIS AWS FOUNDATIONS BENCHMARK — LEVEL 1{C.RESET}")
    print(f"{C.GREY}{'─'*64}{C.RESET}")
    print(f"  Compliance score : {sc}{C.BOLD}{score}%{C.RESET}  ({len(passing)}/{len(results)} controls passing)")
    print(f"{C.GREY}{'═'*64}{C.RESET}")

    # Group by category
    cats = {}
    for r in results:
        cats.setdefault(r["category"], []).append(r)

    for cat, controls in cats.items():
        cat_pass = sum(1 for c in controls if c["passing"])
        cat_pct = round(cat_pass / len(controls) * 100)
        col = C.GREEN if cat_pct == 100 else C.YELLOW if cat_pct >= 60 else C.RED
        print(f"\n  {C.BOLD}{C.WHITE}{cat}{C.RESET}  {col}{cat_pct}%{C.RESET}")
        for ctrl in controls:
            if ctrl["passing"]:
                print(f"    {C.GREEN}✓{C.RESET}  {C.GREY}{ctrl['id']}{C.RESET}  {ctrl['title']}")
            else:
                deadline = {"Critical": "immediately", "High": "within 30 days", "Medium": "within 90 days"}.get(ctrl["level"], "")
                print(f"    {C.RED}✗{C.RESET}  {C.GREY}{ctrl['id']}{C.RESET}  {ctrl['title']}  {C.RED}→ fix {deadline}{C.RESET}")

    if failing:
        print(f"\n{C.GREY}{'─'*64}{C.RESET}")
        print(f"  {C.BOLD}{C.WHITE}REMEDIATION PRIORITY{C.RESET}")
        print(f"{C.GREY}{'─'*64}{C.RESET}")
        for level in ["Critical", "High", "Medium"]:
            lvl_failing = [r for r in failing if r["level"] == level]
            col = C.RED if level == "Critical" else C.ORANGE if level == "High" else C.YELLOW
            for r in lvl_failing:
                deadline = {"Critical": "Immediately", "High": "30 days", "Medium": "90 days"}[level]
                print(f"  {col}[{level}]{C.RESET}  {r['id']} — {r['title']}  {C.GREY}({deadline}){C.RESET}")

    print(f"\n{C.GREY}{'═'*64}{C.RESET}\n")


def main():
    parser = argparse.ArgumentParser(description="CIS AWS Level 1 Compliance Score")
    parser.add_argument("--results", help="Path to scan results JSON")
    parser.add_argument("--demo", action="store_true", help="Run with demo data")
    args = parser.parse_args()

    if args.demo:
        print(f"\n  {C.GREY}Running in demo mode — no AWS credentials required{C.RESET}")
        issues = DEMO_ISSUES
    elif args.results:
        with open(args.results) as f:
            issues = json.load(f)
    else:
        parser.print_help()
        return

    results = calculate(issues)
    print_report(results, issues)


if __name__ == "__main__":
    main()
