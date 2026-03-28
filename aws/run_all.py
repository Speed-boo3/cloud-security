import json
import argparse
from s3.s3_scanner import scan as scan_s3, print_report as print_s3
from iam.iam_analyser import run_analysis as scan_iam, print_report as print_iam
from network.sg_scanner import run_scan as scan_sg, print_report as print_sg
from logging.cloudtrail_check import run_check as scan_ct, print_report as print_ct


def run(profile=None, region="us-east-1", output=None):
    print("\n" + "=" * 60)
    print("  AWS CLOUD SECURITY SCAN")
    print("=" * 60)

    all_issues = []

    print("\n[1/4] Scanning S3 buckets...")
    s3_issues = scan_s3(profile, region)
    print_s3(s3_issues)
    all_issues.extend(s3_issues)

    print("\n[2/4] Analysing IAM users...")
    iam_issues = scan_iam(profile, region)
    print_iam(iam_issues)
    all_issues.extend(iam_issues)

    print("\n[3/4] Scanning security groups...")
    sg_issues = scan_sg(profile, region)
    print_sg(sg_issues)
    all_issues.extend(sg_issues)

    print("\n[4/4] Checking CloudTrail...")
    ct_issues = scan_ct(profile, region)
    print_ct(ct_issues)
    all_issues.extend(ct_issues)

    critical = [i for i in all_issues if i.get("level") == "Critical"]
    high = [i for i in all_issues if i.get("level") == "High"]
    medium = [i for i in all_issues if i.get("level") == "Medium"]

    print("\n" + "=" * 60)
    print("  SUMMARY")
    print("=" * 60)
    print(f"  Total issues : {len(all_issues)}")
    print(f"  Critical     : {len(critical)}")
    print(f"  High         : {len(high)}")
    print(f"  Medium       : {len(medium)}")
    print("=" * 60)

    if output:
        with open(output, "w") as f:
            json.dump(all_issues, f, indent=2)
        print(f"\nFull results saved to {output}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run all AWS security checks")
    parser.add_argument("--profile", help="AWS CLI profile name")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--output", help="Save results as JSON")
    args = parser.parse_args()
    run(args.profile, args.region, args.output)
