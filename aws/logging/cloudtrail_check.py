import boto3
import json
import argparse
from botocore.exceptions import NoCredentialsError


def run_check(profile=None, region="us-east-1"):
    session = boto3.Session(profile_name=profile, region_name=region)
    ct = session.client("cloudtrail", region_name=region)

    try:
        trails = ct.describe_trails(includeShadowTrails=False)["trailList"]
    except NoCredentialsError:
        print("No AWS credentials found. Run: aws configure")
        return []

    findings = []

    if not trails:
        findings.append({
            "level": "Critical",
            "score": 25,
            "finding": f"No CloudTrail trails configured in {region}",
            "risk": "No audit trail of API calls. You cannot investigate incidents or detect unauthorised changes",
            "fix": "Create a CloudTrail trail covering all regions and send logs to an S3 bucket",
        })
        return findings

    for trail in trails:
        name = trail["Name"]
        status = ct.get_trail_status(Name=trail["TrailARN"])

        if not status.get("IsLogging"):
            findings.append({
                "trail": name,
                "level": "Critical",
                "score": 25,
                "finding": f"Trail '{name}' exists but logging is disabled",
                "risk": "API calls are not being recorded even though the trail is configured",
                "fix": f"Enable logging on trail '{name}' immediately",
            })

        if not trail.get("IncludeGlobalServiceEvents"):
            findings.append({
                "trail": name,
                "level": "Medium",
                "score": 9,
                "finding": f"Trail '{name}' does not capture global service events",
                "risk": "IAM and STS events are not being logged, missing key security events",
                "fix": "Enable global service events on the trail",
            })

        if not trail.get("IsMultiRegionTrail"):
            findings.append({
                "trail": name,
                "level": "Medium",
                "score": 9,
                "finding": f"Trail '{name}' is not multi-region",
                "risk": "Activity in other regions is not captured",
                "fix": "Enable multi-region logging on the trail",
            })

    return sorted(findings, key=lambda x: x["score"], reverse=True)


def print_report(findings):
    if not findings:
        print("CloudTrail is properly configured. No issues found.")
        return
    print(f"\nCloudTrail Check\n{'=' * 60}")
    print(f"Issues found: {len(findings)}\n")
    for f in findings:
        trail = f.get("trail", "account-level")
        print(f"[{f['level'].upper()}] {trail}")
        print(f"  Finding : {f['finding']}")
        print(f"  Risk    : {f['risk']}")
        print(f"  Fix     : {f['fix']}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check CloudTrail configuration")
    parser.add_argument("--profile", help="AWS CLI profile name")
    parser.add_argument("--region", default="us-east-1")
    args = parser.parse_args()
    findings = run_check(args.profile, args.region)
    print_report(findings)
