import boto3
import json
import argparse
from botocore.exceptions import NoCredentialsError

DANGEROUS_POLICIES = [
    "AdministratorAccess",
    "PowerUserAccess",
    "AmazonEC2FullAccess",
    "AmazonS3FullAccess",
    "IAMFullAccess",
    "AWSLambdaFullAccess",
    "AmazonRDSFullAccess",
]


def get_users(iam):
    return iam.list_users()["Users"]


def get_user_policies(iam, username):
    attached = iam.list_attached_user_policies(UserName=username)["AttachedPolicies"]
    inline = iam.list_user_policies(UserName=username)["PolicyNames"]
    return [p["PolicyName"] for p in attached] + inline


def check_mfa(iam, username):
    devices = iam.list_mfa_devices(UserName=username)["MFADevices"]
    return len(devices) > 0


def check_access_keys(iam, username):
    keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
    old_keys = []
    for key in keys:
        if key["Status"] == "Active":
            from datetime import datetime, timezone
            created = key["CreateDate"].replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - created).days
            if age_days > 90:
                old_keys.append({"key_id": key["AccessKeyId"], "age_days": age_days})
    return old_keys


def run_analysis(profile=None, region="us-east-1"):
    session = boto3.Session(profile_name=profile, region_name=region)
    iam = session.client("iam")

    try:
        users = get_users(iam)
    except NoCredentialsError:
        print("No AWS credentials found. Run: aws configure")
        return []

    findings = []

    for user in users:
        username = user["UserName"]
        policies = get_user_policies(iam, username)
        has_mfa = check_mfa(iam, username)
        old_keys = check_access_keys(iam, username)

        for policy in policies:
            if policy in DANGEROUS_POLICIES:
                findings.append({
                    "user": username,
                    "level": "High",
                    "score": 16,
                    "finding": f"User has overly permissive policy: {policy}",
                    "risk": "If credentials are compromised, the attacker gains broad access",
                    "fix": "Apply least privilege. Replace with a scoped policy covering only what this user needs",
                })

        if not has_mfa:
            findings.append({
                "user": username,
                "level": "High",
                "score": 12,
                "finding": "MFA is not enabled",
                "risk": "Account can be taken over with just a username and password",
                "fix": "Enable MFA for this user immediately",
            })

        for key in old_keys:
            findings.append({
                "user": username,
                "level": "Medium",
                "score": 9,
                "finding": f"Access key {key['key_id']} is {key['age_days']} days old",
                "risk": "Old access keys increase the window of exposure if they are ever leaked",
                "fix": "Rotate access keys every 90 days",
            })

    return sorted(findings, key=lambda x: x["score"], reverse=True)


def print_report(findings):
    if not findings:
        print("No issues found.")
        return
    print(f"\nIAM Security Analysis\n{'=' * 60}")
    print(f"Issues found: {len(findings)}\n")
    for f in findings:
        print(f"[{f['level'].upper()}] {f['user']}")
        print(f"  Finding : {f['finding']}")
        print(f"  Risk    : {f['risk']}")
        print(f"  Fix     : {f['fix']}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyse IAM users for security issues")
    parser.add_argument("--profile", help="AWS CLI profile name")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--output", help="Save results as JSON")
    args = parser.parse_args()
    findings = run_analysis(args.profile, args.region)
    print_report(findings)
    if args.output and findings:
        with open(args.output, "w") as f:
            json.dump(findings, f, indent=2)
        print(f"Saved to {args.output}")
