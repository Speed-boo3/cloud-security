import boto3
import json
import argparse
from botocore.exceptions import ClientError, NoCredentialsError

RISK_LEVELS = {
    "public_access_block_disabled": {"level": "Critical", "score": 25},
    "encryption_disabled": {"level": "High", "score": 12},
    "versioning_disabled": {"level": "Medium", "score": 9},
    "logging_disabled": {"level": "Medium", "score": 6},
}

DESCRIPTIONS = {
    "public_access_block_disabled": (
        "Block Public Access is not fully enabled",
        "Anyone on the internet may be able to read or download files from this bucket",
        "Enable all four Block Public Access settings on the bucket immediately"
    ),
    "encryption_disabled": (
        "Default encryption is not configured",
        "Objects stored in this bucket are not encrypted at rest",
        "Enable AES-256 or AWS KMS encryption on the bucket"
    ),
    "versioning_disabled": (
        "Versioning is not enabled",
        "Deleted or overwritten objects cannot be recovered",
        "Enable versioning to protect against accidental deletion"
    ),
    "logging_disabled": (
        "Access logging is not enabled",
        "No audit trail exists for who accessed or modified objects in this bucket",
        "Enable server access logging and point it to a dedicated logging bucket"
    ),
}


def check_public_access(s3, bucket):
    try:
        resp = s3.get_public_access_block(Bucket=bucket)
        cfg = resp["PublicAccessBlockConfiguration"]
        if not all([cfg.get("BlockPublicAcls"), cfg.get("IgnorePublicAcls"),
                    cfg.get("BlockPublicPolicy"), cfg.get("RestrictPublicBuckets")]):
            return "public_access_block_disabled"
    except ClientError:
        return "public_access_block_disabled"
    return None


def check_encryption(s3, bucket):
    try:
        s3.get_bucket_encryption(Bucket=bucket)
        return None
    except ClientError:
        return "encryption_disabled"


def check_versioning(s3, bucket):
    resp = s3.get_bucket_versioning(Bucket=bucket)
    return "versioning_disabled" if resp.get("Status") != "Enabled" else None


def check_logging(s3, bucket):
    resp = s3.get_bucket_logging(Bucket=bucket)
    return "logging_disabled" if "LoggingEnabled" not in resp else None


def scan(profile=None, region="us-east-1"):
    session = boto3.Session(profile_name=profile, region_name=region)
    s3 = session.client("s3")
    try:
        buckets = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
    except NoCredentialsError:
        print("No AWS credentials found. Run: aws configure")
        return []

    issues = []
    for bucket in buckets:
        for check in [check_public_access, check_encryption, check_versioning, check_logging]:
            result = check(s3, bucket)
            if result:
                desc = DESCRIPTIONS[result]
                risk = RISK_LEVELS[result]
                issues.append({
                    "bucket": bucket, "issue": result,
                    "level": risk["level"], "score": risk["score"],
                    "finding": desc[0], "risk": desc[1], "fix": desc[2],
                })
    return sorted(issues, key=lambda x: x["score"], reverse=True)


def print_report(issues):
    if not issues:
        print("No issues found.")
        return
    print(f"\nS3 Security Scan\n{'=' * 60}")
    print(f"Issues found: {len(issues)}\n")
    for i in issues:
        print(f"[{i['level'].upper()}] {i['bucket']}")
        print(f"  Finding : {i['finding']}")
        print(f"  Risk    : {i['risk']}")
        print(f"  Fix     : {i['fix']}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan S3 buckets for misconfigurations")
    parser.add_argument("--profile", help="AWS CLI profile name")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--output", help="Save results as JSON")
    args = parser.parse_args()
    issues = scan(args.profile, args.region)
    print_report(issues)
    if args.output and issues:
        with open(args.output, "w") as f:
            json.dump(issues, f, indent=2)
        print(f"Saved to {args.output}")
