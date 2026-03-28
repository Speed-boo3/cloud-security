import boto3
import json
import argparse
from botocore.exceptions import NoCredentialsError

DANGEROUS_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    27017: "MongoDB",
    6379: "Redis",
    21: "FTP",
    23: "Telnet",
    25: "SMTP",
}


def check_sg(sg):
    issues = []
    for rule in sg.get("IpPermissions", []):
        from_port = rule.get("FromPort", 0)
        to_port = rule.get("ToPort", 65535)
        for cidr in rule.get("IpRanges", []):
            if cidr.get("CidrIp") in ("0.0.0.0/0", "::/0"):
                for port, service in DANGEROUS_PORTS.items():
                    if from_port <= port <= to_port:
                        issues.append({
                            "sg_id": sg["GroupId"],
                            "sg_name": sg.get("GroupName", "unknown"),
                            "level": "Critical" if port in (22, 3389) else "High",
                            "score": 25 if port in (22, 3389) else 16,
                            "finding": f"Port {port} ({service}) is open to the entire internet",
                            "risk": f"{service} is exposed to 0.0.0.0/0 — anyone can attempt connections",
                            "fix": f"Restrict port {port} to specific IP addresses or a VPN",
                        })
        for ipv6 in rule.get("Ipv6Ranges", []):
            if ipv6.get("CidrIpv6") == "::/0":
                for port, service in DANGEROUS_PORTS.items():
                    if from_port <= port <= to_port:
                        issues.append({
                            "sg_id": sg["GroupId"],
                            "sg_name": sg.get("GroupName", "unknown"),
                            "level": "High",
                            "score": 16,
                            "finding": f"Port {port} ({service}) is open to all IPv6 addresses",
                            "risk": f"{service} is exposed to ::/0",
                            "fix": f"Restrict port {port} to specific IP addresses",
                        })
    return issues


def run_scan(profile=None, region="us-east-1"):
    session = boto3.Session(profile_name=profile, region_name=region)
    ec2 = session.client("ec2", region_name=region)
    try:
        sgs = ec2.describe_security_groups()["SecurityGroups"]
    except NoCredentialsError:
        print("No AWS credentials found. Run: aws configure")
        return []

    all_issues = []
    for sg in sgs:
        all_issues.extend(check_sg(sg))
    return sorted(all_issues, key=lambda x: x["score"], reverse=True)


def print_report(issues):
    if not issues:
        print("No issues found.")
        return
    print(f"\nSecurity Group Scan\n{'=' * 60}")
    print(f"Issues found: {len(issues)}\n")
    for i in issues:
        print(f"[{i['level'].upper()}] {i['sg_name']} ({i['sg_id']})")
        print(f"  Finding : {i['finding']}")
        print(f"  Risk    : {i['risk']}")
        print(f"  Fix     : {i['fix']}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan security groups for open dangerous ports")
    parser.add_argument("--profile", help="AWS CLI profile name")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--output", help="Save results as JSON")
    args = parser.parse_args()
    issues = run_scan(args.profile, args.region)
    print_report(issues)
    if args.output and issues:
        with open(args.output, "w") as f:
            json.dump(issues, f, indent=2)
        print(f"Saved to {args.output}")
