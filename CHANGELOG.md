# Changelog

## v1.4.0 — 2026-03-29
- Add CIS AWS Level 1 compliance score calculator (`aws/compliance_score.py`)
- Compliance score grouped by category: IAM, Logging, Storage, Networking
- Remediation roadmap with deadlines per severity level
- Coloured terminal output across all scanners (Critical=red, High=orange, Medium=yellow)
- Utility module `aws/utils/colors.py` for consistent output formatting

## v1.3.0 — 2026-03-22
- Add `aws/demo_mode.py` — full scan simulation with no AWS credentials required
- Demo output matches real scanner format exactly
- Demo results saved to `demo_results.json` for downstream use

## v1.2.0 — 2026-03-15
- Add `aws/network/sg_scanner.py` — security group exposure detection
- Scans for dangerous ports open to 0.0.0.0/0: SSH, RDP, MySQL, PostgreSQL, Redis, MongoDB
- Add `aws/logging/cloudtrail_check.py` — CloudTrail configuration verification
- Checks: logging enabled, multi-region, global service events, log file validation

## v1.1.0 — 2026-03-08
- Add `aws/iam/iam_analyser.py` — IAM user and policy analysis
- Detects overly permissive policies (AdministratorAccess, FullAccess variants)
- Detects missing MFA on console users
- Detects access keys older than 90 days

## v1.0.0 — 2026-03-01
- Initial release: `aws/s3/s3_scanner.py`
- S3 checks: Block Public Access, default encryption, versioning, access logging
- `aws/run_all.py` — run all scanners in sequence
- CIS AWS Foundations Benchmark documentation in `frameworks/`
- Remediation report template in `templates/`
