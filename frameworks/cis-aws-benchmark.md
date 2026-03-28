# CIS AWS Foundations Benchmark

## What is it

The CIS AWS Foundations Benchmark is published by the Center for Internet Security. It is a set of security checks specifically for AWS accounts, each with a pass/fail criteria and step-by-step remediation guidance.

It is the most widely referenced standard for assessing AWS security posture. Many organisations use it as the baseline for their cloud GRC compliance programmes.

## Level 1 vs Level 2

**Level 1** controls are the essential baseline. Every AWS account should pass all of them. They are quick to implement and have a large security impact.

**Level 2** controls go deeper. They require more configuration effort and are recommended for organisations with stricter security requirements.

## Key Level 1 checks

**Identity and Access Management**
- MFA must be enabled on the root account
- No access keys should exist on the root account
- MFA should be enabled for all IAM users with console access
- Access keys must be rotated within 90 days
- Unused credentials must be disabled within 90 days
- No inline policies should grant full admin access

**Logging**
- CloudTrail must be enabled in all regions
- CloudTrail log file validation must be enabled
- CloudTrail must be integrated with CloudWatch Logs
- AWS Config must be enabled in all regions

**Monitoring**
- Alarms must exist for root account usage
- Alarms must exist for unauthorised API calls
- Alarms must exist for management console sign-ins without MFA
- Alarms must exist for IAM policy changes
- Alarms must exist for CloudTrail configuration changes
- Alarms must exist for S3 bucket policy changes
- Alarms must exist for security group changes

**Networking**
- No security groups should allow unrestricted inbound access on port 22
- No security groups should allow unrestricted inbound access on port 3389
- VPC flow logging must be enabled
- No default VPCs should exist in any region

## How to use this with the project

Run the scanners in this project and compare the output to the checks above. Any finding maps to a specific CIS control. This gives you a structured way to present your findings and prioritise remediation.

## Useful links

- [Full benchmark (free download)](https://www.cisecurity.org/benchmark/amazon_web_services)
- [AWS Security Hub CIS standard](https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html)
