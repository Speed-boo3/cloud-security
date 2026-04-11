# Contributing

Contributions are welcome. Please open an issue first to discuss what you would like to change.

## Running without AWS

```bash
git clone https://github.com/Speed-boo3/cloud-security.git
cd cloud-security
pip install -r requirements.txt
python aws/demo_mode.py
python aws/compliance_score.py --demo
```

## Running against a real AWS account

```bash
pip install awscli
aws configure
python aws/run_all.py --region eu-west-1 --output results.json
python aws/compliance_score.py --results results.json
```
