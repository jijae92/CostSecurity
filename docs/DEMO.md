# Demo: Intentional Cost × Security Spike

This walkthrough simulates a weekly spike where EC2 spend surges while GuardDuty/Security Hub generate correlated findings. All commands assume the repository root on a workstation with Python 3.11.

## 1. Prepare Sample Inputs
- Cost data: `docs/data/cost_explorer_sample.json` already reflects a steep week-over-week increase for AmazonEC2.
- Security events: `docs/data/security_hub_findings_sample.json` and `docs/data/guardduty_findings_sample.json` contain HIGH/CRITICAL findings timed inside the same week.
- (Optional) Adjust timestamps in the JSON files if you want to test a different ISO week.

## 2. Run the Pipeline in Dry-Run Mode
```bash
export DRY_RUN=true
mkdir -p artifacts
python -m src.correlate.handler --dry-run --use-sample-data --out artifacts/weekly_report.json
python -m src.reporter.handler --dry-run --in artifacts/weekly_report.json
```

### Expected Outputs
- `artifacts/weekly_report.json`: canonical correlation alerts (CostPoint/SecFinding evidence embedded).
- `.tmp/reports-dev-...json` & `.tmp/reports-dev-...csv`: local copies of S3 uploads when running in dry-run mode.

## 3. Markdown Summary Preview
```markdown
# [Cost×Security] 주간 상관 경보 (2025-10-20 주)

| Account | Region | Service | Δ% | 보안 이벤트 | 규칙 |
| --- | --- | --- | --- | --- | --- |
| 123456789012 | us-east-1 | AmazonEC2 | 67.4% | CRITICAL:1, HIGH:1 | RULE_COST30_SEC_HIGH, RULE_GD_THREAT_COSTSPIKE |

## 첨부
- JSON: s3://cost-security-artifacts/reports/dev/alerts.json
- CSV: s3://cost-security-artifacts/reports/dev/alerts.csv
```

## 4. Notification Examples
When `DRY_RUN=false` and valid targets are configured:
- **SNS Email/Text**
  ```text
  [Cost×Security] 주간 상관 경보 (dev)
  - Account: 123456789012 (us-east-1 / AmazonEC2)
  - Δ%: 67.4% | 규칙: RULE_COST30_SEC_HIGH, RULE_GD_THREAT_COSTSPIKE
  Full report: s3://cost-security-artifacts/reports/dev/alerts.json
  ```
- **Slack Message**
  ```text
  [Cost×Security] 주간 상관 경보 (2025-10-20 주)
  • AmazonEC2 @ us-east-1 (123456789012)
  • Δ% 67.4 | 보안 CRITICAL:1 HIGH:1
  • 규칙: RULE_COST30_SEC_HIGH, RULE_GD_THREAT_COSTSPIKE
  첨부: alerts.json / alerts.csv
  ```

## 5. Clean Up
Remove temporary artifacts if desired:
```bash
rm -rf artifacts .tmp
```

> **Note:** Set `SUPPRESS_CONFIG_URI` to point at a suppression file to mute known-good spikes during demos.
