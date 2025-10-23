"""Correlation rule and suppression tests."""

from __future__ import annotations

import json
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest

from src.common import config as config_module
from src.correlate import handler as correlate_handler

ACCOUNT = "123456789012"
REGION = "us-east-1"
SERVICE = "AmazonEC2"


@pytest.fixture(autouse=True)
def _base_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENV", "dev")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("DRY_RUN", "true")
    monkeypatch.setenv("RAW_DATA_BUCKET", "")
    monkeypatch.setenv("REPORTS_BUCKET", "")
    monkeypatch.setenv("SNS_TOPIC_ARN", "")
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "")
    monkeypatch.setenv("SSM_PARAMETER_PREFIX", "")
    monkeypatch.setenv("SECRETS_PREFIX", "")
    monkeypatch.setenv("COST_LOOKBACK_DAYS", "14")
    monkeypatch.setenv("COST_TIMEZONE", "UTC")
    monkeypatch.setenv("TARGET_SERVICES", "")
    monkeypatch.setenv("SEC_PROVIDERS", "securityhub,guardduty")
    monkeypatch.setenv("SEVERITY_MIN", "MEDIUM")
    monkeypatch.setenv("GUARDDUTY_SEVERITY_THRESHOLD", "4.0")
    monkeypatch.setenv("DELTA_THRESHOLD", "30")
    monkeypatch.setenv("ZSCORE_THRESHOLD", "2.0")
    monkeypatch.setenv("SUPPRESS_CONFIG_URI", "")
    config_module.load_config(refresh=True)


@pytest.fixture
def _no_reporter(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(correlate_handler, "_invoke_reporter", lambda object_key: None)


def test_rule_cost30_sec_high(_no_reporter: None) -> None:
    cost_points = _generate_cost_points(spike_amount=200.0)
    findings = [_securityhub_finding()]

    response = correlate_handler.lambda_handler({"cost_points": cost_points, "sec_findings": findings}, {})
    assert response["alert_count"] == 1
    matched = response["alerts"][0]["matched_rules"]
    assert "RULE_COST30_SEC_HIGH" in matched
    assert "RULE_GD_THREAT_COSTSPIKE" not in matched


def test_rule_gd_threat_costspike(_no_reporter: None) -> None:
    cost_points = _generate_cost_points(spike_amount=220.0)
    findings = [
        _guardduty_finding("gd-1", severity=7.0),
        _guardduty_finding("gd-2", severity=6.0),
    ]

    response = correlate_handler.lambda_handler({"cost_points": cost_points, "sec_findings": findings}, {})
    assert response["alert_count"] == 1
    matched = response["alerts"][0]["matched_rules"]
    assert "RULE_GD_THREAT_COSTSPIKE" in matched


def test_suppression_rules_block_alert(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _no_reporter: None) -> None:
    cost_points = _generate_cost_points(spike_amount=210.0)
    findings = [_securityhub_finding()]

    suppress_file = tmp_path / "suppress.json"
    suppress_file.write_text(
        json.dumps(
            {
                "suppress": [
                    {
                        "account_id": ACCOUNT,
                        "service": SERVICE,
                        "reason": "expected spike",
                        "until": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("SUPPRESS_CONFIG_URI", str(suppress_file))
    config_module.load_config(refresh=True)

    response = correlate_handler.lambda_handler({"cost_points": cost_points, "sec_findings": findings}, {})
    assert response["alert_count"] == 0
    assert response["suppressed"] >= 1


def _generate_cost_points(*, spike_amount: float) -> list[dict]:
    base_monday = date.today() - timedelta(days=date.today().weekday()) - timedelta(weeks=8)
    points: list[dict] = []
    for index in range(9):
        week_start = base_monday + timedelta(weeks=index)
        week_end = week_start + timedelta(days=6)
        amount = 100.0 if index < 8 else spike_amount
        points.append(
            {
                "period_start": week_start.isoformat(),
                "period_end": week_end.isoformat(),
                "account_id": ACCOUNT,
                "region": REGION,
                "service": SERVICE,
                "amount": amount,
                "unit": "USD",
            }
        )
    return points


def _securityhub_finding() -> dict:
    occurred = datetime.now(timezone.utc).isoformat()
    return {
        "occurred_at": occurred,
        "account_id": ACCOUNT,
        "region": REGION,
        "service": SERVICE,
        "provider": "SecurityHub",
        "severity": "HIGH",
        "title": "Test high severity finding",
        "finding_id": "sh-1",
        "raw_ref": {},
    }


def _guardduty_finding(fid: str, *, severity: float) -> dict:
    occurred = datetime.now(timezone.utc).isoformat()
    return {
        "occurred_at": occurred,
        "account_id": ACCOUNT,
        "region": REGION,
        "service": SERVICE,
        "provider": "GuardDuty",
        "severity": _severity_label(severity),
        "title": f"GuardDuty finding {fid}",
        "finding_id": fid,
        "raw_ref": {},
    }


def _severity_label(value: float) -> str:
    if value >= 7:
        return "CRITICAL"
    if value >= 4:
        return "HIGH"
    if value >= 2:
        return "MEDIUM"
    if value > 0:
        return "LOW"
    return "INFO"
