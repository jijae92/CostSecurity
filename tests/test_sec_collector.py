"""Tests for security collector handler."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.common import config
from src.correlate.models import SecFinding
from src.sec_collector.handler import lambda_handler


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("APP_ENV", "dev")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("DRY_RUN", "true")
    monkeypatch.setenv("RAW_DATA_BUCKET", "")
    monkeypatch.setenv("REPORTS_BUCKET", "")
    monkeypatch.setenv("SEC_PROVIDERS", "securityhub,guardduty")
    monkeypatch.setenv("SEVERITY_MIN", "MEDIUM")
    monkeypatch.setenv("GUARDDUTY_SEVERITY_THRESHOLD", "4.0")
    monkeypatch.setenv("COST_LOOKBACK_DAYS", "14")

    from src.common import s3io

    monkeypatch.setattr(s3io, "_write_local_backup", lambda object_key, payload: _write(tmp_path, object_key, payload))
    monkeypatch.setattr(s3io, "_load_local_backup", lambda object_key: _read(tmp_path, object_key))
    config.load_config(refresh=True)


def test_security_collector_returns_findings() -> None:
    response = lambda_handler({}, {})
    assert response["status"] == "success"
    findings = [SecFinding.parse_obj(item) for item in response["findings"]]
    assert any(f.provider == "SecurityHub" for f in findings)
    assert any(f.provider == "GuardDuty" for f in findings)
    assert response["severity_counts"].get("CRITICAL", 0) >= 0


def _write(root: Path, object_key: str, payload) -> None:
    target = root / object_key.replace("/", "-")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(str(payload), encoding="utf-8")


def _read(root: Path, object_key: str):
    target = root / object_key.replace("/", "-")
    return {}
