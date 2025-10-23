"""Tests for cost collector handler."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from src.cost_collector.handler import lambda_handler
from src.common import config
from src.correlate.models import CostPoint


@pytest.fixture(autouse=True)
def _setup_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("APP_ENV", "dev")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("DRY_RUN", "true")
    monkeypatch.setenv("RAW_DATA_BUCKET", "")
    monkeypatch.setenv("REPORTS_BUCKET", "")
    monkeypatch.setenv("SSM_PARAMETER_PREFIX", "")
    monkeypatch.setenv("SECRETS_PREFIX", "")
    monkeypatch.setenv("COST_LOOKBACK_DAYS", "14")
    monkeypatch.setenv("COST_TIMEZONE", "UTC")
    monkeypatch.setenv("TARGET_SERVICES", "")

    from src.common import s3io

    monkeypatch.setattr(s3io, "_write_local_backup", lambda object_key, payload: _write_tmp(tmp_path, object_key, payload))
    monkeypatch.setattr(s3io, "_load_local_backup", lambda object_key: _read_tmp(tmp_path, object_key))
    config.load_config(refresh=True)


def test_lambda_handler_returns_cost_points() -> None:
    result = lambda_handler({}, {})
    assert result["status"] == "success"
    points = result["cost_points"]
    assert isinstance(points, list) and points
    parsed = [CostPoint.parse_obj(item) for item in points]
    assert parsed[0].service.lower().startswith("amazonec2")
    assert parsed[0].amount > 0
    assert result["records"] == len(points)


def _write_tmp(root: Path, object_key: str, payload: Any) -> None:
    target = root / object_key.replace("/", "-")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(str(payload), encoding="utf-8")


def _read_tmp(root: Path, object_key: str) -> Any:
    target = root / object_key.replace("/", "-")
    return {}
