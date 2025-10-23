"""GuardDuty client helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from tenacity import RetryError, retry, retry_if_exception_type, stop_after_attempt, wait_exponential_jitter

from src.common.log import get_logger
from src.correlate.models import SecFinding

LOGGER = get_logger(__name__)


@dataclass(slots=True)
class GuardDutyClient:
    """Fetch findings from AWS GuardDuty."""

    client: Any
    sample_data_root: Path
    dry_run: bool

    @classmethod
    def from_config(cls, config: "AppConfig") -> "GuardDutyClient":
        session = boto3.session.Session(region_name=config.aws_region)
        boto_config = Config(connect_timeout=10, read_timeout=10, retries={"max_attempts": 3})
        gd_client = session.client("guardduty", config=boto_config)
        return cls(client=gd_client, sample_data_root=config.sample_data_path, dry_run=config.dry_run)

    def fetch_findings(
        self,
        *,
        min_severity: float,
        lookback_days: int,
        detector_id: str | None = None,
    ) -> Tuple[List[SecFinding], Dict[str, Any]]:
        if self.dry_run:
            LOGGER.debug("Loading GuardDuty findings sample dataset.")
            raw = self._load_sample("guardduty_findings_sample.json")
        else:
            detector = detector_id or self._get_default_detector()
            if not detector:
                raise RuntimeError("GuardDuty detector ID could not be determined.")
            try:
                finding_ids = self._list_finding_ids(
                    detector_id=detector,
                    min_severity=min_severity,
                    lookback_days=lookback_days,
                )
                raw = self._get_findings(detector_id=detector, finding_ids=finding_ids)
            except RetryError as exc:
                LOGGER.error("GuardDuty request exhausted retries", extra={"detector_id": detector})
                raise RuntimeError("GuardDuty unavailable; retry later.") from exc

        findings = [self._to_model(item) for item in raw.get("Findings", [])]
        findings = [finding for finding in findings if _severity_to_numeric(finding.severity) >= min_severity]
        return findings, raw

    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential_jitter(exp_base=2, max=20),
        retry=retry_if_exception_type((ClientError, BotoCoreError)),
        reraise=True,
    )
    def _get_default_detector(self) -> str | None:
        detectors = self.client.list_detectors().get("DetectorIds", [])
        return detectors[0] if detectors else None

    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential_jitter(exp_base=2, max=20),
        retry=retry_if_exception_type((ClientError, BotoCoreError)),
        reraise=True,
    )
    def _list_finding_ids(self, *, detector_id: str, min_severity: float, lookback_days: int) -> List[str]:
        criteria = {
            "Criterion": {
                "severity": {"Gte": min_severity},
                "updatedAt": {"Gte": (datetime.now(timezone.utc) - timedelta(days=lookback_days)).isoformat()},
            }
        }
        response = self.client.list_findings(DetectorId=detector_id, FindingCriteria=criteria)
        return response.get("FindingIds", [])

    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential_jitter(exp_base=2, max=20),
        retry=retry_if_exception_type((ClientError, BotoCoreError)),
        reraise=True,
    )
    def _get_findings(self, *, detector_id: str, finding_ids: List[str]) -> Dict[str, Any]:
        if not finding_ids:
            return {"Findings": []}
        response = self.client.get_findings(DetectorId=detector_id, FindingIds=finding_ids)
        return {"Findings": response.get("Findings", [])}

    def _load_sample(self, filename: str) -> Dict[str, Any]:
        sample_path = self.sample_data_root / filename
        if not sample_path.exists():
            raise FileNotFoundError(f"Sample data file missing: {sample_path}")
        with sample_path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def _to_model(self, payload: Dict[str, Any]) -> SecFinding:
        severity = payload.get("Severity")
        return SecFinding(
            occurred_at=payload.get("CreatedAt") or datetime.utcnow().isoformat(),
            account_id=payload.get("AccountId", "UNKNOWN"),
            region=payload.get("Region", "UNKNOWN"),
            service=payload.get("Type", "UNKNOWN"),
            provider="GuardDuty",
            severity=_severity_to_label(severity),
            title=payload.get("Title", ""),
            finding_id=payload.get("Id", "unknown"),
            raw_ref=payload,
        )


def _severity_to_numeric(value: Any) -> float:
    try:
        if isinstance(value, str) and not value.replace(".", "", 1).isdigit():
            return {
                "INFO": 0.5,
                "LOW": 1.0,
                "MEDIUM": 3.0,
                "HIGH": 6.0,
                "CRITICAL": 8.0,
            }.get(value.upper(), 0.0)
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _severity_to_label(value: Any) -> str:
    numeric = _severity_to_numeric(value)
    if numeric >= 7:
        return "CRITICAL"
    if numeric >= 4:
        return "HIGH"
    if numeric >= 2:
        return "MEDIUM"
    if numeric > 0:
        return "LOW"
    return "INFO"


from src.common.config import AppConfig  # noqa: E402  pylint: disable=wrong-import-position
