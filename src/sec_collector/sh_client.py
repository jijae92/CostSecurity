"""Security Hub client helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from tenacity import RetryError, retry, retry_if_exception_type, stop_after_attempt, wait_exponential_jitter

from src.common.log import get_logger
from src.correlate.models import SecFinding

LOGGER = get_logger(__name__)

SEVERITY_RANK = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


@dataclass(slots=True)
class SecurityHubClient:
    """Fetch findings from AWS Security Hub."""

    client: Any
    sample_data_root: Path
    dry_run: bool

    @classmethod
    def from_config(cls, config: "AppConfig") -> "SecurityHubClient":
        session = boto3.session.Session(region_name=config.aws_region)
        boto_config = Config(connect_timeout=10, read_timeout=10, retries={"max_attempts": 3})
        sh_client = session.client("securityhub", config=boto_config)
        return cls(client=sh_client, sample_data_root=config.sample_data_path, dry_run=config.dry_run)

    def fetch_findings(self, *, min_severity: str, lookback_days: int) -> Tuple[List[SecFinding], Dict[str, Any]]:
        filters = self._build_filters(min_severity=min_severity, lookback_days=lookback_days)
        if self.dry_run:
            LOGGER.debug("Loading security findings sample dataset.")
            raw = self._load_sample("security_hub_findings_sample.json")
        else:
            try:
                raw = self._paged_findings(filters=filters)
            except RetryError as exc:
                LOGGER.error("Security Hub request exhausted retries", extra={"filters": filters})
                raise RuntimeError("Security Hub unavailable; retry later.") from exc

        findings = [self._to_model(item) for item in raw.get("Findings", [])]
        findings = [finding for finding in findings if self._meets_threshold(finding.severity, min_severity)]
        return findings, raw

    def _build_filters(self, *, min_severity: str, lookback_days: int) -> Dict[str, Any]:
        allowed = [label for label in SEVERITY_RANK if self._meets_threshold(label, min_severity)]
        now = datetime.now(timezone.utc)
        start = (now - timedelta(days=lookback_days)).isoformat()
        return {
            "CreatedAt": [{"Start": start}],
            "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
            "SeverityLabel": [{"Value": label, "Comparison": "EQUALS"} for label in allowed],
        }

    def _meets_threshold(self, severity: str, threshold: str) -> bool:
        try:
            return SEVERITY_RANK.index(severity.upper()) >= SEVERITY_RANK.index(threshold.upper())
        except ValueError:
            return False

    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential_jitter(exp_base=2, max=20),
        retry=retry_if_exception_type((ClientError, BotoCoreError)),
        reraise=True,
    )
    def _paged_findings(self, *, filters: Dict[str, Any]) -> Dict[str, Any]:
        paginator = self.client.get_paginator("get_findings")
        findings: List[Dict[str, Any]] = []
        for page in paginator.paginate(Filters=filters):
            findings.extend(page.get("Findings", []))
        return {"Findings": findings}

    def _load_sample(self, filename: str) -> Dict[str, Any]:
        sample_path = self.sample_data_root / filename
        if not sample_path.exists():
            raise FileNotFoundError(f"Sample data file missing: {sample_path}")
        with sample_path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def _to_model(self, payload: Dict[str, Any]) -> SecFinding:
        return SecFinding(
            occurred_at=payload.get("CreatedAt") or payload.get("UpdatedAt") or datetime.utcnow().isoformat(),
            account_id=payload.get("AwsAccountId", "UNKNOWN"),
            region=payload.get("Region", "UNKNOWN"),
            service=payload.get("ProductArn", "UNKNOWN"),
            provider="SecurityHub",
            severity=str(payload.get("Severity", {}).get("Label", payload.get("Severity", "LOW"))).upper(),
            title=payload.get("Title", ""),
            finding_id=payload.get("Id", "unknown"),
            raw_ref=payload,
        )


from datetime import timedelta  # noqa: E402  pylint: disable=wrong-import-position

from src.common.config import AppConfig  # noqa: E402  pylint: disable=wrong-import-position
