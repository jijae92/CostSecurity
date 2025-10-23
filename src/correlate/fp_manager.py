"""False positive suppression utilities."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

import boto3
from botocore.config import Config

from src.common.log import get_logger
from src.correlate.models import CorrelationAlert

LOGGER = get_logger(__name__)


@dataclass(slots=True)
class SuppressionRule:
    """Rule describing when to suppress correlation alerts."""

    account_id: Optional[str]
    region: Optional[str]
    service: Optional[str]
    pattern: Optional[str]
    reason: Optional[str]
    until: Optional[datetime]

    @classmethod
    def from_dict(cls, payload: dict) -> "SuppressionRule":
        until_value = payload.get("until")
        until_dt: Optional[datetime] = None
        if until_value:
            try:
                parsed = datetime.fromisoformat(until_value)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                until_dt = parsed
            except ValueError:
                LOGGER.warning("Invalid until format in suppression entry", extra={"value": until_value})
        return cls(
            account_id=payload.get("account_id"),
            region=payload.get("region"),
            service=payload.get("service"),
            pattern=payload.get("pattern"),
            reason=payload.get("reason"),
            until=until_dt,
        )


class FalsePositiveManager:
    """Manage suppression rules loaded from external configuration."""

    def __init__(self, rules: Iterable[SuppressionRule]):
        self.rules = [rule for rule in rules]

    @classmethod
    def from_uri(cls, uri: Optional[str]) -> "FalsePositiveManager":
        if not uri:
            return cls([])
        try:
            if uri.startswith("s3://"):
                data = cls._load_from_s3(uri)
            else:
                data = cls._load_from_file(uri)
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("Failed to load suppression configuration", extra={"uri": uri, "error": str(exc)})
            return cls([])
        suppress_entries = data.get("suppress", []) if isinstance(data, dict) else []
        rules = [SuppressionRule.from_dict(entry) for entry in suppress_entries]
        return cls(rules)

    def should_suppress(self, alert: CorrelationAlert) -> bool:
        if not self.rules:
            return False
        evidence_strings = [finding.title for finding in alert.evidence.findings]
        evidence_strings.extend(f.finding_id for f in alert.evidence.findings)
        search_blob = " ".join(
            [
                alert.service,
                alert.recommendation or "",
                " ".join(alert.matched_rules or []),
                " ".join(evidence_strings),
            ]
        ).lower()
        now = datetime.now(timezone.utc)
        for rule in self.rules:
            if rule.until and rule.until < now:
                continue
            if rule.account_id and rule.account_id != alert.account_id:
                continue
            if rule.region and (alert.region or "").lower() != rule.region.lower():
                continue
            if rule.service and rule.service.lower() != alert.service.lower():
                continue
            if rule.pattern and rule.pattern.lower() not in search_blob:
                continue
            LOGGER.info("Suppressing alert due to rule", extra={"rule": asdict(rule), "service": alert.service})
            return True
        return False

    @staticmethod
    def _load_from_file(path_str: str) -> dict:
        path = Path(path_str)
        if not path.exists():
            LOGGER.debug("Suppression file not found", extra={"path": str(path)})
            return {}
        return json.loads(path.read_text(encoding="utf-8"))

    @staticmethod
    def _load_from_s3(uri: str) -> dict:
        bucket, key = _parse_s3_uri(uri)
        session = boto3.session.Session()
        client = session.client("s3", config=Config(connect_timeout=10, read_timeout=10, retries={"max_attempts": 3}))
        response = client.get_object(Bucket=bucket, Key=key)
        body = response["Body"].read().decode("utf-8")
        return json.loads(body)


def _parse_s3_uri(uri: str) -> tuple[str, str]:
    without_scheme = uri[len("s3://") :]
    parts = without_scheme.split("/", 1)
    if len(parts) != 2:
        raise ValueError(f"Invalid S3 URI: {uri}")
    return parts[0], parts[1]


__all__ = ["FalsePositiveManager", "SuppressionRule"]
