"""Lambda handler for weekly security signal collection."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List

from src.common.config import load_config
from src.common.log import get_logger
from src.common.s3io import RawS3Writer
from src.correlate.models import SecFinding
from src.sec_collector.gd_client import GuardDutyClient
from src.sec_collector.sh_client import SecurityHubClient

LOGGER = get_logger(__name__)
SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def lambda_handler(event: Dict[str, Any], _context: Any) -> Dict[str, Any]:
    """Collect findings from Security Hub and GuardDuty."""
    config = load_config()
    LOGGER.info("Starting security collection", extra={"env": config.environment, "dry_run": config.dry_run})

    providers = _resolve_providers(event.get("providers"), config.security_providers)
    severity_min = (event.get("severity_min") or config.security_severity_min).upper()
    lookback_days = int(event.get("lookback_days") or config.cost_lookback_days)

    findings: List[SecFinding] = []
    provider_counts: Dict[str, int] = {}
    raw_payload: Dict[str, Any] = {}

    if "securityhub" in providers:
        sh_client = SecurityHubClient.from_config(config)
        sh_findings, sh_raw = sh_client.fetch_findings(min_severity=severity_min, lookback_days=lookback_days)
        findings.extend(sh_findings)
        provider_counts["SecurityHub"] = len(sh_findings)
        raw_payload["securityhub"] = sh_raw

    if "guardduty" in providers:
        gd_client = GuardDutyClient.from_config(config)
        threshold = float(event.get("guardduty_threshold") or config.guardduty_severity_threshold)
        detector_id = event.get("guardduty_detector_id")
        gd_findings, gd_raw = gd_client.fetch_findings(
            min_severity=threshold,
            lookback_days=lookback_days,
            detector_id=detector_id,
        )
        findings.extend(gd_findings)
        provider_counts["GuardDuty"] = len(gd_findings)
        raw_payload["guardduty"] = gd_raw

    if "cloudtrail" in providers:
        raw_payload["cloudtrail"] = {"Findings": [], "message": "CloudTrail@Athena integration pending implementation."}
        provider_counts["CloudTrail"] = 0

    severity_counts = _aggregate_severity(findings)

    object_key = None
    if raw_payload:
        writer = RawS3Writer.from_config(config)
        folder = datetime.now(timezone.utc).date().isoformat()
        object_key = writer.persist(payload=raw_payload, object_key=f"sec/{folder}/sec-{folder}.json")

    response = {
        "status": "success",
        "providers": provider_counts,
        "severity_counts": severity_counts,
        "object_key": object_key,
        "findings": [finding.dict() if hasattr(finding, "dict") else finding.__dict__ for finding in findings],
    }
    LOGGER.info("Security collection completed", extra={"providers": provider_counts, "severity_counts": severity_counts, "object_key": object_key})
    return response


def _resolve_providers(requested: Any, defaults: Iterable[str]) -> List[str]:
    if requested:
        if isinstance(requested, str):
            return [provider.strip().lower() for provider in requested.split(",") if provider.strip()]
        if isinstance(requested, Iterable):
            return [str(provider).lower() for provider in requested]
    return [provider.lower() for provider in defaults]


def _aggregate_severity(findings: Iterable[SecFinding]) -> Dict[str, int]:
    counts: Dict[str, int] = {level: 0 for level in SEVERITY_ORDER}
    for finding in findings:
        level = finding.severity.upper()
        if level in counts:
            counts[level] += 1
    return {level: count for level, count in counts.items() if count > 0}


if __name__ == "__main__":
    raise SystemExit("Use AWS SAM or `make invoke-security` to run the handler.")
