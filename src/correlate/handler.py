"""Lambda handler for correlation stage."""

from __future__ import annotations

from typing import Any, Dict, List

from pydantic import ValidationError

from src.common.config import load_config
from src.common.log import get_logger
from src.common.s3io import RawS3Reader, ReportS3Writer
from src.correlate.correlate import correlate
from src.correlate.fp_manager import FalsePositiveManager
from src.correlate.models import CorrelationAlert, CostPoint, Evidence, SecFinding
from src.correlate.rules import RuleContext, RuleEngine

LOGGER = get_logger(__name__)


def lambda_handler(event: Dict[str, Any], _context: Any) -> Dict[str, Any]:
    """Correlate cost anomalies with security findings."""
    config = load_config()
    LOGGER.info("Starting correlation", extra={"env": config.environment, "dry_run": config.dry_run})

    cost_points = _load_cost_points(event, config)
    sec_findings = _load_sec_findings(event, config)

    candidates = correlate(
        cost_points,
        sec_findings,
        delta_threshold=config.delta_threshold,
        zscore_threshold=config.zscore_threshold,
    )
    rule_engine = RuleEngine()
    alerts: List[CorrelationAlert] = []
    for candidate in candidates:
        context = RuleContext(
            account_id=candidate.account_id,
            region=candidate.region,
            service=candidate.service,
            cost_delta_pct=candidate.delta_pct,
            cost_anomaly_score=candidate.cost_anomaly_score,
            severity_counts=candidate.severity_counts,
            provider_counts=candidate.provider_counts,
            guardduty_high_count=candidate.guardduty_high_count,
            new_service_count=candidate.new_service_count,
            delta_threshold=config.delta_threshold,
            zscore_threshold=config.zscore_threshold,
        )
        matches = rule_engine.evaluate(context)
        matched_rules = [match.name for match in matches]
        recommendations = [match.recommendation for match in matches]
        if not matched_rules:
            continue
        recommendation = " ".join(dict.fromkeys(recommendations)) if recommendations else "추가 분석이 필요합니다."
        alert = CorrelationAlert(
            account_id=candidate.account_id,
            region=candidate.region,
            service=candidate.service,
            cost_delta_pct=candidate.delta_pct,
            cost_anomaly_score=candidate.cost_anomaly_score,
            sec_counts=candidate.severity_counts,
            matched_rules=matched_rules,
            recommendation=recommendation,
            evidence=Evidence(cost=candidate.cost_points, findings=candidate.findings),
        )
        alerts.append(alert)

    fp_manager = FalsePositiveManager.from_uri(config.suppress_config_uri)
    filtered_alerts = [alert for alert in alerts if not fp_manager.should_suppress(alert)]
    suppressed = len(alerts) - len(filtered_alerts)

    object_key = None
    if filtered_alerts:
        writer = ReportS3Writer.from_config(config)
        payload = [_alert_to_dict(alert) for alert in filtered_alerts]
        object_key = writer.persist_json(payload=payload, prefix="correlated")
        _invoke_reporter(object_key)

    LOGGER.info(
        "Correlation run completed",
        extra={"alerts": len(filtered_alerts), "suppressed": suppressed, "object_key": object_key},
    )
    return {
        "status": "success",
        "alert_count": len(filtered_alerts),
        "suppressed": suppressed,
        "object_key": object_key,
        "alerts": [_alert_to_dict(alert) for alert in filtered_alerts],
    }


def _load_cost_points(event: Dict[str, Any], config) -> List[CostPoint]:
    payload = event.get("cost_points")
    if payload is None:
        cost_key = event.get("cost_object_key")
        if not cost_key:
            raise ValueError("cost_points or cost_object_key must be provided")
        reader = RawS3Reader.from_config(config)
        raw = reader.load(object_key=cost_key)
        payload = _convert_raw_cost_to_points(raw)
    cost_points: List[CostPoint] = []
    for item in payload:
        try:
            cost_points.append(CostPoint.parse_obj(item))
        except ValidationError as exc:
            LOGGER.warning("Invalid cost point skipped", extra={"error": str(exc)})
    return cost_points


def _load_sec_findings(event: Dict[str, Any], config) -> List[SecFinding]:
    payload = event.get("sec_findings")
    if payload is None:
        security_key = event.get("sec_object_key") or event.get("security_object_key")
        if not security_key:
            raise ValueError("sec_findings or security_object_key must be provided")
        reader = RawS3Reader.from_config(config)
        raw = reader.load(object_key=security_key)
        payload = _convert_raw_findings_to_sec(raw)
    findings: List[SecFinding] = []
    for item in payload:
        try:
            findings.append(SecFinding.parse_obj(item))
        except ValidationError as exc:
            LOGGER.warning("Invalid security finding skipped", extra={"error": str(exc)})
    return findings



def _alert_to_dict(alert: CorrelationAlert) -> Dict[str, Any]:
    return {
        "window": alert.window,
        "account_id": alert.account_id,
        "region": alert.region,
        "service": alert.service,
        "cost_delta_pct": alert.cost_delta_pct,
        "cost_anomaly_score": alert.cost_anomaly_score,
        "sec_counts": dict(alert.sec_counts),
        "matched_rules": list(alert.matched_rules),
        "recommendation": alert.recommendation,
        "evidence": {
            "cost": [point.dict() for point in alert.evidence.cost],
            "findings": [finding.dict() for finding in alert.evidence.findings],
        },
    }

def _convert_raw_cost_to_points(raw: Dict[str, Any]) -> List[Dict[str, Any]]:
    points: List[Dict[str, Any]] = []
    for time_slice in raw.get("ResultsByTime", []):
        period_start = time_slice.get("TimePeriod", {}).get("Start")
        period_end = time_slice.get("TimePeriod", {}).get("End", period_start)
        for group in time_slice.get("Groups", []):
            keys = group.get("Keys", [])
            points.append(
                {
                    "period_start": period_start,
                    "period_end": period_end,
                    "account_id": keys[1] if len(keys) > 1 else "UNKNOWN",
                    "region": keys[2] if len(keys) > 2 else "ALL",
                    "service": keys[0] if keys else "UNKNOWN",
                    "amount": float(group.get("Metrics", {}).get("BlendedCost", {}).get("Amount", 0.0)),
                    "unit": group.get("Metrics", {}).get("BlendedCost", {}).get("Unit", "USD"),
                }
            )
    return points


def _convert_raw_findings_to_sec(raw: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for finding in raw.get("securityhub", {}).get("Findings", []):
        findings.append(
            {
                "occurred_at": finding.get("CreatedAt") or finding.get("UpdatedAt"),
                "account_id": finding.get("AwsAccountId", "UNKNOWN"),
                "region": finding.get("Region", "UNKNOWN"),
                "service": finding.get("ProductArn", "UNKNOWN"),
                "provider": "SecurityHub",
                "severity": str(finding.get("Severity", {}).get("Label", "LOW")).upper(),
                "title": finding.get("Title", ""),
                "finding_id": finding.get("Id", "unknown"),
                "raw_ref": finding,
            }
        )
    for finding in raw.get("guardduty", {}).get("Findings", []):
        findings.append(
            {
                "occurred_at": finding.get("CreatedAt"),
                "account_id": finding.get("AccountId", "UNKNOWN"),
                "region": finding.get("Region", "UNKNOWN"),
                "service": finding.get("Type", "UNKNOWN"),
                "provider": "GuardDuty",
                "severity": _guardduty_severity_label(finding.get("Severity")),
                "title": finding.get("Title", ""),
                "finding_id": finding.get("Id", "unknown"),
                "raw_ref": finding,
            }
        )
    return findings


def _guardduty_severity_label(value: Any) -> str:
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        numeric = 0.0
    if numeric >= 7:
        return "CRITICAL"
    if numeric >= 4:
        return "HIGH"
    if numeric >= 2:
        return "MEDIUM"
    if numeric > 0:
        return "LOW"
    return "INFO"


def _invoke_reporter(object_key: str) -> None:
    try:
        from src.reporter.handler import lambda_handler as reporter_handler

        reporter_handler({"object_key": object_key}, None)
    except Exception as exc:  # noqa: BLE001
        LOGGER.warning("Reporter invocation failed", extra={"error": str(exc), "object_key": object_key})


if __name__ == "__main__":
    raise SystemExit("Invoke via Lambda or orchestrated workflow only.")
