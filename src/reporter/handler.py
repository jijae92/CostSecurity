"""Lambda handler for reporting stage."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from src.common.config import load_config
from src.common.log import get_logger
from src.common.s3io import ReportS3Reader
from src.reporter.formatter import make_attachment_links, redact, to_csv_rows, to_html, to_markdown
from src.reporter.notifier import Notifier

LOGGER = get_logger(__name__)


def lambda_handler(event: Dict[str, Any], _context: Any) -> Dict[str, Any]:
    """Format correlation alerts and dispatch notifications."""
    config = load_config()
    LOGGER.info("Starting reporter", extra={"env": config.environment, "dry_run": config.dry_run})

    object_key = event.get("object_key")
    if not object_key:
        raise ValueError("object_key must be provided")

    reader = ReportS3Reader.from_config(config)
    payload = reader.load_json(object_key=object_key)
    alerts = _ensure_list(payload)

    week_label = _derive_week_label(alerts) or datetime.now(timezone.utc).date().isoformat()
    csv_rows = to_csv_rows(alerts)
    csv_body = "\n".join(csv_rows)

    notifier = Notifier.from_config(config)
    artifact_prefix = f"reports/{config.environment}/{week_label}"
    artifact_info = notifier.persist_artifacts(
        prefix=artifact_prefix,
        json_payload=alerts,
        csv_body=csv_body,
        generate_presigned=not config.dry_run,
    )
    attachments = make_attachment_links(
        config.reports_bucket,
        {name: key for name, key in (("JSON", artifact_info.json_key), ("CSV", artifact_info.csv_key)) if key},
        {
            key: value
            for key, value in {
                "JSON": artifact_info.json_url,
                "CSV": artifact_info.csv_url,
            }.items()
            if value
        },
    )

    markdown_body = to_markdown(alerts, week_start=week_label, attachments=attachments)
    html_body = to_html(alerts, week_start=week_label, attachments=attachments)

    notifier.send(
        subject=f"[Cost×Security] 주간 상관 경보 ({config.environment})",
        markdown_body=markdown_body,
        html_body=html_body,
    )

    LOGGER.info(
        "Report dispatched",
        extra={
            "sns_topic": redact(config.sns_topic_arn),
            "slack_hook": redact(config.slack_webhook_url),
            "object_key": object_key,
            "artifact_prefix": artifact_prefix,
        },
    )
    return {
        "status": "success",
        "notifications": True,
        "object_key": object_key,
        "week": week_label,
        "artifacts": {
            "json": artifact_info.json_key,
            "csv": artifact_info.csv_key,
        },
    }


def _ensure_list(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    raise TypeError("Report payload must be a list of correlation alert objects.")


def _derive_week_label(alerts: List[Dict[str, Any]]) -> str | None:
    for alert in alerts:
        evidence = alert.get("evidence", {})
        cost_points = evidence.get("cost") or []
        if cost_points:
            first = cost_points[0]
            return str(first.get("period_start") or first.get("period_end"))
    return None


if __name__ == "__main__":
    raise SystemExit("Invoke via Lambda or orchestrated workflow only.")
