"""Lambda handler for weekly cost collection."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, Tuple
from zoneinfo import ZoneInfo

from src.common.config import load_config
from src.common.log import get_logger
from src.common.s3io import RawS3Writer
from src.cost_collector.ce_client import CostExplorerClient

LOGGER = get_logger(__name__)


def lambda_handler(event: Dict[str, Any], _context: Any) -> Dict[str, Any]:
    """Entry point expected by AWS Lambda."""
    config = load_config()
    LOGGER.info("Starting cost collection", extra={"env": config.environment, "dry_run": config.dry_run})

    period_start, period_end = _resolve_time_range(
        event=event,
        timezone_name=config.cost_timezone,
        lookback_days=config.cost_lookback_days,
    )
    target_services = _event_services(event) or config.target_services

    client = CostExplorerClient.from_config(config)
    cost_points, raw_payload = client.fetch_cost_points(
        start=period_start,
        end=period_end,
        services=target_services,
    )

    object_key = None
    if raw_payload:
        writer = RawS3Writer.from_config(config)
        object_key = writer.persist(
            payload=raw_payload,
            object_key=f"cost/{period_start}/cost-{period_start}-to-{period_end}.json",
        )

    result = {
        "status": "success",
        "records": len(cost_points),
        "time_period": {"start": period_start, "end": period_end},
        "object_key": object_key,
        "cost_points": [point.dict() if hasattr(point, "dict") else point.__dict__ for point in cost_points],
    }
    LOGGER.info("Cost collection completed", extra={"records": result["records"], "object_key": object_key})
    return result


def _resolve_time_range(*, event: Dict[str, Any], timezone_name: str, lookback_days: int) -> Tuple[str, str]:
    event_start = event.get("time_min")
    event_end = event.get("time_max")
    if event_start and event_end:
        return event_start[:10], event_end[:10]

    tz = ZoneInfo(timezone_name)
    now = datetime.now(tz=tz)
    start_of_week = now - timedelta(days=now.weekday() + 7)
    min_start = (now - timedelta(days=lookback_days)).date()
    start = start_of_week.replace(hour=0, minute=0, second=0, microsecond=0).date()
    if start < min_start:
        start = min_start
    end = start + timedelta(days=6)
    return start.isoformat(), end.isoformat()


def _event_services(event: Dict[str, Any]) -> Iterable[str] | None:
    services = event.get("services") or event.get("target_services")
    if not services:
        return None
    if isinstance(services, str):
        return [svc.strip() for svc in services.split(",") if svc.strip()]
    if isinstance(services, Iterable):
        return list(services)
    return None


if __name__ == "__main__":
    raise SystemExit("Use AWS SAM or `make invoke-cost` to run the handler.")
