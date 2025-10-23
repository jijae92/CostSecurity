"""Cost Explorer client with retry, timeout, and sample data support."""

from __future__ import annotations

import json
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from tenacity import RetryError, retry, retry_if_exception_type, stop_after_attempt, wait_exponential_jitter

from src.common.log import get_logger
from src.correlate.models import CostPoint

LOGGER = get_logger(__name__)

GROUP_DIMENSIONS = [
    {"Type": "DIMENSION", "Key": "SERVICE"},
    {"Type": "DIMENSION", "Key": "LINKED_ACCOUNT"},
    {"Type": "DIMENSION", "Key": "REGION"},
]


@dataclass(slots=True)
class CostExplorerClient:
    """Wrapper around the AWS Cost Explorer API."""

    client: Any
    sample_data_root: Path
    dry_run: bool
    target_services: frozenset[str]

    @classmethod
    def from_config(cls, config: "AppConfig") -> "CostExplorerClient":
        """Build the client using shared configuration."""
        session = boto3.session.Session(region_name=config.aws_region)
        boto_config = Config(connect_timeout=10, read_timeout=10, retries={"max_attempts": 3})
        ce_client = session.client("ce", config=boto_config)
        targets = frozenset(svc.lower() for svc in config.target_services)
        return cls(
            client=ce_client,
            sample_data_root=config.sample_data_path,
            dry_run=config.dry_run,
            target_services=targets,
        )

    def fetch_cost_points(self, *, start: str, end: str, services: Iterable[str] | None = None) -> Tuple[List[CostPoint], Dict[str, Any]]:
        """Retrieve cost points for the selected time window."""
        time_period = {"Start": start, "End": end}
        group_by = GROUP_DIMENSIONS
        if self.dry_run:
            LOGGER.debug("Loading cost data from sample dataset.")
            raw = self._load_sample("cost_explorer_sample.json")
        else:
            try:
                raw = self._call_cost_explorer(time_period=time_period, group_by=group_by)
            except RetryError as exc:
                LOGGER.error("Cost Explorer request exhausted retries", extra={"time_period": time_period})
                raise RuntimeError("Cost Explorer API unavailable; retry later.") from exc

        allowed_services = self._resolve_allowed_services(services)
        cost_points = self._to_cost_points(raw_payload=raw, allowed_services=allowed_services)
        return cost_points, raw

    def _resolve_allowed_services(self, services: Iterable[str] | None) -> frozenset[str] | None:
        if services:
            explicit = frozenset(svc.lower() for svc in services)
            return explicit
        if self.target_services:
            return self.target_services
        return None

    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential_jitter(exp_base=2, max=20),
        retry=retry_if_exception_type((ClientError, BotoCoreError)),
        reraise=True,
    )
    def _call_cost_explorer(self, *, time_period: Dict[str, str], group_by: List[Dict[str, str]]) -> Dict[str, Any]:
        LOGGER.info("Requesting cost data", extra={"start": time_period.get("Start"), "end": time_period.get("End")})
        return self.client.get_cost_and_usage(
            TimePeriod=time_period,
            Metrics=["AmortizedCost", "BlendedCost", "UnblendedCost"],
            Granularity="DAILY",
            GroupBy=group_by,
        )

    def _to_cost_points(self, *, raw_payload: Dict[str, Any], allowed_services: frozenset[str] | None) -> List[CostPoint]:
        results: List[CostPoint] = []
        for time_slice in raw_payload.get("ResultsByTime", []):
            start = time_slice.get("TimePeriod", {}).get("Start")
            end = time_slice.get("TimePeriod", {}).get("End")
            for group in time_slice.get("Groups", []):
                keys = group.get("Keys", [])
                service = (keys[0] if len(keys) > 0 else "UNKNOWN") or "UNKNOWN"
                account_id = (keys[1] if len(keys) > 1 else "UNKNOWN") or "UNKNOWN"
                region = (keys[2] if len(keys) > 2 else "ALL") or "ALL"
                if allowed_services and service.lower() not in allowed_services:
                    continue
                cost_amount, unit = _extract_amount(group.get("Metrics", {}))
                results.append(
                    CostPoint(
                        period_start=start or "",
                        period_end=end or "",
                        account_id=account_id,
                        region=region,
                        service=service,
                        amount=cost_amount,
                        unit=unit,
                    )
                )
        return results

    def _load_sample(self, filename: str) -> Dict[str, Any]:
        sample_path = self.sample_data_root / filename
        if not sample_path.exists():
            raise FileNotFoundError(f"Sample data file missing: {sample_path}")
        LOGGER.debug("Reading sample file", extra={"path": str(sample_path)})
        with sample_path.open("r", encoding="utf-8") as handler:
            return json.load(handler)


def _extract_amount(metrics: Dict[str, Any]) -> Tuple[float, str]:
    for metric_name in ("AmortizedCost", "BlendedCost", "UnblendedCost"):
        metric = metrics.get(metric_name, {})
        amount = metric.get("Amount")
        unit = metric.get("Unit", "USD")
        if amount is not None:
            return _to_float(amount), unit
    return 0.0, "USD"


def _to_float(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, Decimal):
        return float(value)
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return 0.0


# Avoid circular import at module level
from src.common.config import AppConfig  # noqa: E402  pylint: disable=wrong-import-position
