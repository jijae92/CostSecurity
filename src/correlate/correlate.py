"""Correlation utilities aligning cost anomalies with security findings."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from statistics import mean, median
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from src.correlate.models import CostPoint, SecFinding
from src.common.log import get_logger

LOGGER = get_logger(__name__)

SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


@dataclass(slots=True)
class CorrelationCandidate:
    """Intermediate correlation result prior to rule processing."""

    account_id: str
    region: str
    service: str
    week_start: date
    week_end: date
    amount: float
    delta_pct: float
    robust_z: float
    cost_anomaly_score: float
    cost_points: List[CostPoint]
    findings: List[SecFinding]
    severity_counts: Dict[str, int]
    provider_counts: Dict[str, int]
    guardduty_high_count: int
    new_service_count: int


@dataclass(slots=True)
class _CostWindow:
    amount: float
    cost_points: List[CostPoint]


@dataclass(slots=True)
class _CostAnomaly:
    account_id: str
    region: str
    service: str
    week_start: date
    week_end: date
    amount: float
    delta_pct: float
    robust_z: float
    cost_anomaly_score: float
    cost_points: List[CostPoint]
    previous_amounts: List[float]
    new_service_count: int


def correlate(
    cost_points: Sequence[CostPoint],
    findings: Sequence[SecFinding],
    *,
    delta_threshold: float,
    zscore_threshold: float,
    buffer_hours: int = 24,
) -> List[CorrelationCandidate]:
    """Detect cost anomalies and align them with nearby security findings."""
    anomalies = _detect_cost_anomalies(cost_points, delta_threshold, zscore_threshold)
    if not anomalies:
        LOGGER.info("No cost anomalies detected.")
        return []

    indexes = _build_finding_indexes(findings)
    candidates: List[CorrelationCandidate] = []
    for anomaly in anomalies:
        matched = _match_findings(anomaly, indexes, buffer_hours=buffer_hours)
        if not matched:
            continue
        severity_counts = _count_severity(matched)
        provider_counts = _count_provider(matched)
        guardduty_high = sum(
            1 for finding in matched if finding.provider == "GuardDuty" and finding.severity in {"HIGH", "CRITICAL"}
        )
        candidates.append(
            CorrelationCandidate(
                account_id=anomaly.account_id,
                region=anomaly.region,
                service=anomaly.service,
                week_start=anomaly.week_start,
                week_end=anomaly.week_end,
                amount=anomaly.amount,
                delta_pct=anomaly.delta_pct,
                robust_z=anomaly.robust_z,
                cost_anomaly_score=anomaly.cost_anomaly_score,
                cost_points=anomaly.cost_points,
                findings=matched,
                severity_counts=severity_counts,
                provider_counts=provider_counts,
                guardduty_high_count=guardduty_high,
                new_service_count=anomaly.new_service_count,
            )
        )

    LOGGER.info("Correlation completed", extra={"candidates": len(candidates)})
    return candidates


def _detect_cost_anomalies(
    cost_points: Sequence[CostPoint],
    delta_threshold: float,
    zscore_threshold: float,
    history_weeks: int = 8,
) -> List[_CostAnomaly]:
    if not cost_points:
        return []

    cost_by_key: Dict[Tuple[str, str, str], Dict[date, _CostWindow]] = defaultdict(lambda: defaultdict(lambda: _CostWindow(0.0, [])))  # type: ignore
    account_week_services: Dict[Tuple[str, date], set[str]] = defaultdict(set)

    for point in cost_points:
        week_start = _week_start(_parse_date(point.period_start))
        key = (point.account_id, point.region or "ALL", point.service)
        window = cost_by_key[key][week_start]
        window.amount += point.amount
        window.cost_points.append(point)
        account_week_services[(point.account_id, week_start)].add(point.service)

    account_week_new_services = _calculate_new_services(account_week_services)

    anomalies: List[_CostAnomaly] = []
    for key, week_data in cost_by_key.items():
        account_id, region, service = key
        sorted_weeks = sorted(week_data.keys())
        for idx, week_start in enumerate(sorted_weeks):
            if idx == 0:
                continue
            prev_window_starts = sorted_weeks[max(0, idx - history_weeks) : idx]
            if not prev_window_starts:
                continue
            current_window = week_data[week_start]
            previous_amounts = [week_data[w].amount for w in prev_window_starts]
            avg_prev = mean(previous_amounts)
            delta_pct = ((current_window.amount - avg_prev) / max(1.0, avg_prev)) * 100.0
            robust_z = _robust_z_score(current_window.amount, previous_amounts)
            norm_delta = _normalise(delta_pct, delta_threshold)
            norm_z = _normalise(robust_z, zscore_threshold)
            score = max(norm_delta, norm_z)
            if score < 1.0:
                continue
            anomalies.append(
                _CostAnomaly(
                    account_id=account_id,
                    region=region,
                    service=service,
                    week_start=week_start,
                    week_end=week_start + timedelta(days=6),
                    amount=current_window.amount,
                    delta_pct=delta_pct,
                    robust_z=robust_z,
                    cost_anomaly_score=score,
                    cost_points=current_window.cost_points,
                    previous_amounts=previous_amounts,
                    new_service_count=account_week_new_services.get((account_id, week_start), 0),
                )
            )
    return anomalies


def _calculate_new_services(account_week_services: Dict[Tuple[str, date], set[str]]) -> Dict[Tuple[str, date], int]:
    per_account_weeks: Dict[str, List[date]] = defaultdict(list)
    for (account, week), _services in account_week_services.items():
        per_account_weeks[account].append(week)
    for weeks in per_account_weeks.values():
        weeks.sort()

    new_service_counts: Dict[Tuple[str, date], int] = {}
    seen_services_by_account: Dict[str, set[str]] = defaultdict(set)
    for account, weeks in per_account_weeks.items():
        for week in weeks:
            services = account_week_services[(account, week)]
            new_services = {svc for svc in services if svc not in seen_services_by_account[account]}
            new_service_counts[(account, week)] = len(new_services)
            seen_services_by_account[account].update(services)
    return new_service_counts


def _build_finding_indexes(
    findings: Sequence[SecFinding],
) -> Tuple[Dict[Tuple[str, str, str], List[SecFinding]], Dict[Tuple[str, str], List[SecFinding]]]:
    primary: Dict[Tuple[str, str, str], List[SecFinding]] = defaultdict(list)
    fallback: Dict[Tuple[str, str], List[SecFinding]] = defaultdict(list)
    for finding in findings:
        service = finding.service or "UNKNOWN"
        key = (finding.account_id, finding.region or "UNKNOWN", service)
        primary[key].append(finding)
        if service.upper() == "UNKNOWN":
            fallback[(finding.account_id, finding.region or "UNKNOWN")].append(finding)
        else:
            fallback[(finding.account_id, finding.region or "UNKNOWN")].append(finding)
    return primary, fallback


def _match_findings(
    anomaly: _CostAnomaly,
    indexes: Tuple[Dict[Tuple[str, str, str], List[SecFinding]], Dict[Tuple[str, str], List[SecFinding]]],
    *,
    buffer_hours: int,
) -> List[SecFinding]:
    primary, fallback = indexes
    window_start = datetime.combine(anomaly.week_start, datetime.min.time(), tzinfo=timezone.utc)
    window_end = datetime.combine(anomaly.week_end, datetime.max.time(), tzinfo=timezone.utc)
    buffer = timedelta(hours=buffer_hours)
    search_start = window_start - buffer
    search_end = window_end + buffer

    candidates = []
    candidates.extend(primary.get((anomaly.account_id, anomaly.region, anomaly.service), []))
    candidates.extend(fallback.get((anomaly.account_id, anomaly.region), []))

    matched: List[SecFinding] = []
    seen_ids: set[str] = set()
    for finding in candidates:
        occurred_at = _parse_datetime(finding.occurred_at)
        if not (search_start <= occurred_at <= search_end):
            continue
        if finding.finding_id in seen_ids:
            continue
        matched.append(finding)
        seen_ids.add(finding.finding_id)
    return matched


def _count_severity(findings: Sequence[SecFinding]) -> Dict[str, int]:
    counts = {level: 0 for level in SEVERITY_LEVELS}
    for finding in findings:
        level = (finding.severity or "INFO").upper()
        if level in counts:
            counts[level] += 1
    return {level: count for level, count in counts.items() if count > 0}


def _count_provider(findings: Sequence[SecFinding]) -> Dict[str, int]:
    counts: Dict[str, int] = defaultdict(int)
    for finding in findings:
        counts[finding.provider] += 1
    return dict(counts)


def _week_start(day: date) -> date:
    return day - timedelta(days=day.weekday())


def _parse_date(value: str) -> date:
    return datetime.fromisoformat(value).date()


def _parse_datetime(value: str) -> datetime:
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        dt = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S")
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _robust_z_score(current: float, history: Sequence[float]) -> float:
    if not history:
        return 0.0
    med = median(history)
    mad = median(abs(value - med) for value in history)
    if mad == 0:
        return 0.0
    return (current - med) / mad


def _normalise(value: float, threshold: float) -> float:
    if threshold <= 0:
        return 0.0
    return abs(value) / threshold


__all__ = ["CorrelationCandidate", "correlate"]
