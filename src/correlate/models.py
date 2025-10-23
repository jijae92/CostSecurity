"""Pydantic data models for cost/security correlation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, validator


DateStr = Field(..., regex=r"^\d{4}-\d{2}-\d{2}$", description="Date formatted as YYYY-MM-DD")
IsoDatetimeStr = Field(..., regex=r"^\d{4}-\d{2}-\d{2}T.*$", description="ISO8601 timestamp string")
SeverityLevel = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
ProviderType = Literal["SecurityHub", "GuardDuty", "CloudTrail"]
WindowType = Literal["WEEK"]


class CostPoint(BaseModel):
    """Normalized weekly cost data point."""

    period_start: str = DateStr
    period_end: str = DateStr
    account_id: str
    region: str = Field(..., description="AWS region or ALL for global aggregates")
    service: str
    amount: float
    unit: str = Field(..., description="Currency unit, e.g., USD")


class SecFinding(BaseModel):
    """Unified security finding from multiple providers."""

    occurred_at: str = IsoDatetimeStr
    account_id: str
    region: str
    service: str = Field(..., description="Impacted service or UNKNOWN if not mapped")
    provider: ProviderType
    severity: SeverityLevel
    title: str
    finding_id: str
    raw_ref: Dict[str, Any]


class Evidence(BaseModel):
    """Evidence package bundled with a correlation alert."""

    cost: List[CostPoint] = Field(default_factory=list)
    findings: List[SecFinding] = Field(default_factory=list)


class CorrelationAlert(BaseModel):
    """Combined view of cost and security signals."""

    window: WindowType = "WEEK"
    account_id: str
    region: str
    service: str
    cost_delta_pct: float = Field(..., ge=-100.0)
    cost_anomaly_score: float
    sec_counts: Dict[SeverityLevel, int] = Field(default_factory=dict)
    matched_rules: List[str] = Field(default_factory=list)
    recommendation: str
    evidence: Evidence = Field(default_factory=Evidence)

    @validator("sec_counts")
    def _validate_sec_counts(cls, value: Dict[str, int]) -> Dict[str, int]:
        allowed = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        unknown_keys = set(value.keys()) - allowed
        if unknown_keys:
            raise ValueError(f"sec_counts contains unsupported severities: {sorted(unknown_keys)}")
        for key, count in value.items():
            if count < 0:
                raise ValueError(f"sec_counts[{key}] must be non-negative")
        return value


@dataclass(slots=True)
class CostDatum:
    """Legacy cost datum used by correlation logic."""

    account_id: str
    service: str
    region: str
    amount: float
    currency: str
    usage_quantity: float
    timestamp: datetime


@dataclass(slots=True)
class SecurityFinding:
    """Legacy security finding used by correlation logic."""

    finding_id: str
    account_id: str
    region: str
    service: str
    severity: str
    title: str
    created_at: datetime
    raw: Dict[str, Any]


@dataclass(slots=True)
class CorrelatedSignal:
    """Legacy correlated signal data structure."""

    correlation_id: str
    cost: CostDatum
    findings: List[SecurityFinding]
    score: float
    rule_hits: List[str]
    notes: Optional[str] = None


@dataclass(slots=True)
class FalsePositiveEntry:
    """Represents a suppressed combination for the false-positive manager."""

    scope: str
    expires_at: datetime
    comment: Optional[str] = None


def correlation_alert_to_json(alert: CorrelationAlert, *, indent: int | None = None) -> str:
    """Serialize a correlation alert to JSON."""
    return alert.json(indent=indent)


def validate_correlation_alert(payload: Any) -> CorrelationAlert:
    """Validate an arbitrary payload into a CorrelationAlert."""
    return CorrelationAlert.parse_obj(payload)


__all__ = [
    "CostPoint",
    "SecFinding",
    "Evidence",
    "CorrelationAlert",
    "CostDatum",
    "SecurityFinding",
    "CorrelatedSignal",
    "FalsePositiveEntry",
    "correlation_alert_to_json",
    "validate_correlation_alert",
]
