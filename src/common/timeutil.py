"""Time helpers."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone


def start_of_week(reference: datetime | None = None) -> datetime:
    reference = reference or datetime.now(timezone.utc)
    delta = timedelta(days=reference.weekday())
    return datetime(reference.year, reference.month, reference.day, tzinfo=timezone.utc) - delta


def isoformat_no_ms(reference: datetime | None = None) -> str:
    return (reference or datetime.now(timezone.utc)).replace(microsecond=0).isoformat()


__all__ = ["start_of_week", "isoformat_no_ms"]
