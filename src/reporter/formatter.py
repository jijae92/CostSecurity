"""Report formatting helpers."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from src.common.log import get_logger

LOGGER = get_logger(__name__)


def to_markdown(
    alerts: Iterable[Dict[str, Any]],
    *,
    week_start: str,
    attachments: Optional[Dict[str, str]] = None,
) -> str:
    """Render a Markdown summary for weekly alerts."""
    alerts = list(alerts)
    lines = [f"# [Cost×Security] 주간 상관 경보 ({week_start} 주)", ""]
    if not alerts:
        lines.append("이번 주에는 비용과 보안 간 상관 경보가 없습니다.")
    else:
        lines.append("| Account | Region | Service | Δ% | 보안 이벤트 | 규칙 |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for alert in alerts:
            lines.append(
                "| {account} | {region} | {service} | {delta:.1f}% | {sec_counts} | {rules} |".format(
                    account=alert.get("account_id", "N/A"),
                    region=alert.get("region", "N/A"),
                    service=alert.get("service", "N/A"),
                    delta=float(alert.get("cost_delta_pct", 0.0)),
                    sec_counts=_stringify_sec_counts(alert.get("sec_counts", {})),
                    rules=", ".join(alert.get("matched_rules", [])) or "N/A",
                )
            )
        lines.append("")
    if attachments:
        lines.append("## 첨부")
        for name, link in attachments.items():
            lines.append(f"- {name}: {link}")
    return "\n".join(lines)


def to_html(
    alerts: Iterable[Dict[str, Any]],
    *,
    week_start: str,
    attachments: Optional[Dict[str, str]] = None,
) -> str:
    """Render an HTML summary."""
    alerts = list(alerts)
    table_rows = ""
    for alert in alerts:
        table_rows += (
            "<tr>"
            f"<td>{alert.get('account_id', 'N/A')}</td>"
            f"<td>{alert.get('region', 'N/A')}</td>"
            f"<td>{alert.get('service', 'N/A')}</td>"
            f"<td>{float(alert.get('cost_delta_pct', 0.0)):.1f}%</td>"
            f"<td>{_stringify_sec_counts(alert.get('sec_counts', {}))}</td>"
            f"<td>{', '.join(alert.get('matched_rules', [])) or 'N/A'}</td>"
            "</tr>"
        )
    if not table_rows:
        table_rows = "<tr><td colspan='6'>이번 주에는 비용과 보안 간 상관 경보가 없습니다.</td></tr>"

    attachment_section = ""
    if attachments:
        attachment_items = "".join(f"<li>{name}: <a href='{link}'>{link}</a></li>" for name, link in attachments.items())
        attachment_section = f"<h2>첨부</h2><ul>{attachment_items}</ul>"

    return (
        f"<h1>[Cost×Security] 주간 상관 경보 ({week_start} 주)</h1>"
        "<table>"
        "<thead><tr><th>Account</th><th>Region</th><th>Service</th><th>Δ%</th><th>보안 이벤트</th><th>규칙</th></tr></thead>"
        f"<tbody>{table_rows}</tbody>"
        "</table>"
        f"{attachment_section}"
    )


def to_csv_rows(alerts: Iterable[Dict[str, Any]]) -> List[str]:
    """Generate CSV rows for downstream analytics."""
    header = "account_id,region,service,cost_delta_pct,cost_anomaly_score,sec_counts,matched_rules"
    rows = [header]
    for alert in alerts:
        sec_counts = _stringify_sec_counts(alert.get("sec_counts", {}), delimiter="|")
        matched_rules = "|".join(alert.get("matched_rules", []))
        rows.append(
            ",".join(
                [
                    str(alert.get("account_id", "N/A")),
                    str(alert.get("region", "N/A")),
                    str(alert.get("service", "N/A")),
                    f"{float(alert.get('cost_delta_pct', 0.0)):.2f}",
                    f"{float(alert.get('cost_anomaly_score', 0.0)):.2f}",
                    f"\"{sec_counts}\"",
                    f"\"{matched_rules}\"",
                ]
            )
        )
    return rows


def make_attachment_links(bucket: str | None, keys: Dict[str, str], presigned_urls: Dict[str, str] | None = None) -> Dict[str, str]:
    """Create human readable attachment entries for markdown/html."""
    links: Dict[str, str] = {}
    for name, key in keys.items():
        if presigned_urls and name in presigned_urls:
            links[name] = presigned_urls[name]
        elif bucket:
            links[name] = f"s3://{bucket}/{key}"
        else:
            links[name] = key
    return links


def redact(value: str | None) -> str:
    """Redact sensitive values in logs."""
    if not value:
        return ""
    if len(value) < 6:
        return "***"
    return f"{value[:3]}***{value[-3:]}"


def _stringify_sec_counts(sec_counts: Dict[str, Any], delimiter: str = ", ") -> str:
    if not sec_counts:
        return "N/A"
    items = [f"{key}:{sec_counts[key]}" for key in sorted(sec_counts.keys()) if sec_counts[key] is not None]
    return delimiter.join(items) if items else "N/A"
