"""Tests for reporter formatting utilities."""

from __future__ import annotations

from src.reporter.formatter import make_attachment_links, to_csv_rows, to_html, to_markdown


def test_formatter_outputs_strings() -> None:
    payload = [
        {
            "account_id": "123456789012",
            "region": "us-east-1",
            "service": "AmazonEC2",
            "cost_delta_pct": 42.5,
            "cost_anomaly_score": 3.1,
            "sec_counts": {"HIGH": 2, "CRITICAL": 1},
            "matched_rules": ["RULE_COST30_SEC_HIGH"],
        }
    ]
    attachments = make_attachment_links(
        "reports-bucket",
        {"JSON": "reports/dev/alerts.json", "CSV": "reports/dev/alerts.csv"},
    )
    markdown = to_markdown(payload, week_start="2025-10-20", attachments=attachments)
    assert "[Cost×Security]" in markdown
    assert "RULE_COST30_SEC_HIGH" in markdown
    html = to_html(payload, week_start="2025-10-20", attachments=attachments)
    assert "<h1>" in html and "AmazonEC2" in html
    rows = to_csv_rows(payload)
    assert rows[0].startswith("account_id")
    assert "RULE_COST30_SEC_HIGH" in rows[1]
