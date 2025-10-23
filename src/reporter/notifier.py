"""Notification helpers for SNS, Slack, and S3."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Optional

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from tenacity import RetryError, retry, retry_if_exception_type, stop_after_attempt, wait_exponential_jitter

from src.common.config import AppConfig
from src.common.log import get_logger
from src.common.s3io import ReportS3Writer

LOGGER = get_logger(__name__)


@dataclass(slots=True)
class NotificationTargets:
    sns_topic_arn: Optional[str]
    slack_webhook: Optional[str]
    s3_bucket: Optional[str]


@dataclass(slots=True)
class ArtifactInfo:
    json_key: Optional[str]
    csv_key: Optional[str]
    json_url: Optional[str] = None
    csv_url: Optional[str] = None


@dataclass(slots=True)
class Notifier:
    """Dispatch formatted reports to configured targets."""

    config: AppConfig
    sns_client: Any
    s3_client: Any
    http_session: Any
    targets: NotificationTargets

    @classmethod
    def from_config(cls, config: AppConfig) -> "Notifier":
        session = boto3.session.Session(region_name=config.aws_region)
        boto_config = Config(connect_timeout=10, read_timeout=10, retries={"max_attempts": 3})
        sns_client = session.client("sns", config=boto_config)
        s3_client = session.client("s3", config=boto_config)
        http_session = _build_http_session()
        targets = NotificationTargets(
            sns_topic_arn=config.sns_topic_arn,
            slack_webhook=config.slack_webhook_url,
            s3_bucket=config.reports_bucket,
        )
        return cls(config=config, sns_client=sns_client, s3_client=s3_client, http_session=http_session, targets=targets)

    def persist_artifacts(
        self,
        *,
        prefix: str,
        json_payload: Any,
        csv_body: str,
        generate_presigned: bool = False,
    ) -> ArtifactInfo:
        writer = ReportS3Writer.from_config(self.config)
        json_key = writer.persist_json(payload=json_payload, prefix=prefix, object_key=f"{prefix}/alerts.json")
        csv_key = writer.persist_text(body=csv_body, object_key=f"{prefix}/alerts.csv", content_type="text/csv")

        presigned: Dict[str, str] = {}
        if (
            generate_presigned
            and not self.config.dry_run
            and self.targets.s3_bucket
        ):
            presigned["JSON"] = self._presign(json_key)
            presigned["CSV"] = self._presign(csv_key)

        return ArtifactInfo(
            json_key=json_key,
            csv_key=csv_key,
            json_url=presigned.get("JSON"),
            csv_url=presigned.get("CSV"),
        )

    def send(self, *, subject: str, markdown_body: str, html_body: str) -> None:
        if self.config.dry_run:
            LOGGER.info("Dry-run: notification suppressed", extra={"subject": subject})
            return
        if self.targets.sns_topic_arn:
            self._publish_sns(subject=subject, message=markdown_body)
        if self.targets.slack_webhook:
            self._post_slack(message=markdown_body)

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential_jitter(max=10),
        retry=retry_if_exception_type((ClientError, BotoCoreError)),
        reraise=True,
    )
    def _publish_sns(self, *, subject: str, message: str) -> None:
        self.sns_client.publish(TopicArn=self.targets.sns_topic_arn, Subject=subject[:100], Message=message)

    def _post_slack(self, *, message: str) -> None:
        response = self.http_session.post(
            self.targets.slack_webhook,
            data=json.dumps({"text": message}),
            timeout=10,
            headers={"Content-Type": "application/json"},
        )
        if response.status_code >= 400:
            raise RuntimeError(f"Slack webhook failed: {response.status_code}")

    def _presign(self, object_key: str) -> str:
        return self.s3_client.generate_presigned_url(
            "get_object",
            Params={"Bucket": self.targets.s3_bucket, "Key": object_key},
            ExpiresIn=3600,
        )


def _build_http_session():
    try:
        import requests
    except ImportError as exc:  # pragma: no cover - handled via tests
        raise RuntimeError("requests package missing; required for Slack notifications.") from exc
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(max_retries=3)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def build_quicksight_manifest(*, bucket: str, json_key: str, dataset_name: str, format_type: str = "JSON") -> Dict[str, Any]:
    """Generate a minimal QuickSight manifest structure for manual linking."""
    return {
        "fileLocations": [
            {
                "URIs": [f"s3://{bucket}/{json_key}"],
            }
        ],
        "globalUploadSettings": {
            "format": format_type,
            "delimiter": ",",
            "containsHeader": True,
            "name": dataset_name,
        },
    }


__all__ = [
    "Notifier",
    "NotificationTargets",
    "ArtifactInfo",
    "build_quicksight_manifest",
]
