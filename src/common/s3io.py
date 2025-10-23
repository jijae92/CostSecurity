"""S3 helpers for raw and processed data."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable

import boto3
from botocore.config import Config

from src.common.log import get_logger

LOGGER = get_logger(__name__)


@dataclass(slots=True)
class RawS3Writer:
    s3_client: Any
    bucket: str | None
    dry_run: bool

    @classmethod
    def from_config(cls, config: "AppConfig") -> "RawS3Writer":
        session = boto3.session.Session(region_name=config.aws_region)
        client = session.client("s3", config=Config(connect_timeout=10, read_timeout=10, retries={"max_attempts": 3}))
        return cls(s3_client=client, bucket=config.raw_bucket, dry_run=config.dry_run)

    def persist(self, *, payload: Dict[str, Any], object_key: str) -> str:
        if not self.bucket:
            LOGGER.warning("Raw bucket not configured; skipping upload.")
            return object_key
        if self.dry_run:
            _write_local_backup(object_key=object_key, payload=payload)
            return object_key
        body = json.dumps(payload).encode("utf-8")
        self.s3_client.put_object(Bucket=self.bucket, Key=object_key, Body=body)
        return object_key


@dataclass(slots=True)
class RawS3Reader:
    s3_client: Any
    bucket: str | None
    dry_run: bool

    @classmethod
    def from_config(cls, config: "AppConfig") -> "RawS3Reader":
        session = boto3.session.Session(region_name=config.aws_region)
        client = session.client("s3", config=Config(connect_timeout=10, read_timeout=10, retries={"max_attempts": 3}))
        return cls(s3_client=client, bucket=config.raw_bucket, dry_run=config.dry_run)

    def load(self, *, object_key: str) -> Dict[str, Any]:
        if self.dry_run:
            return _load_local_backup(object_key=object_key)
        response = self.s3_client.get_object(Bucket=self.bucket, Key=object_key)
        return json.loads(response["Body"].read())


@dataclass(slots=True)
class ReportS3Writer:
    s3_client: Any
    bucket: str | None
    dry_run: bool

    @classmethod
    def from_config(cls, config: "AppConfig") -> "ReportS3Writer":
        session = boto3.session.Session(region_name=config.aws_region)
        client = session.client("s3", config=Config(connect_timeout=10, read_timeout=10, retries={"max_attempts": 3}))
        return cls(s3_client=client, bucket=config.reports_bucket, dry_run=config.dry_run)

    def persist_json(self, *, payload: Any, prefix: str, object_key: str | None = None) -> str:
        if object_key is None:
            object_key = f"{prefix}/{Path(prefix).name}-{len(str(payload))}.json"
        if not self.bucket:
            LOGGER.warning("Report bucket not configured; skipping upload.")
            _write_local_backup(object_key=object_key, payload=payload)
            return object_key
        if self.dry_run:
            _write_local_backup(object_key=object_key, payload=payload)
            return object_key
        self.s3_client.put_object(Bucket=self.bucket, Key=object_key, Body=json.dumps(payload).encode("utf-8"))
        return object_key

    def persist_text(self, *, body: str, object_key: str, content_type: str = "text/plain") -> str:
        if not self.bucket:
            LOGGER.warning("Report bucket not configured; skipping upload.")
            _write_local_text(object_key=object_key, body=body)
            return object_key
        if self.dry_run:
            _write_local_text(object_key=object_key, body=body)
            return object_key
        self.s3_client.put_object(Bucket=self.bucket, Key=object_key, Body=body.encode("utf-8"), ContentType=content_type)
        return object_key


@dataclass(slots=True)
class ReportS3Reader:
    s3_client: Any
    bucket: str | None
    dry_run: bool

    @classmethod
    def from_config(cls, config: "AppConfig") -> "ReportS3Reader":
        session = boto3.session.Session(region_name=config.aws_region)
        client = session.client("s3", config=Config(connect_timeout=10, read_timeout=10, retries={"max_attempts": 3}))
        return cls(s3_client=client, bucket=config.reports_bucket, dry_run=config.dry_run)

    def load_json(self, *, object_key: str) -> Any:
        if self.dry_run:
            return _load_local_backup(object_key=object_key)
        response = self.s3_client.get_object(Bucket=self.bucket, Key=object_key)
        return json.loads(response["Body"].read())


def _write_local_backup(*, object_key: str, payload: Any) -> None:
    backup_root = Path(".tmp")
    backup_root.mkdir(exist_ok=True)
    file_path = backup_root / object_key.replace("/", "-")
    file_path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(payload, str):
        file_path.write_text(payload, encoding="utf-8")
    else:
        file_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _write_local_text(*, object_key: str, body: str) -> None:
    backup_root = Path(".tmp")
    backup_root.mkdir(exist_ok=True)
    file_path = backup_root / object_key.replace("/", "-")
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(body, encoding="utf-8")


def _load_local_backup(*, object_key: str) -> Any:
    file_path = Path(".tmp") / object_key.replace("/", "-")
    if not file_path.exists():
        raise FileNotFoundError(f"Local backup missing for {object_key}")
    return json.loads(file_path.read_text(encoding="utf-8"))


from src.common.config import AppConfig  # noqa: E402  pylint: disable=wrong-import-position

__all__ = [
    "RawS3Writer",
    "RawS3Reader",
    "ReportS3Writer",
    "ReportS3Reader",
]
