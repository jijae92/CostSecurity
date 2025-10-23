"""Optional CloudTrail via Athena integration."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict

import boto3
from botocore.config import Config

from src.common.log import get_logger

LOGGER = get_logger(__name__)


@dataclass(slots=True)
class CloudTrailAthenaClient:
    """Query CloudTrail logs stored in S3 via Amazon Athena."""

    client: Any
    sample_data_root: Path
    dry_run: bool

    @classmethod
    def from_config(cls, config: "AppConfig") -> "CloudTrailAthenaClient":
        session = boto3.session.Session(region_name=config.aws_region)
        boto_config = Config(connect_timeout=10, read_timeout=10, retries={"max_attempts": 3})
        athena_client = session.client("athena", config=boto_config)
        return cls(client=athena_client, sample_data_root=config.sample_data_path, dry_run=config.dry_run)

    def run_query(self, query: str) -> Dict[str, Any]:
        if self.dry_run:
            LOGGER.info("Skipping CloudTrail query in dry-run mode", extra={"query": query})
            return {"Query": query, "Rows": []}
        # TODO: implement query submission, polling, and result download with S3 spillover handling.
        raise NotImplementedError("CloudTrail@Athena integration is pending implementation.")


from src.common.config import AppConfig  # noqa: E402  pylint: disable=wrong-import-position
