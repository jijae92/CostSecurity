"""Configuration loader supporting .env, SSM, and Secrets Manager."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

import boto3
from botocore.config import Config

from src.common.log import get_logger

LOGGER = get_logger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SAMPLE_DATA_DIR = PROJECT_ROOT / "docs" / "data"


@dataclass(slots=True)
class AppConfig:
    """Runtime configuration."""

    environment: str
    aws_region: str
    dry_run: bool
    raw_bucket: Optional[str]
    reports_bucket: Optional[str]
    sns_topic_arn: Optional[str]
    slack_webhook_url: Optional[str]
    parameter_prefix: Optional[str]
    secrets_prefix: Optional[str]
    sample_data_path: Path
    cost_lookback_days: int
    cost_timezone: str
    target_services: List[str]
    security_providers: List[str]
    security_severity_min: str
    guardduty_severity_threshold: float
    delta_threshold: float
    zscore_threshold: float
    suppress_config_uri: Optional[str]

    @property
    def ssm_config_path(self) -> Optional[str]:
        if not self.parameter_prefix:
            return None
        return f"/{self.parameter_prefix}/{self.environment}"

    @property
    def secrets_path(self) -> Optional[str]:
        if not self.secrets_prefix:
            return None
        return f"{self.secrets_prefix}/{self.environment}"


def _read_env_flag(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).lower() in {"1", "true", "yes", "on"}


@lru_cache(maxsize=1)
def load_config(refresh: bool = False) -> AppConfig:
    """Load configuration with optional refresh."""
    if refresh:
        load_config.cache_clear()
    environment = os.getenv("APP_ENV", "dev")
    aws_region = os.getenv("AWS_REGION", "us-east-1")
    dry_run = _read_env_flag("DRY_RUN", "true")
    raw_bucket = os.getenv("RAW_DATA_BUCKET")
    reports_bucket = os.getenv("REPORTS_BUCKET")
    sns_topic_arn = os.getenv("REPORT_TOPIC_ARN") or os.getenv("SNS_TOPIC_ARN")
    slack_webhook_url = os.getenv("SLACK_WEBHOOK_URL")
    parameter_prefix = os.getenv("SSM_PARAMETER_PREFIX")
    secrets_prefix = os.getenv("SECRETS_PREFIX")
    cost_lookback_days = int(os.getenv("COST_LOOKBACK_DAYS", "14"))
    cost_timezone = os.getenv("COST_TIMEZONE", "UTC")
    target_services = [svc.strip() for svc in os.getenv("TARGET_SERVICES", "").split(",") if svc.strip()]
    security_providers = [provider.strip().lower() for provider in os.getenv("SEC_PROVIDERS", "securityhub,guardduty").split(",") if provider.strip()]
    security_severity_min = os.getenv("SEVERITY_MIN", "MEDIUM").upper()
    guardduty_severity_threshold = float(os.getenv("GUARDDUTY_SEVERITY_THRESHOLD", "4.0"))
    delta_threshold = float(os.getenv("DELTA_THRESHOLD", "30"))
    zscore_threshold = float(os.getenv("ZSCORE_THRESHOLD", "2.0"))
    suppress_config_uri = os.getenv("SUPPRESS_CONFIG_URI")

    config = AppConfig(
        environment=environment,
        aws_region=aws_region,
        dry_run=dry_run,
        raw_bucket=raw_bucket,
        reports_bucket=reports_bucket,
        sns_topic_arn=sns_topic_arn,
        slack_webhook_url=slack_webhook_url,
        parameter_prefix=parameter_prefix,
        secrets_prefix=secrets_prefix,
        sample_data_path=SAMPLE_DATA_DIR,
        cost_lookback_days=cost_lookback_days,
        cost_timezone=cost_timezone,
        target_services=target_services,
        security_providers=security_providers,
        security_severity_min=security_severity_min,
        guardduty_severity_threshold=guardduty_severity_threshold,
        delta_threshold=delta_threshold,
        zscore_threshold=zscore_threshold,
        suppress_config_uri=suppress_config_uri,
    )

    if not dry_run:
        _enrich_from_parameter_store(config)
        _enrich_from_secrets_manager(config)

    LOGGER.debug("Configuration loaded", extra={"environment": config.environment, "dry_run": config.dry_run})
    return config


def _enrich_from_parameter_store(config: AppConfig) -> None:
    if not config.ssm_config_path:
        LOGGER.debug("SSM parameter prefix not configured; skipping load.")
        return
    session = boto3.session.Session(region_name=config.aws_region)
    ssm = session.client("ssm", config=Config(connect_timeout=10, read_timeout=10, retries={"max_attempts": 3}))
    try:
        response = ssm.get_parameters_by_path(Path=config.ssm_config_path, Recursive=True, WithDecryption=True)
    except ssm.exceptions.ParameterNotFound:  # type: ignore[attr-defined]
        LOGGER.warning("SSM parameters not found", extra={"path": config.ssm_config_path})
        return
    for parameter in response.get("Parameters", []):
        name = parameter.get("Name")
        value = parameter.get("Value")
        if not name or value is None:
            continue
        key = name.split("/")[-1]
        os.environ.setdefault(key, value)


def _enrich_from_secrets_manager(config: AppConfig) -> None:
    if not config.secrets_path:
        LOGGER.debug("Secrets prefix not configured; skipping load.")
        return
    session = boto3.session.Session(region_name=config.aws_region)
    secrets = session.client("secretsmanager", config=Config(connect_timeout=10, read_timeout=10, retries={"max_attempts": 3}))
    try:
        secret_value = secrets.get_secret_value(SecretId=config.secrets_path)
    except secrets.exceptions.ResourceNotFoundException:  # type: ignore[attr-defined]
        LOGGER.warning("Secrets Manager entry missing", extra={"secret_id": config.secrets_path})
        return
    payload = secret_value.get("SecretString")
    if not payload:
        return
    try:
        data: Dict[str, Any] = json.loads(payload)
    except json.JSONDecodeError:
        LOGGER.error("Secret payload is not valid JSON", extra={"secret_id": config.secrets_path})
        return
    for key, value in data.items():
        if isinstance(value, str):
            os.environ.setdefault(key, value)


__all__ = ["AppConfig", "load_config"]
