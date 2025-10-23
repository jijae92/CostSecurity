"""Pytest configuration for path and dependency stubs."""

from __future__ import annotations

import os
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if SRC.exists():
    sys.path.insert(0, str(ROOT))
    sys.path.insert(0, str(SRC))


class _FakeClient:
    def __init__(self, service_name: str):
        self.service_name = service_name

    def get_paginator(self, _name: str):
        return types.SimpleNamespace(paginate=lambda **_: [{"Findings": []}])

    def get_cost_and_usage(self, **_kwargs):
        return {"ResultsByTime": []}

    def put_object(self, **_kwargs):
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def get_object(self, **_kwargs):
        return {"Body": types.SimpleNamespace(read=lambda: b"{}")}

    def publish(self, **_kwargs):
        return {"MessageId": "stub"}

    def generate_presigned_url(self, *_args, **_kwargs):
        return "https://example.com/presigned"

    def post(self, **_kwargs):
        return types.SimpleNamespace(status_code=200)

    def list_detectors(self):
        return {"DetectorIds": ["stub-detector"]}

    def list_findings(self, **_kwargs):
        return {"FindingIds": ["finding-1"]}

    def get_findings(self, **_kwargs):
        return {"Findings": []}

    def get_parameters_by_path(self, **_kwargs):
        return {"Parameters": []}

    def get_secret_value(self, **_kwargs):
        return {"SecretString": "{}"}


if "boto3" not in sys.modules:
    boto3_stub = types.ModuleType("boto3")

    class Session:
        def __init__(self, region_name: str | None = None):
            self.region_name = region_name

        def client(self, service_name: str, config=None):
            return _FakeClient(service_name)

    boto3_stub.session = types.SimpleNamespace(Session=Session)
    sys.modules["boto3"] = boto3_stub

if "botocore" not in sys.modules:
    botocore_stub = types.ModuleType("botocore")
    errors = types.ModuleType("botocore.exceptions")

    class BotoCoreError(Exception):
        """Stub boto exception."""

    class ClientError(Exception):
        """Stub boto client error."""

    errors.BotoCoreError = BotoCoreError
    errors.ClientError = ClientError

    config_module = types.ModuleType("botocore.config")

    class Config:
        def __init__(self, **_kwargs):
            self.kwargs = _kwargs

    config_module.Config = Config

    botocore_stub.config = config_module
    botocore_stub.exceptions = errors

    sys.modules["botocore"] = botocore_stub
    sys.modules["botocore.config"] = config_module
    sys.modules["botocore.exceptions"] = errors

if "tenacity" not in sys.modules:
    tenacity_stub = types.ModuleType("tenacity")

    class RetryError(Exception):
        """Stub retry error."""

    def retry(*_args, **_kwargs):  # noqa: D401
        def decorator(func):
            return func
        return decorator

    def retry_if_exception_type(*_args, **_kwargs):
        return lambda exc: True

    def stop_after_attempt(_attempts):
        return None

    def wait_exponential_jitter(*_args, **_kwargs):
        return None

    tenacity_stub.RetryError = RetryError
    tenacity_stub.retry = retry
    tenacity_stub.retry_if_exception_type = retry_if_exception_type
    tenacity_stub.stop_after_attempt = stop_after_attempt
    tenacity_stub.wait_exponential_jitter = wait_exponential_jitter

    sys.modules["tenacity"] = tenacity_stub

if "pydantic" not in sys.modules:
    pydantic_stub = types.ModuleType("pydantic")

    class ValidationError(Exception):
        def __init__(self, errors=None):
            super().__init__(str(errors) if errors is not None else "Validation error")
            self.errors = errors or []

    class _FieldInfo:
        def __init__(self, default=..., default_factory=None):
            self.default = default
            self.default_factory = default_factory

    class BaseModel:
        """Minimal BaseModel replacement for tests."""

        def __init_subclass__(cls, **kwargs):
            super().__init_subclass__(**kwargs)
            validators = {}
            for name, value in cls.__dict__.items():
                if getattr(value, "__validator_fields__", None):
                    for field in value.__validator_fields__:
                        validators.setdefault(field, []).append(value)
            cls.__validators__ = validators

        def __init__(self, **data):
            cls = self.__class__
            annotations = getattr(cls, "__annotations__", {})
            for field in annotations:
                if field in data:
                    value = data[field]
                elif hasattr(cls, field):
                    field_def = getattr(cls, field)
                    if isinstance(field_def, _FieldInfo):
                        if field_def.default is not ...:
                            value = field_def.default
                        elif field_def.default_factory is not None:
                            value = field_def.default_factory()
                        else:
                            value = None
                    else:
                        value = field_def
                else:
                    value = None
                setattr(self, field, value)
            extras = set(data) - set(annotations)
            if extras:
                for extra in extras:
                    setattr(self, extra, data[extra])
            for field, validators in getattr(self.__class__, "__validators__", {}).items():
                value = getattr(self, field)
                for validator_func in validators:
                    new_value = validator_func(self.__class__, value)
                    if new_value is not None:
                        setattr(self, field, new_value)

        def dict(self, **_kwargs):
            return {field: getattr(self, field) for field in getattr(self.__class__, "__annotations__", {})}

        def json(self, **_kwargs):
            import json as _json

            return _json.dumps(self.dict(), **_kwargs)

        @classmethod
        def parse_obj(cls, obj):
            if isinstance(obj, cls):
                return obj
            if isinstance(obj, dict):
                return cls(**obj)
            raise TypeError("parse_obj expects mapping")

    def Field(default=..., **_kwargs):
        default_factory = _kwargs.get("default_factory")
        return _FieldInfo(default=default, default_factory=default_factory)

    def validator(field_name):
        def decorator(func):
            func.__validator_fields__ = (field_name,)
            return func
        return decorator

    pydantic_stub.BaseModel = BaseModel
    pydantic_stub.Field = Field
    pydantic_stub.validator = validator
    pydantic_stub.ValidationError = ValidationError

    sys.modules["pydantic"] = pydantic_stub

os.environ.setdefault("APP_ENV", "dev")
os.environ.setdefault("DRY_RUN", "true")
