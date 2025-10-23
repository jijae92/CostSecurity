"""Core package for cost-security correlation project."""

from importlib import metadata

def get_version() -> str:
    """Return the installed package version if available, otherwise a placeholder."""
    try:
        return metadata.version("cost_security")
    except metadata.PackageNotFoundError:
        return "0.0.0-dev"

__all__ = ["get_version"]
