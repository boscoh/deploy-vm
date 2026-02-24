"""Shared utility functions."""

import json
import logging
import subprocess
import sys

from rich.console import Console
from rich.logging import RichHandler

logger = logging.getLogger("deployvm")

# Pass to uvicorn.run(log_config=UVICORN_LOG_CONFIG) to prevent uvicorn from
# installing its own StreamHandler, so all logs flow through our RichHandler.
UVICORN_LOG_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {},
    "handlers": {},
    "loggers": {
        "uvicorn": {"propagate": True, "level": "INFO"},
        "uvicorn.access": {"propagate": False, "level": "WARNING"},
        "uvicorn.error": {"propagate": True, "level": "INFO"},
    },
}


class LogStream:
    """File-like stream that routes output through the logger line by line.

    Use as out_stream/err_stream in fabric c.run() calls so remote SSH output
    goes through the logging system instead of directly to the terminal.
    """

    def __init__(self) -> None:
        self._buf = ""

    def write(self, text: str) -> None:
        self._buf += text
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            if line.strip():
                logger.info(line)

    def flush(self) -> None:
        if self._buf.strip():
            logger.info(self._buf)
            self._buf = ""


def setup_logging(level: int | str = logging.INFO) -> None:
    """Set up logging with Rich handler to stderr."""
    if isinstance(level, str):
        level = getattr(logging, level.upper())
    rich_handler = RichHandler(
        console=Console(stderr=True),
        log_time_format="[%X]",
        show_path=False,
        markup=True,
    )
    rich_handler.setLevel(level)

    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    for handler in root_logger.handlers[:]:
        handler.close()
        root_logger.removeHandler(handler)
    root_logger.addHandler(rich_handler)

    for name, lvl, propagate in [
        ("boto3", logging.INFO, True),
        ("botocore", logging.WARNING, True),
        ("urllib3", logging.WARNING, True),
        ("httpx", logging.WARNING, True),
        ("paramiko", logging.WARNING, True),
        ("fabric", logging.WARNING, True),
        ("uvicorn", logging.INFO, True),
        ("uvicorn.access", logging.WARNING, True),
        ("uvicorn.error", logging.INFO, True),
    ]:
        lg = logging.getLogger(name)
        for h in lg.handlers[:]:
            lg.removeHandler(h)
        lg.setLevel(lvl)
        lg.propagate = propagate


def log(msg: str) -> None:
    """Log info message."""
    logger.info(msg)


def warn(msg: str) -> None:
    """Log warning message."""
    logger.warning(msg)


def error(msg: str) -> None:
    """Log error message and exit."""
    logger.error(msg)
    sys.exit(1)


def get_ssh_user(provider_name: str) -> str:
    """Get default SSH user for cloud provider.

    :param provider_name: Cloud provider (aws, digitalocean, or vultr)
    :return: SSH username (admin for AWS, root for DigitalOcean and Vultr)
    """
    return "admin" if provider_name == "aws" else "root"


def resolve_app_name(
    apps: list[dict],
    app_type: str,
    app_name: str | None = None,
    fallback: str | None = None,
) -> str:
    """Resolve app name when multiple apps exist on instance.

    :param apps: List of app dicts with 'name' and 'type' keys
    :param app_type: App type to filter by (npm or uv)
    :param app_name: Explicit app name (optional)
    :param fallback: Fallback name if no apps found
    :return: Resolved app name
    :raises: SystemExit if multiple apps found without explicit name
    """
    if app_name is not None:
        return app_name

    if len(apps) == 1:
        return apps[0]["name"]
    elif len(apps) > 1:
        app_names = ", ".join(app["name"] for app in apps)
        error(
            f"Multiple '{app_type}' apps found: '{app_names}'. Use --app-name to specify."
        )
    else:
        return fallback if fallback else app_type


def run_cmd(*args, check: bool = True) -> str:
    """Execute local command and return stdout."""
    result = subprocess.run(args, capture_output=True, text=True)
    if check and result.returncode != 0:
        error(f"Command failed: {result.stderr}")
    return result.stdout.strip()


def run_cmd_json(*args) -> dict | list:
    """Execute command with -o json flag and parse output."""
    output = run_cmd(*args, "-o", "json")
    return json.loads(output) if output else []
