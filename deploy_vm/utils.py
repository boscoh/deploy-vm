"""Shared utility functions."""

import json
import subprocess
import sys

from rich import print


def log(msg: str):
    """Log info message in green."""
    print(f"[green][INFO][/green] {msg}")


def warn(msg: str):
    """Log warning message in yellow."""
    print(f"[yellow][WARN][/yellow] {msg}")


def error(msg: str):
    """Log error message in red and exit."""
    print(f"[red][ERROR][/red] {msg}")
    sys.exit(1)


def get_ssh_user(provider_name: str) -> str:
    """Get default SSH user for cloud provider.

    :param provider_name: Cloud provider (aws or digitalocean)
    :return: SSH username (ubuntu for AWS, root for DigitalOcean)
    """
    return "ubuntu" if provider_name == "aws" else "root"


def resolve_app_name(
    apps: list[dict],
    app_type: str,
    app_name: str | None = None,
    fallback: str | None = None,
) -> str:
    """Resolve app name when multiple apps exist on instance.

    :param apps: List of app dicts with 'name' and 'type' keys
    :param app_type: App type to filter by (nuxt or fastapi)
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
