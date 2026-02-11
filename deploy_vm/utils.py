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


def get_sudo_prefix(ssh_user: str) -> str:
    """Get sudo prefix for commands based on SSH user.

    :param ssh_user: SSH username
    :return: Empty string for root, "sudo " for other users
    """
    return "" if ssh_user == "root" else "sudo "


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
