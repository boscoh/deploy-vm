#!/usr/bin/env python3
"""Deploy apps to cloud providers.

Prerequisites: doctl CLI authenticated, SSH key in DigitalOcean, domain nameservers configured.

Usage: uv run deploy-vm <noun> <verb> [options]

Examples:
    uv run deploy-vm instance create myapp
    uv run deploy-vm instance list
    uv run deploy-vm fastapi deploy myapp ./src
    uv run deploy-vm nginx ssl myapp example.com user@example.com
"""

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from textwrap import dedent
from typing import Literal, Protocol

from dotenv import load_dotenv

import boto3
import cyclopts
import dns.resolver
from botocore.exceptions import ClientError, ProfileNotFound
from fabric import Connection
from rich import print

app = cyclopts.App(
    name="deploy-vm", help="Deploy apps to cloud providers", sort_key=None
)

instance_app = cyclopts.App(name="instance", help="Manage cloud instances", sort_key=1)
nginx_app = cyclopts.App(name="nginx", help="Configure nginx reverse proxy", sort_key=2)
nuxt_app = cyclopts.App(name="nuxt", help="Deploy and manage Nuxt apps", sort_key=3)
fastapi_app = cyclopts.App(
    name="fastapi", help="Deploy and manage FastAPI apps", sort_key=4
)

# Provider-specific valid options for reference
PROVIDER_OPTIONS = {
    "digitalocean": {
        "regions": ["syd1", "sgp1", "nyc1", "nyc3", "sfo3", "lon1", "fra1", "ams3", "tor1", "blr1"],
        "vm_sizes": ["s-1vcpu-512mb", "s-1vcpu-1gb", "s-1vcpu-2gb", "s-2vcpu-2gb", "s-2vcpu-4gb", "s-4vcpu-8gb"],
        "os_images": ["ubuntu-24-04-x64", "ubuntu-22-04-x64", "ubuntu-20-04-x64"],
    },
    "aws": {
        "regions": ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "ca-central-1",
                    "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1",
                    "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2",
                    "ap-south-1", "sa-east-1"],
        "vm_sizes": ["t3.micro", "t3.small", "t3.medium", "t3.large", "t3.xlarge", "t3.2xlarge",
                     "t4g.micro", "t4g.small", "t4g.medium", "t4g.large",
                     "m5.large", "m5.xlarge", "m5.2xlarge"],
        "os_images": ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*",
                      "ubuntu/images/hvm-ssd/ubuntu-noble-24.04-amd64-server-*"],
    },
}

app.command(instance_app)
app.command(nginx_app)
app.command(nuxt_app)
app.command(fastapi_app)

ProviderName = Literal["digitalocean", "aws"]

SSH_TIMEOUT = 120
HTTP_VERIFY_RETRIES = 6
HTTP_VERIFY_DELAY = 5
DNS_VERIFY_RETRIES = 30
DNS_VERIFY_DELAY = 10


def log(msg: str):
    print(f"[green][INFO][/green] {msg}")


def warn(msg: str):
    print(f"[yellow][WARN][/yellow] {msg}")


def error(msg: str):
    print(f"[red][ERROR][/red] {msg}")
    sys.exit(1)


def get_ssh_user(provider_name: str) -> str:
    """Get default SSH user for cloud provider.

    :param provider_name: Cloud provider (aws or digitalocean)
    :return: SSH username (ubuntu for AWS, root for DigitalOcean)
    """
    return "ubuntu" if provider_name == "aws" else "root"


def run_cmd(*args, check: bool = True) -> str:
    result = subprocess.run(args, capture_output=True, text=True)
    if check and result.returncode != 0:
        error(f"Command failed: {result.stderr}")
    return result.stdout.strip()


def run_cmd_json(*args) -> dict | list:
    output = run_cmd(*args, "-o", "json")
    return json.loads(output) if output else []


def ssh(ip: str, cmd: str, user: str = "root") -> str:
    with Connection(ip, user=user, connect_kwargs={"look_for_keys": True}) as c:
        result = c.run(cmd, hide=True, warn=True)
        if result.failed:
            error(f"SSH command failed: {result.stderr}")
        return result.stdout


def ssh_script(ip: str, script: str, user: str = "root") -> str:
    with Connection(ip, user=user, connect_kwargs={"look_for_keys": True}) as c:
        escaped = script.replace("'", "'\\''")
        result = c.run(f"bash -c '{escaped}'", hide=True, warn=True)
        if result.failed:
            error(f"SSH script failed: {result.stderr}")
        return result.stdout


def ssh_as_user(ip: str, app_user: str, cmd: str, ssh_user: str = "root") -> str:
    return ssh(ip, f'su - {app_user} -c "{cmd}"', user=ssh_user)


def ssh_write_file(ip: str, path: str, content: str, user: str = "root"):
    encoded = base64.b64encode(content.encode()).decode()
    if user != "root" and (path.startswith("/etc/") or path.startswith("/var/")):
        ssh(ip, f"echo '{encoded}' | base64 -d | sudo tee {path} > /dev/null", user=user)
    else:
        ssh(ip, f"echo '{encoded}' | base64 -d > {path}", user=user)


def rsync(
    local: str, ip: str, remote: str, exclude: list[str] = None, user: str = "root"
):
    ssh_opts = (
        "ssh -o StrictHostKeyChecking=no "
        "-o UserKnownHostsFile=/dev/null "
        "-o ServerAliveInterval=60 "
        "-o ServerAliveCountMax=3 "
        "-o TCPKeepAlive=yes "
        "-o Compression=yes "
        "-o LogLevel=ERROR"
    )
    
    cmd = [
        "rsync",
        "-avz",
        "--delete",
        "--partial",
        "--inplace",
        "--no-whole-file",
        "--block-size=8192",
        "-e",
        ssh_opts,
    ]
    for ex in exclude or []:
        cmd.extend(["--exclude", ex])
    cmd.extend([f"{local}/", f"{user}@{ip}:{remote}/"])
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        return
    
    if "Result too large" in result.stderr or "unexpected end of file" in result.stderr:
        log("rsync failed with large file error, falling back to tar+ssh...")
        _rsync_tar_fallback(local, ip, remote, exclude, user, ssh_opts)
    else:
        error(f"rsync failed: {result.stderr}")


def _rsync_tar_fallback(
    local: str, ip: str, remote: str, exclude: list[str], user: str, ssh_opts: str
):
    import tempfile

    log("Creating tar archive...")
    exclude_args = []
    for ex in exclude or []:
        exclude_args.extend(["--exclude", ex.lstrip("/")])

    with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
        tar_cmd = [
            "tar",
            "-czf",
            tmp.name,
            "-C",
            local,
        ] + exclude_args + ["."]
        result = subprocess.run(tar_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            error(f"tar creation failed: {result.stderr}")
        tar_path = tmp.name

    try:
        log("Uploading tar archive...")
        remote_tar = f"/tmp/deploy_{int(time.time())}.tar.gz"

        scp_cmd = [
            "scp",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "Compression=yes",
            tar_path,
            f"{user}@{ip}:{remote_tar}",
        ]
        result = subprocess.run(scp_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            error(f"scp upload failed: {result.stderr}")

        log("Extracting on remote server...")
        sudo = "" if user == "root" else "sudo "
        app_user = remote.split("/")[2] if remote.startswith("/home/") else user
        extract_script = f"""
            set -e
            {sudo}mkdir -p {remote}
            {sudo}tar -xzf {remote_tar} -C {remote}
            {sudo}chown -R {app_user}:{app_user} {remote}
            {sudo}rm -f {remote_tar}
        """
        ssh_script(ip, extract_script, user=user)
        log("Transfer complete")
    finally:
        Path(tar_path).unlink(missing_ok=True)


def load_instance(name: str) -> dict:
    path = Path(f"{name}.instance.json")
    if not path.exists():
        error(f"Instance file not found: {path}")
    data = json.loads(path.read_text())
    if "apps" not in data and "app_name" in data:
        app_data = {"name": data["app_name"], "type": data.get("app_type", "nuxt")}
        if "port" in data:
            app_data["port"] = data["port"]
        data["apps"] = [app_data]
        data.pop("app_name", None)
        data.pop("app_type", None)
        save_instance(name, data)
    return data


def get_instance_apps(instance: dict) -> list[dict]:
    if "apps" in instance:
        return instance["apps"]
    if "app_name" in instance:
        return [{"name": instance["app_name"], "type": instance.get("app_type", "nuxt")}]
    return []


def add_app_to_instance(instance: dict, app_name: str, app_type: str, port: int | None = None):
    """Add or update app in instance with conflict detection.

    :param instance: Instance data dict
    :param app_type: App type (nuxt or fastapi)
    :param port: Port number (optional)
    """
    if "apps" not in instance:
        instance["apps"] = []

    existing_app = None
    for app in instance["apps"]:
        if app["name"] == app_name:
            existing_app = app
            break

    if existing_app:
        old_type = existing_app.get("type", "unknown")
        old_port = existing_app.get("port")

        if old_type != app_type:
            warn(f"App '{app_name}' type changing from {old_type} to {app_type}")

        if port is not None and port != old_port:
            conflicting_apps = [
                app for app in instance["apps"]
                if app["name"] != app_name and app.get("port") == port
            ]
            if conflicting_apps:
                conflict_names = ", ".join(app["name"] for app in conflicting_apps)
                warn(f"Port {port} already in use by: {conflict_names}")

        existing_app["type"] = app_type
        if port is not None:
            existing_app["port"] = port
        elif "port" in existing_app and old_port is not None:
            pass

        log(f"Updated app '{app_name}' ({old_type} -> {app_type})")
    else:
        if port is not None:
            conflicting_apps = [
                app for app in instance["apps"]
                if app.get("port") == port
            ]
            if conflicting_apps:
                conflict_names = ", ".join(app["name"] for app in conflicting_apps)
                warn(f"Port {port} already in use by: {conflict_names}")

        app_data = {"name": app_name, "type": app_type}
        if port is not None:
            app_data["port"] = port
        instance["apps"].append(app_data)
        log(f"Added app '{app_name}' ({app_type})")


def is_valid_ip(ip: str) -> bool:
    parts = ip.split(".")
    return len(parts) == 4 and all(
        part.isdigit() and 0 <= int(part) <= 255 for part in parts
    )


def resolve_dns_a(domain: str, nameserver: str = "8.8.8.8") -> str | None:
    """Resolve domain to IPv4 address.

    :param nameserver: DNS nameserver IP (default: 8.8.8.8)
    :return: First A record IP or None
    """
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [nameserver]
        answer = resolver.resolve(domain, "A")
        return str(answer[0]) if answer else None
    except Exception:
        return None


def check_http_status(url: str, timeout: int = 5) -> tuple[int | None, str]:
    """:return: (status_code, response_text) or (None, error_message)"""
    try:
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, timeout=timeout) as response:
            status_code = response.getcode()
            return status_code, f"HTTP/{response.version} {status_code} {response.reason}"
    except urllib.error.HTTPError as e:
        return e.code, f"HTTP/{e.version} {e.code} {e.reason}"
    except urllib.error.URLError as e:
        return None, str(e)
    except Exception as e:
        return None, str(e)


def resolve_ip(target: str) -> str:
    if is_valid_ip(target):
        return target
    data = load_instance(target)
    return data["ip"]


def resolve_instance(target: str) -> dict:
    """:return: Instance dict with at least ``ip`` key"""
    if is_valid_ip(target):
        return {"ip": target}
    return load_instance(target)


def save_instance(name: str, data: dict):
    Path(f"{name}.instance.json").write_text(json.dumps(data, indent=2))


def detect_node_version(source: str) -> int | None:
    source_path = Path(source)

    for filename in [".nvmrc", ".node-version"]:
        version_file = source_path / filename
        if version_file.exists():
            content = version_file.read_text().strip().lstrip("v")
            try:
                return int(content.split(".")[0])
            except ValueError:
                pass

    package_json = source_path / "package.json"
    if package_json.exists():
        try:
            data = json.loads(package_json.read_text())
            node_constraint = data.get("engines", {}).get("node", "")
            match = re.search(r"(\d+)", node_constraint)
            if match:
                return int(match.group(1))
        except (json.JSONDecodeError, ValueError):
            pass

    return None


def compute_hash(source: str, exclude: list[str] | None = None) -> str:
    source_path = Path(source)
    if exclude is None:
        exclude = [".git"]

    hasher = hashlib.md5()
    for f in sorted(source_path.rglob("*")):
        if f.is_file() and not any(ex in str(f) for ex in exclude):
            hasher.update(str(f.relative_to(source_path)).encode())
            hasher.update(f.read_bytes())
    return hasher.hexdigest()


@lru_cache(maxsize=None)
def get_aws_config(is_raise_exception: bool = True):
    """Get AWS configuration for boto3 client initialization.

    Searches AWS_PROFILE and AWS_REGION environment variables, validates
    credentials via STS GetCallerIdentity, and checks token expiration.

    :return: Dict with profile_name and region_name keys
    """
    load_dotenv()

    aws_config = {}

    profile_name = os.getenv("AWS_PROFILE")
    if profile_name:
        aws_config["profile_name"] = profile_name

    region = os.getenv("AWS_REGION")
    if region:
        aws_config["region_name"] = region

    try:
        aws_credentials_path = os.path.expanduser("~/.aws/credentials")
        if not os.path.exists(aws_credentials_path):
            log("No AWS credentials file at ~/.aws/credentials")
            return aws_config

        session = (
            boto3.Session(profile_name=profile_name)
            if profile_name
            else boto3.Session()
        )
        credentials = session.get_credentials()

        if not credentials or not credentials.access_key or not credentials.secret_key:
            return aws_config

        sts = session.client("sts")
        _ = sts.get_caller_identity()

        if hasattr(credentials, "token"):
            creds = credentials.get_frozen_credentials()
            if hasattr(creds, "expiry_time") and creds.expiry_time < datetime.now(
                timezone.utc
            ):
                warn(f"AWS credentials expired on {creds.expiry_time}")
                return aws_config

    except ProfileNotFound:
        if is_raise_exception:
            raise
        warn(f"AWS profile '{profile_name}' not found")
    except ClientError as e:
        if is_raise_exception:
            raise
        error_code = e.response["Error"]["Code"]
        if error_code == "ExpiredToken":
            warn("AWS credentials have expired")
        elif error_code == "InvalidClientTokenId":
            warn(
                "AWS credentials are invalid. Please reconfigure:\n"
                "  aws configure\n"
                "Or check your ~/.aws/credentials file"
            )
        else:
            warn(f"Error validating AWS credentials: {str(e)}")
    except Exception as e:
        if is_raise_exception:
            raise
        error(f"Unexpected error checking AWS credentials: {str(e)}")

    return aws_config


def get_local_ssh_key() -> tuple[str, str]:
    ssh_dir = Path.home() / ".ssh"
    key_names = ["id_ed25519.pub", "id_rsa.pub", "id_ecdsa.pub"]

    for name in key_names:
        key_path = ssh_dir / name
        if key_path.exists():
            content = key_path.read_text().strip()
            key_data = content.split()[1]
            decoded = base64.b64decode(key_data)
            fingerprint = hashlib.md5(decoded).hexdigest()
            fingerprint = ":".join(fingerprint[i : i + 2] for i in range(0, 32, 2))
            log(f"Using SSH key: {key_path}")
            return content, fingerprint

    error(f"No SSH key found in ~/.ssh/ (tried: {', '.join(key_names)})")


def wait_for_ssh(ip: str, user: str = "root", timeout: int = SSH_TIMEOUT):
    log(f"Waiting for SSH on {ip}...")
    start = time.time()
    while time.time() - start < timeout:
        try:
            with Connection(
                ip, user=user, connect_kwargs={"look_for_keys": True, "timeout": 5}
            ) as c:
                c.run("echo ok", hide=True)
                log("SSH ready")
                return
        except Exception:
            pass
        time.sleep(5)
    error(f"SSH timeout after {timeout}s")


def verify_http(ip: str) -> bool:
    log("Verifying HTTP connectivity on port 80...")
    for i in range(HTTP_VERIFY_RETRIES):
        try:
            req = urllib.request.Request(f"http://{ip}/")
            with urllib.request.urlopen(req, timeout=5) as response:
                status_code = response.getcode()
                if str(status_code)[0] in "2345":
                    log("HTTP connectivity verified")
                    return True
        except (urllib.error.URLError, urllib.error.HTTPError, Exception):
            pass
        warn(f"Cannot connect to http://{ip}/ ({i + 1}/{HTTP_VERIFY_RETRIES})")
        time.sleep(HTTP_VERIFY_DELAY)
    error(f"Cannot connect to server on port 80. Check UFW: ssh root@{ip} 'ufw status'")


class Provider(Protocol):
    provider_name: ProviderName
    region: str
    os_image: str
    vm_size: str

    def validate_auth(self) -> None: ...

    def validate_config(self) -> None: ...

    def instance_exists(self, name: str) -> bool: ...

    def create_instance(self, name: str, region: str, vm_size: str) -> dict: ...

    def delete_instance(self, instance_id: str) -> None: ...

    def list_instances(self) -> list[dict]: ...

    def setup_dns(self, domain: str, ip: str) -> None: ...

    def cleanup_resources(self, *, dry_run: bool = True) -> None: ...


class DigitalOceanProvider:
    def __init__(
        self,
        os_image: str | None = None,
        region: str | None = None,
        vm_size: str | None = None,
    ):
        self.provider_name: ProviderName = "digitalocean"
        self.region = region or "syd1"
        self.os_image = os_image or "ubuntu-24-04-x64"
        self.vm_size = vm_size or "s-1vcpu-1gb"
        self.validate_config()

    def validate_auth(self) -> None:
        result = subprocess.run(
            ["doctl", "auth", "validate"], capture_output=True, text=True
        )
        if result.returncode != 0:
            error("doctl not authenticated. Run: doctl auth init")

    def validate_config(self) -> None:
        if self.vm_size.startswith("t3.") or self.vm_size.startswith("t4g.") or self.vm_size.startswith("m5."):
            error(
                f"VM size '{self.vm_size}' is an AWS instance type, not DigitalOcean.\n"
                f"DigitalOcean sizes: s-1vcpu-1gb, s-2vcpu-2gb, s-4vcpu-8gb, etc.\n"
                f"See PROVIDER_COMPARISON.md for size mappings."
            )

    def instance_exists(self, name: str) -> bool:
        droplets = run_cmd_json("doctl", "compute", "droplet", "list")
        return any(d["name"] == name for d in droplets)

    def get_instance_by_name(self, name: str) -> dict | None:
        droplets = run_cmd_json("doctl", "compute", "droplet", "list", name)
        droplet = next((d for d in droplets if d["name"] == name), None)
        if not droplet:
            return None
        ip = next(
            (
                n["ip_address"]
                for n in droplet["networks"]["v4"]
                if n["type"] == "public"
            ),
            "N/A",
        )
        return {"id": droplet["id"], "ip": ip}

    def create_instance(self, name: str, region: str, vm_size: str) -> dict:
        self.validate_auth()

        if self.instance_exists(name):
            error(f"Droplet '{name}' already exists")

        key_content, fingerprint = get_local_ssh_key()
        keys = run_cmd_json("doctl", "compute", "ssh-key", "list")

        existing = next((k for k in keys if k["fingerprint"] == fingerprint), None)
        if existing:
            ssh_key_id = str(existing["id"])
            log(f"Found matching SSH key in DigitalOcean: {existing['name']}")
        else:
            log("Uploading SSH key to DigitalOcean...")
            key_name = f"deploy-vm-{fingerprint[-8:]}"
            run_cmd(
                "doctl",
                "compute",
                "ssh-key",
                "create",
                key_name,
                "--public-key",
                key_content,
            )
            keys = run_cmd_json("doctl", "compute", "ssh-key", "list")
            uploaded = next((k for k in keys if k["fingerprint"] == fingerprint), None)
            if not uploaded:
                error("Failed to upload SSH key")
            ssh_key_id = str(uploaded["id"])
            log(f"Uploaded SSH key: {key_name}")

        run_cmd(
            "doctl",
            "compute",
            "droplet",
            "create",
            name,
            "--region",
            region,
            "--size",
            vm_size,
            "--image",
            self.os_image,
            "--ssh-keys",
            ssh_key_id,
            "--wait",
        )

        droplets = run_cmd_json("doctl", "compute", "droplet", "list", name)
        if not droplets:
            error("Failed to find created droplet")

        droplet = droplets[0]
        ip = next(
            (
                n["ip_address"]
                for n in droplet["networks"]["v4"]
                if n["type"] == "public"
            ),
            None,
        )
        if not ip:
            error("No public IP found")

        return {"id": droplet["id"], "ip": ip}

    def delete_instance(self, instance_id: str) -> None:
        self.validate_auth()
        run_cmd("doctl", "compute", "droplet", "delete", str(instance_id), "--force")

    def list_instances(self) -> list[dict]:
        self.validate_auth()
        droplets = run_cmd_json("doctl", "compute", "droplet", "list")
        return [
            {
                "name": d["name"],
                "ip": next(
                    (
                        n["ip_address"]
                        for n in d["networks"]["v4"]
                        if n["type"] == "public"
                    ),
                    "N/A",
                ),
                "status": d["status"],
                "region": d["region"]["slug"],
            }
            for d in droplets
        ]

    def setup_dns(self, domain: str, ip: str) -> None:
        self.validate_auth()
        domains = run_cmd_json("doctl", "compute", "domain", "list")
        domain_exists = any(d["name"] == domain for d in domains)

        if not domain_exists:
            log("Creating domain...")
            run_cmd("doctl", "compute", "domain", "create", domain, "--ip-address", ip)
        else:
            log("Domain exists, updating records...")

        records = run_cmd_json("doctl", "compute", "domain", "records", "list", domain)

        for name in ["@", "www"]:
            existing = [r for r in records if r["type"] == "A" and r["name"] == name]
            if existing:
                record_id = str(existing[0]["id"])
                run_cmd(
                    "doctl",
                    "compute",
                    "domain",
                    "records",
                    "update",
                    domain,
                    "--record-id",
                    record_id,
                    "--record-data",
                    ip,
                )
            else:
                run_cmd(
                    "doctl",
                    "compute",
                    "domain",
                    "records",
                    "create",
                    domain,
                    "--record-type",
                    "A",
                    "--record-name",
                    name,
                    "--record-data",
                    ip,
                )

    def cleanup_resources(self, *, dry_run: bool = True) -> None:
        log("No cleanup operations available for DigitalOcean provider")


class AWSProvider:
    def __init__(
        self,
        os_image: str | None = None,
        region: str | None = None,
        vm_size: str | None = None,
    ):
        self.provider_name: ProviderName = "aws"
        self.os_image = os_image or "ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"
        self.vm_size = vm_size or "t3.micro"
        self.aws_config = get_aws_config(is_raise_exception=False)

        if region:
            self.aws_config["region_name"] = region

        region = region or self.aws_config.get("region_name", "ap-southeast-2")
        self.region = self._validate_and_normalize_region(region)

        if not self.aws_config:
            error(
                "AWS credentials not configured. Please run:\n"
                "  aws configure\n"
                "Or set environment variables:\n"
                "  export AWS_PROFILE=your-profile\n"
                "  export AWS_REGION=ap-southeast-2"
            )

        self.validate_config()

    def validate_auth(self) -> None:
        try:
            session = boto3.Session(**self.aws_config)
            sts = session.client("sts")
            sts.get_caller_identity()
        except Exception as e:
            error(f"AWS authentication failed: {e}")

    def _validate_and_normalize_region(self, region: str) -> str:
        """Validate and normalize AWS region (converts AZ to region if needed)."""
        valid_regions = PROVIDER_OPTIONS["aws"]["regions"]

        if region and region[-1].isalpha() and region[:-1] in valid_regions:
            normalized_region = region[:-1]
            log(f"Converted availability zone '{region}' to region '{normalized_region}'")
            return normalized_region

        if region not in valid_regions:
            error(
                f"Invalid AWS region: '{region}'\n"
                f"Valid AWS regions: {', '.join(valid_regions[:6])}, ...\n"
                f"See PROVIDER_COMPARISON.md for full list."
            )

        return region

    def validate_config(self) -> None:
        if self.vm_size.startswith("s-"):
            error(
                f"VM size '{self.vm_size}' is a DigitalOcean size, not AWS.\n"
                f"AWS instance types: t3.micro, t3.small, t3.medium, t3.large, etc.\n"
                f"See PROVIDER_COMPARISON.md for size mappings."
            )

    def _get_ec2_client(self):
        session = boto3.Session(**self.aws_config)
        return session.client("ec2")

    def _get_route53_client(self):
        session = boto3.Session(**self.aws_config)
        return session.client("route53")

    def _validate_vpc(self, ec2, vpc_id: str) -> tuple[bool, str | None]:
        """:return: (is_valid, error_message)"""
        subnets = ec2.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )["Subnets"]
        if not subnets:
            return False, "No subnets found in VPC"

        igws = ec2.describe_internet_gateways(
            Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}]
        )["InternetGateways"]
        if not igws:
            return False, "No internet gateway attached to VPC"

        has_public_subnet = False
        for subnet in subnets:
            route_tables = ec2.describe_route_tables(
                Filters=[
                    {"Name": "association.subnet-id", "Values": [subnet["SubnetId"]]}
                ]
            )["RouteTables"]

            if not route_tables:
                route_tables = ec2.describe_route_tables(
                    Filters=[
                        {"Name": "vpc-id", "Values": [vpc_id]},
                        {"Name": "association.main", "Values": ["true"]}
                    ]
                )["RouteTables"]

            for rt in route_tables:
                for route in rt.get("Routes", []):
                    if route.get("GatewayId", "").startswith("igw-"):
                        has_public_subnet = True
                        break
                if has_public_subnet:
                    break
            if has_public_subnet:
                break

        if not has_public_subnet:
            return False, "No public subnets found (subnets need route to internet gateway)"

        return True, None

    def _get_my_ip(self) -> str:
        try:
            import urllib.request
            response = urllib.request.urlopen('https://api.ipify.org', timeout=5)
            return response.read().decode('utf8')
        except Exception:
            log("[WARN] Could not determine your public IP, using 0.0.0.0/0 for SSH access")
            return None

    def _find_ami(self, ec2_client) -> str:
        response = ec2_client.describe_images(
            Filters=[
                {"Name": "name", "Values": [self.os_image]},
                {"Name": "state", "Values": ["available"]},
                {"Name": "architecture", "Values": ["x86_64"]},
            ],
            Owners=["099720109477"],  # Canonical's AWS account ID
        )

        if not response["Images"]:
            error(f"No AMI found matching pattern: {self.os_image}")

        images = sorted(response["Images"], key=lambda x: x["CreationDate"], reverse=True)
        return images[0]["ImageId"]

    def instance_exists(self, name: str) -> bool:
        ec2 = self._get_ec2_client()
        response = ec2.describe_instances(
            Filters=[
                {"Name": "tag:Name", "Values": [name]},
                {"Name": "instance-state-name", "Values": ["running", "pending", "stopping", "stopped"]},
            ]
        )
        return len(response["Reservations"]) > 0

    def get_instance_by_name(self, name: str) -> dict | None:
        ec2 = self._get_ec2_client()
        response = ec2.describe_instances(
            Filters=[
                {"Name": "tag:Name", "Values": [name]},
                {"Name": "instance-state-name", "Values": ["running", "pending"]},
            ]
        )

        if not response["Reservations"] or not response["Reservations"][0]["Instances"]:
            return None

        instance = response["Reservations"][0]["Instances"][0]
        return {
            "id": instance["InstanceId"],
            "ip": instance.get("PublicIpAddress", "N/A"),
        }

    def create_instance(self, name: str, region: str, vm_size: str) -> dict:
        self.validate_auth()

        if self.instance_exists(name):
            error(f"EC2 instance '{name}' already exists")

        ec2 = self._get_ec2_client()

        # Find AMI
        ami_id = self._find_ami(ec2)
        log(f"Using AMI: {ami_id}")

        key_content, fingerprint = get_local_ssh_key()
        key_name = f"deploy-vm-{fingerprint[-8:]}"

        try:
            ec2.describe_key_pairs(KeyNames=[key_name])
            log(f"Using existing SSH key: {key_name}")
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidKeyPair.NotFound":
                log("Uploading SSH key to AWS...")
                ec2.import_key_pair(KeyName=key_name, PublicKeyMaterial=key_content)
                log(f"Uploaded SSH key: {key_name}")
            else:
                raise

        sg_name = "deploy-vm-web"
        try:
            response = ec2.describe_security_groups(
                Filters=[{"Name": "group-name", "Values": [sg_name]}]
            )
            if response["SecurityGroups"]:
                sg_id = response["SecurityGroups"][0]["GroupId"]
                log(f"Using existing security group: {sg_name}")
            else:
                raise ClientError(
                    {"Error": {"Code": "InvalidGroup.NotFound"}}, "DescribeSecurityGroups"
                )
        except ClientError as e:
            if e.response["Error"]["Code"] in ["InvalidGroup.NotFound", "VPCIdNotSpecified"]:
                log("Creating security group...")

                vpcs = ec2.describe_vpcs()["Vpcs"]
                if not vpcs:
                    error("No VPC found in this region. Please create a VPC first:\n"
                          "  aws ec2 create-default-vpc --region " + self.aws_config.get("region_name", "ap-southeast-2"))

                default_vpc = next((v for v in vpcs if v.get("IsDefault")), None)
                vpc_id = default_vpc["VpcId"] if default_vpc else vpcs[0]["VpcId"]

                is_valid, error_msg = self._validate_vpc(ec2, vpc_id)
                if not is_valid:
                    error(
                        f"VPC {vpc_id} is not properly configured: {error_msg}\n"
                        f"The VPC needs:\n"
                        f"  1. Subnets (for instance placement)\n"
                        f"  2. Internet gateway (for outbound connectivity)\n"
                        f"  3. Route table with route to internet gateway (for public access)\n"
                        f"Fix with: aws ec2 create-default-vpc --region {self.aws_config.get('region_name', 'ap-southeast-2')}"
                    )

                log(f"Using VPC: {vpc_id}")

                response = ec2.create_security_group(
                    GroupName=sg_name,
                    Description="Security group for deploy-vm web servers",
                    VpcId=vpc_id,
                    TagSpecifications=[{
                        "ResourceType": "security-group",
                        "Tags": [
                            {"Key": "Name", "Value": sg_name},
                            {"Key": "ManagedBy", "Value": "deploy-vm"},
                            {"Key": "CreatedAt", "Value": datetime.now(timezone.utc).isoformat()},
                        ]
                    }]
                )
                sg_id = response["GroupId"]

                my_ip = self._get_my_ip()
                ssh_cidr = f"{my_ip}/32" if my_ip else "0.0.0.0/0"
                if my_ip:
                    log(f"Restricting SSH access to your IP: {my_ip}")

                ec2.authorize_security_group_ingress(
                    GroupId=sg_id,
                    IpPermissions=[
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": ssh_cidr, "Description": "SSH access"}],
                        },
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 80,
                            "ToPort": 80,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "HTTP access"}],
                        },
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 443,
                            "ToPort": 443,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "HTTPS access"}],
                        },
                    ],
                )
                log(f"Created security group: {sg_name}")
            else:
                raise

        log(f"Creating EC2 instance '{name}' ({vm_size})...")
        response = ec2.run_instances(
            ImageId=ami_id,
            InstanceType=vm_size,
            KeyName=key_name,
            SecurityGroupIds=[sg_id],
            MinCount=1,
            MaxCount=1,
            TagSpecifications=[
                {
                    "ResourceType": "instance",
                    "Tags": [
                        {"Key": "Name", "Value": name},
                        {"Key": "ManagedBy", "Value": "deploy-vm"},
                        {"Key": "CreatedAt", "Value": datetime.now(timezone.utc).isoformat()},
                        {"Key": "CreatedBy", "Value": os.getenv("USER", "unknown")},
                    ],
                }
            ],
        )

        instance_id = response["Instances"][0]["InstanceId"]
        log("Waiting for instance to start...")

        waiter = ec2.get_waiter("instance_running")
        waiter.wait(InstanceIds=[instance_id])

        response = ec2.describe_instances(InstanceIds=[instance_id])
        instance = response["Reservations"][0]["Instances"][0]
        ip = instance.get("PublicIpAddress")

        if not ip:
            error("No public IP address assigned to instance")

        return {"id": instance_id, "ip": ip}

    def delete_instance(self, instance_id: str) -> None:
        self.validate_auth()
        ec2 = self._get_ec2_client()
        ec2.terminate_instances(InstanceIds=[instance_id])
        log("Waiting for instance to terminate...")
        waiter = ec2.get_waiter("instance_terminated")
        waiter.wait(InstanceIds=[instance_id])

    def list_instances(self) -> list[dict]:
        self.validate_auth()
        ec2 = self._get_ec2_client()
        response = ec2.describe_instances(
            Filters=[
                {"Name": "instance-state-name", "Values": ["running", "pending", "stopping", "stopped"]}
            ]
        )

        instances = []
        for reservation in response["Reservations"]:
            for instance in reservation["Instances"]:
                name = next(
                    (tag["Value"] for tag in instance.get("Tags", []) if tag["Key"] == "Name"),
                    instance["InstanceId"],
                )
                instances.append({
                    "name": name,
                    "ip": instance.get("PublicIpAddress", "N/A"),
                    "status": instance["State"]["Name"],
                    "region": instance["Placement"]["AvailabilityZone"],
                })

        return instances

    def setup_dns(self, domain: str, ip: str) -> None:
        self.validate_auth()
        route53 = self._get_route53_client()

        response = route53.list_hosted_zones()
        zone_id = None
        for zone in response["HostedZones"]:
            if zone["Name"] == f"{domain}." or zone["Name"] == domain:
                zone_id = zone["Id"]
                break

        if not zone_id:
            error(f"No Route53 hosted zone found for domain: {domain}")

        log(f"Updating Route53 DNS records for {domain}...")

        for record_name in [domain, f"www.{domain}"]:
            change_batch = {
                "Changes": [
                    {
                        "Action": "UPSERT",
                        "ResourceRecordSet": {
                            "Name": record_name,
                            "Type": "A",
                            "TTL": 300,
                            "ResourceRecords": [{"Value": ip}],
                        },
                    }
                ]
            }

            route53.change_resource_record_sets(
                HostedZoneId=zone_id,
                ChangeBatch=change_batch,
            )

        log("DNS records updated")

    def cleanup_resources(self, *, dry_run: bool = True) -> None:
        """Cleanup orphaned security groups not attached to running instances.

        :param dry_run: Show what would be deleted without deleting
        """
        self.validate_auth()
        ec2 = self._get_ec2_client()
        region = self.aws_config.get("region_name", "ap-southeast-2")

        log(f"Scanning for orphaned security groups in {region}...")

        try:
            sgs = ec2.describe_security_groups(
                Filters=[
                    {"Name": "group-name", "Values": ["deploy-vm-web"]},
                ]
            )["SecurityGroups"]
        except Exception as e:
            error(f"Failed to list security groups: {e}")

        if not sgs:
            log("No deploy-vm security groups found")
            return

        for sg in sgs:
            sg_id = sg["GroupId"]
            sg_name = sg["GroupName"]

            try:
                instances = ec2.describe_instances(
                    Filters=[
                        {"Name": "instance.group-id", "Values": [sg_id]},
                        {"Name": "instance-state-name", "Values": ["running", "pending", "stopping"]}
                    ]
                )["Reservations"]

                if instances:
                    instance_count = sum(len(r["Instances"]) for r in instances)
                    log(f"Security group {sg_name} ({sg_id}) in use by {instance_count} instance(s)")
                else:
                    if dry_run:
                        log(f"[DRY RUN] Would delete unused security group: {sg_name} ({sg_id})")
                    else:
                        ec2.delete_security_group(GroupId=sg_id)
                        log(f"✓ Deleted security group: {sg_name} ({sg_id})")
            except ClientError as e:
                if "DependencyViolation" in str(e):
                    log(f"Security group {sg_name} ({sg_id}) is still in use")
                else:
                    log(f"[WARN] Could not process {sg_name}: {e}")

        if dry_run:
            log("\nRun with --no-dry-run to actually delete resources")


def get_provider(
    provider_name: ProviderName | None = None,
    *,
    region: str | None = None,
    os_image: str | None = None,
    vm_size: str | None = None,
) -> Provider:
    if provider_name is None:
        load_dotenv()
        provider_name = os.getenv("DEPLOY_VM_PROVIDER", "digitalocean")
        if provider_name not in ["digitalocean", "aws"]:
            log(f"[WARN] Invalid DEPLOY_VM_PROVIDER '{provider_name}', using 'digitalocean'")
            provider_name = "digitalocean"
    elif provider_name not in ["digitalocean", "aws"]:
        error(f"Unknown provider: {provider_name}. Available: digitalocean, aws")

    if provider_name == "digitalocean":
        return DigitalOceanProvider(os_image=os_image, region=region, vm_size=vm_size)
    else:  # aws
        return AWSProvider(os_image=os_image, region=region, vm_size=vm_size)


@instance_app.command(name="create")
def create_instance(
    name: str,
    *,
    provider_name: ProviderName | None = None,
    region: str | None = None,
    vm_size: str | None = None,
    os_image: str | None = None,
    user: str = "deploy",
    swap_size: str = "4G",
    no_setup: bool = False,
):
    """Create cloud instance and set it up.

    :param provider_name: Cloud provider (default: DEPLOY_VM_PROVIDER or digitalocean)
    :param user: App user for running services
    :param no_setup: Skip firewall, swap, and user setup
    """
    p = get_provider(provider_name, region=region, os_image=os_image, vm_size=vm_size)

    log(f"Creating instance '{name}' on {p.provider_name} in {p.region} ({p.vm_size})...")
    result = p.create_instance(name, p.region, p.vm_size)

    save_instance(
        name,
        {
            "id": result["id"],
            "ip": result["ip"],
            "provider": p.provider_name,
            "region": p.region,
            "vm_size": p.vm_size,
            "user": user,
        },
    )

    log("Instance ready!")
    print(f"  IP: {result['ip']}")

    ssh_user = get_ssh_user(p.provider_name)
    print(f"  SSH: ssh {ssh_user}@{result['ip']}")

    if not no_setup:
        wait_for_ssh(result["ip"], user=ssh_user)
        setup_server(result["ip"], user=user, ssh_user=ssh_user, swap_size=swap_size)


@instance_app.command(name="delete")
def delete_instance(
    name: str, *, provider_name: ProviderName | None = None, force: bool = False
):
    """Delete instance."""
    instance_file = Path(f"{name}.instance.json")
    p = get_provider(provider_name)

    if instance_file.exists():
        data = json.loads(instance_file.read_text())
        provider_name = data.get("provider", provider_name)
        p = get_provider(provider_name)
    else:
        log(f"No {name}.instance.json found, looking up from {p.provider_name}...")
        p.validate_auth()
        lookup = p.get_instance_by_name(name)
        if not lookup:
            error(f"Instance '{name}' not found in {p.provider_name}")
        data = {"id": lookup["id"], "ip": lookup["ip"], "provider": p.provider_name}

    print("[yellow]Instance to delete:[/yellow]")
    print(f"  Name: {name}")
    print(f"  Provider: {data.get('provider', p.provider_name)}")
    print(f"  ID: {data['id']}")
    print(f"  IP: {data['ip']}")

    if not force:
        confirm = input("Delete this instance? (yes/no): ")
        if confirm != "yes":
            log("Cancelled")
            return

    log("Deleting instance...")
    p.delete_instance(str(data["id"]))
    if instance_file.exists():
        instance_file.unlink()
    log("Instance deleted")


@instance_app.command(name="list")
def list_instances(
    *,
    provider_name: ProviderName | None = None,
    region: str | None = None,
):
    p = get_provider(provider_name, region=region)

    if p.provider_name == "aws":
        log(f"Listing instances in {p.region}...")
    instances = p.list_instances()

    if not instances:
        log(f"No instances found in {p.region}")
        return

    max_name = max(len(i['name']) for i in instances)
    max_ip = max(len(i['ip']) for i in instances)
    max_region = max(len(i['region']) for i in instances)

    name_header = "NAME".ljust(max_name)
    ip_header = "IP ADDRESS".ljust(max_ip)
    region_header = "REGION".ljust(max_region)
    print(f"  {name_header}  {ip_header}  {region_header}  STATUS")
    print(f"  {'-' * max_name}  {'-' * max_ip}  {'-' * max_region}  {'---'}")

    for i in instances:
        name = i['name'].ljust(max_name)
        ip = i['ip'].ljust(max_ip)
        region = i['region'].ljust(max_region)
        print(f"  {name}  {ip}  {region}  {i['status']}")


@instance_app.command(name="apps")
def list_instance_apps(target: str):
    instance = resolve_instance(target)
    apps = get_instance_apps(instance)

    if not apps:
        print(f"No apps tracked for instance '{target}'")
        return

    print(f"Apps on {target} ({instance['ip']}):")
    for app in apps:
        port_info = f" (port {app.get('port', '?')})" if app.get('port') else ""
        print(f"  - {app['name']}: {app['type']}{port_info}")


@instance_app.command(name="cleanup")
def cleanup_resources(
    *,
    provider_name: ProviderName | None = None,
    region: str | None = None,
    dry_run: bool = True,
):
    """Cleanup orphaned security groups not attached to running instances.

    :param provider_name: Cloud provider
    :param region: AWS region (default: ap-southeast-2)
    :param dry_run: Show what would be deleted without deleting (default: true)
    """
    p = get_provider(provider_name, region=region)
    p.cleanup_resources(dry_run=dry_run)


@instance_app.command(name="verify")
def verify_instance(
    name: str,
    *,
    domain: str | None = None,
    ssh_user: str = "root",
    provider_name: ProviderName = "digitalocean",
):
    """Verify instance health: SSH, firewall, DNS, nginx, app.

    :param name: Instance name
    :param domain: Domain to check DNS for
    :param ssh_user: SSH user for connection
    :param provider_name: Cloud provider for DNS checks
    """
    data = load_instance(name)
    ip = data["ip"]

    print(f"Verifying {name} ({ip})...")
    print("-" * 40)
    issues = []

    # SSH check
    try:
        uptime = ssh(ip, "uptime", user=ssh_user).strip()
        print(f"[OK] SSH: {uptime}")
    except Exception as e:
        print(f"[FAIL] SSH: {e}")
        issues.append("SSH connection failed")
        return

    ufw_status = ssh(ip, "ufw status", user=ssh_user)
    has_80 = "80/tcp" in ufw_status
    has_443 = "443/tcp" in ufw_status
    if has_80 and has_443:
        print("[OK] Firewall: ports 80, 443 open")
    else:
        missing = []
        if not has_80:
            missing.append("80")
        if not has_443:
            missing.append("443")
        print(f"[FAIL] Firewall: ports {', '.join(missing)} not open")
        issues.append(f"Firewall missing ports: {', '.join(missing)}")

    nginx_status = ssh(ip, "systemctl is-active nginx 2>/dev/null || echo 'inactive'", user=ssh_user).strip()
    if nginx_status == "active":
        print("[OK] Nginx: running")
    else:
        print(f"[FAIL] Nginx: {nginx_status}")
        issues.append("Nginx not running")

    if domain:
        dns_ip = resolve_dns_a(domain)
        if dns_ip == ip:
            print(f"[OK] DNS: {domain} -> {ip}")
        elif dns_ip:
            print(f"[FAIL] DNS: {domain} -> {dns_ip} (expected {ip})")
            issues.append(f"DNS mismatch: {dns_ip} != {ip}")
        else:
            print(f"[FAIL] DNS: {domain} -> no A record found")
            issues.append("DNS check failed")

    status_code, response_line = check_http_status(f"http://{ip}")
    if status_code and status_code in [200, 301, 302]:
        print("[OK] HTTP: responding")
    elif status_code:
        print(f"[WARN] HTTP: {response_line}")
    else:
        print(f"[FAIL] HTTP: {response_line}")
        issues.append("HTTP not responding")

    if domain:
        status_code, response_line = check_http_status(f"https://{domain}")
        if status_code == 200:
            print(f"[OK] HTTPS: {domain} responding")
        elif status_code:
            print(f"[WARN] HTTPS: {response_line}")
        else:
            print(f"[FAIL] HTTPS: {response_line}")
            issues.append("HTTPS not responding")

    print("-" * 40)
    if issues:
        print(f"Issues found ({len(issues)}):")
        for issue in issues:
            print(f"  - {issue}")
    else:
        print("All checks passed!")


def setup_server(
    ip: str, *, user: str = "deploy", ssh_user: str = "root", swap_size: str = "4G"
):
    log(f"Setting up server at {ip}...")

    sudo = "" if ssh_user == "root" else "sudo "

    script = dedent(f"""
        set -e
        echo "Waiting for cloud-init..."
        {sudo}cloud-init status --wait > /dev/null 2>&1 || true

        echo "Installing packages..."
        {sudo}apt-get update
        {sudo}apt-get install -y curl wget git ufw

        echo "Configuring firewall..."
        {sudo}ufw allow OpenSSH
        {sudo}ufw --force enable

        echo "Setting up swap..."
        if ! swapon --show | grep -q swapfile; then
            {sudo}fallocate -l {swap_size} /swapfile
            {sudo}chmod 600 /swapfile
            {sudo}mkswap /swapfile
            {sudo}swapon /swapfile
            echo '/swapfile none swap sw 0 0' | {sudo}tee -a /etc/fstab
        fi
        echo "Done!"
    """).strip()
    print(ssh_script(ip, script, user=ssh_user))

    log(f"Creating user: {user}")

    auth_keys_path = "~/.ssh/authorized_keys" if ssh_user == "root" else "/home/ubuntu/.ssh/authorized_keys"

    user_script = dedent(f"""
        set -e
        if id "{user}" &>/dev/null; then
            echo "User {user} already exists"
        else
            {sudo}adduser --disabled-password --gecos "" {user}
            {sudo}usermod -aG sudo {user}
            echo "{user} ALL=(ALL) NOPASSWD:ALL" | {sudo}tee /etc/sudoers.d/{user}
            {sudo}chmod 440 /etc/sudoers.d/{user}
            {sudo}mkdir -p /home/{user}/.ssh
            {sudo}cp {auth_keys_path} /home/{user}/.ssh/
            {sudo}chown -R {user}:{user} /home/{user}/.ssh
            {sudo}chmod 700 /home/{user}/.ssh
            {sudo}chmod 600 /home/{user}/.ssh/authorized_keys
            echo "User {user} created"
        fi
    """).strip()
    print(ssh_script(ip, user_script, user=ssh_user))
    log("Server setup complete")


def generate_pm2_ecosystem_config(
    app_name: str,
    script: str,
    cwd: str,
    port: int,
) -> str:
    return dedent(f"""
        const fs = require('fs');
        const path = require('path');

        // Load .env file if it exists
        const envPath = path.join(__dirname, '.env');
        const envVars = {{}};
        if (fs.existsSync(envPath)) {{
          const content = fs.readFileSync(envPath, 'utf-8');
          content.split('\\n').forEach(line => {{
            const trimmed = line.trim();
            if (trimmed && !trimmed.startsWith('#')) {{
              const [key, ...valueParts] = trimmed.split('=');
              if (key && valueParts.length) {{
                let value = valueParts.join('=').trim();
                if ((value.startsWith('"') && value.endsWith('"')) ||
                    (value.startsWith("'") && value.endsWith("'"))) {{
                  value = value.slice(1, -1);
                }}
                envVars[key.trim()] = value;
              }}
            }}
          }});
        }}

        module.exports = {{
          apps: [{{
            name: '{app_name}',
            script: '{script}',
            cwd: '{cwd}',
            instances: 'max',
            exec_mode: 'cluster',
            env: {{
              NODE_ENV: 'production',
              PORT: {port},
              ...envVars
            }}
          }}]
        }};
    """).strip()


def ensure_web_firewall(ip: str, ssh_user: str = "root"):
    log("Checking firewall...")
    sudo = "" if ssh_user == "root" else "sudo "
    result = ssh(ip, f"{sudo}ufw status", user=ssh_user)
    needs_80 = "80/tcp" not in result
    needs_443 = "443/tcp" not in result

    if needs_80 or needs_443:
        log("Opening web ports in firewall...")
        cmds = []
        if needs_80:
            cmds.append(f"{sudo}ufw allow 80/tcp")
        if needs_443:
            cmds.append(f"{sudo}ufw allow 443/tcp")
        cmds.append(f"{sudo}ufw reload")
        ssh_script(ip, " && ".join(cmds), user=ssh_user)
        log("Firewall updated")
    else:
        log("Firewall OK")


def ensure_dns_matches(
    domain: str, expected_ip: str, provider_name: ProviderName = "digitalocean"
) -> bool:
    current_ip = resolve_dns_a(domain) or ""

    if current_ip == expected_ip:
        return False

    warn(f"DNS mismatch: {domain} points to {current_ip or 'nothing'}, expected {expected_ip}")
    log("Updating DNS...")
    p = get_provider(provider_name)
    p.setup_dns(domain, expected_ip)
    log("DNS updated (may take a few minutes to propagate)")
    return True


def generate_nginx_server_block(
    server_name: str,
    port: int,
    static_dir: str | None = None,
    listen: str = "80",
) -> str:
    """Generate nginx server block.

    :param static_dir: If provided, nginx serves static files and proxies non-static requests
    """
    proxy_block = dedent("""
        proxy_pass http://127.0.0.1:{port};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    """).strip().format(port=port)

    if static_dir:
        location_block = dedent(f"""
            location / {{
                root {static_dir};
                try_files $uri $uri/ @backend;
            }}

            location @backend {{
                {proxy_block}
            }}
        """).strip()
    else:
        location_block = dedent(f"""
            location / {{
                {proxy_block}
            }}
        """).strip()

    return dedent(f"""
        server {{
            listen {listen};
            server_name {server_name};

            {location_block}
        }}
    """).strip()


@nginx_app.command(name="ip")
def setup_nginx_ip(
    target: str,
    *,
    port: int = 3000,
    static_dir: str | None = None,
    ssh_user: str = "root",
):
    """Setup nginx for IP-only access (no SSL)."""
    ip = resolve_ip(target)

    ensure_web_firewall(ip, ssh_user=ssh_user)

    server_block = generate_nginx_server_block("_", port, static_dir, listen="80 default_server")

    sudo = "" if ssh_user == "root" else "sudo "
    log(f"Setting up nginx for IP access on {ip}...")
    ssh_script(ip, f"{sudo}apt-get update && {sudo}apt-get install -y nginx", user=ssh_user)
    ssh_write_file(ip, "/etc/nginx/sites-available/default", server_block, user=ssh_user)
    ssh_script(
        ip,
        f"{sudo}ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/ && {sudo}nginx -t && {sudo}systemctl reload nginx",
        user=ssh_user,
    )

    verify_http(ip)
    log(f"Nginx configured! http://{ip}")


@nginx_app.command(name="ssl")
def setup_nginx_ssl(
    target: str,
    domain: str,
    email: str,
    *,
    port: int = 3000,
    static_dir: str | None = None,
    skip_dns: bool = False,
    ssh_user: str = "root",
    provider_name: ProviderName = "digitalocean",
):
    """Setup nginx and SSL certificate."""
    ip = resolve_ip(target)

    ensure_web_firewall(ip, ssh_user=ssh_user)
    if not skip_dns:
        ensure_dns_matches(domain, ip, provider_name=provider_name)

    server_block = generate_nginx_server_block(f"{domain} www.{domain}", port, static_dir)

    sudo = "" if ssh_user == "root" else "sudo "
    log("Setting up nginx...")
    ssh_script(ip, f"{sudo}apt-get update && {sudo}apt-get install -y nginx", user=ssh_user)
    ssh_write_file(ip, f"/etc/nginx/sites-available/{domain}", server_block, user=ssh_user)
    ssh_script(
        ip,
        f"{sudo}ln -sf /etc/nginx/sites-available/{domain} /etc/nginx/sites-enabled/ && "
        f"{sudo}rm -f /etc/nginx/sites-enabled/default && {sudo}nginx -t && {sudo}systemctl reload nginx",
        user=ssh_user,
    )

    log("Verifying DNS...")
    for i in range(DNS_VERIFY_RETRIES):
        resolved = resolve_dns_a(domain)
        if resolved == ip:
            log(f"DNS verified: {domain} -> {ip}")
            break
        warn(f"Waiting for DNS... ({i + 1}/{DNS_VERIFY_RETRIES})")
        time.sleep(DNS_VERIFY_DELAY)
    else:
        error("DNS verification timeout")

    verify_http(ip)

    log("Obtaining SSL certificate...")
    ssl_script = dedent(f"""
        set -e
        {sudo}apt-get install -y certbot python3-certbot-nginx
        if [ -d "/etc/letsencrypt/live/{domain}" ]; then
            echo "Certificate exists, renewing if needed..."
            {sudo}certbot --nginx -d {domain} -d www.{domain} \\
                --non-interactive --agree-tos --email {email} \\
                --redirect --keep-until-expiring
        else
            echo "Issuing new certificate..."
            {sudo}certbot --nginx -d {domain} -d www.{domain} \\
                --non-interactive --agree-tos --email {email} --redirect
        fi
    """).strip()
    ssh_script(ip, ssl_script, user=ssh_user)
    log(f"SSL configured! https://{domain}")


@nuxt_app.command(name="sync")
def sync_nuxt(
    target: str,
    source: str,
    *,
    user: str | None = None,
    ssh_user: str = "root",
    port: int = 3000,
    app_name: str = "nuxt",
    local_build: bool = True,
    force: bool = False,
    node_version: int = 20,
):
    """Sync Nuxt app to server.

    :param local_build: Build locally instead of on server
    :param force: Force rebuild even if source unchanged
    """
    instance = resolve_instance(target)
    ip = instance["ip"]
    user = user or instance.get("user", "deploy")
    
    if not is_valid_ip(target):
        add_app_to_instance(instance, app_name, "nuxt", port)
        save_instance(target, instance)
    
    source = str(Path(source).resolve())

    if not Path(source).exists():
        error(f"Source directory not found: {source}")

    detected_version = detect_node_version(source)
    if detected_version:
        log(f"Detected Node.js version {detected_version} from project config")
        node_version = detected_version

    log(f"Deploying to {ip}...")

    app_dir = f"/home/{user}/{app_name}"

    log(f"Installing Node.js {node_version} and PM2...")
    node_script = dedent(f"""
        set -e
        if ! command -v node &> /dev/null; then
            curl -fsSL https://deb.nodesource.com/setup_{node_version}.x | bash -
            apt-get install -y nodejs
        fi
        node --version
        if ! command -v pm2 &> /dev/null; then
            npm install -g pm2
        fi
        mkdir -p {app_dir}
        chown -R {user}:{user} {app_dir}
    """).strip()
    ssh_script(ip, node_script, user=ssh_user)

    log("Generating PM2 ecosystem config...")
    ecosystem_config = generate_pm2_ecosystem_config(
        app_name=app_name,
        script="./.output/server/index.mjs",
        cwd=app_dir,
        port=port,
    )
    ssh_write_file(ip, f"{app_dir}/ecosystem.config.cjs", ecosystem_config, user=ssh_user)
    ssh(ip, f"chown {user}:{user} {app_dir}/ecosystem.config.cjs", user=ssh_user)

    nuxt_exclude = [
        "node_modules",
        ".git",
        ".output",
        ".nuxt",
        "public/projects",
        "data/scripts/models",
        "json/projects",
    ]
    local_hash = compute_hash(source, nuxt_exclude)
    try:
        remote_hash = ssh(
            ip,
            f"cat {app_dir}/.source_hash 2>/dev/null || echo ''",
            user=ssh_user,
        ).strip()
    except Exception:
        remote_hash = ""

    if not force and local_hash == remote_hash and remote_hash:
        log("Source unchanged, restarting app...")
        restart_script = dedent(f"""
            if ! su - {user} -c "pm2 reload {app_name}" 2>/dev/null; then
                pkill -u {user} -f pm2 || true
                rm -rf /home/{user}/.pm2 || true
                rm -f /home/{user}/.pm2/*.sock /home/{user}/.pm2/pm2.pid 2>/dev/null || true
                sleep 1
                su - {user} -c "cd {app_dir} && pm2 start ecosystem.config.cjs && pm2 save"
            fi
        """).strip()
        ssh_script(ip, restart_script, user=ssh_user)
        log("App restarted")
        return

    if local_build:
        log("Building locally...")
        subprocess.run(["npm", "install"], cwd=source, check=True)
        subprocess.run(["npm", "run", "build"], cwd=source, check=True)

        if not Path(source, ".output").exists():
            error("Build failed - no .output directory")

    log("Uploading...")
    exclude = [
        "/node_modules",
        ".nuxt",
        ".git",
        "ecosystem.config.cjs",
        ".source_hash",
        "public/projects",
        "data/scripts/models",
        "json/projects",
    ]
    if not local_build:
        exclude.append(".output")
    rsync(source, ip, app_dir, exclude=exclude, user=ssh_user)

    if not local_build:
        log("Building on server...")
        build_script = dedent(f"""
            set -e
            cd {app_dir}
            export NODE_OPTIONS="--max-old-space-size=1024"
            su - {user} -c "cd {app_dir} && rm -rf package-lock.json .nuxt && npm install && npm run build"
        """).strip()
        ssh_script(ip, build_script, user=ssh_user)

    log("Starting app...")
    start_script = dedent(f"""
        set -e
        echo "{local_hash}" > {app_dir}/.source_hash
        # Legacy fallback: fix Nitro import.meta.url resolution for PM2
        # (nginx now serves .output/public directly, so this is rarely needed)
        sed -i 's/dirname(fileURLToPath(import.meta.url))/dirname(fileURLToPath(globalThis._importMeta_.url))/g' \
            {app_dir}/.output/server/chunks/nitro/nitro.mjs 2>/dev/null || true
        chown -R {user}:{user} {app_dir}
        pkill -u {user} -f pm2 || true
        pkill -u {user} -f "node.*index.mjs" || true
        rm -rf /home/{user}/.pm2 || true
        rm -f /home/{user}/.pm2/*.sock /home/{user}/.pm2/pm2.pid 2>/dev/null || true
        sleep 1
        su - {user} -c "cd {app_dir} && pm2 start ecosystem.config.cjs && pm2 save"
        pm2 startup systemd -u {user} --hp /home/{user} 2>/dev/null || true
    """).strip()
    ssh_script(ip, start_script, user=ssh_user)
    log("App deployed!")


@nuxt_app.command(name="restart")
def restart_pm2(target: str, *, user: str | None = None, ssh_user: str = "root", app_name: str | None = None):
    instance = resolve_instance(target)
    ip = instance["ip"]
    user = user or instance.get("user", "deploy")
    
    apps = [app for app in get_instance_apps(instance) if app["type"] == "nuxt"]
    
    if app_name is None:
        if len(apps) == 1:
            app_name = apps[0]["name"]
        elif len(apps) > 1:
            app_names = ", ".join(app["name"] for app in apps)
            error(f"Multiple Nuxt apps found: {app_names}. Use --app-name to specify.")
        else:
            app_name = target if not target.replace(".", "").isdigit() else "nuxt"
    
    log(f"Restarting {app_name}...")
    ssh_as_user(ip, user, f"pm2 reload {app_name}", ssh_user=ssh_user)
    log("App restarted")


@nuxt_app.command(name="status")
def show_pm2_status(target: str, *, user: str | None = None, ssh_user: str = "root"):
    instance = resolve_instance(target)
    ip = instance["ip"]
    user = user or instance.get("user", "deploy")
    print(ssh_as_user(ip, user, "pm2 list", ssh_user=ssh_user))


@nuxt_app.command(name="logs")
def show_pm2_logs(
    target: str, *, user: str | None = None, ssh_user: str = "root", lines: int = 50, app_name: str | None = None
):
    """View PM2 logs.

    :param target: Server IP address or instance name (loads from <name>.instance.json)
    :param user: App user (reads from instance.json if not specified)
    :param ssh_user: SSH user for connection
    :param lines: Number of lines to show
    :param app_name: PM2 app name (required if multiple apps exist on instance)
    """
    instance = resolve_instance(target)
    ip = instance["ip"]
    user = user or instance.get("user", "deploy")
    
    apps = [app for app in get_instance_apps(instance) if app["type"] == "nuxt"]
    
    if app_name is None:
        if len(apps) == 1:
            app_name = apps[0]["name"]
        elif len(apps) > 1:
            app_names = ", ".join(app["name"] for app in apps)
            error(f"Multiple Nuxt apps found: {app_names}. Use --app-name to specify.")
        else:
            app_name = target if not target.replace(".", "").isdigit() else "nuxt"
    print(
        ssh_as_user(
            ip, user, f"pm2 logs {app_name} --lines {lines} --nostream", ssh_user=ssh_user
        )
    )


@nuxt_app.command(name="deploy")
def deploy_nuxt(
    name: str,
    source: str,
    *,
    domain: str | None = None,
    email: str | None = None,
    user: str = "deploy",
    ssh_user: str = "root",
    port: int = 3000,
    app_name: str = "nuxt",
    provider_name: ProviderName = "digitalocean",
    region: str = "syd1",
    vm_size: str = "s-1vcpu-1gb",
    os_image: str = "ubuntu-24-04-x64",
    swap_size: str = "4G",
    node_version: int = 20,
    local_build: bool = True,
    no_ssl: bool = False,
):
    """Deploy Nuxt app: create instance, setup server, deploy app, configure nginx."""
    if not no_ssl and (not domain or not email):
        error("--domain and --email are required unless --no-ssl is set")

    instance_file = Path(f"{name}.instance.json")

    if not instance_file.exists():
        create_instance(
            name,
            provider_name=provider_name,
            region=region,
            vm_size=vm_size,
            os_image=os_image,
            user=user,
            swap_size=swap_size,
        )

    data = load_instance(name)

    if "user" not in data or data["user"] != user:
        data["user"] = user
    
    add_app_to_instance(data, app_name, "nuxt", port)
    save_instance(name, data)

    ip = data["ip"]

    log(f"Deploying {name} to {ip}")
    print("=" * 50)

    sync_nuxt(
        name,
        source,
        ssh_user=ssh_user,
        port=port,
        app_name=app_name,
        local_build=local_build,
        node_version=node_version,
    )

    ensure_web_firewall(ip, ssh_user=ssh_user)
    if not no_ssl:
        ensure_dns_matches(domain, ip, provider=data["provider"])

    nuxt_static_dir = f"/home/{user}/{app_name}/.output/public"
    if no_ssl:
        setup_nginx_ip(name, port=port, static_dir=nuxt_static_dir, ssh_user=ssh_user)
    else:
        setup_nginx_ssl(
            name,
            domain,
            email,
            port=port,
            static_dir=nuxt_static_dir,
            ssh_user=ssh_user,
            provider=data["provider"],
        )

    log("Verifying deployment...")
    verify_script = f"curl -sI http://localhost:{port} | head -1"
    result = ssh(ip, verify_script, user=ssh_user)
    if "200" not in result:
        warn(f"App health check returned: {result.strip()}")

    print("=" * 50)
    if no_ssl:
        log(f"Done! http://{ip}")
    else:
        log(f"Done! https://{domain}")


@fastapi_app.command(name="sync")
def sync_fastapi(
    target: str,
    source: str,
    *,
    user: str | None = None,
    ssh_user: str | None = None,
    port: int = 8000,
    app_name: str = "fastapi",
    app_module: str = "app:app",
    workers: int = 2,
    force: bool = False,
) -> bool:
    """Sync FastAPI app to server using supervisord.

    :return: True if full sync, False if source unchanged
    """
    instance = resolve_instance(target)
    ip = instance["ip"]
    user = user or instance.get("user", "deploy")

    if ssh_user is None:
        provider = instance.get("provider", "digitalocean")
        ssh_user = get_ssh_user(provider)
    
    if not is_valid_ip(target):
        add_app_to_instance(instance, app_name, "fastapi", port)
        save_instance(target, instance)
    
    source = str(Path(source).resolve())

    if not Path(source).exists():
        error(f"Source directory not found: {source}")

    if not (Path(source) / "pyproject.toml").exists():
        error(f"pyproject.toml not found in {source}")

    log(f"Deploying FastAPI to {ip}...")

    sudo = "" if ssh_user == "root" else "sudo "

    log("Installing uv and supervisor...")
    setup_script = dedent(f"""
        set -e
        {sudo}apt-get update
        {sudo}apt-get install -y supervisor curl

        {sudo}mkdir -p /home/{user}/{app_name}
        {sudo}mkdir -p /var/log/{app_name}
        {sudo}chown -R {user}:{user} /home/{user}/{app_name}
        {sudo}chown -R {user}:{user} /var/log/{app_name}

        {sudo}su - {user} -c "curl -LsSf https://astral.sh/uv/install.sh | sh"
    """).strip()
    ssh_script(ip, setup_script, user=ssh_user)

    python_exclude = [".venv", "__pycache__", ".git", "*.pyc"]
    local_hash = compute_hash(source, python_exclude)
    try:
        remote_hash = ssh(
            ip,
            f"cat /home/{user}/{app_name}/.source_hash 2>/dev/null || echo ''",
            user=ssh_user,
        ).strip()
    except Exception:
        remote_hash = ""

    if not force and local_hash == remote_hash and remote_hash:
        log("Source unchanged, restarting app...")
        ssh_script(ip, f"{sudo}supervisorctl restart {app_name}", user=ssh_user)
        log("App restarted")
        return False

    log("Uploading...")
    exclude = [".venv", "__pycache__", ".git", "*.pyc", ".source_hash"]
    rsync(source, ip, f"/home/{user}/{app_name}", exclude=exclude, user=ssh_user)

    log("Setting up Python environment...")
    venv_script = dedent(f"""
        set -e
        {sudo}chown -R {user}:{user} /home/{user}/{app_name}

        FROZEN=""
        if [ -f "/home/{user}/{app_name}/uv.lock" ]; then
            FROZEN="--frozen"
        fi

        {sudo}su - {user} -c "cd /home/{user}/{app_name} && ~/.local/bin/uv sync $FROZEN"
    """).strip()
    ssh_script(ip, venv_script, user=ssh_user)

    log("Configuring supervisord...")
    supervisor_config = dedent(f"""
        [program:{app_name}]
        directory=/home/{user}/{app_name}
        command=/home/{user}/{app_name}/.venv/bin/uvicorn {app_module} --host 0.0.0.0 --port {port} --workers {workers}
        user={user}
        autostart=true
        autorestart=true
        stopasgroup=true
        killasgroup=true
        stderr_logfile=/var/log/{app_name}/error.log
        stdout_logfile=/var/log/{app_name}/access.log
        environment=PATH="/home/{user}/{app_name}/.venv/bin:/home/{user}/.local/bin"
    """).strip()
    ssh_write_file(ip, f"/etc/supervisor/conf.d/{app_name}.conf", supervisor_config, user=ssh_user)

    if ssh_user == "root":
        hash_write_cmd = f'echo "{local_hash}" > /home/{user}/{app_name}/.source_hash'
    else:
        hash_write_cmd = f'echo "{local_hash}" | {sudo}tee /home/{user}/{app_name}/.source_hash > /dev/null'

    ssh_script(
        ip,
        f'{hash_write_cmd} && '
        f"{sudo}chown {user}:{user} /home/{user}/{app_name}/.source_hash && "
        f"{sudo}supervisorctl reread && {sudo}supervisorctl update && {sudo}supervisorctl restart {app_name}",
        user=ssh_user,
    )
    log("FastAPI app deployed!")
    return True


@fastapi_app.command(name="restart")
def restart_supervisor(
    target: str, *, app_name: str | None = None, ssh_user: str | None = None
):
    instance = resolve_instance(target)
    ip = instance["ip"]

    if ssh_user is None:
        provider = instance.get("provider", "digitalocean")
        ssh_user = get_ssh_user(provider)

    apps = [app for app in get_instance_apps(instance) if app["type"] == "fastapi"]

    if app_name is None:
        if len(apps) == 1:
            app_name = apps[0]["name"]
        elif len(apps) > 1:
            app_names = ", ".join(app["name"] for app in apps)
            error(f"Multiple FastAPI apps found: {app_names}. Use --app-name to specify.")
        else:
            app_name = target if not target.replace(".", "").isdigit() else "fastapi"

    sudo = "" if ssh_user == "root" else "sudo "
    log(f"Restarting {app_name}...")
    ssh(ip, f"{sudo}supervisorctl restart {app_name}", user=ssh_user)
    log("App restarted")


@fastapi_app.command(name="status")
def show_supervisor_status(target: str, *, ssh_user: str | None = None):
    instance = resolve_instance(target)
    ip = instance["ip"]

    if ssh_user is None:
        provider = instance.get("provider", "digitalocean")
        ssh_user = get_ssh_user(provider)

    sudo = "" if ssh_user == "root" else "sudo "
    print(ssh(ip, f"{sudo}supervisorctl status", user=ssh_user))


@fastapi_app.command(name="logs")
def show_supervisor_logs(
    target: str, *, app_name: str | None = None, ssh_user: str | None = None, lines: int = 50
):
    instance = resolve_instance(target)
    ip = instance["ip"]

    if ssh_user is None:
        provider = instance.get("provider", "digitalocean")
        ssh_user = get_ssh_user(provider)

    apps = [app for app in get_instance_apps(instance) if app["type"] == "fastapi"]

    if app_name is None:
        if len(apps) == 1:
            app_name = apps[0]["name"]
        elif len(apps) > 1:
            app_names = ", ".join(app["name"] for app in apps)
            error(f"Multiple FastAPI apps found: {app_names}. Use --app-name to specify.")
        else:
            app_name = target if not target.replace(".", "").isdigit() else "fastapi"
    log(f"Last {lines} lines of {app_name} logs:")
    print(
        ssh(
            ip,
            f"tail -n {lines} /var/log/{app_name}/access.log /var/log/{app_name}/error.log 2>/dev/null || echo 'No logs found'",
            user=ssh_user,
        )
    )


@fastapi_app.command(name="deploy")
def deploy_fastapi(
    name: str,
    source: str,
    *,
    domain: str | None = None,
    email: str | None = None,
    user: str = "deploy",
    ssh_user: str | None = None,
    port: int = 8000,
    app_name: str = "fastapi",
    app_module: str = "app:app",
    workers: int = 2,
    static_subdir: str | None = None,
    provider_name: ProviderName | None = None,
    region: str | None = None,
    vm_size: str | None = None,
    os_image: str | None = None,
    swap_size: str = "4G",
    no_ssl: bool = False,
):
    """Deploy FastAPI app: create instance, setup server, deploy app, configure nginx."""
    if not no_ssl and (not domain or not email):
        error("--domain and --email are required unless --no-ssl is set")

    instance_file = Path(f"{name}.instance.json")

    if not instance_file.exists():
        create_instance(
            name,
            provider_name=provider_name,
            region=region,
            vm_size=vm_size,
            os_image=os_image,
            user=user,
            swap_size=swap_size,
        )

    data = load_instance(name)

    if "user" not in data or data["user"] != user:
        data["user"] = user

    add_app_to_instance(data, app_name, "fastapi", port)
    save_instance(name, data)

    ip = data["ip"]

    if ssh_user is None:
        instance_provider = data.get("provider", "digitalocean")
        ssh_user = get_ssh_user(instance_provider)

    log(f"Deploying {name} to {ip}")
    print("=" * 50)

    full_sync = sync_fastapi(
        name,
        source,
        ssh_user=ssh_user,
        port=port,
        app_name=app_name,
        app_module=app_module,
        workers=workers,
    )

    ensure_web_firewall(ip, ssh_user=ssh_user)
    if not no_ssl:
        ensure_dns_matches(domain, ip, provider=data["provider"])

    static_dir = f"/home/{user}/{app_name}/{static_subdir}" if static_subdir else None
    if no_ssl:
        setup_nginx_ip(name, port=port, static_dir=static_dir, ssh_user=ssh_user)
    else:
        setup_nginx_ssl(
            name,
            domain,
            email,
            port=port,
            static_dir=static_dir,
            ssh_user=ssh_user,
            provider=data["provider"],
        )

    log("Verifying deployment...")
    verify_script = f"curl -sI http://localhost:{port} | head -1"
    result = ssh(ip, verify_script, user=ssh_user)
    if "200" not in result:
        warn(f"App health check returned: {result.strip()}")

    print("=" * 50)
    if no_ssl:
        log(f"Done! http://{ip}")
    else:
        log(f"Done! https://{domain}")


if __name__ == "__main__":
    app()
