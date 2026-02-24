"""Server operations: SSH, rsync, network validation, and server setup."""

import base64
import hashlib
import json
import re
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from textwrap import dedent
from typing import Literal

import dns.resolver
from fabric import Connection
from rich import print

from .providers import check_aws_auth, get_provider
from .utils import LogStream, error, log, warn

ProviderName = Literal["digitalocean", "aws", "vultr"]

SSH_TIMEOUT = 600
HTTP_VERIFY_RETRIES = 6
HTTP_VERIFY_DELAY = 5
DNS_VERIFY_RETRIES = 30
DNS_VERIFY_DELAY = 10


def check_instance_auth(instance: dict) -> None:
    """Validate cloud provider auth for instance, fail fast if credentials expired.

    :param instance: Instance data dictionary (must have 'provider' key)
    """
    provider = instance.get("provider")
    aws_profile = instance.get("aws_profile")
    p = get_provider(provider, aws_profile=aws_profile)
    p.validate_auth()


def check_instance_reachable(ip: str, ssh_user: str = "deploy", timeout: int = 10) -> bool:
    """Quick check if instance is reachable via SSH.

    :param ip: Instance IP address
    :param ssh_user: SSH user for connection
    :param timeout: Connection timeout in seconds
    :return: True if reachable, False otherwise
    """
    try:
        with Connection(
            ip, user=ssh_user, connect_kwargs={"look_for_keys": True, "timeout": timeout}
        ) as c:
            c.run("echo ping", hide=True, in_stream=False)
        return True
    except Exception:
        return False


def _run_ssh(ip: str, cmd: str, user: str, show_output: bool) -> str:
    """Single SSH attempt - open connection, run cmd, return stdout."""
    with Connection(ip, user=user, connect_kwargs={"look_for_keys": True}) as c:
        if show_output:
            stream = LogStream()
            result = c.run(cmd, hide=True, warn=True, in_stream=False,
                           out_stream=stream, err_stream=stream)
            stream.flush()
        else:
            result = c.run(cmd, hide=True, warn=True, in_stream=False)
        if result.failed:
            raise RuntimeError(result.stderr)
        return result.stdout


def _retry_ssh(ip: str, cmd: str, user: str, show_output: bool, fail_msg: str) -> str:
    """Run SSH command with up to 3 retries on transient connection resets."""
    from paramiko.ssh_exception import SSHException as ParamikoSSH

    for attempt in range(3):
        try:
            return _run_ssh(ip, cmd, user, show_output)
        except RuntimeError as e:
            error(fail_msg + str(e))
        except ParamikoSSH as e:
            if "Error reading SSH protocol banner" in str(e) and attempt < 2:
                time.sleep(5)
                continue
            error(f"SSH connection failed: {e}")
    error(f"SSH connection failed after retries")  # unreachable but satisfies type checker


def ssh(ip: str, cmd: str, user: str = "deploy", show_output: bool = False) -> str:
    return _retry_ssh(ip, cmd, user, show_output, "SSH command failed: ")


def ssh_script(ip: str, script: str, user: str = "deploy", show_output: bool = False) -> str:
    escaped = script.replace("'", "'\\''")
    return _retry_ssh(ip, f"bash -c '{escaped}'", user, show_output, "SSH script failed: ")


def ssh_as_user(ip: str, app_user: str, cmd: str, ssh_user: str = "deploy") -> str:
    return ssh(ip, f'su - {app_user} -c "{cmd}"', user=ssh_user)


def ssh_write_file(ip: str, path: str, content: str, user: str = "deploy"):
    encoded = base64.b64encode(content.encode()).decode()
    if user != "root" and (path.startswith("/etc/") or path.startswith("/var/")):
        ssh(
            ip, f"echo '{encoded}' | base64 -d | sudo tee {path} > /dev/null", user=user
        )
    else:
        ssh(ip, f"echo '{encoded}' | base64 -d > {path}", user=user)


def rsync(
    local: str, ip: str, remote: str, exclude: list[str] = None, user: str = "deploy"
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
        _rsync_tar_fallback(local, ip, remote, exclude, user)
    else:
        error(f"rsync failed: {result.stderr}")


def _rsync_tar_fallback(
    local: str, ip: str, remote: str, exclude: list[str], user: str
):
    import tempfile

    log("Creating tar archive...")
    exclude_args = []
    for ex in exclude or []:
        exclude_args.extend(["--exclude", ex.lstrip("/")])

    with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
        tar_cmd = (
            [
                "tar",
                "-czf",
                tmp.name,
                "-C",
                local,
            ]
            + exclude_args
            + ["."]
        )
        result = subprocess.run(tar_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            error(f"tar creation failed: {result.stderr}")
        tar_path = tmp.name

    try:
        log("Uploading tar archive...")
        remote_tar = f"/tmp/deploy_{int(time.time())}.tar.gz"

        scp_cmd = [
            "scp",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "Compression=yes",
            tar_path,
            f"{user}@{ip}:{remote_tar}",
        ]
        result = subprocess.run(scp_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            error(f"scp upload failed: {result.stderr}")

        log("Extracting on remote server...")
        app_user = remote.split("/")[2] if remote.startswith("/home/") else user
        extract_script = f"""
            set -e
            sudo mkdir -p {remote}
            sudo tar -xzf {remote_tar} -C {remote}
            sudo chown -R {app_user}:{app_user} {remote}
            sudo rm -f {remote_tar}
        """
        ssh_script(ip, extract_script, user=user)
        log("Transfer complete")
    finally:
        Path(tar_path).unlink(missing_ok=True)


def load_instance(name: str) -> dict:
    """Load instance data from JSON file and migrate legacy format.

    :param name: Instance name (JSON file prefix)
    :return: Instance data dictionary with apps list
    """
    path = Path(f"{name}.instance.json")
    if not path.exists():
        error(f"Instance file not found: '{path}'")
    data = json.loads(path.read_text())
    if "apps" not in data and "app_name" in data:
        app_data = {"name": data["app_name"], "type": data.get("app_type", "npm")}
        if "port" in data:
            app_data["port"] = data["port"]
        data["apps"] = [app_data]
        data.pop("app_name", None)
        data.pop("app_type", None)
        save_instance(name, data)
    # Migrate legacy app types
    changed = False
    for app in data.get("apps", []):
        if app.get("type") == "fastapi":
            app["type"] = "uv"
            changed = True
        elif app.get("type") == "nuxt":
            app["type"] = "npm"
            changed = True
    if changed:
        save_instance(name, data)
    return data


def save_instance(name: str, data: dict):
    """Save instance data to JSON file.

    :param name: Instance name (JSON file prefix)
    :param data: Instance data dictionary to save
    """
    Path(f"{name}.instance.json").write_text(json.dumps(data, indent=2))


def get_instance_apps(instance: dict) -> list[dict]:
    if "apps" in instance:
        return instance["apps"]
    if "app_name" in instance:
        return [
            {"name": instance["app_name"], "type": instance.get("app_type", "npm")}
        ]
    return []


def add_app_to_instance(
    instance: dict, app_name: str, app_type: str, port: int | None = None, **extra
):
    """Add or update app in instance with conflict detection.

    :param instance: Instance data dictionary to modify
    :param app_name: Application name
    :param app_type: App type (npm or uv)
    :param port: Port number (optional)
    :param extra: Additional fields to store on the app (source, command, domain, etc.)
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
            warn(f"App '{app_name}' type changing from '{old_type}' to '{app_type}'")

        if port is not None and port != old_port:
            conflicting_apps = [
                app
                for app in instance["apps"]
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
        existing_app.update({k: v for k, v in extra.items() if v is not None})

        log(f"Updated app '{app_name}' ('{old_type}' -> '{app_type}')")
    else:
        if port is not None:
            conflicting_apps = [
                app for app in instance["apps"] if app.get("port") == port
            ]
            if conflicting_apps:
                conflict_names = ", ".join(app["name"] for app in conflicting_apps)
                warn(f"Port {port} already in use by: {conflict_names}")

        app_data = {"name": app_name, "type": app_type}
        if port is not None:
            app_data["port"] = port
        app_data.update({k: v for k, v in extra.items() if v is not None})
        instance["apps"].append(app_data)
        log(f"Added app '{app_name}' ('{app_type}')")


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
            return (
                status_code,
                f"HTTP/{response.version} {status_code} {response.reason}",
            )
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


def wait_for_ssh(ip: str, user: str = "deploy", timeout: int = SSH_TIMEOUT):
    log(f"Waiting for SSH on '{ip}'...")
    start = time.time()
    ever_connected = False  # True once we see TCP response (not pure timeout)
    thread_exc_start = None  # When we first saw ThreadException(OSError)
    while time.time() - start < timeout:
        try:
            with Connection(
                ip, user=user, connect_kwargs={"look_for_keys": True, "timeout": 5}
            ) as c:
                c.run("echo ok", hide=True, in_stream=False)
                log("SSH ready")
                return
        except Exception as e:
            elapsed = int(time.time() - start)
            exc_name = type(e).__name__
            # NoValidConnectionsError = connection refused (port reachable, SSH not up)
            # AuthenticationException = SSH up but key rejected
            # TimeoutError / socket.timeout = no route or firewall block
            # ThreadException(OSError) = TCP connects but SSH banner fails (broken sshd)
            if exc_name not in ("TimeoutError", "socket.timeout"):
                ever_connected = True
            # After 60s if still only seeing timeouts, the IP is likely unreachable
            if elapsed > 60 and not ever_connected:
                error(
                    f"IP '{ip}' appears unreachable after {elapsed}s "
                    "(only connection timeouts, no TCP response). "
                    "Check firewall rules or try recreating the instance."
                )
            if exc_name == "ThreadException":
                inner_types = [x.type.__name__ for x in e.exceptions]
                inner_vals = [str(x.value)[:60] for x in e.exceptions]
                detail = f"inner: {', '.join(f'{t}: {v}' for t, v in zip(inner_types, inner_vals))}"
                # Track when we first started seeing ThreadException(OSError)
                if any(t == "OSError" for t in inner_types):
                    if thread_exc_start is None:
                        thread_exc_start = time.time()
                    elif time.time() - thread_exc_start > 120:
                        error(
                            f"SSH on '{ip}' appears broken after {elapsed}s "
                            "(TCP connects but SSH banner fails with OSError for >120s). "
                            "Try recreating the instance."
                        )
            else:
                detail = ""
                thread_exc_start = None  # Reset if we see a different error
            suffix = f" ({detail})" if detail else ""
            log(f"SSH not ready yet ({elapsed}s, {exc_name}){suffix}, retrying...")
        time.sleep(5)
    error(f"SSH timeout after '{timeout}s'")


def verify_http(ip: str, domain: str | None = None, port: int = 80) -> bool:
    # Use domain URL when available — nginx server_name won't match raw IP requests
    base = domain if domain else ip
    url = f"http://{base}/" if port == 80 else f"http://{base}:{port}/"
    log(f"Verifying HTTP connectivity on port {port} via '{url}'...")
    for i in range(HTTP_VERIFY_RETRIES):
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=5) as response:
                status_code = response.getcode()
                if str(status_code)[0] in "2345":
                    log("HTTP connectivity verified")
                    return True
        except (urllib.error.URLError, urllib.error.HTTPError, Exception):
            pass
        warn(f"Cannot connect to '{url}' ({i + 1}/{HTTP_VERIFY_RETRIES})")
        time.sleep(HTTP_VERIFY_DELAY)
    error(f"Cannot connect to '{url}' on port {port}. Check UFW: ssh deploy@'{ip}' 'sudo ufw status'")


def setup_firewall(ip: str, ssh_user: str = "root"):
    """Configure UFW firewall to allow OpenSSH access.

    :param ip: Server IP address
    :param ssh_user: SSH user for remote connection
    """
    script = dedent("""
        set -e
        echo "Configuring firewall..."
        sudo ufw allow OpenSSH
        sudo ufw --force enable
    """).strip()
    ssh_script(ip, script, user=ssh_user)


def setup_swap(ip: str, swap_size: str = "4G", ssh_user: str = "root"):
    """Create and enable swap file if not already present.

    :param ip: Server IP address
    :param swap_size: Swap file size (e.g., "4G")
    :param ssh_user: SSH user for remote connection
    """
    script = dedent(f"""
        set -e
        echo "Setting up swap..."
        if ! swapon --show | grep -q swapfile; then
            sudo fallocate -l {swap_size} /swapfile
            sudo chmod 600 /swapfile
            sudo mkswap /swapfile
            sudo swapon /swapfile
            echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
        fi
    """).strip()
    ssh_script(ip, script, user=ssh_user)


def create_user(ip: str, user: str = "deploy", ssh_user: str = "root"):
    """Create deploy user with sudo privileges and SSH key access.

    :param ip: Server IP address
    :param user: Username to create
    :param ssh_user: SSH user for remote connection
    """
    auth_keys_path = (
        "~/.ssh/authorized_keys"
        if ssh_user == "root"
        else f"/home/{ssh_user}/.ssh/authorized_keys"
    )

    script = dedent(f"""
        set -e
        if id "{user}" &>/dev/null; then
            echo "User {user} already exists"
        else
            sudo adduser --disabled-password --gecos "" {user}
            sudo usermod -aG sudo {user}
            echo "{user} ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/{user}
            sudo chmod 440 /etc/sudoers.d/{user}
            sudo mkdir -p /home/{user}/.ssh
            sudo cp {auth_keys_path} /home/{user}/.ssh/
            sudo chown -R {user}:{user} /home/{user}/.ssh
            sudo chmod 700 /home/{user}/.ssh
            sudo chmod 600 /home/{user}/.ssh/authorized_keys
            echo "User {user} created"
        fi
        # Allow nginx (www-data) to traverse the home directory for static file serving
        sudo chmod o+x /home/{user}
    """).strip()
    ssh_script(ip, script, user=ssh_user)


def setup_server(
    ip: str, *, user: str = "deploy", ssh_user: str = "root", swap_size: str = "4G"
):
    log(f"Setting up server at '{ip}'...")

    script = dedent("""
        set -e
        echo "Waiting for cloud-init..."
        sudo cloud-init status --wait > /dev/null 2>&1 || true

        echo "Installing packages..."
        sudo apt-get update
        sudo apt-get install -y curl wget git ufw
        echo "Done!"
    """).strip()
    print(ssh_script(ip, script, user=ssh_user))

    setup_firewall(ip, ssh_user=ssh_user)
    setup_swap(ip, swap_size=swap_size, ssh_user=ssh_user)

    log(f"Creating user: '{user}'")
    create_user(ip, user=user, ssh_user=ssh_user)
    log("Server setup complete")


def ensure_web_firewall(
    ip: str,
    ssh_user: str = "deploy",
    extra_port: int | None = None,
    provider=None,
):
    """Ensure firewall allows HTTP (80), HTTPS (443), and an optional extra port.

    Updates both the OS-level UFW firewall and, when a provider is given,
    the cloud-level firewall (AWS security group, Vultr firewall group).

    :param extra_port: Additional TCP port to open (e.g. custom outgoing_port)
    :param provider: Cloud provider instance for updating cloud-level firewall rules
    """
    log("Checking firewall...")
    result = ssh(ip, "sudo ufw status", user=ssh_user)
    needs_80 = "80/tcp" not in result
    needs_443 = "443/tcp" not in result
    needs_extra = (
        extra_port is not None
        and extra_port not in (80, 443)
        and f"{extra_port}/tcp" not in result
    )

    if needs_80 or needs_443 or needs_extra:
        log("Opening web ports in firewall...")
        cmds = []
        if needs_80:
            cmds.append("sudo ufw allow 80/tcp")
        if needs_443:
            cmds.append("sudo ufw allow 443/tcp")
        if needs_extra:
            cmds.append(f"sudo ufw allow {extra_port}/tcp")
        cmds.append("sudo ufw reload")
        ssh_script(ip, " && ".join(cmds), user=ssh_user)
        log("Firewall updated")
    else:
        log("Firewall OK")

    if provider is not None and extra_port is not None and extra_port not in (80, 443):
        provider.open_firewall_port(extra_port)


def ensure_dns_matches(
    domain: str,
    expected_ip: str,
    provider_name: ProviderName = "digitalocean",
    aws_profile: str | None = None,
) -> bool:
    from deployvm.providers import get_provider

    current_ip = resolve_dns_a(domain) or ""

    if current_ip == expected_ip:
        return False

    warn(
        f"DNS mismatch: '{domain}' points to '{current_ip or 'nothing'}', expected '{expected_ip}'"
    )
    profile_info = f" (profile: {aws_profile})" if aws_profile else ""
    log(f"Updating DNS via {provider_name}{profile_info}...")
    p = get_provider(provider_name, aws_profile=aws_profile)
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
    proxy_block = (
        dedent("""
        proxy_pass http://127.0.0.1:{port};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    """)
        .strip()
        .format(port=port)
    )

    if static_dir:
        location_block = dedent(f"""
            location / {{
                root {static_dir};
                try_files $uri @backend;
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


def setup_nginx_ip(
    ip: str,
    *,
    app_name: str = "default",
    port: int = 3000,
    outgoing_port: int = 80,
    static_dir: str | None = None,
    ssh_user: str = "deploy",
    provider=None,
):
    """Setup nginx for IP-only access (no SSL).

    :param app_name: App name used as nginx config filename (default: default)
    :param port: Internal application port to proxy to
    :param outgoing_port: External port nginx listens on (default: 80)
    :param provider: Cloud provider instance for updating cloud-level firewall rules
    """
    ensure_web_firewall(ip, ssh_user=ssh_user, extra_port=outgoing_port, provider=provider)

    # Use default_server only for the primary app on port 80
    listen_directive = f"{outgoing_port} default_server" if app_name == "default" else str(outgoing_port)
    server_block = generate_nginx_server_block(
        "_", port, static_dir, listen=listen_directive
    )

    log(f"Setting up nginx for IP access on '{ip}' port {outgoing_port} (app: {app_name})...")
    ssh_script(
        ip, "sudo apt-get update && sudo apt-get install -y nginx", user=ssh_user
    )
    ssh_write_file(
        ip, f"/etc/nginx/sites-available/{app_name}", server_block, user=ssh_user
    )
    ssh_script(
        ip,
        f"sudo ln -sf /etc/nginx/sites-available/{app_name} /etc/nginx/sites-enabled/{app_name} && sudo nginx -t && sudo systemctl reload nginx",
        user=ssh_user,
    )

    verify_http(ip, port=outgoing_port)
    port_suffix = f":{outgoing_port}" if outgoing_port != 80 else ""
    log(f"Nginx configured! 'http://{ip}{port_suffix}'")


def setup_nginx_ssl(
    ip: str,
    domain: str,
    email: str,
    *,
    port: int = 3000,
    outgoing_port: int = 443,
    static_dir: str | None = None,
    skip_dns: bool = False,
    staging: bool = False,
    ssh_user: str = "deploy",
    provider_name: ProviderName = "digitalocean",
    aws_profile: str | None = None,
    provider=None,
):
    """Setup nginx and SSL certificate.

    :param port: Internal application port to proxy to
    :param outgoing_port: External HTTPS port nginx listens on (default: 443).
        Certbot always validates via port 443; if a different port is given, nginx
        is configured to also listen on that port after the certificate is issued.
    :param provider: Cloud provider instance for updating cloud-level firewall rules
    """
    ensure_web_firewall(ip, ssh_user=ssh_user, extra_port=outgoing_port, provider=provider)
    if not skip_dns:
        ensure_dns_matches(domain, ip, provider_name=provider_name, aws_profile=aws_profile)

    # Remove default site so it doesn't conflict with domain-based config
    ssh_script(
        ip,
        "sudo rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true",
        user=ssh_user,
    )

    server_block = generate_nginx_server_block(
        f"{domain} www.{domain}", port, static_dir
    )

    profile_info = f" (profile: {aws_profile})" if aws_profile else ""
    log(f"Setting up nginx for '{domain}' via {provider_name}{profile_info}...")
    ssh_script(
        ip, "sudo apt-get update && sudo apt-get install -y nginx", user=ssh_user
    )
    ssh_write_file(
        ip, f"/etc/nginx/sites-available/{domain}", server_block, user=ssh_user
    )
    ssh_script(
        ip,
        f"sudo ln -sf /etc/nginx/sites-available/{domain} /etc/nginx/sites-enabled/ && "
        f"sudo nginx -t && sudo systemctl reload nginx",
        user=ssh_user,
    )

    log("Verifying DNS...")
    for i in range(DNS_VERIFY_RETRIES):
        resolved = resolve_dns_a(domain)
        if resolved == ip:
            log(f"DNS verified: '{domain}' -> '{ip}'")
            break
        warn(f"Waiting for DNS... ({i + 1}/{DNS_VERIFY_RETRIES})")
        time.sleep(DNS_VERIFY_DELAY)
    else:
        error("DNS verification timeout")

    verify_http(ip, domain=domain)

    log("Obtaining SSL certificate...")
    staging_flag = "--staging " if staging else ""
    ssl_script = dedent(f"""
        set -e
        sudo apt-get install -y certbot python3-certbot-nginx
        if [ -d "/etc/letsencrypt/live/{domain}" ]; then
            echo "Certificate exists, renewing if needed..."
            sudo certbot --nginx {staging_flag}-d {domain} -d www.{domain} \\
                --non-interactive --agree-tos --email {email} \\
                --redirect --keep-until-expiring
        else
            echo "Issuing new certificate..."
            sudo certbot --nginx {staging_flag}-d {domain} -d www.{domain} \\
                --non-interactive --agree-tos --email {email} --redirect
        fi
        sudo systemctl enable --now certbot.timer
    """).strip()
    ssh_script(ip, ssl_script, user=ssh_user)

    # Certbot always configures 443. If a custom port is requested, add an
    # additional listen directive to the SSL server block.
    if outgoing_port != 443:
        log(f"Adding listen directive for custom SSL port {outgoing_port}...")
        add_listen_script = dedent(f"""
            set -e
            CONFIG="/etc/nginx/sites-available/{domain}"
            # Insert 'listen <port> ssl;' after the existing 'listen 443 ssl;' line
            sudo sed -i '/listen 443 ssl;/a\\    listen {outgoing_port} ssl;' "$CONFIG"
            sudo nginx -t && sudo systemctl reload nginx
        """).strip()
        ssh_script(ip, add_listen_script, user=ssh_user)

    # Ensure direct IP access still works alongside the domain SSL config.
    # Certbot's HTTP block only matches the domain, so IP requests need a catch-all.
    # Remove any prior catch-all configs first to avoid duplicate server_name _ conflicts.
    ssh_script(
        ip,
        "for f in $(grep -rl 'server_name _' /etc/nginx/sites-enabled/ 2>/dev/null);"
        " do sudo rm -f \"$f\"; done",
        user=ssh_user,
    )
    ip_block = generate_nginx_server_block("_", port, static_dir, listen="80")
    ssh_write_file(ip, "/etc/nginx/sites-available/ip-access", ip_block, user=ssh_user)
    ssh_script(
        ip,
        "sudo ln -sf /etc/nginx/sites-available/ip-access /etc/nginx/sites-enabled/ip-access"
        " && sudo nginx -t && sudo systemctl reload nginx",
        user=ssh_user,
    )

    port_suffix = f":{outgoing_port}" if outgoing_port != 443 else ""
    log(f"SSL configured! http://{ip} and https://{domain}{port_suffix}")


def verify_instance(
    name: str,
    *,
    domain: str | None = None,
    ssh_user: str = "deploy",
):
    """Verify instance health: SSH, firewall, DNS, nginx, app.

    :param name: Instance name
    :param domain: Domain to check DNS for
    :param ssh_user: SSH user for connection
    """
    data = load_instance(name)
    ip = data["ip"]

    print(f"Verifying '{name}' ('{ip}')...")
    print("-" * 40)
    issues = []

    # SSH check
    try:
        uptime = ssh(ip, "uptime", user=ssh_user).strip()
        print(f"[OK] SSH: '{uptime}'")
    except Exception as e:
        print(f"[FAIL] SSH: {e}")
        issues.append("SSH connection failed")
        return

    ufw_status = ssh(ip, "sudo ufw status", user=ssh_user)
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

    nginx_status = ssh(
        ip, "systemctl is-active nginx 2>/dev/null || echo 'inactive'", user=ssh_user
    ).strip()
    if nginx_status == "active":
        print("[OK] Nginx: running")
    else:
        print(f"[FAIL] Nginx: '{nginx_status}'")
        issues.append("Nginx not running")

    if domain:
        dns_ip = resolve_dns_a(domain)
        if dns_ip == ip:
            print(f"[OK] DNS: '{domain}' -> '{ip}'")
        elif dns_ip:
            print(f"[FAIL] DNS: '{domain}' -> '{dns_ip}' (expected '{ip}')")
            issues.append(f"DNS mismatch: '{dns_ip}' != '{ip}'")
        else:
            print(f"[FAIL] DNS: '{domain}' -> no A record found")
            issues.append("DNS check failed")

    status_code, response_line = check_http_status(f"http://{ip}")
    if status_code and status_code in [200, 301, 302]:
        print("[OK] HTTP: responding")
    elif status_code:
        print(f"[WARN] HTTP: '{response_line}'")
    else:
        print(f"[FAIL] HTTP: '{response_line}'")
        issues.append("HTTP not responding")

    if domain:
        status_code, response_line = check_http_status(f"https://{domain}")
        if status_code == 200:
            print(f"[OK] HTTPS: '{domain}' responding")
        elif status_code:
            print(f"[WARN] HTTPS: '{response_line}'")
        else:
            print(f"[FAIL] HTTPS: '{response_line}'")
            issues.append("HTTPS not responding")

    print("-" * 40)
    if issues:
        print(f"Issues found ({len(issues)}):")
        for issue in issues:
            print(f"  - {issue}")
    else:
        print("All checks passed!")
