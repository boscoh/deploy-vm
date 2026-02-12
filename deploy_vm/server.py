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

from .utils import error, log, warn

ProviderName = Literal["digitalocean", "aws"]

SSH_TIMEOUT = 120
HTTP_VERIFY_RETRIES = 6
HTTP_VERIFY_DELAY = 5
DNS_VERIFY_RETRIES = 30
DNS_VERIFY_DELAY = 10


def ssh(ip: str, cmd: str, user: str = "deploy") -> str:
    with Connection(ip, user=user, connect_kwargs={"look_for_keys": True}) as c:
        result = c.run(cmd, hide=True, warn=True)
        if result.failed:
            error(f"SSH command failed: {result.stderr}")
        return result.stdout


def ssh_script(ip: str, script: str, user: str = "deploy") -> str:
    with Connection(ip, user=user, connect_kwargs={"look_for_keys": True}) as c:
        escaped = script.replace("'", "'\\''")
        result = c.run(f"bash -c '{escaped}'", hide=True, warn=True)
        if result.failed:
            error(f"SSH script failed: {result.stderr}")
        return result.stdout


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
        app_data = {"name": data["app_name"], "type": data.get("app_type", "nuxt")}
        if "port" in data:
            app_data["port"] = data["port"]
        data["apps"] = [app_data]
        data.pop("app_name", None)
        data.pop("app_type", None)
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
            {"name": instance["app_name"], "type": instance.get("app_type", "nuxt")}
        ]
    return []


def add_app_to_instance(
    instance: dict, app_name: str, app_type: str, port: int | None = None
):
    """Add or update app in instance with conflict detection.

    :param instance: Instance data dictionary to modify
    :param app_name: Application name
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
    error(f"SSH timeout after '{timeout}s'")


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
        warn(f"Cannot connect to 'http://{ip}/' ({i + 1}/{HTTP_VERIFY_RETRIES})")
        time.sleep(HTTP_VERIFY_DELAY)
    error(f"Cannot connect to server on port 80. Check UFW: ssh deploy@'{ip}' 'sudo ufw status'")


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
        else "/home/ubuntu/.ssh/authorized_keys"
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


def ensure_web_firewall(ip: str, ssh_user: str = "deploy"):
    log("Checking firewall...")
    result = ssh(ip, "sudo ufw status", user=ssh_user)
    needs_80 = "80/tcp" not in result
    needs_443 = "443/tcp" not in result

    if needs_80 or needs_443:
        log("Opening web ports in firewall...")
        cmds = []
        if needs_80:
            cmds.append("sudo ufw allow 80/tcp")
        if needs_443:
            cmds.append("sudo ufw allow 443/tcp")
        cmds.append("sudo ufw reload")
        ssh_script(ip, " && ".join(cmds), user=ssh_user)
        log("Firewall updated")
    else:
        log("Firewall OK")


def ensure_dns_matches(
    domain: str, expected_ip: str, provider_name: ProviderName = "digitalocean"
) -> bool:
    from deploy_vm.providers import get_provider

    current_ip = resolve_dns_a(domain) or ""

    if current_ip == expected_ip:
        return False

    warn(
        f"DNS mismatch: '{domain}' points to '{current_ip or 'nothing'}', expected '{expected_ip}'"
    )
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


def setup_nginx_ip(
    ip: str,
    *,
    port: int = 3000,
    static_dir: str | None = None,
    ssh_user: str = "deploy",
):
    """Setup nginx for IP-only access (no SSL)."""
    ensure_web_firewall(ip, ssh_user=ssh_user)

    server_block = generate_nginx_server_block(
        "_", port, static_dir, listen="80 default_server"
    )

    log(f"Setting up nginx for IP access on '{ip}'...")
    ssh_script(
        ip, "sudo apt-get update && sudo apt-get install -y nginx", user=ssh_user
    )
    ssh_write_file(
        ip, "/etc/nginx/sites-available/default", server_block, user=ssh_user
    )
    ssh_script(
        ip,
        "sudo ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/ && sudo nginx -t && sudo systemctl reload nginx",
        user=ssh_user,
    )

    verify_http(ip)
    log(f"Nginx configured! 'http://{ip}'")


def setup_nginx_ssl(
    ip: str,
    domain: str,
    email: str,
    *,
    port: int = 3000,
    static_dir: str | None = None,
    skip_dns: bool = False,
    ssh_user: str = "deploy",
    provider_name: ProviderName = "digitalocean",
):
    """Setup nginx and SSL certificate."""
    ensure_web_firewall(ip, ssh_user=ssh_user)
    if not skip_dns:
        ensure_dns_matches(domain, ip, provider_name=provider_name)

    server_block = generate_nginx_server_block(
        f"{domain} www.{domain}", port, static_dir
    )

    log("Setting up nginx...")
    ssh_script(
        ip, "sudo apt-get update && sudo apt-get install -y nginx", user=ssh_user
    )
    ssh_write_file(
        ip, f"/etc/nginx/sites-available/{domain}", server_block, user=ssh_user
    )
    ssh_script(
        ip,
        f"sudo ln -sf /etc/nginx/sites-available/{domain} /etc/nginx/sites-enabled/ && "
        f"sudo rm -f /etc/nginx/sites-enabled/default && sudo nginx -t && sudo systemctl reload nginx",
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

    verify_http(ip)

    log("Obtaining SSL certificate...")
    ssl_script = dedent(f"""
        set -e
        sudo apt-get install -y certbot python3-certbot-nginx
        if [ -d "/etc/letsencrypt/live/{domain}" ]; then
            echo "Certificate exists, renewing if needed..."
            sudo certbot --nginx -d {domain} -d www.{domain} \\
                --non-interactive --agree-tos --email {email} \\
                --redirect --keep-until-expiring
        else
            echo "Issuing new certificate..."
            sudo certbot --nginx -d {domain} -d www.{domain} \\
                --non-interactive --agree-tos --email {email} --redirect
        fi
    """).strip()
    ssh_script(ip, ssl_script, user=ssh_user)
    log(f"SSL configured! 'https://{domain}'")


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
