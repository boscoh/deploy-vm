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

from pathlib import Path
from typing import Literal

import cyclopts
from rich import print

from .apps import NuxtApp, FastAPIApp
from .providers import get_provider, ProviderName
from .server import (
    log,
    warn,
    error,
    ssh,
    ssh_script,
    resolve_ip,
    resolve_instance,
    load_instance,
    save_instance,
    get_instance_apps,
    add_app_to_instance,
    wait_for_ssh,
    verify_http,
    setup_server,
    ensure_web_firewall,
    ensure_dns_matches,
    generate_nginx_server_block,
    get_ssh_user,
    resolve_dns_a,
    check_http_status,
    ssh_write_file,
)
from .utils import get_sudo_prefix

app = cyclopts.App(
    name="deploy-vm", help="Deploy apps to cloud providers", sort_key=None
)

instance_app = cyclopts.App(name="instance", help="Manage cloud instances", sort_key=1)
nginx_app = cyclopts.App(name="nginx", help="Configure nginx reverse proxy", sort_key=2)
nuxt_app = cyclopts.App(name="nuxt", help="Deploy and manage Nuxt apps", sort_key=3)
fastapi_app = cyclopts.App(
    name="fastapi", help="Deploy and manage FastAPI apps", sort_key=4
)

app.command(instance_app)
app.command(nginx_app)
app.command(nuxt_app)
app.command(fastapi_app)


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
    import json

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
    import time

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


@nginx_app.command(name="ip")
def setup_nginx_ip(
    target: str,
    *,
    port: int = 3000,
    static_dir: str | None = None,
    ssh_user: str = "root",
):
    """Setup nginx for IP-only access (no SSL)."""
    from textwrap import dedent

    ip = resolve_ip(target)

    ensure_web_firewall(ip, ssh_user=ssh_user)

    server_block = generate_nginx_server_block("_", port, static_dir, listen="80 default_server")

    sudo = get_sudo_prefix(ssh_user)
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
    import time
    from textwrap import dedent

    ip = resolve_ip(target)

    ensure_web_firewall(ip, ssh_user=ssh_user)
    if not skip_dns:
        ensure_dns_matches(domain, ip, provider_name=provider_name)

    server_block = generate_nginx_server_block(f"{domain} www.{domain}", port, static_dir)

    sudo = get_sudo_prefix(ssh_user)
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
    from .server import DNS_VERIFY_RETRIES, DNS_VERIFY_DELAY
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
    provider = instance.get("provider", "digitalocean")

    if not Path(target).exists() or not target.endswith(".json"):
        add_app_to_instance(instance, app_name, "nuxt", port)
        save_instance(target, instance)

    nuxt = NuxtApp(instance, provider, user=user, app_name=app_name, port=port, node_version=node_version)
    nuxt.sync(source, local_build=local_build, force=force)


@nuxt_app.command(name="restart")
def restart_pm2(target: str, *, user: str | None = None, ssh_user: str = "root", app_name: str | None = None):
    instance = resolve_instance(target)
    user = user or instance.get("user", "deploy")
    provider = instance.get("provider", "digitalocean")

    apps = [app for app in get_instance_apps(instance) if app["type"] == "nuxt"]

    if app_name is None:
        if len(apps) == 1:
            app_name = apps[0]["name"]
        elif len(apps) > 1:
            app_names = ", ".join(app["name"] for app in apps)
            error(f"Multiple Nuxt apps found: {app_names}. Use --app-name to specify.")
        else:
            app_name = target if not target.replace(".", "").isdigit() else "nuxt"

    nuxt = NuxtApp(instance, provider, user=user, app_name=app_name)
    nuxt.restart()


@nuxt_app.command(name="status")
def show_pm2_status(target: str, *, user: str | None = None, ssh_user: str = "root"):
    instance = resolve_instance(target)
    user = user or instance.get("user", "deploy")
    provider = instance.get("provider", "digitalocean")

    nuxt = NuxtApp(instance, provider, user=user)
    print(nuxt.status())


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
    user = user or instance.get("user", "deploy")
    provider = instance.get("provider", "digitalocean")

    apps = [app for app in get_instance_apps(instance) if app["type"] == "nuxt"]

    if app_name is None:
        if len(apps) == 1:
            app_name = apps[0]["name"]
        elif len(apps) > 1:
            app_names = ", ".join(app["name"] for app in apps)
            error(f"Multiple Nuxt apps found: {app_names}. Use --app-name to specify.")
        else:
            app_name = target if not target.replace(".", "").isdigit() else "nuxt"

    nuxt = NuxtApp(instance, provider, user=user, app_name=app_name)
    print(nuxt.logs(lines))


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
        ensure_dns_matches(domain, ip, provider_name=data["provider"])

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
            provider_name=data["provider"],
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
    user = user or instance.get("user", "deploy")
    provider = instance.get("provider", "digitalocean")

    if ssh_user is None:
        ssh_user = get_ssh_user(provider)

    if not Path(target).exists() or not target.endswith(".json"):
        add_app_to_instance(instance, app_name, "fastapi", port)
        save_instance(target, instance)

    fastapi = FastAPIApp(
        instance, provider, user=user, app_name=app_name, port=port, app_module=app_module, workers=workers
    )
    return fastapi.sync(source, force=force)


@fastapi_app.command(name="restart")
def restart_supervisor(
    target: str, *, app_name: str | None = None, ssh_user: str | None = None
):
    instance = resolve_instance(target)
    provider = instance.get("provider", "digitalocean")

    if ssh_user is None:
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

    user = instance.get("user", "deploy")
    fastapi = FastAPIApp(instance, provider, user=user, app_name=app_name)
    fastapi.restart()


@fastapi_app.command(name="status")
def show_supervisor_status(target: str, *, ssh_user: str | None = None):
    instance = resolve_instance(target)
    provider = instance.get("provider", "digitalocean")

    if ssh_user is None:
        ssh_user = get_ssh_user(provider)

    user = instance.get("user", "deploy")
    fastapi = FastAPIApp(instance, provider, user=user)
    print(fastapi.status())


@fastapi_app.command(name="logs")
def show_supervisor_logs(
    target: str, *, app_name: str | None = None, ssh_user: str | None = None, lines: int = 50
):
    instance = resolve_instance(target)
    provider = instance.get("provider", "digitalocean")

    if ssh_user is None:
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

    user = instance.get("user", "deploy")
    fastapi = FastAPIApp(instance, provider, user=user, app_name=app_name)
    print(fastapi.logs(lines))


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
        ensure_dns_matches(domain, ip, provider_name=data["provider"])

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
            provider_name=data["provider"],
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
