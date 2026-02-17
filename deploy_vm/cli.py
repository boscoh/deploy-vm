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

import cyclopts
from rich import print

from .apps import FastAPIApp, NuxtApp
from .providers import ProviderName, get_provider
from .server import (
    add_app_to_instance,
    check_instance_reachable,
    ensure_dns_matches,
    ensure_web_firewall,
    get_instance_apps,
    is_valid_ip,
    load_instance,
    resolve_instance,
    resolve_ip,
    save_instance,
    setup_nginx_ip,
    setup_nginx_ssl,
    setup_server,
    ssh,
    verify_instance,
    wait_for_ssh,
)
from .utils import error, get_ssh_user, log, resolve_app_name, warn

app = cyclopts.App(
    name="deploy-vm", help="Deploy apps to cloud providers", sort_key=None
)

instance_app = cyclopts.App(name="instance", help="Manage cloud instances", sort_key=1)
nginx_app = cyclopts.App(name="nginx", help="Configure nginx reverse proxy", sort_key=2)
nuxt_app = cyclopts.App(name="nuxt", help="Deploy and manage Nuxt apps", sort_key=3)
fastapi_app = cyclopts.App(
    name="fastapi", help="Deploy and manage FastAPI apps", sort_key=4
)
dns_app = cyclopts.App(name="dns", help="Manage DNS records", sort_key=5)

app.command(instance_app)
app.command(nginx_app)
app.command(nuxt_app)
app.command(fastapi_app)
app.command(dns_app)


@instance_app.command(name="create")
def create_instance(
    name: str,
    *,
    provider: ProviderName | None = None,
    region: str | None = None,
    vm_size: str | None = None,
    os_image: str | None = None,
    user: str = "deploy",
    swap_size: str = "4G",
    no_setup: bool = False,
    iam_role: str | None = None,
):
    """Create cloud instance and set it up.

    :param provider: Cloud provider (default: DEPLOY_VM_PROVIDER or digitalocean)
    :param region: Cloud region
    :param vm_size: Instance size (AWS: t3.micro, t3.small, etc. | DO: s-1vcpu-1gb, s-2vcpu-2gb, etc.)
    :param os_image: OS image to use
    :param user: App user for running services
    :param no_setup: Skip firewall, swap, and user setup
    :param iam_role: AWS only: IAM role name for instance profile (default: deploy-vm-bedrock)
    """
    p = get_provider(provider, region=region, os_image=os_image, vm_size=vm_size)

    # Default IAM role for AWS instances (for Bedrock access)
    if p.provider_name == "aws" and iam_role is None:
        iam_role = "deploy-vm-bedrock"

    log(
        f"Creating instance '{name}' on '{p.provider_name}' in '{p.region}' ('{p.vm_size}')..."
    )
    result = p.create_instance(name, p.region, p.vm_size, iam_role=iam_role)

    instance_data = {
        "id": result["id"],
        "ip": result["ip"],
        "provider": p.provider_name,
        "region": p.region,
        "os_image": result.get("os_image", p.os_image),
        "vm_size": p.vm_size,
        "user": user,
    }
    if iam_role:
        instance_data["iam_role"] = iam_role

    save_instance(name, instance_data)

    log("Instance ready!")
    print(f"  IP: {result['ip']}")

    ssh_user = get_ssh_user(p.provider_name)
    print(f"  SSH: ssh {ssh_user}@{result['ip']}")

    if not no_setup:
        wait_for_ssh(result["ip"], user=ssh_user)
        setup_server(result["ip"], user=user, ssh_user=ssh_user, swap_size=swap_size)


@instance_app.command(name="delete")
def delete_instance(
    name: str, *, provider: ProviderName | None = None, force: bool = False
):
    """Delete instance."""
    import json

    instance_file = Path(f"{name}.instance.json")
    p = get_provider(provider)

    if instance_file.exists():
        data = json.loads(instance_file.read_text())
        provider = data.get("provider", provider)
        p = get_provider(provider)
    else:
        log(f"No '{name}.instance.json' found, looking up from '{p.provider_name}'...")
        p.validate_auth()
        lookup = p.get_instance_by_name(name)
        if not lookup:
            error(f"Instance '{name}' not found in '{p.provider_name}'")
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
    provider: ProviderName | None = None,
    region: str | None = None,
):
    p = get_provider(provider, region=region)

    if p.provider_name == "aws":
        log(f"Listing instances in '{p.region}'...")
    instances = p.list_instances()

    if not instances:
        log(f"No instances found in '{p.region}'")
        return

    max_name = max(len(i["name"]) for i in instances)
    max_ip = max(len(i["ip"]) for i in instances)
    max_region = max(len(i["region"]) for i in instances)

    name_header = "NAME".ljust(max_name)
    ip_header = "IP ADDRESS".ljust(max_ip)
    region_header = "REGION".ljust(max_region)
    print(f"  {name_header}  {ip_header}  {region_header}  STATUS")
    print(f"  {'-' * max_name}  {'-' * max_ip}  {'-' * max_region}  {'---'}")

    for i in instances:
        name = i["name"].ljust(max_name)
        ip = i["ip"].ljust(max_ip)
        region = i["region"].ljust(max_region)
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
        port_info = f" (port {app.get('port', '?')})" if app.get("port") else ""
        print(f"  - {app['name']}: {app['type']}{port_info}")


@instance_app.command(name="cleanup")
def cleanup_resources(
    *,
    provider: ProviderName | None = None,
    region: str | None = None,
    dry_run: bool = True,
):
    """Cleanup orphaned security groups not attached to running instances.

    :param provider: Cloud provider
    :param region: AWS region (default: ap-southeast-2)
    :param dry_run: Show what would be deleted without deleting (default: true)
    """
    p = get_provider(provider, region=region)
    p.cleanup_resources(dry_run=dry_run)


@instance_app.command(name="verify")
def verify_command(
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
    verify_instance(name, domain=domain, ssh_user=ssh_user)


@nginx_app.command(name="ip")
def nginx_ip_command(
    target: str,
    *,
    port: int = 3000,
    static_dir: str | None = None,
    ssh_user: str = "deploy",
):
    """Setup nginx for IP-only access (no SSL)."""
    ip = resolve_ip(target)
    setup_nginx_ip(ip, port=port, static_dir=static_dir, ssh_user=ssh_user)


@nginx_app.command(name="ssl")
def nginx_ssl_command(
    target: str,
    domain: str,
    email: str,
    *,
    port: int = 3000,
    static_dir: str | None = None,
    skip_dns: bool = False,
    ssh_user: str = "deploy",
    provider: ProviderName = "digitalocean",
):
    """Setup nginx and SSL certificate."""
    ip = resolve_ip(target)
    setup_nginx_ssl(
        ip,
        domain,
        email,
        port=port,
        static_dir=static_dir,
        skip_dns=skip_dns,
        ssh_user=ssh_user,
        provider_name=provider,
    )


@nuxt_app.command(name="sync")
def sync_nuxt(
    target: str,
    source: str,
    *,
    user: str | None = None,
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
    # Check if instance file exists (unless target is an IP address)
    if not is_valid_ip(target):
        instance_file = Path(f"{target}.instance.json") if not target.endswith(".json") else Path(target)
        if not instance_file.exists():
            error(f"Instance file not found: {instance_file}\nCreate an instance first with: deploy-vm instance create {target}")

    instance = resolve_instance(target)
    user = user or instance.get("user", "deploy")
    provider = instance.get("provider", "digitalocean")
    ip = instance.get("ip")

    ssh_user = get_ssh_user(provider)

    # Check if instance is reachable
    if not check_instance_reachable(ip, ssh_user):
        error(f"Instance '{ip}' is not reachable via SSH. Please verify the instance is running and SSH access is configured.")

    # Update instance metadata with app info if needed
    if "apps" not in instance or not any(a["name"] == app_name for a in instance.get("apps", [])):
        add_app_to_instance(instance, app_name, "nuxt", port)
        save_instance(target, instance)

    nuxt = NuxtApp(
        instance,
        provider,
        user=user,
        app_name=app_name,
        port=port,
        node_version=node_version,
    )
    nuxt.sync(source, local_build=local_build, force=force)


@nuxt_app.command(name="restart")
def restart_pm2(
    target: str,
    *,
    user: str | None = None,
    app_name: str | None = None,
):
    instance = resolve_instance(target)
    user = user or instance.get("user", "deploy")
    provider = instance.get("provider", "digitalocean")

    apps = [app for app in get_instance_apps(instance) if app["type"] == "nuxt"]

    fallback = target if not target.replace(".", "").isdigit() else "nuxt"
    app_name = resolve_app_name(apps, "Nuxt", app_name, fallback)

    nuxt = NuxtApp(instance, provider, user=user, app_name=app_name)
    nuxt.restart()


@nuxt_app.command(name="status")
def show_pm2_status(target: str, *, user: str | None = None):
    instance = resolve_instance(target)
    user = user or instance.get("user", "deploy")
    provider = instance.get("provider", "digitalocean")

    nuxt = NuxtApp(instance, provider, user=user)
    print(nuxt.status())


@nuxt_app.command(name="logs")
def show_pm2_logs(
    target: str,
    *,
    user: str | None = None,
    lines: int = 50,
    app_name: str | None = None,
):
    """View PM2 logs.

    :param target: Server IP address or instance name (loads from <name>.instance.json)
    :param user: App user (reads from instance.json if not specified)
    :param lines: Number of lines to show
    :param app_name: PM2 app name (required if multiple apps exist on instance)
    """
    instance = resolve_instance(target)
    user = user or instance.get("user", "deploy")
    provider = instance.get("provider", "digitalocean")

    apps = [app for app in get_instance_apps(instance) if app["type"] == "nuxt"]

    fallback = target if not target.replace(".", "").isdigit() else "nuxt"
    app_name = resolve_app_name(apps, "Nuxt", app_name, fallback)

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
    ssh_user: str = "deploy",
    port: int = 3000,
    app_name: str = "nuxt",
    provider: ProviderName = "digitalocean",
    region: str = "syd1",
    vm_size: str = "s-1vcpu-1gb",
    os_image: str = "ubuntu-24-04-x64",
    swap_size: str = "4G",
    node_version: int = 20,
    local_build: bool = True,
    no_ssl: bool = False,
    iam_role: str | None = None,
):
    """Deploy Nuxt app: create instance, setup server, deploy app, configure nginx.

    :param vm_size: Instance size (AWS: t3.micro, t3.small, etc. | DO: s-1vcpu-1gb, s-2vcpu-2gb, etc.)
    :param os_image: OS image name/ID
    :param swap_size: Swap file size (default: 4G)
    :param no_ssl: Skip SSL/domain setup, use IP-only access
    :param iam_role: AWS only: IAM role name for instance profile (default: deploy-vm-bedrock)
    """
    if not no_ssl and (not domain or not email):
        error("--domain and --email are required unless --no-ssl is set")

    instance_file = Path(f"{name}.instance.json")

    if not instance_file.exists():
        # IAM role will be set to default in create_instance for AWS
        create_instance(
            name,
            provider=provider,
            region=region,
            vm_size=vm_size,
            os_image=os_image,
            user=user,
            swap_size=swap_size,
            iam_role=iam_role,
        )

    data = load_instance(name)

    if "user" not in data or data["user"] != user:
        data["user"] = user

    add_app_to_instance(data, app_name, "nuxt", port)
    save_instance(name, data)

    ip = data["ip"]

    log(f"Deploying '{name}' to '{ip}'")
    print("=" * 50)

    sync_nuxt(
        name,
        source,
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
        setup_nginx_ip(ip, port=port, static_dir=nuxt_static_dir, ssh_user=ssh_user)
    else:
        setup_nginx_ssl(
            ip,
            domain,
            email,
            port=port,
            static_dir=nuxt_static_dir,
            ssh_user=ssh_user,
            provider_name=data["provider"],
        )

    log("Verifying deployment...")
    verify_script = f"curl -s -o /dev/null -w '%{{http_code}}' http://localhost:{port}"
    result = ssh(ip, verify_script, user=ssh_user)
    if "200" not in result:
        warn(f"App health check returned HTTP status: {result.strip()}")

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
    command: str | None = None,
    force: bool = False,
) -> bool:
    """Sync FastAPI app to server using supervisord.

    :param target: Instance name or path to .instance.json file
    :param source: Local source directory path
    :param user: Remote user to run the app as (default: deploy)
    :param ssh_user: SSH user for remote connection (default: provider-specific)
    :param port: Port number for the app (default: 8000)
    :param app_name: Name of the app (default: fastapi)
    :param command: Full command to run (default: "uv run --no-sync uvicorn app:app --host 0.0.0.0 --port {port} --workers 2")
    :param force: Force rebuild even if source unchanged
    :return: True if full sync, False if source unchanged
    """
    # Check if instance file exists (unless target is an IP address)
    if not is_valid_ip(target):
        instance_file = Path(f"{target}.instance.json") if not target.endswith(".json") else Path(target)
        if not instance_file.exists():
            error(f"Instance file not found: {instance_file}\nCreate an instance first with: deploy-vm instance create {target}")

    instance = resolve_instance(target)
    user = user or instance.get("user", "deploy")
    provider = instance.get("provider", "digitalocean")
    ip = instance.get("ip")

    if ssh_user is None:
        ssh_user = get_ssh_user(provider)

    # Check if instance is reachable
    if not check_instance_reachable(ip, ssh_user):
        error(f"Instance '{ip}' is not reachable via SSH. Please verify the instance is running and SSH access is configured.")

    # Update instance metadata with app info if needed
    if "apps" not in instance or not any(a["name"] == app_name for a in instance.get("apps", [])):
        add_app_to_instance(instance, app_name, "fastapi", port)
        save_instance(target, instance)

    fastapi = FastAPIApp(
        instance,
        provider,
        user=user,
        app_name=app_name,
        port=port,
        command=command,
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

    fallback = target if not target.replace(".", "").isdigit() else "fastapi"
    app_name = resolve_app_name(apps, "FastAPI", app_name, fallback)

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
    target: str,
    *,
    app_name: str | None = None,
    ssh_user: str | None = None,
    lines: int = 50,
):
    instance = resolve_instance(target)
    provider = instance.get("provider", "digitalocean")

    if ssh_user is None:
        ssh_user = get_ssh_user(provider)

    apps = [app for app in get_instance_apps(instance) if app["type"] == "fastapi"]

    fallback = target if not target.replace(".", "").isdigit() else "fastapi"
    app_name = resolve_app_name(apps, "FastAPI", app_name, fallback)

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
    command: str | None = None,
    static_subdir: str | None = None,
    provider: ProviderName | None = None,
    region: str | None = None,
    vm_size: str | None = None,
    os_image: str | None = None,
    swap_size: str = "4G",
    no_ssl: bool = False,
    iam_role: str | None = None,
):
    """Deploy FastAPI app: create instance, setup server, deploy app, configure nginx.

    :param name: Instance name (will create {name}.instance.json)
    :param source: Local source directory path
    :param domain: Domain name for SSL setup (required unless --no-ssl)
    :param email: Email for Let's Encrypt SSL certificate (required unless --no-ssl)
    :param user: Remote user to run the app as (default: deploy)
    :param ssh_user: SSH user for remote connection (default: provider-specific)
    :param port: Port number for the app (default: 8000)
    :param app_name: Name of the app (default: fastapi)
    :param command: Full command to run (default: "uv run --no-sync uvicorn app:app --host 0.0.0.0 --port {port} --workers 2")
    :param static_subdir: Subdirectory for static files to serve directly via nginx
    :param provider: Cloud provider (aws or digitalocean, default: digitalocean)
    :param region: Cloud provider region
    :param vm_size: Instance size (AWS: t3.micro, t3.small, etc. | DO: s-1vcpu-1gb, s-2vcpu-2gb, etc.)
    :param os_image: OS image name/ID
    :param swap_size: Swap file size (default: 4G)
    :param no_ssl: Skip SSL/domain setup, use IP-only access
    :param iam_role: AWS only: IAM role name for instance profile (default: deploy-vm-bedrock)
    """
    if not no_ssl and (not domain or not email):
        error("--domain and --email are required unless --no-ssl is set")

    instance_file = Path(f"{name}.instance.json")

    if not instance_file.exists():
        # IAM role will be set to default in create_instance for AWS
        create_instance(
            name,
            provider=provider,
            region=region,
            vm_size=vm_size,
            os_image=os_image,
            user=user,
            swap_size=swap_size,
            iam_role=iam_role,
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

    log(f"Deploying '{name}' to '{ip}'")
    print("=" * 50)

    sync_fastapi(
        name,
        source,
        ssh_user=ssh_user,
        port=port,
        app_name=app_name,
        command=command,
    )

    ensure_web_firewall(ip, ssh_user=ssh_user)
    if not no_ssl:
        ensure_dns_matches(domain, ip, provider_name=data["provider"])

    static_dir = f"/home/{user}/{app_name}/{static_subdir}" if static_subdir else None
    if no_ssl:
        setup_nginx_ip(ip, port=port, static_dir=static_dir, ssh_user=ssh_user)
    else:
        setup_nginx_ssl(
            ip,
            domain,
            email,
            port=port,
            static_dir=static_dir,
            ssh_user=ssh_user,
            provider_name=data["provider"],
        )

    log("Verifying deployment...")
    verify_script = f"curl -s -o /dev/null -w '%{{http_code}}' http://localhost:{port}"
    result = ssh(ip, verify_script, user=ssh_user)
    if "200" not in result:
        warn(f"App health check returned HTTP status: {result.strip()}")

    print("=" * 50)
    if no_ssl:
        log(f"Done! http://{ip}")
    else:
        log(f"Done! https://{domain}")


@dns_app.command(name="nameservers")
def get_nameservers(
    domain: str,
    *,
    provider: ProviderName | None = None,
):
    """Get nameservers for a domain (creates hosted zone if needed for AWS).

    For AWS: Creates a Route53 hosted zone if it doesn't exist, then returns nameservers.
    Caches result in <domain>.nameservers.json for faster subsequent lookups.
    For DigitalOcean: Returns standard DigitalOcean nameservers.

    :param domain: Domain name (e.g., example.com)
    :param provider: Cloud provider (aws or digitalocean)
    """
    import json
    from pathlib import Path

    p = get_provider(provider)

    if p.provider_name == "aws":
        import time

        ns_file = Path(f"{domain}.nameservers.json")

        # Check if we have cached nameservers
        if ns_file.exists():
            log(f"Loading nameservers from '{ns_file}'")
            data = json.loads(ns_file.read_text())
            zone_id = data["zone_id"]
            zone_name = data["zone_name"]
            nameservers = data["nameservers"]
        else:
            p.validate_auth()
            route53 = p._get_route53_client()

            response = route53.list_hosted_zones()
            zone_id = None
            zone_name = None

            for zone in response["HostedZones"]:
                if zone["Name"] == f"{domain}." or zone["Name"] == domain:
                    zone_id = zone["Id"]
                    zone_name = zone["Name"]
                    break

            if not zone_id:
                log(f"Creating Route53 hosted zone for '{domain}'...")
                create_response = route53.create_hosted_zone(
                    Name=domain,
                    CallerReference=str(int(time.time() * 1000)),
                )
                zone_id = create_response["HostedZone"]["Id"]
                zone_name = create_response["HostedZone"]["Name"]
                log(f"Created hosted zone: '{zone_id}'")

            zone_response = route53.get_hosted_zone(Id=zone_id)
            nameservers = zone_response["DelegationSet"]["NameServers"]

            # Save nameservers to file
            data = {
                "domain": domain,
                "provider": "aws",
                "zone_id": zone_id,
                "zone_name": zone_name,
                "nameservers": nameservers,
            }
            ns_file.write_text(json.dumps(data, indent=2))
            log(f"Saved nameservers to '{ns_file}'")

        print(f"Route53 Hosted Zone: {zone_name}")
        print(f"Zone ID: {zone_id}")
        print("\nNameservers:")
        for ns in nameservers:
            print(f"  {ns}")

        print("\nConfigure these nameservers at your domain registrar:")
        print("  1. Log in to your domain registrar (GoDaddy, Namecheap, etc.)")
        print(f"  2. Find DNS/Nameserver settings for {domain}")
        print("  3. Replace existing nameservers with the ones listed above")
        print("  4. Wait 24-48 hours for DNS propagation")

    elif p.provider_name == "digitalocean":
        print("DigitalOcean DNS Nameservers:")
        print("  ns1.digitalocean.com")
        print("  ns2.digitalocean.com")
        print("  ns3.digitalocean.com")
        print("\nConfigure these nameservers at your domain registrar:")
        print("  1. Log in to your domain registrar (GoDaddy, Namecheap, etc.)")
        print(f"  2. Find DNS/Nameserver settings for {domain}")
        print("  3. Replace existing nameservers with the ones listed above")
        print("  4. Wait 24-48 hours for DNS propagation")


if __name__ == "__main__":
    app()
