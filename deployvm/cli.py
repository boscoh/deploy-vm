#!/usr/bin/env python3
"""Deploy apps to cloud providers.

Prerequisites: doctl CLI authenticated, SSH key in DigitalOcean, domain nameservers configured.

Usage: uv run deployvm <noun> <verb> [options]

Examples:
    uv run deployvm instance create myapp
    uv run deployvm instance list
    uv run deployvm uv deploy myapp ./src "uv run uvicorn app:app --port 8000"
    uv run deployvm nginx ssl myapp example.com user@example.com
"""

from pathlib import Path

import cyclopts
from rich import print

from .apps import UVApp, NpmApp
from .providers import ProviderName, get_provider
from .server import (
    add_app_to_instance,
    check_instance_auth,
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
    name="deployvm", help="Deploy apps to cloud providers", sort_key=None
)

instance_app = cyclopts.App(name="instance", help="Manage cloud instances", sort_key=1)
npm_app = cyclopts.App(name="npm", help="Deploy and manage npm apps", sort_key=2)
uv_app = cyclopts.App(name="uv", help="Deploy and manage uv Python apps", sort_key=3)

app.command(instance_app)
app.command(npm_app)
app.command(uv_app)


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
    if p.provider_name == "aws":
        aws_profile = p.aws_config.get("profile_name")
        if aws_profile:
            instance_data["aws_profile"] = aws_profile

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
    """Delete cloud instance and local instance file.

    :param name: Instance name to delete
    :param provider: Cloud provider (default: digitalocean)
    :param force: Skip confirmation prompt
    """
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


@instance_app.command(name="update-ssh-ip")
def update_ssh_ip(name: str):
    """Update the AWS security group SSH rule to the current public IP.

    :param name: Instance name
    """
    from .providers import AWSProvider

    instance = load_instance(name)
    check_instance_auth(instance)

    if instance.get("provider") != "aws":
        error("update-ssh-ip is only supported for AWS instances")

    p = AWSProvider(aws_profile=instance.get("aws_profile"), region=instance.get("region"))
    p.update_ssh_ip()


@instance_app.command(name="list")
def list_instances(
    *,
    provider: ProviderName | None = None,
    region: str | None = None,
):
    """List all instances in the specified region.

    :param provider: Cloud provider (default: digitalocean)
    :param region: Cloud region (default: provider-specific)
    """
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


def _ensure_ssh_reachable(ip: str, ssh_user: str, instance: dict) -> None:
    """Check SSH reachability, auto-updating AWS security group IP if needed.

    :param ip: Instance IP address
    :param ssh_user: SSH user for connection
    :param instance: Instance data dictionary
    """
    if check_instance_reachable(ip, ssh_user):
        return
    if instance.get("provider") == "aws":
        log("SSH unreachable — updating AWS security group SSH rule to current IP...")
        from .providers import AWSProvider
        p = AWSProvider(aws_profile=instance.get("aws_profile"), region=instance.get("region"))
        p.update_ssh_ip()
        if check_instance_reachable(ip, ssh_user):
            return
    error(f"Instance '{ip}' is not reachable via SSH. Please verify the instance is running and SSH access is configured.")


def _select_nginx_app(instance: dict, port: int | None, app_name: str | None = None) -> tuple[int, dict]:
    """Select app entry from instance by app_name, port, or single-app fallback.

    :param instance: Instance data dictionary
    :param port: Explicit port to match against app entries (optional)
    :param app_name: Explicit app name to match (optional)
    :return: (resolved_port, app_data) where app_data is matched app dict or {}
    """
    apps = instance.get("apps") or []

    if not apps:
        return port or 3000, {}

    if app_name is not None:
        matched = next((a for a in apps if a.get("name") == app_name), None)
        if matched is None:
            app_list = ", ".join(a.get("name", "?") for a in apps)
            error(f"No app named '{app_name}'. Available: {app_list}")
        return matched.get("port") or port or 3000, matched

    if port is not None:
        matched = next((a for a in apps if a.get("port") == port), None)
        if matched is None:
            error(f"No app found with port {port}. Available ports: {[a.get('port') for a in apps]}")
        return port, matched

    if len(apps) == 1:
        app_data = apps[0]
        return app_data.get("port") or 3000, app_data

    app_list = ", ".join(
        f"{a.get('name', '?')} (port {a.get('port', '?')})" for a in apps
    )
    error(f"Multiple apps found: {app_list}. Use --app-name or --port to specify which app.")



@app.command(name="ssl", sort_key=4)
def nginx_ssl_command(
    target: str,
    domain: str,
    email: str,
    *,
    app_name: str | None = None,
    port: int | None = None,
    outgoing_port: int = 443,
    static_dir: str | None = None,
    skip_dns: bool = False,
    ssh_user: str = "deploy",
    provider: ProviderName | None = None,
):
    """Setup nginx with SSL certificate using Let's Encrypt.

    :param target: Instance name or IP address
    :param domain: Domain name for SSL certificate
    :param email: Email for Let's Encrypt registration
    :param app_name: App name to configure SSL for (required if multiple apps on instance)
    :param port: App port (alternative to --app-name; default: read from instance)
    :param outgoing_port: External HTTPS port nginx listens on (default: 443)
    :param static_dir: Static files directory to serve directly
    :param skip_dns: Skip DNS validation check
    :param ssh_user: SSH user for remote connection
    :param provider: Cloud provider for DNS validation (default: read from instance, fallback digitalocean)
    """
    instance = resolve_instance(target)
    ip = instance["ip"]
    resolved_port, app_data = _select_nginx_app(instance, port, app_name)

    # Read static_dir from app entry as fallback
    static_dir = static_dir or app_data.get("static_dir")

    # Persist static_dir into the app entry for named instances
    if static_dir and app_data and not is_valid_ip(target):
        app_data["static_dir"] = static_dir
        save_instance(target, instance)

    provider_name: ProviderName = provider or instance.get("provider", "digitalocean")
    aws_profile = instance.get("aws_profile") if provider_name == "aws" else None
    p = get_provider(provider_name, aws_profile=aws_profile)

    if not skip_dns:
        # Create DNS zone + A records, then print nameservers as a reminder
        log(f"Setting up DNS zone for '{domain}' -> '{ip}'...")
        p.setup_dns(domain, ip)
        nameservers = p.get_nameservers(domain)
        log(f"Nameservers for '{domain}' (set these at your registrar if not already done):")
        for ns in nameservers:
            print(f"  {ns}")

    setup_nginx_ssl(
        ip,
        domain,
        email,
        port=resolved_port,
        outgoing_port=outgoing_port,
        static_dir=static_dir,
        skip_dns=True,  # DNS already handled above
        ssh_user=ssh_user,
        provider_name=provider_name,
        aws_profile=aws_profile,
        provider=p,
    )


@npm_app.command(name="sync")
def sync_npm(
    target: str,
    source: str,
    *,
    app_name: str | None = None,
    local_build: bool = True,
    force: bool = False,
    node_version: int = 20,
    start_script: str = ".output/server/index.mjs",
    build_command: str = "npm run build",
    dist_dir: str = ".output",
):
    """Sync npm app to existing server.

    Deploys the npm application to an already-running instance by syncing files,
    building the app, and restarting PM2. Does not create instances or configure nginx.

    :param target: Instance name or IP address
    :param source: Local source directory path
    :param app_name: App name (required if multiple apps exist on instance)
    :param local_build: Build locally instead of on server
    :param force: Force rebuild even if source unchanged
    :param node_version: Node.js version to use (default: 20)
    :param start_script: Script or file PM2 runs (default: .output/server/index.mjs)
    :param build_command: Build command to run (default: npm run build)
    :param dist_dir: Build output directory excluded from upload (default: .output)
    """
    # Check if instance file exists (unless target is an IP address)
    if not is_valid_ip(target):
        instance_file = Path(f"{target}.instance.json") if not target.endswith(".json") else Path(target)
        if not instance_file.exists():
            error(f"Instance file not found: {instance_file}\nCreate an instance first with: deploy-vm instance create {target}")

    instance = resolve_instance(target)
    check_instance_auth(instance)
    user = instance.get("user", "deploy")
    provider = instance.get("provider", "digitalocean")
    ip = instance.get("ip")

    ssh_user = get_ssh_user(provider)

    _ensure_ssh_reachable(ip, ssh_user, instance)

    apps = [a for a in get_instance_apps(instance) if a["type"] == "npm"]
    fallback = target if not is_valid_ip(target) else "npm"
    app_name = resolve_app_name(apps, "npm", app_name, fallback)
    app_data = next((a for a in apps if a["name"] == app_name), {})
    port = app_data.get("port", 3000)

    npm_inst = NpmApp(
        instance,
        provider,
        user=user,
        app_name=app_name,
        port=port,
        node_version=node_version,
        start_script=start_script,
        build_command=build_command,
        dist_dir=dist_dir,
    )
    npm_inst.sync(source, local_build=local_build, force=force)


@npm_app.command(name="restart")
def restart_pm2(
    target: str,
    *,
    user: str | None = None,
    app_name: str | None = None,
):
    """Restart npm app using PM2.

    :param target: Instance name or IP address
    :param user: App user (reads from instance.json if not specified)
    :param app_name: PM2 app name (required if multiple apps exist on instance)
    """
    instance = resolve_instance(target)
    user = user or instance.get("user", "deploy")
    provider = instance.get("provider", "digitalocean")

    apps = [app for app in get_instance_apps(instance) if app["type"] == "npm"]

    fallback = target if not target.replace(".", "").isdigit() else "npm"
    app_name = resolve_app_name(apps, "npm", app_name, fallback)

    npm_inst = NpmApp(instance, provider, user=user, app_name=app_name)
    npm_inst.restart()


@npm_app.command(name="status")
def show_pm2_status(target: str, *, user: str | None = None):
    """Show PM2 status for npm apps.

    :param target: Instance name or IP address
    :param user: App user (reads from instance.json if not specified)
    """
    instance = resolve_instance(target)
    user = user or instance.get("user", "deploy")
    provider = instance.get("provider", "digitalocean")

    npm_inst = NpmApp(instance, provider, user=user)
    print(npm_inst.status())


@npm_app.command(name="logs")
def show_pm2_logs(
    target: str,
    *,
    user: str | None = None,
    lines: int = 50,
    app_name: str | None = None,
):
    """View PM2 logs for npm apps.

    :param target: Server IP address or instance name (loads from <name>.instance.json)
    :param user: App user (reads from instance.json if not specified)
    :param lines: Number of lines to show
    :param app_name: PM2 app name (required if multiple apps exist on instance)
    """
    instance = resolve_instance(target)
    user = user or instance.get("user", "deploy")
    provider = instance.get("provider", "digitalocean")

    apps = [app for app in get_instance_apps(instance) if app["type"] == "npm"]

    fallback = target if not target.replace(".", "").isdigit() else "npm"
    app_name = resolve_app_name(apps, "npm", app_name, fallback)

    npm_inst = NpmApp(instance, provider, user=user, app_name=app_name)
    print(npm_inst.logs(lines))


@npm_app.command(name="deploy")
def deploy_npm(
    name: str,
    source: str,
    *,
    domain: str | None = None,
    email: str | None = None,
    user: str = "deploy",
    port: int = 3000,
    outgoing_port: int | None = None,
    app_name: str = "npm",
    provider: ProviderName = "digitalocean",
    region: str = "syd1",
    vm_size: str = "s-1vcpu-1gb",
    os_image: str = "ubuntu-24-04-x64",
    swap_size: str = "4G",
    node_version: int = 20,
    local_build: bool = True,
    iam_role: str | None = None,
    start_script: str = ".output/server/index.mjs",
    build_command: str = "npm run build",
    dist_dir: str = ".output",
    static_subdir: str | None = None,
):
    """Deploy npm app with full infrastructure setup.

    Creates a new cloud instance (if needed), sets up the server, deploys the app,
    and configures nginx. Omit --domain to deploy with IP-only access (no SSL).

    :param name: Instance name (will create {name}.instance.json)
    :param source: Local source directory path
    :param domain: Domain name for SSL setup (omit for IP-only access)
    :param email: Email for Let's Encrypt SSL certificate (required with --domain)
    :param user: Remote user to run the app as (default: deploy)
    :param port: Application port (default: 3000)
    :param outgoing_port: External port nginx listens on (default: 80 without SSL, 443 with SSL)
    :param app_name: Name of the app (default: npm)
    :param provider: Cloud provider (aws or digitalocean, default: digitalocean)
    :param region: Cloud provider region (default: syd1)
    :param vm_size: Instance size (AWS: t3.micro, t3.small, etc. | DO: s-1vcpu-1gb, s-2vcpu-2gb, etc.)
    :param os_image: OS image name/ID (default: ubuntu-24-04-x64)
    :param swap_size: Swap file size (default: 4G)
    :param node_version: Node.js version to use (default: 20)
    :param local_build: Build locally instead of on server
    :param iam_role: AWS only: IAM role name for instance profile (default: deploy-vm-bedrock)
    :param start_script: Script or file PM2 runs, or "npm run <cmd>" (default: .output/server/index.mjs)
    :param build_command: Build command to run (default: npm run build)
    :param dist_dir: Build output directory excluded from upload (default: .output)
    :param static_subdir: Path within app dir for nginx to serve static files directly.
        Defaults to {dist_dir}/public (Nuxt). Use {dist_dir}/client for SvelteKit/Remix,
        or {dist_dir} for a plain Vite app. Pass empty string to disable static serving.
    """
    no_ssl = not domain

    if domain and not email:
        error("--email is required when --domain is set")

    resolved_outgoing_port = outgoing_port if outgoing_port is not None else (80 if no_ssl else 443)

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
    check_instance_auth(data)

    ip = data["ip"]
    provider_name = data.get("provider", "digitalocean")
    npm_ssh_user = get_ssh_user(provider_name)

    _ensure_ssh_reachable(ip, npm_ssh_user, data)

    if "user" not in data or data["user"] != user:
        data["user"] = user

    add_app_to_instance(data, app_name, "npm", port,
        source=source, domain=domain, node_version=node_version, local_build=local_build,
        start_script=start_script, build_command=build_command, dist_dir=dist_dir,
        static_subdir=static_subdir, email=email, outgoing_port=resolved_outgoing_port)
    save_instance(name, data)

    log(f"Deploying '{name}' to '{ip}'")
    print("=" * 50)

    sync_npm(
        name,
        source,
        local_build=local_build,
        node_version=node_version,
        start_script=start_script,
        build_command=build_command,
        dist_dir=dist_dir,
    )

    aws_profile = data.get("aws_profile") if data.get("provider") == "aws" else None
    provider = get_provider(data["provider"], aws_profile=aws_profile)
    ensure_web_firewall(ip, ssh_user=npm_ssh_user, extra_port=resolved_outgoing_port, provider=provider)
    if not no_ssl:
        ensure_dns_matches(domain, ip, provider_name=data["provider"], aws_profile=aws_profile)

    _static_subdir = static_subdir if static_subdir is not None else f"{dist_dir}/public"
    npm_static_dir = f"/home/{user}/{app_name}/{_static_subdir}" if _static_subdir else None
    if no_ssl:
        setup_nginx_ip(ip, app_name=app_name, port=port, outgoing_port=resolved_outgoing_port, static_dir=npm_static_dir, ssh_user=npm_ssh_user, provider=provider)
    else:
        setup_nginx_ssl(
            ip,
            domain,
            email,
            port=port,
            outgoing_port=resolved_outgoing_port,
            static_dir=npm_static_dir,
            ssh_user=npm_ssh_user,
            provider_name=data["provider"],
            aws_profile=aws_profile,
            provider=provider,
        )

    log("Verifying deployment...")
    verify_script = f"curl -s -o /dev/null -w '%{{http_code}}' http://localhost:{port}"
    result = ssh(ip, verify_script, user=npm_ssh_user)
    if "200" not in result:
        warn(f"App health check returned HTTP status: {result.strip()}")

    print("=" * 50)
    port_suffix = f":{resolved_outgoing_port}" if (no_ssl and resolved_outgoing_port != 80) or (not no_ssl and resolved_outgoing_port != 443) else ""
    if no_ssl:
        log(f"Done! http://{ip}{port_suffix}")
    else:
        log(f"Done! https://{domain}{port_suffix}")


@uv_app.command(name="sync")
def sync_uv(
    target: str,
    source: str,
    command: str,
    *,
    app_name: str | None = None,
    force: bool = False,
) -> bool:
    """Sync uv app to existing server.

    Deploys the uv application to an already-running instance by syncing files,
    installing dependencies, and restarting supervisord. Does not create instances or configure nginx.

    :param target: Instance name or path to .instance.json file
    :param source: Local source directory path
    :param command: Command to run (must start with "uv", e.g., "uv run --no-sync uvicorn app:app --host 0.0.0.0 --port 8000 --workers 2")
    :param app_name: App name (required if multiple apps exist on instance)
    :param force: Force rebuild even if source unchanged
    :return: True if full sync, False if source unchanged
    """
    # Check if instance file exists (unless target is an IP address)
    if not is_valid_ip(target):
        instance_file = Path(f"{target}.instance.json") if not target.endswith(".json") else Path(target)
        if not instance_file.exists():
            error(f"Instance file not found: {instance_file}\nCreate an instance first with: deploy-vm instance create {target}")

    instance = resolve_instance(target)
    check_instance_auth(instance)
    user = instance.get("user", "deploy")
    provider = instance.get("provider", "digitalocean")
    ip = instance.get("ip")

    ssh_user = get_ssh_user(provider)

    _ensure_ssh_reachable(ip, ssh_user, instance)

    apps = [a for a in get_instance_apps(instance) if a["type"] == "uv"]
    fallback = target if not is_valid_ip(target) else "uv"
    app_name = resolve_app_name(apps, "uv", app_name, fallback)
    app_data = next((a for a in apps if a["name"] == app_name), {})
    port = app_data.get("port", 8000)

    uv_inst = UVApp(
        instance,
        provider,
        user=user,
        app_name=app_name,
        port=port,
        command=command,
    )
    return uv_inst.sync(source, force=force)


@uv_app.command(name="restart")
def restart_supervisor(
    target: str, *, app_name: str | None = None
):
    """Restart uv app using supervisord.

    :param target: Instance name or IP address
    :param app_name: App name (required if multiple apps exist on instance)
    """
    instance = resolve_instance(target)
    provider = instance.get("provider", "digitalocean")

    apps = [app for app in get_instance_apps(instance) if app["type"] == "uv"]

    fallback = target if not target.replace(".", "").isdigit() else "uv"
    app_name = resolve_app_name(apps, "uv", app_name, fallback)

    user = instance.get("user", "deploy")
    uv_inst = UVApp(instance, provider, user=user, app_name=app_name)
    uv_inst.restart()


@uv_app.command(name="status")
def show_supervisor_status(target: str):
    """Show supervisord status for uv apps.

    :param target: Instance name or IP address
    """
    instance = resolve_instance(target)
    provider = instance.get("provider", "digitalocean")

    user = instance.get("user", "deploy")
    uv_inst = UVApp(instance, provider, user=user)
    print(uv_inst.status())


@uv_app.command(name="logs")
def show_supervisor_logs(
    target: str,
    *,
    app_name: str | None = None,
    lines: int = 50,
):
    """View supervisord logs for uv apps.

    :param target: Instance name or IP address
    :param app_name: App name (required if multiple apps exist on instance)
    :param lines: Number of lines to show (default: 50)
    """
    instance = resolve_instance(target)
    provider = instance.get("provider", "digitalocean")

    apps = [app for app in get_instance_apps(instance) if app["type"] == "uv"]

    fallback = target if not target.replace(".", "").isdigit() else "uv"
    app_name = resolve_app_name(apps, "uv", app_name, fallback)

    user = instance.get("user", "deploy")
    uv_inst = UVApp(instance, provider, user=user, app_name=app_name)
    print(uv_inst.logs(lines))


@uv_app.command(name="deploy")
def deploy_uv(
    name: str,
    source: str,
    command: str,
    *,
    domain: str | None = None,
    email: str | None = None,
    user: str = "deploy",
    port: int = 8000,
    outgoing_port: int | None = None,
    app_name: str = "uv",
    static_subdir: str | None = None,
    provider: ProviderName | None = None,
    region: str | None = None,
    vm_size: str | None = None,
    os_image: str | None = None,
    swap_size: str = "4G",
    iam_role: str | None = None,
):
    """Deploy uv app with full infrastructure setup.

    Creates a new cloud instance (if needed), sets up the server, deploys the app,
    and configures nginx. Omit --domain to deploy with IP-only access (no SSL).

    :param name: Instance name (will create {name}.instance.json)
    :param source: Local source directory path
    :param command: Command to run (must start with "uv", e.g., "uv run --no-sync uvicorn app:app --host 0.0.0.0 --port 8000 --workers 2")
    :param domain: Domain name for SSL setup (omit for IP-only access)
    :param email: Email for Let's Encrypt SSL certificate (required with --domain)
    :param user: Remote user to run the app as (default: deploy)
    :param port: Port number for the app (default: 8000)
    :param outgoing_port: External port nginx listens on (default: 80 without SSL, 443 with SSL)
    :param app_name: Name of the app (default: uv)
    :param static_subdir: Subdirectory for static files to serve directly via nginx
    :param provider: Cloud provider (aws or digitalocean, default: digitalocean)
    :param region: Cloud provider region
    :param vm_size: Instance size (AWS: t3.micro, t3.small, etc. | DO: s-1vcpu-1gb, s-2vcpu-2gb, etc.)
    :param os_image: OS image name/ID
    :param swap_size: Swap file size (default: 4G)
    :param iam_role: AWS only: IAM role name for instance profile (default: deploy-vm-bedrock)
    """
    no_ssl = not domain

    if domain and not email:
        error("--email is required when --domain is set")

    resolved_outgoing_port = outgoing_port if outgoing_port is not None else (80 if no_ssl else 443)

    if port == resolved_outgoing_port:
        error(
            f"--port ({port}) and --outgoing-port ({resolved_outgoing_port}) must differ. "
            "nginx binds to 0.0.0.0:outgoing-port and proxies to 127.0.0.1:port — "
            "Linux does not allow both on the same port number. "
            f"Use a different internal port, e.g. --port {port + 1000} --outgoing-port {resolved_outgoing_port}."
        )

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
    check_instance_auth(data)

    ip = data["ip"]
    ssh_user = get_ssh_user(data.get("provider", "digitalocean"))

    wait_for_ssh(ip, user=ssh_user)

    if "user" not in data or data["user"] != user:
        data["user"] = user

    add_app_to_instance(data, app_name, "uv", port,
        source=source, command=command, domain=domain, static_subdir=static_subdir,
        email=email, outgoing_port=resolved_outgoing_port)
    save_instance(name, data)

    log(f"Deploying '{name}' to '{ip}'")
    print("=" * 50)

    sync_uv(
        name,
        source,
        command=command,
        app_name=app_name,
    )

    aws_profile = data.get("aws_profile") if data.get("provider") == "aws" else None
    provider = get_provider(data["provider"], aws_profile=aws_profile)
    ensure_web_firewall(ip, ssh_user=ssh_user, extra_port=resolved_outgoing_port, provider=provider)
    if not no_ssl:
        ensure_dns_matches(domain, ip, provider_name=data["provider"], aws_profile=aws_profile)

    static_dir = f"/home/{user}/{app_name}/{static_subdir}" if static_subdir else None
    if no_ssl:
        setup_nginx_ip(ip, app_name=app_name, port=port, outgoing_port=resolved_outgoing_port, static_dir=static_dir, ssh_user=ssh_user, provider=provider)
    else:
        setup_nginx_ssl(
            ip,
            domain,
            email,
            port=port,
            outgoing_port=resolved_outgoing_port,
            static_dir=static_dir,
            ssh_user=ssh_user,
            provider_name=data["provider"],
            aws_profile=aws_profile,
            provider=provider,
        )

    log("Verifying deployment...")
    verify_script = f"curl -s -o /dev/null -w '%{{http_code}}' http://localhost:{port}"
    result = ssh(ip, verify_script, user=ssh_user)
    if "200" not in result:
        warn(f"App health check returned HTTP status: {result.strip()}")

    print("=" * 50)
    port_suffix = f":{resolved_outgoing_port}" if (no_ssl and resolved_outgoing_port != 80) or (not no_ssl and resolved_outgoing_port != 443) else ""
    if no_ssl:
        log(f"Done! http://{ip}{port_suffix}")
    else:
        log(f"Done! https://{domain}{port_suffix}")


@app.command(name="nameservers", sort_key=5)
def get_nameservers(
    domain: str,
    *,
    provider: ProviderName | None = None,
):
    """Get nameservers to set at your domain registrar.

    For AWS: creates a Route53 hosted zone if it doesn't exist, then returns its nameservers.
    For DigitalOcean and Vultr: returns the standard nameservers.

    :param domain: Domain name (e.g., example.com)
    :param provider: Cloud provider (aws, digitalocean, or vultr)
    """
    p = get_provider(provider)
    nameservers = p.get_nameservers(domain)

    print(f"Nameservers for {domain} ({p.provider_name}):")
    for ns in nameservers:
        print(f"  {ns}")
    print(f"\nSet these at your domain registrar under DNS/Nameserver settings for '{domain}'.")




if __name__ == "__main__":
    app()
