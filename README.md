# VM Deployment Tool

Python CLI for deploying web applications to cloud providers (currently DigitalOcean).

## Installation

```bash
uv sync
```

## Quick Start

This guide walks you through three main tasks: creating a cloud instance, deploying a FastAPI application, and deploying a Nuxt application.

### Task 1: Create a Cloud Instance

Create a new cloud instance on DigitalOcean:

```bash
uv run deploy-vm instance create my-server
```

Instance details saved to `my-server.instance.json`. You can now SSH to the instance with passwordless SSH:

```bash
ssh root@<ip>
ssh deploy@<ip>
```

### Task 2: Deploy a FastAPI Application

Deploy a FastAPI application with nginx as a reverse proxy in front of it:

```bash
# IP-only access (no SSL)
uv run deploy-vm fastapi deploy my-server /path/to/app --no-ssl

# With SSL certificate
uv run deploy-vm fastapi deploy my-server /path/to/app \
    --domain example.com --email you@example.com
```

Configures nginx as reverse proxy to FastAPI (port 8000), managed by supervisord. SSL uses certbot (requires DigitalOcean nameservers).

### Task 3: Deploy a Nuxt Application

Deploy a Nuxt application with SSL:

```bash
uv run deploy-vm nuxt deploy my-server example.com /path/to/nuxt you@example.com
```

Builds Nuxt app and configures nginx with SSL. Managed by PM2. Nginx serves static files from `.output/public/` and proxies API requests. SSL uses certbot (requires DigitalOcean nameservers).

## Commands

```
uv run deploy-vm --help
```

- `uv run deploy-vm instance`
  - `create` - Create a new cloud instance
    - Regions: syd1, sgp1, nyc1, sfo3, lon1, fra1
    - VM sizes: s-1vcpu-512mb* (nyc1, fra1, sfo3, sgp1, ams3 only), s-1vcpu-1gb, s-1vcpu-2gb, s-2vcpu-2gb, s-4vcpu-8gb
    - OS: ubuntu-24-04-x64, ubuntu-22-04-x64
  - `delete` - Delete an instance (use `--force` to skip confirmation)
  - `list` - List all instances
  - `verify` - Verify server health (SSH, firewall, nginx, DNS)
    - Use `--domain` to check DNS and HTTPS
- `uv run deploy-vm nginx`
  - `ip` - Setup nginx for IP-only access
  - `ssl` - Setup nginx with SSL certificate
    - Configures DigitalOcean DNS (A records for @ and www), verifies DNS propagation (retries up to 5 minutes), issues Let's Encrypt certificate
    - Use `--skip-dns` if managing DNS elsewhere
    - For Nuxt, nginx serves static files from `.output/public/` by default (use `--nuxt-static-dir` to customize)
- `uv run deploy-vm nuxt`
  - `deploy` - Full deploy: create instance, setup, deploy, nginx
    - Options: `--port` (default: 3000), `--local-build` (default: true), `--node-version` (default: 20)
    - App name defaults to instance name
  - `sync` - Sync Nuxt app to existing server
    - Smart rebuild detection: computes source checksum and skips rebuild if unchanged
    - Use `--local-build=false` to build on server
  - `restart` - Restart Nuxt app via PM2
  - `status` - Check PM2 process status
  - `logs` - View PM2 logs
- `uv run deploy-vm fastapi`
  - `deploy` - Full deploy: create instance, setup, deploy, nginx
    - Options: `--app-module` (default: app:app), `--app-name` (default: fastapi), `--port` (default: 8000), `--workers` (default: 2)
    - App name defaults to instance name
  - `sync` - Sync FastAPI app to existing server
    - Smart rebuild detection: computes source checksum and skips rebuild if unchanged
  - `restart` - Restart FastAPI app via supervisor
  - `status` - Check supervisor process status
  - `logs` - View supervisor logs

## Requirements

### Local Tools

| Tool   | Purpose                  | Install                                             |
|--------|--------------------------|-----------------------------------------------------|
| uv     | Python package manager   | `curl -LsSf https://astral.sh/uv/install.sh \| sh`  |
| doctl  | DigitalOcean CLI         | `brew install doctl`                                |
| rsync  | File sync to server      | `brew install rsync`                                |
| ssh    | Remote command execution | Pre-installed on macOS/Linux                        |
| npm    | Nuxt local builds        | `brew install node`                                 |

### Setup

1. Authenticate doctl: `doctl auth init`
2. SSH key in `~/.ssh/` (id_ed25519, id_rsa, or id_ecdsa)
3. SSH key uploaded to DigitalOcean (auto-uploaded on first deploy)

### Domain Setup

Configure your domain registrar to use DigitalOcean's nameservers:

```
ns1.digitalocean.com
ns2.digitalocean.com
ns3.digitalocean.com
```

Nameserver changes can take up to 48 hours to propagate.

## Instance State

Instance details are stored in `<name>.instance.json`:

```json
{
  "id": 543540359,
  "ip": "170.64.235.136",
  "provider": "digitalocean",
  "region": "syd1",
  "os_image": "ubuntu-24-04-x64",
  "vm_size": "s-1vcpu-1gb",
  "user": "deploy"
}
```

