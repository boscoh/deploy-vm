# deployvm

Python CLI for deploying web applications to cloud providers (DigitalOcean, AWS, and Vultr).

When setting up a VM it will:
- Create a cloud instance (DigitalOcean droplet, AWS EC2, or Vultr VPS)
- Configure firewall rules to open ports 80, 443, and SSH
- Create a `deploy` user with passwordless sudo
- Set up a swap file
- Upload your SSH key to the provider
- Install `uv`, `nginx`, `supervisord` (uv apps) or `pm2` (npm apps)
- Deploy your app and configure it to run as a service
- Set up nginx as a reverse proxy
- Optionally provision a Let's Encrypt SSL certificate via certbot

## Installation

```bash
uv tool install deployvm
```

## Quick Start

### 1. Configure Provider

Create `.env` in your project root:

```bash
# DigitalOcean (default)
DEPLOY_VM_PROVIDER=digitalocean

# AWS
DEPLOY_VM_PROVIDER=aws
AWS_PROFILE=default
AWS_REGION=ap-southeast-2

# Vultr
DEPLOY_VM_PROVIDER=vultr
VULTR_API_KEY=your-api-key
```

**Auth setup:**
- DigitalOcean: `doctl auth init`
- AWS: `aws configure`
- Vultr: set `VULTR_API_KEY` in your environment or `.env`

### 2. Deploy Your App

**Without SSL (IP-only):**
```bash
deployvm uv deploy my-server /path/to/app \
    "uv run uvicorn app:app --port 8000" \
    --port 8000
```

**With domain + SSL:**
```bash
# 1. Get nameservers and set them at your registrar
deployvm nameservers example.com

# 2. Deploy — handles DNS zone setup and waits for propagation automatically
deployvm uv deploy my-server \
    /path/to/app \
    "uv run uvicorn app:app --port 8000" \
    --port 8000 \
    --domain example.com \
    --email you@example.com
```

**Supported app types:**

- `uv deploy` — any Python app managed by `uv` + supervisord
  - Requires `pyproject.toml` and `uv` for dependency management
  - Command must be a `uv run ...` invocation (e.g. uvicorn, gunicorn, custom CLI)

- `npm deploy` — any npm app managed by PM2
  - Requires `package.json` with a `build` script
  - Node.js managed via `nvm` on the server
  - Builds locally by default (`--local-build`), uploads build output

### 3. Manage Your Deployment

```bash
deployvm instance verify my-server --domain example.com
deployvm uv logs my-server
deployvm uv restart my-server
deployvm uv sync my-server /path/to/app "uv run uvicorn app:app --port 8000"
```

## Common Workflows

### Add SSL After Deployment

```bash
# 1. Deploy without domain first
deployvm uv deploy my-server /path/to/app "uv run uvicorn app:app --port 8000" --port 8000

# 2. Check nameservers and set them at your registrar
deployvm nameservers example.com

# 3. Add SSL — creates DNS zone, sets A records, waits for propagation, runs certbot
deployvm ssl my-server example.com you@example.com

# For a specific app on a multi-app instance, use --app-name or --port
deployvm ssl my-server api.example.com you@example.com --app-name api
deployvm ssl my-server api.example.com you@example.com --port 8000
```

### Multiple Apps on One Instance

Each app on the same instance needs a unique `--app-name` and a unique `--outgoing-port`.

**With SSL (domain per app):**
```bash
# First app — creates the instance
deployvm uv deploy my-server /path/to/api \
    "uv run uvicorn app:app --port 8000" \
    --port 8000 --app-name api \
    --domain api.example.com --email you@example.com

# Second app — reuses the existing instance
deployvm uv deploy my-server /path/to/worker \
    "uv run worker --port 8001" \
    --port 8001 --app-name worker \
    --domain worker.example.com --email you@example.com

# Mix Python + npm on the same instance
deployvm npm deploy my-server /path/to/frontend \
    --app-name frontend --port 3000 \
    --domain example.com --email you@example.com
```

**Without SSL (IP + port):**
```bash
# First app on port 80 (default)
deployvm uv deploy my-server /path/to/api \
    "uv run uvicorn app:app --port 8000" \
    --port 8000 --app-name api

# Second app on port 8080 — internal port must differ from outgoing port
deployvm uv deploy my-server /path/to/app2 \
    "uv run myapp --port 9080" \
    --port 9080 --outgoing-port 8080 --app-name app2
```

**Port rules for `--no-ssl` apps:**

- `--port` — internal port the app listens on (`127.0.0.1` only)
- `--outgoing-port` — external port nginx listens on (default: `80`)
- These **must be different**: nginx cannot bind to the same port as the app
- Each app needs a unique `--outgoing-port`

## Configuration

### Environment Variables

| Variable             | Description                                        | Default          |
|----------------------|----------------------------------------------------|------------------|
| `DEPLOY_VM_PROVIDER` | Cloud provider (`aws`, `digitalocean`, or `vultr`) | `digitalocean`   |
| `AWS_PROFILE`        | AWS CLI profile name                               | None             |
| `AWS_REGION`         | Default AWS region                                 | `ap-southeast-2` |
| `VULTR_API_KEY`      | Vultr API key                                      | None             |

### Application Credentials

Your app's `.env` inside the app directory is automatically uploaded during `deploy` or `sync`.

When deploying to AWS EC2, `AWS_PROFILE`, `AWS_ACCESS_KEY_ID`, and `AWS_SECRET_ACCESS_KEY` are stripped (EC2 uses IAM roles), and `AWS_REGION` is preserved/added.

### Provider Settings

| Setting      | AWS                                          | DigitalOcean                                  | Vultr                                    |
|--------------|----------------------------------------------|-----------------------------------------------|------------------------------------------|
| **Regions**  | `us-east-1`, `us-west-2`, `ap-southeast-2`  | `syd1`, `sgp1`, `nyc1`, `sfo3`, `lon1`       | `syd`, `sgp`, `ewr`, `lax`, `lhr`       |
| **VM Sizes** | `t3.micro`, `t3.small`, `t3.medium`         | `s-1vcpu-1gb`, `s-2vcpu-2gb`, `s-4vcpu-8gb` | `vc2-1c-1gb`, `vc2-1c-2gb`, `vc2-2c-4gb` |
| **DNS**      | Route53 (auto-created)                      | `ns1-3.digitalocean.com`                      | `ns1.vultr.com`, `ns2.vultr.com`        |
| **Auth**     | `aws configure`                             | `doctl auth init`                             | `VULTR_API_KEY` env var                 |

## AWS Infrastructure Setup

When creating an EC2 instance, the script automatically handles all required AWS infrastructure:

**VPC**
- Checks for an existing VPC with subnets, an attached internet gateway, and a route table with a route to the internet gateway
- Creates a default VPC if none exists in the region

**Security group**
- Creates a `deploy-vm-web` security group (once per region) with:
  - SSH (port 22) restricted to your current public IP
  - HTTP (port 80) open to all
  - HTTPS (port 443) open to all
- Reuses the existing group on subsequent deploys
- `instance update-ssh-ip` updates the SSH rule if your IP changes

**SSH key pair**
- Uploads your local SSH public key (`~/.ssh/id_ed25519.pub` etc.) to EC2 if not already registered

**AMI**
- Finds the latest Ubuntu 22.04 LTS AMI from Canonical for your region

**IAM role and instance profile** (when Bedrock access is needed)
- Creates an IAM role with EC2 trust policy and `AmazonBedrockFullAccess` managed policy
- Creates an EC2 instance profile and attaches the role
- Waits for IAM propagation before launching the instance

**Route53 DNS**
- `nameservers` creates a hosted zone for your domain if one doesn't exist, then returns the nameservers to configure at your registrar
- `ssl` and `uv/npm deploy` create or upsert A records for `domain` and `www.domain` pointing to the instance IP

## AWS Bedrock Access

EC2 instances automatically get Bedrock access via IAM roles:

```bash
deployvm uv deploy my-server /path/to/app "uv run uvicorn app:app --port 8000" --port 8000
# or with custom role:
deployvm uv deploy my-server /path/to/app "uv run uvicorn app:app --port 8000" --port 8000 --iam-role my-role
```

Your app code needs no credentials:
```python
import boto3
bedrock = boto3.client('bedrock-runtime', region_name=os.getenv('AWS_REGION'))
```

## Commands Reference

```
deployvm instance create|delete|list|verify|update-ssh-ip|cleanup
deployvm uv deploy|sync|restart|status|logs
deployvm npm deploy|sync|restart|status|logs
deployvm nameservers <domain>
deployvm ssl <instance> <domain> <email>
```

**`ssl`** is idempotent and handles the full SSL setup sequence:
creates the DNS zone and A records, prints nameservers, waits for propagation, installs nginx, and runs certbot. Both IP and domain access work afterwards.

**Common options:**
- `--provider aws|digitalocean|vultr`
- `--region <region>`
- `--vm-size <size>`
- `--domain <domain>` (omit for IP-only access)
- `--email <email>` (required with `--domain`)
- `--app-name <name>`
- `--iam-role <name>` (AWS only)

## Requirements

| Tool                         | Purpose                    | Required | Install                     |
|------------------------------|----------------------------|----------|-----------------------------|
| `uv`                         | Python package manager     | Yes      | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| `ssh`, `rsync`, `tar`, `scp` | File transfer & remote ops | Yes      | Pre-installed (macOS/Linux) |
| `doctl`                      | DigitalOcean CLI           | Optional | `brew install doctl`        |
| `aws`                        | AWS CLI                    | Optional | `brew install awscli`       |
| `vultr-cli`                  | Vultr CLI                  | Optional | `brew install vultr-cli`    |
| `npm`                        | npm app local builds       | Optional | `brew install node`         |

### SSH Key

Automatically uploads `~/.ssh/id_ed25519.pub`, `id_rsa.pub`, or `id_ecdsa.pub` to the provider on first use.

### Instance State

Metadata stored in `<name>.instance.json`:

```json
{
  "id": "i-0abc123",
  "ip": "54.123.45.67",
  "provider": "aws",
  "region": "ap-southeast-2",
  "vm_size": "t3.small",
  "user": "deploy",
  "apps": [
    {"name": "api", "type": "uv", "port": 8000},
    {"name": "frontend", "type": "npm", "port": 3000}
  ]
}
```

## Running Integration Tests

Integration tests spin up a real cloud instance, run the full deployment lifecycle, then delete it.

```bash
# Run all integration tests (Vultr, Sydney region by default)
pytest tests/ -m integration --provider vultr -s -v

# Run a single test
pytest tests/test_integration.py::test_01_create -m integration -s
```

**Prerequisites:**
- `VULTR_API_KEY` set in environment or `.env`
- `vultr-cli` installed (`brew install vultr-cli`)
- SSH key at `~/.ssh/id_rsa` (no passphrase)

The fixture automatically retries up to 5 times if a newly created instance gets an unreachable IP — common with Vultr Sydney due to IP range variability.

## Support

- **Issues**: [GitHub Issues](https://github.com/boscoh/deployvm/issues)
- **Help**: `deployvm --help` or `deployvm <command> --help`
