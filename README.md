# deployvm

Python CLI for deploying web applications to cloud providers (DigitalOcean and AWS).

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
```

**Auth setup:**
- AWS: `aws configure`
- DigitalOcean: `doctl auth init`

### 2. Deploy Your App

**Without SSL:**
```bash
uv run deployvm fastapi deploy my-server /path/to/app --no-ssl
```

**With domain + SSL:**
```bash
# 1. Get nameservers
uv run deployvm dns nameservers example.com --provider aws

# 2. Configure at registrar, wait 24-48h for propagation

# 3. Deploy with SSL
uv run deployvm fastapi deploy my-server /path/to/app \
    --domain example.com --email you@example.com
```

**Supported app types:**
- `fastapi deploy` - FastAPI apps with uvicorn + supervisord
- `nuxt deploy` - Nuxt apps with PM2

### 3. Manage Your Deployment

```bash
uv run deployvm instance verify my-server --domain example.com
uv run deployvm fastapi logs my-server
uv run deployvm fastapi restart my-server
uv run deployvm fastapi sync my-server /path/to/app
```

## Common Workflows

### Add SSL After Deployment

```bash
# 1. Deploy without SSL
uv run deployvm fastapi deploy my-server /path/to/app --no-ssl

# 2. Get nameservers and configure at registrar, wait 24-48h

# 3. Add SSL
uv run deployvm nginx ssl my-server example.com you@example.com --port 8000
```

### Multiple Apps on One Instance

```bash
uv run deployvm fastapi deploy my-server /path/to/api \
    --app-name api --port 8000 --domain api.example.com --email you@example.com

uv run deployvm nuxt deploy my-server /path/to/frontend \
    --app-name frontend --port 3000 --domain example.com --email you@example.com

uv run deployvm instance apps my-server
```

## Configuration

### Environment Variables

| Variable             | Description                              | Default        |
|----------------------|------------------------------------------|----------------|
| `DEPLOY_VM_PROVIDER` | Cloud provider (`aws` or `digitalocean`) | `digitalocean` |
| `AWS_PROFILE`        | AWS CLI profile name                     | None           |
| `AWS_REGION`         | Default AWS region                       | `ap-southeast-2` |

### Application Credentials

Your app's `.env` inside the app directory is automatically uploaded during `deploy` or `sync`.

When deploying to AWS EC2, `AWS_PROFILE`, `AWS_ACCESS_KEY_ID`, and `AWS_SECRET_ACCESS_KEY` are stripped (EC2 uses IAM roles), and `AWS_REGION` is preserved/added.

### Provider Settings

| Setting      | AWS                                         | DigitalOcean                                  |
|--------------|---------------------------------------------|-----------------------------------------------|
| **Regions**  | `us-east-1`, `us-west-2`, `ap-southeast-2` | `syd1`, `sgp1`, `nyc1`, `sfo3`, `lon1`       |
| **VM Sizes** | `t3.micro`, `t3.small`, `t3.medium`        | `s-1vcpu-1gb`, `s-2vcpu-2gb`, `s-4vcpu-8gb` |
| **DNS**      | Route53 (auto-created)                     | DigitalOcean nameservers required             |
| **Auth**     | `aws configure`                            | `doctl auth init`                             |

## AWS Bedrock Access

EC2 instances automatically get Bedrock access via IAM roles:

```bash
uv run deployvm fastapi deploy my-server /path/to/app --no-ssl
# or with custom role:
uv run deployvm fastapi deploy my-server /path/to/app --iam-role my-role --no-ssl
```

Your app code needs no credentials:
```python
import boto3
bedrock = boto3.client('bedrock-runtime', region_name=os.getenv('AWS_REGION'))
```

## Commands Reference

```
deployvm instance create|delete|list|verify|apps
deployvm dns nameservers
deployvm nginx ip|ssl
deployvm fastapi deploy|sync|restart|status|logs
deployvm nuxt deploy|sync|restart|status|logs
```

**Common options:**
- `--provider aws|digitalocean`
- `--region <region>`
- `--vm-size <size>`
- `--domain <domain>`
- `--no-ssl`
- `--app-name <name>`
- `--iam-role <name>` (AWS only)

## Requirements

| Tool                         | Purpose                    | Required | Install                     |
|------------------------------|----------------------------|----------|-----------------------------|
| `uv`                         | Python package manager     | Yes      | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| `ssh`, `rsync`, `tar`, `scp` | File transfer & remote ops | Yes      | Pre-installed (macOS/Linux) |
| `doctl`                      | DigitalOcean CLI           | Optional | `brew install doctl`        |
| `aws`                        | AWS CLI                    | Optional | `brew install awscli`       |
| `npm`                        | Nuxt local builds          | Optional | `brew install node`         |

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
    {"name": "api", "type": "fastapi", "port": 8000},
    {"name": "frontend", "type": "nuxt", "port": 3000}
  ]
}
```

## Support

- **Issues**: [GitHub Issues](https://github.com/boscoh/deployvm/issues)
- **Help**: `deployvm --help` or `deployvm <command> --help`
