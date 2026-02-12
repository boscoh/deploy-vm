# deploy-vm

Python CLI for deploying web applications to cloud providers (DigitalOcean and AWS).

## Installation

```bash
uv tool install deploy-vm
```

## Quick Start

### 1. Configure Provider (Optional)

Create `.env` in your project root:

```bash
# AWS (recommended for production)
# Includes full Bedrock access by default
DEPLOY_VM_PROVIDER=aws
AWS_PROFILE=default
AWS_REGION=ap-southeast-2
# IAM role with Bedrock access is enabled by default (deploy-vm-bedrock)

# Or use DigitalOcean
DEPLOY_VM_PROVIDER=digitalocean
```

**Setup requirements:**
- **AWS**: Run `aws configure` to set credentials ([AWS setup guide](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html))
- **DigitalOcean**: Run `doctl auth init` to authenticate

### 2. Deploy Your App

**With domain + SSL (recommended):**
```bash
# Get nameservers and configure at registrar first
uv run deploy-vm dns nameservers example.com --provider aws

# Deploy with SSL (creates instance, deploys app, configures SSL)
uv run deploy-vm fastapi deploy my-server /path/to/app \
    --domain example.com --email you@example.com
```

**Without SSL (test/staging):**
```bash
# Deploy to IP only
uv run deploy-vm fastapi deploy my-server /path/to/app --no-ssl

# Add SSL later when domain is ready
uv run deploy-vm nginx ssl my-server example.com you@example.com --port 8000
```

**Supported apps:**
- `fastapi deploy` - FastAPI apps with uvicorn + supervisord
- `nuxt deploy` - Nuxt apps with PM2

**AWS instances include:**
- ✅ Full Bedrock access via IAM role (AmazonBedrockFullAccess policy)
- ✅ Automatic IAM instance profile configuration
- ✅ Access to all Bedrock foundation models and runtime APIs

**FastAPI deployment requirements:**
- Uses `uv` for Python package management
- Expects `pyproject.toml` with project dependencies
- Runs via `uvicorn` with supervisord for process management
- App source must be a valid Python package

**AWS Bedrock and IAM roles:**

AWS instances automatically get an IAM role with Bedrock access enabled by default:
```bash
# Deploy with default Bedrock access (automatic)
uv run deploy-vm fastapi deploy my-server /path/to/app --no-ssl

# Or use a custom IAM role name:
uv run deploy-vm fastapi deploy my-server /path/to/app \
    --iam-role custom-role-name --no-ssl
```

The default IAM role (`deploy-vm-bedrock`):
- Creates IAM role with EC2 trust policy
- Attaches `AmazonBedrockFullAccess` managed policy
- Creates and attaches instance profile
- Enables Bedrock API access from your application
- Use `--iam-role <name>` to customize the role name

### 3. Manage Your Deployment

```bash
# Check status
uv run deploy-vm instance verify my-server --domain example.com

# View logs
uv run deploy-vm fastapi logs my-server

# Restart app
uv run deploy-vm fastapi restart my-server

# Redeploy code
uv run deploy-vm fastapi sync my-server /path/to/app
```

## Common Workflows

### Add SSL After Deployment

Deploy without SSL first, add it when ready:

```bash
# 1. Deploy
uv run deploy-vm fastapi deploy my-server /path/to/app --no-ssl

# 2. Get nameservers (creates hosted zone automatically)
uv run deploy-vm dns nameservers example.com --provider aws

# 3. Configure nameservers at registrar, wait 24-48h

# 4. Add SSL
uv run deploy-vm nginx ssl my-server example.com you@example.com --port 8000
```

**Note:** See [DOMAIN_SETUP.md](DOMAIN_SETUP.md) for detailed usage patterns and troubleshooting.

### Multiple Apps on One Instance

```bash
# Deploy first app
uv run deploy-vm fastapi deploy my-server /path/to/api \
    --app-name api --port 8000 --domain api.example.com --email you@example.com

# Deploy second app
uv run deploy-vm nuxt deploy my-server /path/to/frontend \
    --app-name frontend --port 3000 --domain example.com --email you@example.com

# List all apps
uv run deploy-vm instance apps my-server

# Manage specific app
uv run deploy-vm fastapi restart my-server --app-name api
```

## Configuration Reference

### Environment Variables

| Variable               | Description                              | Default          |
|------------------------|------------------------------------------|------------------|
| `DEPLOY_VM_PROVIDER`   | Cloud provider (`aws` or `digitalocean`) | `digitalocean`   |
| `AWS_PROFILE`          | AWS CLI profile name                     | None             |
| `AWS_REGION`           | Default AWS region                       | `ap-southeast-2` |

**Priority:** Command-line flags > `.env` file > Built-in defaults

### Application Credentials (.env)

Apps deployed with `deploy-vm` use a `.env` file in the app directory to store credentials and configuration:

- **Location**: `.env` in your app's root directory (e.g., `/path/to/app/.env`)
- **Purpose**: Stores API keys, secrets, and other credentials needed for your app to work
- **Deployment**: Automatically uploaded during `deploy` or `sync` operations

**AWS credential handling:**

When deploying to AWS EC2, there is special logic for AWS credentials:

- **`AWS_PROFILE`**: Automatically removed (EC2 instances use IAM roles instead)
- **`AWS_ACCESS_KEY_ID`** and **`AWS_SECRET_ACCESS_KEY`**: Automatically removed
- **`AWS_REGION`**: Preserved if present, or auto-added from your AWS profile configuration
  - Required for Bedrock and other AWS services
  - Automatically extracted from your local AWS profile when `AWS_PROFILE` is removed

**Example `.env` in your app directory:**
```bash
# API credentials
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-proj-...

# AWS region (automatically added if missing when deploying to AWS)
AWS_REGION=ap-southeast-2

# Other app config
DATABASE_URL=postgresql://...
SECRET_KEY=your-secret-key
```

**Note:** The filtered `.env` (without AWS credentials) is uploaded to your EC2 instance, ensuring secure credential management.

### Provider-Specific Settings

| Setting    | AWS                                          | DigitalOcean                                    |
|------------|----------------------------------------------|-------------------------------------------------|
| **Regions** | `us-east-1`, `us-west-2`, `ap-southeast-2`  | `syd1`, `sgp1`, `nyc1`, `sfo3`, `lon1`         |
| **VM Sizes** | `t3.micro`, `t3.small`, `t3.medium`         | `s-1vcpu-1gb`, `s-2vcpu-2gb`, `s-4vcpu-8gb`   |
| **DNS**     | Requires Route53 hosted zone                | Requires DigitalOcean nameservers              |
| **Auth**    | `aws configure` or `.env` file              | `doctl auth init`                              |
| **Bedrock** | ✅ Full access included by default          | ❌ Not available                                |

See [PROVIDER_COMPARISON.md](PROVIDER_COMPARISON.md) for complete details.

## Commands Reference

```bash
deploy-vm --help  # See all commands

# Core commands
deploy-vm instance create|delete|list|verify|apps
deploy-vm dns nameservers
deploy-vm nginx ip|ssl
deploy-vm fastapi deploy|sync|restart|status|logs
deploy-vm nuxt deploy|sync|restart|status|logs
```

**Key options:**
- `--provider aws|digitalocean` - Cloud provider
- `--region <region>` - Provider region
- `--vm-size <size>` - Instance size
- `--domain <domain>` - Domain for SSL
- `--no-ssl` - Skip SSL configuration
- `--app-name <name>` - App identifier (for multiple apps)
- `--iam-role <name>` - AWS only: Custom IAM role name (default: deploy-vm-bedrock with Bedrock access)

See full command documentation: `deploy-vm <command> --help`

## Domain Setup

See [DOMAIN_SETUP.md](DOMAIN_SETUP.md) for complete domain and SSL configuration guide including prerequisites, troubleshooting, and technical reference.

**Quick reference:**
- **AWS Route53**: `uv run deploy-vm dns nameservers example.com --provider aws` (creates hosted zone automatically)
- **DigitalOcean**: Configure ns1/2/3.digitalocean.com at your domain registrar

After configuring nameservers, wait 24-48 hours for DNS propagation before deploying with `--domain`.

## Requirements

### Local Tools

| Tool                           | Purpose                    | Required | Install                     |
|--------------------------------|----------------------------|----------|-----------------------------|
| `uv`                           | Python package manager     | ✅ Yes   | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| `ssh`, `rsync`, `tar`, `scp`   | File transfer & remote ops | ✅ Yes   | Pre-installed (macOS/Linux) |
| `doctl`                        | DigitalOcean CLI           | Optional | `brew install doctl`        |
| `aws`                          | AWS CLI                    | Optional | `brew install awscli`       |
| `npm`                          | Nuxt local builds          | Optional | `brew install node`         |

**Install uv:**
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

**Install provider CLIs:**
```bash
# AWS
brew install awscli
aws configure

# DigitalOcean
brew install doctl
doctl auth init
```

### SSH Key

Tool automatically uploads your SSH key (`~/.ssh/id_ed25519.pub`, `id_rsa.pub`, or `id_ecdsa.pub`) to the provider on first use.

### Server Access

All server operations use the `deploy` user by default after initial setup:

1. **Initial creation**: Connects as cloud default user (`root` for DigitalOcean, `ubuntu` for AWS)
2. **Setup**: Creates `deploy` user with passwordless sudo privileges
3. **All subsequent operations**: Use `deploy` user with `sudo` for privileged commands

This follows security best practices by avoiding direct root access while maintaining full control. You can override the SSH user with `--ssh-user` flag if needed.

## Instance State

Instance metadata stored in `<name>.instance.json`:

```json
{
  "id": "i-0abc123",
  "ip": "54.123.45.67",
  "provider": "aws",
  "region": "ap-southeast-2",
  "os_image": "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*",
  "vm_size": "t3.small",
  "user": "deploy",
  "iam_role": "bedrock-access",
  "apps": [
    {"name": "api", "type": "fastapi", "port": 8000},
    {"name": "frontend", "type": "nuxt", "port": 3000}
  ]
}
```

DNS nameservers cached in `<domain>.nameservers.json` (auto-generated).

## Advanced Topics

- **Domain & SSL setup**: See [DOMAIN_SETUP.md](DOMAIN_SETUP.md) for complete guide, troubleshooting, and technical reference
- **Provider comparison**: See [PROVIDER_COMPARISON.md](PROVIDER_COMPARISON.md)
- **Multiple environments**: Use different `.env` files or AWS profiles
- **CI/CD integration**: Use `--force` flags to skip confirmations

## Support

- Issues: [GitHub Issues](https://github.com/boscoh/deploy-vm/issues)
- Documentation: `deploy-vm --help` or `deploy-vm <command> --help`
