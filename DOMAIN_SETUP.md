# Domain Setup Specification

## Overview

This document specifies how to add domain name support to AWS (and DigitalOcean) instances in the deploy-vm system. Domain support enables HTTPS/SSL certificates via Let's Encrypt and automatic DNS record management.

## Current Implementation

Domain support is **already implemented** for both providers through the following features:

1. **Automatic DNS Management**: Updates DNS A records when deploying with `--domain` flag
2. **SSL Certificate Issuance**: Uses certbot to obtain Let's Encrypt certificates
3. **DNS Verification**: Waits for DNS propagation before issuing certificates
4. **Nginx Configuration**: Generates SSL-enabled nginx server blocks

## Architecture

### Components

```
┌─────────────────────────────────────────────────────────────┐
│                     User Command                             │
│  deploy-vm [nuxt|fastapi] deploy --domain example.com       │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│                  setup_nginx_ssl()                           │
│  server.py:565-630                                           │
└─────────────────────────────────────────────────────────────┘
                           ↓
                ┌──────────┴──────────┐
                ↓                      ↓
┌──────────────────────────┐  ┌──────────────────────────┐
│  ensure_dns_matches()    │  │  verify_http()           │
│  server.py:459-477       │  │  server.py:360-375       │
└──────────────────────────┘  └──────────────────────────┘
                ↓
┌──────────────────────────────────────────────────────────────┐
│              Provider.setup_dns()                             │
│  DigitalOcean: providers.py:269-313                          │
│  AWS:          providers.py:779-816                          │
└──────────────────────────────────────────────────────────────┘
                ↓
        ┌───────┴────────┐
        ↓                 ↓
┌──────────────┐  ┌──────────────────┐
│ DigitalOcean │  │  AWS Route53     │
│     DNS      │  │                  │
└──────────────┘  └──────────────────┘
```

### Data Flow

1. **User initiates deployment** with `--domain example.com --email user@example.com`
2. **DNS validation** checks if domain points to correct IP
3. **DNS update** (if needed) via provider API:
   - **AWS**: Updates Route53 A records for `example.com` and `www.example.com`
   - **DigitalOcean**: Updates DigitalOcean DNS for `example.com` and `www.example.com`
4. **DNS propagation wait** polls DNS (up to 5 minutes)
5. **Firewall configuration** opens ports 80 and 443
6. **Nginx setup** creates server blocks
7. **SSL certificate** obtained via certbot
8. **Verification** checks HTTP/HTTPS connectivity

## Prerequisites

### AWS Route53 Setup

**CRITICAL**: Domain must be configured in Route53 **before** deployment:

1. **Create Hosted Zone**:
   ```bash
   aws route53 create-hosted-zone \
     --name example.com \
     --caller-reference $(date +%s)
   ```

2. **Update Domain Registrar**: Point nameservers to AWS Route53
   - Find nameservers: `aws route53 get-hosted-zone --id <zone-id>`
   - Update at your domain registrar (GoDaddy, Namecheap, etc.)
   - Example nameservers:
     ```
     ns-1234.awsdns-12.org
     ns-5678.awsdns-34.com
     ns-9012.awsdns-56.net
     ns-3456.awsdns-78.co.uk
     ```

3. **Verify Propagation** (24-48 hours):
   ```bash
   dig example.com NS
   # Should show Route53 nameservers
   ```

### DigitalOcean DNS Setup

1. **Configure Nameservers** at domain registrar:
   ```
   ns1.digitalocean.com
   ns2.digitalocean.com
   ns3.digitalocean.com
   ```

2. **Verify** (24-48 hours):
   ```bash
   dig example.com NS
   # Should show DigitalOcean nameservers
   ```

## Usage Patterns

### Pattern 1: New Deployment with Domain (Recommended)

Deploy a new app with domain from the start:

```bash
# AWS
uv run deploy-vm fastapi deploy my-server /path/to/app \
  --provider aws \
  --region us-east-1 \
  --vm-size t3.small \
  --domain example.com \
  --email admin@example.com

# DigitalOcean
uv run deploy-vm nuxt deploy my-server /path/to/nuxt \
  --domain example.com \
  --email admin@example.com
```

**What happens**:
1. Creates instance (if doesn't exist)
2. Deploys application
3. Updates DNS records automatically
4. Configures nginx with SSL
5. Obtains Let's Encrypt certificate

### Pattern 2: Add Domain to Existing Instance

Add domain to instance that was deployed with `--no-ssl`:

```bash
# 1. Update DNS manually or via provider
uv run deploy-vm nginx ssl my-server example.com admin@example.com \
  --port 8000 \
  --skip-dns  # If DNS already configured elsewhere
```

**What happens**:
1. Configures nginx for the domain
2. Waits for DNS propagation
3. Obtains SSL certificate

### Pattern 3: IP-Only Deployment (No Domain)

Deploy without domain (HTTP only, no SSL):

```bash
uv run deploy-vm fastapi deploy my-server /path/to/app \
  --provider aws \
  --no-ssl
```

Access via: `http://<ip-address>`

### Pattern 4: Change Domain for Existing Instance

Update DNS records to point to a different instance:

```bash
# Method 1: Use nginx ssl command
uv run deploy-vm nginx ssl my-server newdomain.com admin@example.com

# Method 2: Manually update DNS (not implemented yet)
# Would require: deploy-vm dns update newdomain.com <instance-name>
```

## Implementation Details

### DNS Management

#### AWS Provider (providers.py:779-816)

```python
def setup_dns(self, domain: str, ip: str) -> None:
    """Update Route53 A records for domain and www subdomain.

    Prerequisites:
    - Route53 hosted zone must exist for domain
    - AWS credentials configured

    Creates/updates:
    - example.com -> <ip>
    - www.example.com -> <ip>
    """
```

**Key behaviors**:
- Uses `UPSERT` action (creates or updates)
- Sets TTL to 300 seconds (5 minutes)
- Fails if no hosted zone found
- Updates both apex and www subdomain

#### DigitalOcean Provider (providers.py:269-313)

```python
def setup_dns(self, domain: str, ip: str) -> None:
    """Update DigitalOcean DNS A records.

    Prerequisites:
    - Domain nameservers pointed to DigitalOcean
    - doctl authenticated

    Creates/updates:
    - @ (apex) -> <ip>
    - www -> <ip>
    """
```

**Key behaviors**:
- Creates domain if doesn't exist
- Uses `doctl compute domain records` API
- Updates existing records or creates new ones

### SSL Certificate Issuance (server.py:613-629)

```bash
# certbot command generated by setup_nginx_ssl
certbot --nginx \
  -d example.com \
  -d www.example.com \
  --non-interactive \
  --agree-tos \
  --email admin@example.com \
  --redirect \
  --keep-until-expiring  # Renews only if needed
```

**Requirements**:
1. Nginx configured and running
2. Ports 80 and 443 open in firewall
3. DNS resolving to instance IP
4. HTTP accessible (certbot uses HTTP-01 challenge)

### DNS Verification (server.py:600-609)

```python
# Retry logic
DNS_VERIFY_RETRIES = 30  # attempts
DNS_VERIFY_DELAY = 10    # seconds between attempts
# Total wait time: 5 minutes

for i in range(DNS_VERIFY_RETRIES):
    resolved = resolve_dns_a(domain)
    if resolved == ip:
        break
    time.sleep(DNS_VERIFY_DELAY)
```

## Error Handling

### Common Failures

| Error | Cause | Solution |
|-------|-------|----------|
| `No Route53 hosted zone found` | Hosted zone not created | Create hosted zone in Route53 |
| `DNS verification timeout` | Nameservers not updated | Wait 24-48h, verify NS records |
| `certbot failed` | HTTP not accessible | Check firewall, nginx status |
| `Security group DependencyViolation` | SG still attached | Wait for instance termination |

### Verification Command

```bash
# Check all components
uv run deploy-vm instance verify my-server --domain example.com

# Output shows:
# [OK/FAIL] SSH connection
# [OK/FAIL] Firewall (ports 80, 443)
# [OK/FAIL] Nginx running
# [OK/FAIL] DNS: example.com -> <ip>
# [OK/FAIL] HTTP responding
# [OK/FAIL] HTTPS responding
```

## Instance State Tracking

### instance.json Schema

```json
{
  "id": "i-0abc123def456",
  "ip": "54.123.45.67",
  "provider": "aws",
  "region": "ap-southeast-2",
  "vm_size": "t3.small",
  "os_image": "ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*",
  "user": "deploy",
  "domain": "example.com",  // Added when domain configured
  "apps": [
    {
      "name": "api",
      "type": "fastapi",
      "port": 8000
    }
  ]
}
```

**Note**: `domain` field is **not currently tracked** in instance.json but could be added for better state management.

## Future Enhancements

### 1. Domain Field in Instance State

**Problem**: Domain not tracked in instance.json

**Proposal**:
```python
# In cli.py deploy commands
if domain:
    data["domain"] = domain
    data["email"] = email
    save_instance(name, data)
```

**Benefits**:
- Enables `deploy-vm instance info` to show domain
- Allows `deploy-vm nginx renew` without re-specifying domain
- Better state visibility

### 2. Subdomain Support

**Current limitation**: Only supports apex and www

**Proposal**: Add `--subdomain` flag
```bash
uv run deploy-vm nginx ssl my-server api.example.com admin@example.com
```

**Implementation**:
- Modify `setup_dns()` to handle subdomains
- Update certbot command generation
- Add subdomain validation

### 3. Multiple Domains per Instance

**Use case**: Single instance serves multiple domains

**Proposal**:
```json
{
  "domains": [
    {"domain": "example.com", "app": "site"},
    {"domain": "api.example.com", "app": "api"}
  ]
}
```

**Implementation**:
- Multiple nginx server blocks
- Separate SSL certificates per domain
- Domain-to-app routing

### 4. DNS-only Command

**Current gap**: No standalone DNS update command

**Proposal**:
```bash
uv run deploy-vm dns update example.com <instance-name>
uv run deploy-vm dns list <instance-name>
uv run deploy-vm dns delete example.com
```

**Implementation**:
- Add `dns_app` to cli.py
- Call `provider.setup_dns()` directly
- Skip nginx/SSL configuration

### 5. Certificate Renewal Automation

**Current state**: certbot auto-renews via cron

**Enhancement**: Add manual renewal command
```bash
uv run deploy-vm ssl renew <instance-name>
```

## Testing Checklist

### Pre-deployment Testing

- [ ] Route53 hosted zone exists (AWS)
- [ ] Nameservers configured at registrar
- [ ] DNS propagation complete (`dig example.com NS`)
- [ ] AWS credentials valid (`aws sts get-caller-identity`)
- [ ] SSH key exists (`ls ~/.ssh/id_*.pub`)

### Post-deployment Testing

- [ ] DNS resolves: `dig example.com A` returns instance IP
- [ ] HTTP accessible: `curl http://example.com`
- [ ] HTTPS redirects: `curl -I http://example.com` shows 301/302
- [ ] HTTPS works: `curl https://example.com`
- [ ] Certificate valid: `openssl s_client -connect example.com:443 -servername example.com`
- [ ] Nginx configured: `ssh root@<ip> 'nginx -T'`
- [ ] App responds: `curl https://example.com/health` (if implemented)

## Security Considerations

### SSL/TLS

- **Let's Encrypt certificates**: 90-day validity, auto-renewed
- **TLS versions**: Configured by certbot (TLS 1.2+)
- **Cipher suites**: Default certbot/nginx strong ciphers
- **HSTS**: Not enabled by default (could be added)

### DNS

- **Route53 access**: Requires AWS credentials with Route53 permissions
- **DigitalOcean DNS**: Requires doctl authentication
- **DNS hijacking**: No DNSSEC support currently

### Firewall

- **AWS Security Groups**: Ports 22, 80, 443 open
- **UFW (Ubuntu)**: Managed on instance, same ports
- **SSH restriction**: AWS SG restricts SSH to creator's IP (if available)

## References

### Code Locations

- DNS setup: `deploy_vm/providers.py`
  - AWS: lines 779-816
  - DigitalOcean: lines 269-313
- SSL configuration: `deploy_vm/server.py:565-630`
- DNS verification: `deploy_vm/server.py:600-609`
- CLI commands: `deploy_vm/cli.py`
  - nginx ssl: line 240-263
  - deploy commands: lines 360-449 (nuxt), 548-642 (fastapi)

### External Documentation

- [AWS Route53 API](https://docs.aws.amazon.com/route53/)
- [DigitalOcean DNS API](https://docs.digitalocean.com/reference/api/api-reference/#tag/Domains)
- [Let's Encrypt certbot](https://certbot.eff.org/docs/)
- [nginx SSL configuration](https://nginx.org/en/docs/http/configuring_https_servers.html)

## Examples

### Example 1: AWS FastAPI with Domain

```bash
# 1. Prerequisites
aws route53 create-hosted-zone --name myapi.com --caller-reference $(date +%s)
# Update registrar nameservers to Route53 NS records
# Wait 24-48 hours for propagation

# 2. Verify DNS
dig myapi.com NS
# Should show: ns-xxx.awsdns-xx.org

# 3. Deploy
uv run deploy-vm fastapi deploy my-api /path/to/app \
  --provider aws \
  --region us-west-2 \
  --vm-size t3.small \
  --domain myapi.com \
  --email admin@myapi.com

# 4. Verify
uv run deploy-vm instance verify my-api --domain myapi.com
curl https://myapi.com
```

### Example 2: Add Domain to Existing Instance

```bash
# Instance already exists with --no-ssl
uv run deploy-vm instance list

# Add domain and SSL
uv run deploy-vm nginx ssl my-api myapi.com admin@myapi.com \
  --port 8000 \
  --provider-name aws

# The provider-name flag ensures correct DNS provider is used
```

### Example 3: DigitalOcean Nuxt with Domain

```bash
# 1. Prerequisites
# Update registrar nameservers:
#   ns1.digitalocean.com
#   ns2.digitalocean.com
#   ns3.digitalocean.com

# 2. Verify DNS
dig mysite.com NS

# 3. Deploy
uv run deploy-vm nuxt deploy my-site /path/to/nuxt \
  --domain mysite.com \
  --email admin@mysite.com \
  --region syd1 \
  --vm-size s-1vcpu-2gb

# 4. Access
open https://mysite.com
```

## Troubleshooting

### Issue: "No Route53 hosted zone found"

**Symptoms**: Deployment fails with error message

**Diagnosis**:
```bash
aws route53 list-hosted-zones
```

**Solution**:
1. Create hosted zone:
   ```bash
   aws route53 create-hosted-zone \
     --name example.com \
     --caller-reference $(date +%s)
   ```
2. Update domain registrar with Route53 nameservers
3. Wait for propagation (24-48 hours)

### Issue: "DNS verification timeout"

**Symptoms**: Deployment hangs for 5 minutes then fails

**Diagnosis**:
```bash
dig example.com A
dig example.com NS
```

**Solutions**:
1. If NS records wrong: Update nameservers at registrar
2. If A record wrong: Check DNS update succeeded
3. If DNS not propagated: Use `--skip-dns` flag and configure DNS manually

### Issue: certbot fails with "Connection refused"

**Symptoms**: SSL certificate issuance fails

**Diagnosis**:
```bash
ssh root@<ip> 'systemctl status nginx'
ssh root@<ip> 'ufw status'
curl http://example.com
```

**Solutions**:
1. Nginx not running: `ssh root@<ip> 'systemctl start nginx'`
2. Firewall blocks: `ssh root@<ip> 'ufw allow 80/tcp && ufw allow 443/tcp'`
3. DNS not resolving: Wait longer for DNS propagation

### Issue: HTTPS shows wrong certificate

**Symptoms**: Browser shows SSL error or wrong domain

**Diagnosis**:
```bash
openssl s_client -connect example.com:443 -servername example.com | grep subject
```

**Solution**: Re-run certbot manually:
```bash
ssh root@<ip>
certbot --nginx -d example.com -d www.example.com \
  --email admin@example.com \
  --agree-tos --redirect --force-renewal
```

## Summary

The deploy-vm tool provides **complete domain support** for both AWS and DigitalOcean:

✅ **Automatic DNS management** via provider APIs
✅ **SSL certificate issuance** via Let's Encrypt
✅ **DNS propagation verification** with retry logic
✅ **Nginx configuration** with SSL/TLS
✅ **Health verification** command

**Key requirement**: DNS must be configured at the provider (Route53 for AWS, DigitalOcean DNS) **before** deployment.

**Recommended workflow**:
1. Configure nameservers at domain registrar
2. Wait 24-48 hours for propagation
3. Deploy with `--domain` and `--email` flags
4. Verify with `deploy-vm instance verify --domain`
