# Domain Setup Guide

Complete guide for adding custom domains with SSL/HTTPS to your deploy-vm instances.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Prerequisites](#prerequisites)
3. [Usage Patterns](#usage-patterns)
4. [Verification](#verification)
5. [Troubleshooting](#troubleshooting)
6. [Technical Reference](#technical-reference)
7. [Future Enhancements](#future-enhancements)

---

## Quick Start

Deploy with a custom domain in three steps:

```bash
# 1. Get nameservers (creates hosted zone automatically for AWS)
#    AWS:
uv run deploy-vm dns nameservers example.com --provider-name aws
#    DigitalOcean: Use ns1/2/3.digitalocean.com

# 2. Configure nameservers at your domain registrar, then wait 24-48 hours

# 3. Deploy with domain
uv run deploy-vm fastapi deploy my-api /path/to/app \
  --domain example.com \
  --email admin@example.com \
  --provider aws \
  --region us-east-1
```

**What you get:**
- ✅ Automatic DNS A record creation (example.com + www.example.com)
- ✅ Free SSL certificate from Let's Encrypt (auto-renews)
- ✅ HTTPS with HTTP→HTTPS redirect
- ✅ Nginx configured and ready

---

## Prerequisites

### AWS Route53

**One-time setup** (must be done before deployment):

<details>
<summary>📋 Step-by-step AWS setup</summary>

**Step 1: Get Route53 Nameservers (creates hosted zone automatically)**
```bash
uv run deploy-vm dns nameservers example.com --provider-name aws
```

This command:
- ✅ Creates Route53 hosted zone if it doesn't exist
- ✅ Retrieves nameservers from the zone
- ✅ Caches result in `example.com.nameservers.json` for faster lookups

You'll see output like:
```
Route53 Hosted Zone: example.com.
Zone ID: Z1234567890ABC

Nameservers:
  ns-1234.awsdns-12.org
  ns-5678.awsdns-34.com
  ns-9012.awsdns-56.net
  ns-3456.awsdns-78.co.uk

Configure these nameservers at your domain registrar:
  1. Log in to your domain registrar (GoDaddy, Namecheap, etc.)
  2. Find DNS/Nameserver settings for example.com
  3. Replace existing nameservers with the ones listed above
  4. Wait 24-48 hours for DNS propagation
```

**Step 2: Update Domain Registrar**

Go to your domain registrar and replace their nameservers with the Route53 nameservers from Step 1.

**Step 3: Verify Propagation** (24-48 hours later)
```bash
dig example.com NS
# Should show Route53 nameservers
```

</details>

### DigitalOcean DNS

**One-time setup:**

<details>
<summary>📋 Step-by-step DigitalOcean setup</summary>

**Step 1: Update Domain Registrar**

Configure these nameservers at your domain registrar:
```
ns1.digitalocean.com
ns2.digitalocean.com
ns3.digitalocean.com
```

**Step 2: Verify Propagation** (24-48 hours later)
```bash
dig example.com NS
# Should show DigitalOcean nameservers
```

**Step 3: Check doctl Authentication**
```bash
doctl auth validate
# Should show "Authenticated successfully"
```

</details>

### Both Providers

Ensure you have:
- ✅ SSH key: `ls ~/.ssh/id_*.pub` shows a public key
- ✅ Provider credentials configured (AWS CLI or doctl)
- ✅ Domain nameservers updated at registrar
- ✅ 24-48 hours passed for DNS propagation

---

## Usage Patterns

### Pattern 1: New Deployment with Domain (Recommended)

Deploy a new application with domain from the start.

**AWS Example:**
```bash
uv run deploy-vm fastapi deploy my-api /path/to/app \
  --provider aws \
  --region us-east-1 \
  --vm-size t3.small \
  --domain api.example.com \
  --email admin@example.com
```

**DigitalOcean Example:**
```bash
uv run deploy-vm nuxt deploy my-site /path/to/nuxt \
  --domain mysite.com \
  --email admin@mysite.com \
  --region syd1 \
  --vm-size s-1vcpu-2gb
```

**What happens:**
1. Creates cloud instance (if doesn't exist)
2. Deploys application code
3. Updates DNS records: `example.com` and `www.example.com` → instance IP
4. Waits for DNS propagation (up to 5 minutes)
5. Configures nginx with SSL
6. Obtains Let's Encrypt certificate
7. Sets up HTTP→HTTPS redirect

**Access your app:**
```bash
curl https://example.com
# or
open https://example.com
```

---

### Pattern 2: Add Domain to Existing Instance

Add a domain to an instance that was initially deployed without one.

**Example:**
```bash
# Instance was created with --no-ssl, now add domain
uv run deploy-vm nginx ssl my-api example.com admin@example.com \
  --port 8000 \
  --provider-name aws
```

**Note:** Must specify `--provider-name` so deploy-vm knows which DNS provider to use.

**What happens:**
1. Updates DNS records (example.com → instance IP)
2. Waits for DNS propagation
3. Configures nginx for the domain
4. Obtains SSL certificate

---

### Pattern 3: IP-Only Deployment (No Domain)

Deploy without a custom domain (HTTP only, no SSL).

**Example:**
```bash
uv run deploy-vm fastapi deploy my-server /path/to/app \
  --provider aws \
  --no-ssl
```

**Access:** `http://<instance-ip>:8000`

**When to use:**
- Testing/development
- Internal services
- When domain not ready yet

**Add domain later:** Use Pattern 2 above

---

### Pattern 4: Check Domain Nameservers

Verify domain configuration before deployment.

**AWS:**
```bash
uv run deploy-vm dns nameservers example.com --provider-name aws
```

**DigitalOcean:**
```bash
uv run deploy-vm dns nameservers example.com --provider-name digitalocean
```

**Output shows:**
- Nameservers you need to configure at registrar
- Setup instructions
- Current DNS status

**Use case:** Confirm domain is configured correctly before attempting deployment.

---

## Verification

### Automated Verification

Run comprehensive health check:

```bash
uv run deploy-vm instance verify my-server --domain example.com
```

**Checks:**
- ✅ SSH connection
- ✅ Firewall (ports 80, 443 open)
- ✅ Nginx running
- ✅ DNS resolution (example.com → instance IP)
- ✅ HTTP responding
- ✅ HTTPS responding
- ✅ SSL certificate valid

### Manual Verification

**Check DNS resolution:**
```bash
dig example.com A
# Should return your instance IP
```

**Check HTTP:**
```bash
curl -I http://example.com
# Should show 301/302 redirect to HTTPS
```

**Check HTTPS:**
```bash
curl https://example.com
# Should return your app response
```

**Check SSL certificate:**
```bash
openssl s_client -connect example.com:443 -servername example.com
# Shows Let's Encrypt certificate info
```

**Check nginx configuration:**
```bash
ssh root@<instance-ip> 'nginx -T'
# Shows complete nginx config
```

---

## Troubleshooting

### Issue: "No Route53 hosted zone found"

**Symptoms:** AWS deployment fails immediately

**Diagnosis:**
```bash
aws route53 list-hosted-zones
```

**Solution:**
1. Create hosted zone and get nameservers:
   ```bash
   uv run deploy-vm dns nameservers example.com --provider-name aws
   ```
2. Update domain registrar with Route53 nameservers (shown in command output)
3. Wait 24-48 hours for propagation
4. Retry deployment

---

### Issue: "DNS verification timeout"

**Symptoms:** Deployment hangs for 5 minutes, then fails with DNS timeout

**Diagnosis:**
```bash
# Check nameservers
dig example.com NS

# Check A record
dig example.com A
```

**Solutions:**

| Finding | Action |
|---------|--------|
| Wrong NS records | Update nameservers at registrar, wait 24-48h |
| No A record | Check if DNS update succeeded, check provider credentials |
| A record wrong IP | Manually update DNS or re-run deployment |
| DNS not propagated yet | Use `--skip-dns` flag and configure DNS manually |

**Workaround - skip DNS management:**
```bash
uv run deploy-vm nginx ssl my-server example.com admin@example.com \
  --skip-dns
```
Then manually configure DNS at your provider.

---

### Issue: certbot fails

**Symptoms:** SSL certificate issuance fails with "Connection refused" or "Failed authorization"

**Diagnosis:**
```bash
# Check nginx status
ssh root@<instance-ip> 'systemctl status nginx'

# Check firewall
ssh root@<instance-ip> 'ufw status'

# Check HTTP accessibility
curl http://example.com
```

**Solutions:**

| Problem | Fix |
|---------|-----|
| Nginx not running | `ssh root@<ip> 'systemctl start nginx'` |
| Firewall blocking | `ssh root@<ip> 'ufw allow 80/tcp && ufw allow 443/tcp'` |
| DNS not resolving | Wait longer for DNS propagation |
| Port 80 not accessible | Check cloud provider security group/firewall rules |

**Manual retry:**
```bash
ssh root@<instance-ip>
certbot --nginx -d example.com -d www.example.com \
  --email admin@example.com \
  --agree-tos --redirect --force-renewal
```

---

### Issue: HTTPS shows wrong certificate or SSL error

**Symptoms:** Browser shows SSL error or certificate for wrong domain

**Diagnosis:**
```bash
openssl s_client -connect example.com:443 -servername example.com | grep subject
```

**Solution:** Force certificate re-issuance:
```bash
ssh root@<instance-ip>
certbot --nginx -d example.com -d www.example.com \
  --email admin@example.com \
  --agree-tos --redirect --force-renewal
```

---

### Issue: Security group DependencyViolation

**Symptoms:** Cannot delete security group, "DependencyViolation" error

**Cause:** Security group still attached to terminating instance

**Solution:**
```bash
# Wait for instance to fully terminate
aws ec2 describe-instances --instance-ids <instance-id>
# Status should be "terminated"

# Then delete security group
aws ec2 delete-security-group --group-id <sg-id>
```

---

## Technical Reference

### Architecture Flow

```
User Command (--domain --email)
         ↓
    Deploys App
         ↓
    setup_nginx_ssl()
         ↓
    ┌────┴────┐
    ↓         ↓
ensure_dns() verify_http()
    ↓
Provider.setup_dns()
    ↓
  ┌─┴─┐
  ↓   ↓
Route53  DO DNS
    ↓
Wait for DNS (5 min max)
    ↓
certbot --nginx
    ↓
SSL Certificate ✅
```

### DNS Management

**AWS Route53** (`AWSProvider.setup_dns()`):
- Creates/updates Route53 A records using UPSERT
- Sets TTL to 300 seconds
- Updates both apex (`example.com`) and www subdomain
- Requires: Route53 hosted zone exists, AWS credentials valid

**DigitalOcean** (`DigitalOceanProvider.setup_dns()`):
- Creates/updates DigitalOcean DNS records via doctl
- Creates domain if doesn't exist
- Updates both `@` (apex) and `www` records
- Requires: Nameservers pointed to DO, doctl authenticated

### SSL Certificate Issuance

**certbot command:**
```bash
certbot --nginx \
  -d example.com \
  -d www.example.com \
  --non-interactive \
  --agree-tos \
  --email admin@example.com \
  --redirect \
  --keep-until-expiring
```

**Requirements:**
- Nginx installed and running
- Ports 80 and 443 open in firewall
- DNS resolving to instance IP
- HTTP accessible (uses HTTP-01 challenge)

**Certificate details:**
- Provider: Let's Encrypt
- Validity: 90 days
- Auto-renewal: Yes (via certbot cron job)
- TLS versions: 1.2+
- Cipher suites: Strong ciphers (certbot defaults)

### DNS Verification Logic

**Retry parameters:**
```python
DNS_VERIFY_RETRIES = 30  # attempts
DNS_VERIFY_DELAY = 10    # seconds between attempts
# Total wait: up to 5 minutes
```

**Process:**
1. Resolve domain A record
2. Compare with instance IP
3. If match: proceed
4. If no match: wait 10 seconds, retry
5. After 30 attempts: fail with timeout

### Instance State Tracking

**instance.json schema:**
```json
{
  "id": "i-0abc123def456",
  "ip": "54.123.45.67",
  "provider": "aws",
  "region": "ap-southeast-2",
  "vm_size": "t3.small",
  "os_image": "ami-0abc123def456",
  "user": "deploy",
  "iam_role": "deploy-vm-bedrock",
  "apps": [
    {
      "name": "api",
      "type": "fastapi",
      "port": 8000
    }
  ]
}
```

**Note:** Domain field not currently stored but could be added for better state management.

### Security Configuration

**Firewall rules:**
- Port 22: SSH (AWS: restricted to creator IP if available, DO: open)
- Port 80: HTTP (required for Let's Encrypt verification)
- Port 443: HTTPS

**SSL/TLS:**
- Let's Encrypt certificates (free, auto-renewed)
- TLS 1.2+ supported
- Strong cipher suites (nginx/certbot defaults)
- HSTS: Not enabled by default

**DNS Security:**
- Route53: Requires AWS credentials with Route53 permissions
- DigitalOcean: Requires doctl authentication
- DNSSEC: Not supported currently

### Code Locations

**DNS setup:**
- `AWSProvider.setup_dns()` in `deploy_vm/providers.py`
- `DigitalOceanProvider.setup_dns()` in `deploy_vm/providers.py`

**SSL configuration:**
- `setup_nginx_ssl()` in `deploy_vm/server.py`

**DNS verification:**
- `ensure_dns_matches()` in `deploy_vm/server.py`
- `verify_http()` in `deploy_vm/server.py`

**CLI commands:**
- `deploy-vm nginx ssl` - Add SSL to existing instance
- `deploy-vm [nuxt|fastapi] deploy` - Deploy with domain
- `deploy-vm dns nameservers` - Get nameservers for domain
- `deploy-vm instance verify` - Health check

### External Resources

- [AWS Route53 Documentation](https://docs.aws.amazon.com/route53/)
- [DigitalOcean DNS API](https://docs.digitalocean.com/reference/api/api-reference/#tag/Domains)
- [Let's Encrypt certbot](https://certbot.eff.org/docs/)
- [nginx SSL Configuration](https://nginx.org/en/docs/http/configuring_https_servers.html)

---

## Future Enhancements

<details>
<summary>📋 Planned features (click to expand)</summary>

### 1. Domain Field in Instance State

**Status:** Proposed

**Problem:** Domain not tracked in instance.json

**Proposal:** Add domain field to instance state:
```python
if domain:
    data["domain"] = domain
    data["email"] = email
    save_instance(name, data)
```

**Benefits:**
- `deploy-vm instance info` shows domain
- `deploy-vm ssl renew` doesn't need domain re-specified
- Better state visibility

---

### 2. Subdomain Support

**Status:** Proposed

**Current limitation:** Only supports apex and www

**Proposal:** Add `--subdomain` flag:
```bash
uv run deploy-vm nginx ssl my-server api.example.com admin@example.com
```

**Implementation:**
- Modify `setup_dns()` to handle subdomains
- Update certbot command generation
- Add subdomain validation

---

### 3. Multiple Domains per Instance

**Status:** Proposed

**Use case:** Single instance serves multiple domains

**Proposal:**
```json
{
  "domains": [
    {"domain": "example.com", "app": "site"},
    {"domain": "api.example.com", "app": "api"}
  ]
}
```

**Implementation:**
- Multiple nginx server blocks
- Separate SSL certificates per domain
- Domain-to-app routing

---

### 4. Additional DNS Commands

**Status:** Partially implemented

**Available now:**
```bash
deploy-vm dns nameservers example.com --provider-name aws
```

**Planned:**
```bash
deploy-vm dns update example.com <instance-name>
deploy-vm dns list <instance-name>
deploy-vm dns delete example.com
```

---

### 5. Manual Certificate Renewal

**Status:** Proposed

**Current:** certbot auto-renews via cron

**Enhancement:** Add manual renewal command:
```bash
deploy-vm ssl renew <instance-name>
```

</details>

---

## Summary

The deploy-vm tool provides **complete domain support** for both AWS and DigitalOcean:

✅ Automatic DNS management via provider APIs
✅ SSL certificate issuance via Let's Encrypt
✅ DNS propagation verification with retry logic
✅ Nginx configuration with SSL/TLS
✅ Health verification command

**Key requirement:** DNS must be configured at the provider **before** deployment.

**Recommended workflow:**
1. Configure nameservers at domain registrar (one-time)
2. Wait 24-48 hours for propagation
3. Deploy with `--domain` and `--email` flags
4. Verify with `deploy-vm instance verify --domain`

**Questions?** Check [Troubleshooting](#troubleshooting) or file an issue.
