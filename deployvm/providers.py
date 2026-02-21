"""Cloud provider abstractions for DigitalOcean and AWS."""

import base64
import hashlib
import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Protocol

import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv

from .utils import error, log, run_cmd, run_cmd_json, warn

ProviderName = Literal["digitalocean", "aws", "vultr"]


def get_local_ssh_key() -> tuple[str, str]:
    """:return: (key_content, md5_fingerprint)"""
    ssh_dir = Path.home() / ".ssh"
    key_names = ["id_ed25519.pub", "id_rsa.pub", "id_ecdsa.pub"]

    for name in key_names:
        key_path = ssh_dir / name
        if key_path.exists():
            content = key_path.read_text().strip()
            key_data = content.split()[1]
            decoded = base64.b64decode(key_data)
            fingerprint = hashlib.md5(decoded).hexdigest()
            fingerprint = ":".join(fingerprint[i : i + 2] for i in range(0, 32, 2))
            log(f"Using SSH key: '{key_path}'")
            return content, fingerprint

    error(f"No SSH key found in ~/.ssh/ (tried: {', '.join(key_names)})")


class Provider(Protocol):
    provider_name: ProviderName
    region: str
    os_image: str
    vm_size: str

    def validate_auth(self) -> None: ...

    def instance_exists(self, name: str) -> bool: ...

    def create_instance(
        self, name: str, region: str, vm_size: str, iam_role: str | None = None
    ) -> dict: ...

    def delete_instance(self, instance_id: str) -> None: ...

    def list_instances(self) -> list[dict]: ...

    def setup_dns(self, domain: str, ip: str) -> None: ...

    def cleanup_resources(self, *, dry_run: bool = True) -> None: ...


def _get_my_ip() -> str | None:
    """Get the current public IP address for SSH restriction.

    Queries an external service to determine the public IP address of the
    current machine. Falls back to None if the service is unreachable.

    :return: Public IP address string, or None if detection fails
    """
    try:
        import urllib.request

        response = urllib.request.urlopen("https://api.ipify.org", timeout=5)
        return response.read().decode("utf8")
    except Exception:
        log(
            "[WARN] Could not determine your public IP, using 0.0.0.0/0 for SSH access"
        )
        return None


class DigitalOceanProvider:
    VM_SIZES = [
        "s-1vcpu-512mb",
        "s-1vcpu-1gb",
        "s-1vcpu-2gb",
        "s-2vcpu-2gb",
        "s-2vcpu-4gb",
        "s-4vcpu-8gb",
        "s-8vcpu-16gb",
    ]

    REGIONS = [
        "syd1",
        "sgp1",
        "nyc1",
        "nyc3",
        "sfo3",
        "lon1",
        "fra1",
        "ams3",
        "tor1",
        "blr1",
    ]

    def __init__(
        self,
        os_image: str | None = None,
        region: str | None = None,
        vm_size: str | None = None,
    ):
        self.provider_name: ProviderName = "digitalocean"
        self.region = region or "syd1"
        self.os_image = os_image or "ubuntu-24-04-x64"
        self.vm_size = vm_size or "s-1vcpu-1gb"

        if self.vm_size not in self.VM_SIZES:
            error(
                f"Invalid DigitalOcean VM size: '{self.vm_size}'\n"
                f"Valid sizes: '{', '.join(self.VM_SIZES)}'\n"
                f"See PROVIDER_COMPARISON.md for details."
            )

    def validate_auth(self) -> None:
        """Validate DigitalOcean authentication via doctl CLI.

        :raises SystemExit: If authentication validation fails
        """
        result = subprocess.run(
            ["doctl", "auth", "validate"], capture_output=True, text=True
        )
        if result.returncode != 0:
            error("doctl not authenticated. Run: doctl auth init")

    def instance_exists(self, name: str) -> bool:
        """Check if a droplet with the given name exists.

        :param name: The droplet name to check
        :return: True if droplet exists, False otherwise
        """
        droplets = run_cmd_json("doctl", "compute", "droplet", "list")
        return any(d["name"] == name for d in droplets)

    def get_instance_by_name(self, name: str) -> dict | None:
        droplets = run_cmd_json("doctl", "compute", "droplet", "list", name)
        droplet = next((d for d in droplets if d["name"] == name), None)
        if not droplet:
            return None
        ip = next(
            (
                n["ip_address"]
                for n in droplet["networks"]["v4"]
                if n["type"] == "public"
            ),
            "N/A",
        )
        return {"id": droplet["id"], "ip": ip}

    def create_instance(
        self, name: str, region: str, vm_size: str, iam_role: str | None = None
    ) -> dict:
        """Create a new DigitalOcean droplet with SSH key setup.

        :param name: The name for the new droplet
        :param region: The DigitalOcean region to create the droplet in
        :param vm_size: The droplet size (e.g., 's-1vcpu-1gb')
        :param iam_role: Unused for DigitalOcean (AWS compatibility parameter)
        :return: Dictionary with 'id' and 'ip' keys for the created droplet
        :raises SystemExit: If droplet already exists or creation fails
        """
        self.validate_auth()

        if self.instance_exists(name):
            error(f"Droplet '{name}' already exists")

        key_content, fingerprint = get_local_ssh_key()
        keys = run_cmd_json("doctl", "compute", "ssh-key", "list")

        existing = next((k for k in keys if k["fingerprint"] == fingerprint), None)
        if existing:
            ssh_key_id = str(existing["id"])
            log(f"Found matching SSH key in DigitalOcean: '{existing['name']}'")
        else:
            log("Uploading SSH key to DigitalOcean...")
            key_name = f"deploy-vm-{fingerprint[-8:]}"
            run_cmd(
                "doctl",
                "compute",
                "ssh-key",
                "create",
                key_name,
                "--public-key",
                key_content,
            )
            keys = run_cmd_json("doctl", "compute", "ssh-key", "list")
            uploaded = next((k for k in keys if k["fingerprint"] == fingerprint), None)
            if not uploaded:
                error("Failed to upload SSH key")
            ssh_key_id = str(uploaded["id"])
            log(f"Uploaded SSH key: '{key_name}'")

        run_cmd(
            "doctl",
            "compute",
            "droplet",
            "create",
            name,
            "--region",
            region,
            "--size",
            vm_size,
            "--image",
            self.os_image,
            "--ssh-keys",
            ssh_key_id,
            "--wait",
        )

        droplets = run_cmd_json("doctl", "compute", "droplet", "list", name)
        if not droplets:
            error("Failed to find created droplet")

        droplet = droplets[0]
        ip = next(
            (
                n["ip_address"]
                for n in droplet["networks"]["v4"]
                if n["type"] == "public"
            ),
            None,
        )
        if not ip:
            error("No public IP found")

        return {"id": droplet["id"], "ip": ip}

    def delete_instance(self, instance_id: str) -> None:
        """Delete a DigitalOcean droplet by ID.

        :param instance_id: The droplet ID to delete
        :raises SystemExit: If authentication fails or deletion fails
        """
        self.validate_auth()
        run_cmd("doctl", "compute", "droplet", "delete", str(instance_id), "--force")

    def list_instances(self) -> list[dict]:
        """List all DigitalOcean droplets in the account.

        :return: List of dictionaries with 'name', 'ip', 'status', and 'region' keys
        :raises SystemExit: If authentication fails
        """
        self.validate_auth()
        droplets = run_cmd_json("doctl", "compute", "droplet", "list")
        return [
            {
                "name": d["name"],
                "ip": next(
                    (
                        n["ip_address"]
                        for n in d["networks"]["v4"]
                        if n["type"] == "public"
                    ),
                    "N/A",
                ),
                "status": d["status"],
                "region": d["region"]["slug"],
            }
            for d in droplets
        ]

    def setup_dns(self, domain: str, ip: str) -> None:
        self.validate_auth()
        domains = run_cmd_json("doctl", "compute", "domain", "list")
        domain_exists = any(d["name"] == domain for d in domains)

        if not domain_exists:
            log("Creating domain...")
            run_cmd("doctl", "compute", "domain", "create", domain, "--ip-address", ip)
        else:
            log("Domain exists, updating records...")

        records = run_cmd_json("doctl", "compute", "domain", "records", "list", domain)

        for name in ["@", "www"]:
            existing = [r for r in records if r["type"] == "A" and r["name"] == name]
            if existing:
                record_id = str(existing[0]["id"])
                run_cmd(
                    "doctl",
                    "compute",
                    "domain",
                    "records",
                    "update",
                    domain,
                    "--record-id",
                    record_id,
                    "--record-data",
                    ip,
                )
            else:
                run_cmd(
                    "doctl",
                    "compute",
                    "domain",
                    "records",
                    "create",
                    domain,
                    "--record-type",
                    "A",
                    "--record-name",
                    name,
                    "--record-data",
                    ip,
                )

    def cleanup_resources(self, *, dry_run: bool = True) -> None:
        log("No cleanup operations available for DigitalOcean provider")


class AWSProvider:
    REGIONS = [
        "us-east-1",
        "us-east-2",
        "us-west-1",
        "us-west-2",
        "ca-central-1",
        "eu-west-1",
        "eu-west-2",
        "eu-west-3",
        "eu-central-1",
        "eu-north-1",
        "ap-southeast-1",
        "ap-southeast-2",
        "ap-northeast-1",
        "ap-northeast-2",
        "ap-south-1",
        "sa-east-1",
    ]

    VM_SIZES = [
        "t3.micro",
        "t3.small",
        "t3.medium",
        "t3.large",
        "t3.xlarge",
        "t3.2xlarge",
        "t4g.micro",
        "t4g.small",
        "t4g.medium",
        "t4g.large",
        "m5.large",
        "m5.xlarge",
        "m5.2xlarge",
        "m6i.large",
        "m6i.xlarge",
        "c5.large",
        "c5.xlarge",
    ]

    def __init__(
        self,
        os_image: str | None = None,
        region: str | None = None,
        vm_size: str | None = None,
        aws_profile: str | None = None,
    ):
        self.provider_name: ProviderName = "aws"
        self.os_image = (
            os_image or "ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"
        )
        self.vm_size = vm_size or "t3.micro"
        self.aws_config = AWSProvider.get_aws_config(profile=aws_profile)

        if region:
            self.aws_config["region_name"] = region

        region = region or self.aws_config.get("region_name", "ap-southeast-2")

        # Validate and normalize region (converts AZ like us-east-1a to region us-east-1)
        if region and region[-1].isalpha() and region[:-1] in self.REGIONS:
            normalized_region = region[:-1]
            log(
                f"Converted availability zone '{region}' to region '{normalized_region}'"
            )
            self.region = normalized_region
        elif region not in self.REGIONS:
            error(
                f"Invalid AWS region: '{region}'\n"
                f"Valid AWS regions: '{', '.join(self.REGIONS[:6])}', ...\n"
                f"See PROVIDER_COMPARISON.md for full list."
            )
        else:
            self.region = region

        if not self.aws_config:
            error(
                "AWS credentials not configured. Please run:\n"
                "  aws configure\n"
                "Or set environment variables:\n"
                "  export AWS_PROFILE=your-profile\n"
                "  export AWS_REGION=ap-southeast-2"
            )

        if self.vm_size not in self.VM_SIZES:
            error(
                f"Invalid AWS instance type: '{self.vm_size}'\n"
                f"Valid types: '{', '.join(self.VM_SIZES[:6])}', ...\n"
                f"See PROVIDER_COMPARISON.md for full list."
            )

    @staticmethod
    def get_aws_config(profile: str | None = None) -> dict:
        """Load AWS configuration for boto3 session initialization.

        Reads profile and region from config files and environment variables.
        Does not validate credentials — call check_aws_auth() for that.

        :param profile: Explicit AWS profile name (overrides AWS_PROFILE env var)
        :return: Dict with profile_name and/or region_name keys for boto3.Session()
        """
        load_dotenv()

        aws_config = {}
        available_profiles = set()
        credentials_path = os.path.expanduser("~/.aws/credentials")
        config_path = os.path.expanduser("~/.aws/config")

        import configparser
        for path in [credentials_path, config_path]:
            if os.path.exists(path):
                cfg = configparser.ConfigParser()
                cfg.read(path)
                for section in cfg.sections():
                    if section.startswith("profile "):
                        available_profiles.add(section[8:])
                    elif section != "default":
                        available_profiles.add(section)

        profile_name = profile or os.getenv("AWS_PROFILE")
        if profile_name:
            if profile_name in available_profiles:
                aws_config["profile_name"] = profile_name
            else:
                log(f"AWS profile '{profile_name}' not found, using default credential chain...")
                os.environ.pop("AWS_PROFILE", None)

        region = os.getenv("AWS_REGION")
        if region:
            aws_config["region_name"] = region

        return aws_config

    def validate_auth(self) -> None:
        check_aws_auth(self.aws_config.get("profile_name"))

    def _get_ec2_client(self):
        return self._get_session().client("ec2")

    def _get_route53_client(self):
        return self._get_session().client("route53")

    def _validate_vpc(self, ec2, vpc_id: str) -> tuple[bool, str | None]:
        """Validate VPC has required components (subnets, IGW, route table).

        Checks that the specified VPC has all necessary components for hosting
        EC2 instances with public internet access: subnets, an attached internet
        gateway, and at least one public subnet with a route to the IGW.

        :param ec2: Boto3 EC2 client instance
        :param vpc_id: VPC ID to validate
        :return: Tuple of (is_valid, error_message). error_message is None if valid
        """
        subnets = ec2.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )["Subnets"]
        if not subnets:
            return False, "No subnets found in VPC"

        igws = ec2.describe_internet_gateways(
            Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}]
        )["InternetGateways"]
        if not igws:
            return False, "No internet gateway attached to VPC"

        has_public_subnet = False
        for subnet in subnets:
            route_tables = ec2.describe_route_tables(
                Filters=[
                    {"Name": "association.subnet-id", "Values": [subnet["SubnetId"]]}
                ]
            )["RouteTables"]

            if not route_tables:
                route_tables = ec2.describe_route_tables(
                    Filters=[
                        {"Name": "vpc-id", "Values": [vpc_id]},
                        {"Name": "association.main", "Values": ["true"]},
                    ]
                )["RouteTables"]

            for rt in route_tables:
                for route in rt.get("Routes", []):
                    if route.get("GatewayId", "").startswith("igw-"):
                        has_public_subnet = True
                        break
                if has_public_subnet:
                    break
            if has_public_subnet:
                break

        if not has_public_subnet:
            return (
                False,
                "No public subnets found (subnets need route to internet gateway)",
            )

        return True, None

    def _get_my_ip(self) -> str | None:
        """Get the current public IP address for SSH restriction.

        :return: Public IP address string, or None if detection fails
        """
        return _get_my_ip()

    def _find_ami(self, ec2_client) -> str:
        response = ec2_client.describe_images(
            Filters=[
                {"Name": "name", "Values": [self.os_image]},
                {"Name": "state", "Values": ["available"]},
                {"Name": "architecture", "Values": ["x86_64"]},
            ],
            Owners=["099720109477"],
        )

        if not response["Images"]:
            error(f"No AMI found matching pattern: '{self.os_image}'")

        images = sorted(
            response["Images"], key=lambda x: x["CreationDate"], reverse=True
        )
        return images[0]["ImageId"]

    def _ensure_ssh_key(self, ec2) -> str:
        """Ensure SSH key exists in AWS, upload if needed.

        Checks if a local SSH key is already registered with AWS EC2. If not found,
        uploads the local public key to AWS for use with new instances.

        :param ec2: Boto3 EC2 client instance
        :return: SSH key name registered in AWS
        """
        key_content, fingerprint = get_local_ssh_key()
        key_name = f"deploy-vm-{fingerprint[-8:]}"

        try:
            ec2.describe_key_pairs(KeyNames=[key_name])
            log(f"Using existing SSH key: '{key_name}'")
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidKeyPair.NotFound":
                log("Uploading SSH key to AWS...")
                ec2.import_key_pair(KeyName=key_name, PublicKeyMaterial=key_content)
                log(f"Uploaded SSH key: '{key_name}'")
            else:
                raise

        return key_name

    def _update_ssh_cidr(self, ec2, sg_id: str) -> None:
        """Update SSH ingress rule to the current public IP if it has changed.

        :param ec2: Boto3 EC2 client instance
        :param sg_id: Security group ID to update
        """
        my_ip = self._get_my_ip()
        if not my_ip:
            return

        new_cidr = f"{my_ip}/32"

        sg = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
        ssh_rules = [
            r for r in sg["IpPermissions"]
            if r.get("IpProtocol") == "tcp"
            and r.get("FromPort") == 22
            and r.get("ToPort") == 22
        ]

        existing_cidrs = [
            ip_range["CidrIp"]
            for rule in ssh_rules
            for ip_range in rule.get("IpRanges", [])
        ]

        if existing_cidrs == [new_cidr]:
            return

        if ssh_rules:
            ec2.revoke_security_group_ingress(GroupId=sg_id, IpPermissions=ssh_rules)

        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": new_cidr, "Description": "SSH access"}],
            }],
        )
        log(f"Updated SSH access to '{new_cidr}'")

    def update_ssh_ip(self) -> None:
        """Update the deploy-vm-web security group SSH rule to the current public IP."""
        ec2 = self._get_ec2_client()
        response = ec2.describe_security_groups(
            Filters=[{"Name": "group-name", "Values": ["deploy-vm-web"]}]
        )
        if not response["SecurityGroups"]:
            error("No 'deploy-vm-web' security group found")
        sg_id = response["SecurityGroups"][0]["GroupId"]
        self._update_ssh_cidr(ec2, sg_id)

    def _ensure_security_group(self, ec2) -> str:
        """Ensure security group exists in AWS, create if needed.

        Checks for the 'deploy-vm-web' security group. If not found, creates a new
        security group with rules allowing SSH (port 22), HTTP (port 80), and HTTPS
        (port 443) access. SSH access is restricted to the current public IP when possible.

        :param ec2: Boto3 EC2 client instance
        :return: Security group ID
        """
        sg_name = "deploy-vm-web"
        try:
            response = ec2.describe_security_groups(
                Filters=[{"Name": "group-name", "Values": [sg_name]}]
            )
            if response["SecurityGroups"]:
                sg_id = response["SecurityGroups"][0]["GroupId"]
                log(f"Using existing security group: '{sg_name}'")
                self._update_ssh_cidr(ec2, sg_id)
            else:
                raise ClientError(
                    {"Error": {"Code": "InvalidGroup.NotFound"}},
                    "DescribeSecurityGroups",
                )
        except ClientError as e:
            if e.response["Error"]["Code"] in [
                "InvalidGroup.NotFound",
                "VPCIdNotSpecified",
            ]:
                log("Creating security group...")

                vpcs = ec2.describe_vpcs()["Vpcs"]
                if not vpcs:
                    log("No VPC found. Creating default VPC...")
                    try:
                        vpc_response = ec2.create_default_vpc()
                        vpc_id = vpc_response["Vpc"]["VpcId"]
                        log(f"✓ Created default VPC: {vpc_id}")

                        # Wait a moment for VPC to be fully ready
                        time.sleep(2)

                        # Refresh VPC list
                        vpcs = ec2.describe_vpcs()["Vpcs"]
                    except ClientError as vpc_error:
                        error(
                            f"Failed to create default VPC: {vpc_error}\n"
                            "Please create a VPC manually:\n"
                            "  aws ec2 create-default-vpc --region "
                            + self.aws_config.get("region_name", "ap-southeast-2")
                        )

                default_vpc = next((v for v in vpcs if v.get("IsDefault")), None)
                vpc_id = default_vpc["VpcId"] if default_vpc else vpcs[0]["VpcId"]

                is_valid, error_msg = self._validate_vpc(ec2, vpc_id)
                if not is_valid:
                    error(
                        f"VPC {vpc_id} is not properly configured: {error_msg}\n"
                        f"The VPC needs:\n"
                        f"  1. Subnets (for instance placement)\n"
                        f"  2. Internet gateway (for outbound connectivity)\n"
                        f"  3. Route table with route to internet gateway (for public access)\n"
                        f"Fix with: aws ec2 create-default-vpc --region {self.aws_config.get('region_name', 'ap-southeast-2')}"
                    )

                log(f"Using VPC: '{vpc_id}'")

                response = ec2.create_security_group(
                    GroupName=sg_name,
                    Description="Security group for deploy-vm web servers",
                    VpcId=vpc_id,
                    TagSpecifications=[
                        {
                            "ResourceType": "security-group",
                            "Tags": [
                                {"Key": "Name", "Value": sg_name},
                                {"Key": "ManagedBy", "Value": "deploy-vm"},
                                {
                                    "Key": "CreatedAt",
                                    "Value": datetime.now(timezone.utc).isoformat(),
                                },
                            ],
                        }
                    ],
                )
                sg_id = response["GroupId"]

                my_ip = self._get_my_ip()
                ssh_cidr = f"{my_ip}/32" if my_ip else "0.0.0.0/0"
                if my_ip:
                    log(f"Restricting SSH access to your IP: '{my_ip}'")

                ec2.authorize_security_group_ingress(
                    GroupId=sg_id,
                    IpPermissions=[
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [
                                {"CidrIp": ssh_cidr, "Description": "SSH access"}
                            ],
                        },
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 80,
                            "ToPort": 80,
                            "IpRanges": [
                                {"CidrIp": "0.0.0.0/0", "Description": "HTTP access"}
                            ],
                        },
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 443,
                            "ToPort": 443,
                            "IpRanges": [
                                {"CidrIp": "0.0.0.0/0", "Description": "HTTPS access"}
                            ],
                        },
                    ],
                )
                log(f"Created security group: '{sg_name}'")
            else:
                raise

        return sg_id

    def _get_session(self):
        """Get boto3 session using aws_config."""
        return boto3.Session(**self.aws_config)

    def _get_iam_client(self):
        return self._get_session().client("iam")

    def _ensure_iam_role_and_profile(self, role_name: str) -> str:
        """Ensure IAM role and instance profile exist with Bedrock access.

        Creates or retrieves an IAM role with EC2 trust policy, attaches the
        AmazonBedrockFullAccess managed policy, creates an instance profile with
        the same name, and associates the role with the profile. Waits for the
        profile to be fully propagated before returning.

        :param role_name: Name for both the IAM role and instance profile
        :return: Instance profile name (same as role_name)
        """
        iam = self._get_iam_client()

        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }
            ]
        }

        try:
            iam.get_role(RoleName=role_name)
            log(f"Using existing IAM role: '{role_name}'")
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                log(f"Creating IAM role: '{role_name}'")
                iam.create_role(
                    RoleName=role_name,
                    AssumeRolePolicyDocument=json.dumps(trust_policy),
                    Description=f"Role for deploy-vm managed instances (Bedrock access)",
                    Tags=[
                        {"Key": "ManagedBy", "Value": "deploy-vm"},
                        {"Key": "CreatedAt", "Value": datetime.now(timezone.utc).isoformat()},
                    ]
                )
                log(f"Created IAM role: '{role_name}'")
            else:
                raise

        bedrock_policy_arn = "arn:aws:iam::aws:policy/AmazonBedrockFullAccess"
        try:
            iam.attach_role_policy(RoleName=role_name, PolicyArn=bedrock_policy_arn)
            log(f"Attached AmazonBedrockFullAccess policy to '{role_name}'")
        except ClientError as e:
            if e.response["Error"]["Code"] != "EntityAlreadyExists":
                pass

        profile_name = role_name
        try:
            iam.get_instance_profile(InstanceProfileName=profile_name)
            log(f"Using existing instance profile: '{profile_name}'")
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                log(f"Creating instance profile: '{profile_name}'")
                iam.create_instance_profile(
                    InstanceProfileName=profile_name,
                    Tags=[
                        {"Key": "ManagedBy", "Value": "deploy-vm"},
                        {"Key": "CreatedAt", "Value": datetime.now(timezone.utc).isoformat()},
                    ]
                )
                log(f"Created instance profile: '{profile_name}'")
            else:
                raise

        try:
            iam.add_role_to_instance_profile(
                InstanceProfileName=profile_name,
                RoleName=role_name
            )
            log(f"Added role '{role_name}' to instance profile")
        except ClientError as e:
            if e.response["Error"]["Code"] != "LimitExceeded":
                pass

        max_attempts = 10
        for attempt in range(max_attempts):
            try:
                profile = iam.get_instance_profile(InstanceProfileName=profile_name)
                if profile["InstanceProfile"]["Roles"]:
                    if attempt > 0:
                        log(f"Instance profile ready after {attempt + 1} attempts")
                    break
            except ClientError:
                pass

            if attempt < max_attempts - 1:
                time.sleep(2)
        else:
            log(f"Warning: Instance profile may not be fully propagated yet")

        return profile_name

    def instance_exists(self, name: str) -> bool:
        ec2 = self._get_ec2_client()
        response = ec2.describe_instances(
            Filters=[
                {"Name": "tag:Name", "Values": [name]},
                {
                    "Name": "instance-state-name",
                    "Values": ["running", "pending", "stopping", "stopped"],
                },
            ]
        )
        return len(response["Reservations"]) > 0

    def get_instance_by_name(self, name: str) -> dict | None:
        ec2 = self._get_ec2_client()
        response = ec2.describe_instances(
            Filters=[
                {"Name": "tag:Name", "Values": [name]},
                {"Name": "instance-state-name", "Values": ["running", "pending"]},
            ]
        )

        if not response["Reservations"] or not response["Reservations"][0]["Instances"]:
            return None

        instance = response["Reservations"][0]["Instances"][0]
        return {
            "id": instance["InstanceId"],
            "ip": instance.get("PublicIpAddress", "N/A"),
        }

    def create_instance(
        self, name: str, region: str, vm_size: str, iam_role: str | None = None
    ) -> dict:
        self.validate_auth()

        if self.instance_exists(name):
            error(f"EC2 instance '{name}' already exists")

        ec2 = self._get_ec2_client()

        ami_id = self._find_ami(ec2)
        log(f"Using AMI: '{ami_id}'")

        # Setup IAM role if specified
        instance_profile_name = None
        if iam_role:
            instance_profile_name = self._ensure_iam_role_and_profile(iam_role)

        key_name = self._ensure_ssh_key(ec2)
        sg_id = self._ensure_security_group(ec2)

        log(f"Creating EC2 instance '{name}' ({vm_size})...")

        run_params = {
            "ImageId": ami_id,
            "InstanceType": vm_size,
            "KeyName": key_name,
            "SecurityGroupIds": [sg_id],
            "MinCount": 1,
            "MaxCount": 1,
            "TagSpecifications": [
                {
                    "ResourceType": "instance",
                    "Tags": [
                        {"Key": "Name", "Value": name},
                        {"Key": "ManagedBy", "Value": "deploy-vm"},
                        {
                            "Key": "CreatedAt",
                            "Value": datetime.now(timezone.utc).isoformat(),
                        },
                        {"Key": "CreatedBy", "Value": os.getenv("USER", "unknown")},
                    ],
                }
            ],
        }

        if instance_profile_name:
            run_params["IamInstanceProfile"] = {"Name": instance_profile_name}
            log(f"Attaching IAM instance profile: '{instance_profile_name}'")

        response = ec2.run_instances(**run_params)

        instance_id = response["Instances"][0]["InstanceId"]
        log("Waiting for instance to start...")

        waiter = ec2.get_waiter("instance_running")
        waiter.wait(InstanceIds=[instance_id])

        response = ec2.describe_instances(InstanceIds=[instance_id])
        instance = response["Reservations"][0]["Instances"][0]
        ip = instance.get("PublicIpAddress")

        if not ip:
            error("No public IP address assigned to instance")

        return {"id": instance_id, "ip": ip, "os_image": ami_id}

    def delete_instance(self, instance_id: str) -> None:
        self.validate_auth()
        ec2 = self._get_ec2_client()
        ec2.terminate_instances(InstanceIds=[instance_id])
        log("Waiting for instance to terminate...")
        waiter = ec2.get_waiter("instance_terminated")
        waiter.wait(InstanceIds=[instance_id])

    def list_instances(self) -> list[dict]:
        self.validate_auth()
        ec2 = self._get_ec2_client()
        response = ec2.describe_instances(
            Filters=[
                {
                    "Name": "instance-state-name",
                    "Values": ["running", "pending", "stopping", "stopped"],
                }
            ]
        )

        instances = []
        for reservation in response["Reservations"]:
            for instance in reservation["Instances"]:
                name = next(
                    (
                        tag["Value"]
                        for tag in instance.get("Tags", [])
                        if tag["Key"] == "Name"
                    ),
                    instance["InstanceId"],
                )
                instances.append(
                    {
                        "name": name,
                        "ip": instance.get("PublicIpAddress", "N/A"),
                        "status": instance["State"]["Name"],
                        "region": instance["Placement"]["AvailabilityZone"],
                    }
                )

        return instances

    def setup_dns(self, domain: str, ip: str) -> None:
        self.validate_auth()
        route53 = self._get_route53_client()

        response = route53.list_hosted_zones()
        zone_id = None
        for zone in response["HostedZones"]:
            if zone["Name"] == f"{domain}." or zone["Name"] == domain:
                zone_id = zone["Id"]
                break

        if not zone_id:
            error(f"No Route53 hosted zone found for domain: '{domain}'")

        profile = self.aws_config.get("profile_name", "default")
        log(f"Updating Route53 DNS records for '{domain}' (profile: {profile})...")

        for record_name in [domain, f"www.{domain}"]:
            change_batch = {
                "Changes": [
                    {
                        "Action": "UPSERT",
                        "ResourceRecordSet": {
                            "Name": record_name,
                            "Type": "A",
                            "TTL": 300,
                            "ResourceRecords": [{"Value": ip}],
                        },
                    }
                ]
            }

            route53.change_resource_record_sets(
                HostedZoneId=zone_id,
                ChangeBatch=change_batch,
            )

        log("DNS records updated")

    def cleanup_resources(self, *, dry_run: bool = True) -> None:
        """Cleanup orphaned security groups not attached to running instances.

        :param dry_run: Show what would be deleted without deleting
        """
        self.validate_auth()
        ec2 = self._get_ec2_client()
        region = self.aws_config.get("region_name", "ap-southeast-2")

        log(f"Scanning for orphaned security groups in '{region}'...")

        try:
            sgs = ec2.describe_security_groups(
                Filters=[
                    {"Name": "group-name", "Values": ["deploy-vm-web"]},
                ]
            )["SecurityGroups"]
        except Exception as e:
            error(f"Failed to list security groups: {e}")

        if not sgs:
            log("No deploy-vm security groups found")
            return

        for sg in sgs:
            sg_id = sg["GroupId"]
            sg_name = sg["GroupName"]

            try:
                instances = ec2.describe_instances(
                    Filters=[
                        {"Name": "instance.group-id", "Values": [sg_id]},
                        {
                            "Name": "instance-state-name",
                            "Values": ["running", "pending", "stopping"],
                        },
                    ]
                )["Reservations"]

                if instances:
                    instance_count = sum(len(r["Instances"]) for r in instances)
                    log(
                        f"Security group '{sg_name}' ('{sg_id}') in use by {instance_count} instance(s)"
                    )
                else:
                    if dry_run:
                        log(
                            f"[DRY RUN] Would delete unused security group: '{sg_name}' ('{sg_id}')"
                        )
                    else:
                        ec2.delete_security_group(GroupId=sg_id)
                        log(f"✓ Deleted security group: '{sg_name}' ('{sg_id}')")
            except ClientError as e:
                if "DependencyViolation" in str(e):
                    log(f"Security group '{sg_name}' ('{sg_id}') is still in use")
                else:
                    log(f"[WARN] Could not process '{sg_name}': {e}")

        if dry_run:
            log("\nRun with --no-dry-run to actually delete resources")


class VultrProvider:
    """Cloud provider implementation for Vultr VPS."""

    VM_SIZES = [
        "vc2-1c-1gb",
        "vc2-1c-2gb",
        "vc2-2c-4gb",
        "vc2-4c-8gb",
        "vc2-6c-16gb",
    ]

    REGIONS = [
        "syd",
        "sgp",
        "ewr",
        "ord",
        "lax",
        "dfw",
        "sea",
        "lhr",
        "fra",
        "ams",
        "tor",
        "blr",
    ]

    # Ubuntu 24.04 LTS
    DEFAULT_OS_ID = 2284

    def __init__(
        self,
        os_image: str | None = None,
        region: str | None = None,
        vm_size: str | None = None,
    ):
        self.provider_name: ProviderName = "vultr"
        self.region = region or "syd"
        self.os_id = int(os_image) if os_image else self.DEFAULT_OS_ID
        self.vm_size = vm_size or "vc2-1c-1gb"

        if self.vm_size not in self.VM_SIZES:
            error(
                f"Invalid Vultr VM size: '{self.vm_size}'\n"
                f"Valid sizes: '{', '.join(self.VM_SIZES)}'"
            )

    def validate_auth(self) -> None:
        """Validate Vultr authentication via vultr-cli.

        :raises SystemExit: If authentication validation fails
        """
        result = subprocess.run(
            ["vultr-cli", "version"], capture_output=True, text=True
        )
        if result.returncode != 0:
            error("vultr-cli not authenticated or not installed. Check your API key.")

    def instance_exists(self, name: str) -> bool:
        """Check if an instance with the given label exists.

        :param name: The instance label to check
        :return: True if instance exists, False otherwise
        """
        result = run_cmd_json("vultr-cli", "instance", "list")
        instances = result.get("instances") or []
        return any(i["label"] == name for i in instances)

    def get_instance_by_name(self, name: str) -> dict | None:
        """Get instance info by label.

        :param name: The instance label to find
        :return: Dictionary with 'id' and 'ip' keys, or None if not found
        """
        result = run_cmd_json("vultr-cli", "instance", "list")
        instances = result.get("instances") or []
        inst = next((i for i in instances if i["label"] == name), None)
        if not inst:
            return None
        return {"id": inst["id"], "ip": inst["main_ip"]}

    def _ensure_ssh_key(self) -> str:
        """Ensure SSH key exists in Vultr, upload if needed. Matches by content.

        :return: Vultr SSH key ID
        :raises SystemExit: If key cannot be uploaded or found
        """
        key_content, fingerprint = get_local_ssh_key()
        result = run_cmd_json("vultr-cli", "ssh-key", "list")
        keys = result.get("ssh_keys") or []

        match = next(
            (k for k in keys if k["ssh_key"].strip() == key_content.strip()), None
        )
        if match:
            log(f"Found matching SSH key in Vultr: '{match['name']}'")
            return match["id"]

        key_name = f"deploy-vm-{fingerprint[-8:]}"
        log("Uploading SSH key to Vultr...")
        run_cmd(
            "vultr-cli", "ssh-key", "create",
            "--name", key_name,
            "--key", key_content,
        )

        result = run_cmd_json("vultr-cli", "ssh-key", "list")
        keys = result.get("ssh_keys") or []
        uploaded = next(
            (k for k in keys if k["ssh_key"].strip() == key_content.strip()), None
        )
        if not uploaded:
            error("Failed to upload SSH key to Vultr")
        log(f"Uploaded SSH key: '{key_name}'")
        return uploaded["id"]

    def _ensure_firewall_group(self) -> str:
        """Ensure firewall group exists with correct rules; update SSH CIDR if changed.

        :return: Vultr firewall group ID
        :raises SystemExit: If firewall group cannot be created or rules cannot be set
        """
        group_name = "deploy-vm-web"

        result = run_cmd_json("vultr-cli", "firewall", "group", "list")
        groups = result.get("firewall-groups") or []
        group = next(
            (g for g in groups if g.get("description") == group_name), None
        )

        if group:
            group_id = group["id"]
            log(f"Using existing firewall group: '{group_name}'")
        else:
            log(f"Creating firewall group: '{group_name}'...")
            run_cmd(
                "vultr-cli", "firewall", "group", "create",
                "--description", group_name,
            )
            result = run_cmd_json("vultr-cli", "firewall", "group", "list")
            groups = result.get("firewall-groups") or []
            group = next(
                (g for g in groups if g.get("description") == group_name), None
            )
            if not group:
                error(f"Failed to create firewall group '{group_name}'")
            group_id = group["id"]
            log(f"Created firewall group: '{group_name}' ('{group_id}')")

        rules_result = run_cmd_json("vultr-cli", "firewall", "rule", "list", group_id)
        rules = rules_result.get("firewall_rules") or []

        def _has_port_rule(port: str) -> bool:
            return any(str(r.get("port")) == port for r in rules)

        if not _has_port_rule("80"):
            run_cmd(
                "vultr-cli", "firewall", "rule", "create",
                "--id", group_id,
                "--ip-type", "v4",
                "--protocol", "tcp",
                "--port", "80",
                "--subnet", "0.0.0.0",
                "--size", "0",
            )
            log("Added HTTP (port 80) firewall rule")

        if not _has_port_rule("443"):
            run_cmd(
                "vultr-cli", "firewall", "rule", "create",
                "--id", group_id,
                "--ip-type", "v4",
                "--protocol", "tcp",
                "--port", "443",
                "--subnet", "0.0.0.0",
                "--size", "0",
            )
            log("Added HTTPS (port 443) firewall rule")

        my_ip = _get_my_ip()
        if my_ip:
            ssh_subnet = my_ip
            ssh_size = 32
        else:
            ssh_subnet = "0.0.0.0"
            ssh_size = 0

        ssh_rules = [r for r in rules if str(r.get("port")) == "22"]
        needs_new_ssh = False

        if ssh_rules:
            existing = ssh_rules[0]
            if (
                existing.get("subnet") != ssh_subnet
                or existing.get("subnet_size") != ssh_size
            ):
                run_cmd(
                    "vultr-cli", "firewall", "rule", "delete",
                    group_id, str(existing["id"]),
                )
                log(f"Removed outdated SSH rule")
                needs_new_ssh = True
        else:
            needs_new_ssh = True

        if needs_new_ssh:
            run_cmd(
                "vultr-cli", "firewall", "rule", "create",
                "--id", group_id,
                "--ip-type", "v4",
                "--protocol", "tcp",
                "--port", "22",
                "--subnet", ssh_subnet,
                "--size", str(ssh_size),
            )
            log(f"Added SSH (port 22) firewall rule for '{ssh_subnet}/{ssh_size}'")

        return group_id

    def create_instance(
        self, name: str, region: str, vm_size: str, iam_role: str | None = None
    ) -> dict:
        """Create a new Vultr instance.

        :param name: The label for the new instance
        :param region: The Vultr region slug (e.g., 'syd')
        :param vm_size: The plan ID (e.g., 'vc2-1c-1gb')
        :param iam_role: Unused for Vultr (AWS compatibility parameter)
        :return: Dictionary with 'id' and 'ip' keys for the created instance
        :raises SystemExit: If instance already exists, creation fails, or timeout
        """
        self.validate_auth()

        if self.instance_exists(name):
            error(f"Instance '{name}' already exists")

        ssh_key_id = self._ensure_ssh_key()
        firewall_group_id = self._ensure_firewall_group()

        log(f"Creating Vultr instance '{name}' ({vm_size}) in '{region}'...")
        run_cmd(
            "vultr-cli", "instance", "create",
            "--label", name,
            "--region", region,
            "--plan", vm_size,
            "--os", str(self.os_id),
            "--ssh-keys", ssh_key_id,
            "--firewall-group", firewall_group_id,
        )

        result = run_cmd_json("vultr-cli", "instance", "list")
        instances = result.get("instances") or []
        inst = next((i for i in instances if i["label"] == name), None)
        if not inst:
            error(f"Failed to find newly created instance '{name}'")
        instance_id = inst["id"]

        log("Waiting for instance to become active...")
        start = time.time()
        while time.time() - start < 300:
            result = run_cmd_json("vultr-cli", "instance", "get", instance_id)
            inst = result["instance"]
            if (
                inst["status"] == "active"
                and inst.get("main_ip")
                and inst["main_ip"] != "0.0.0.0"
            ):
                return {"id": instance_id, "ip": inst["main_ip"]}
            if inst["status"] in ("stopped", "error"):
                error(f"Instance entered state '{inst['status']}'")
            time.sleep(10)
        error("Timeout waiting for instance to become active")

    def delete_instance(self, instance_id: str) -> None:
        """Delete a Vultr instance by ID.

        :param instance_id: The instance ID to delete
        :raises SystemExit: If deletion fails
        """
        self.validate_auth()
        run_cmd("vultr-cli", "instance", "delete", str(instance_id))

    def list_instances(self) -> list[dict]:
        """List all Vultr instances in the account.

        :return: List of dictionaries with 'name', 'ip', 'status', and 'region' keys
        :raises SystemExit: If authentication fails
        """
        self.validate_auth()
        result = run_cmd_json("vultr-cli", "instance", "list")
        instances = result.get("instances") or []
        return [
            {
                "name": i["label"],
                "ip": i["main_ip"],
                "status": i["status"],
                "region": i["region"],
            }
            for i in instances
        ]

    def setup_dns(self, domain: str, ip: str) -> None:
        """Stub: Vultr DNS management not implemented.

        :param domain: Domain to configure
        :param ip: IP address to point domain to
        """
        warn(
            f"Vultr DNS management not implemented. "
            f"Configure DNS manually to point '{domain}' to '{ip}'."
        )

    def cleanup_resources(self, *, dry_run: bool = True) -> None:
        """Cleanup orphaned firewall groups not attached to any instance.

        :param dry_run: Show what would be deleted without deleting
        """
        self.validate_auth()

        result = run_cmd_json("vultr-cli", "firewall", "group", "list")
        groups = result.get("firewall-groups") or []
        managed = [
            g for g in groups
            if g.get("description", "").startswith("deploy-vm")
        ]

        inst_result = run_cmd_json("vultr-cli", "instance", "list")
        instances = inst_result.get("instances") or []
        used_group_ids = {
            i["firewall_group_id"]
            for i in instances
            if i.get("firewall_group_id")
        }

        for group in managed:
            group_id = group["id"]
            description = group.get("description", "")
            if group_id not in used_group_ids:
                if dry_run:
                    log(
                        f"[DRY RUN] Would delete orphaned firewall group: "
                        f"'{description}' ('{group_id}')"
                    )
                else:
                    run_cmd("vultr-cli", "firewall", "group", "delete", group_id)
                    log(f"Deleted firewall group: '{description}' ('{group_id}')")

        if dry_run:
            log("Run with --no-dry-run to actually delete resources")


def check_aws_auth(profile: str | None = None) -> None:
    """Validate AWS credentials, fail fast with clear error if expired or invalid.

    :param profile: AWS profile name to check (uses default chain if None)
    :raises SystemExit: If credentials are missing, expired, or invalid
    """
    aws_config = {}
    if profile:
        aws_config["profile_name"] = profile

    try:
        session = boto3.Session(**aws_config)
        sts = session.client("sts")
        sts.get_caller_identity()
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code in ("ExpiredToken", "ExpiredTokenException"):
            login_cmd = f"aws sso login --profile {profile}" if profile else "aws sso login"
            error(f"AWS credentials expired. Run:\n  {login_cmd}")
        else:
            error(f"AWS authentication failed ({error_code}): {e}")
    except Exception as e:
        error(f"AWS authentication failed: {e}")


def get_provider(
    provider: ProviderName | None = None,
    *,
    region: str | None = None,
    os_image: str | None = None,
    vm_size: str | None = None,
    aws_profile: str | None = None,
) -> Provider:
    """Get a provider instance with defaults applied."""
    if provider is None:
        load_dotenv()
        provider = os.getenv("DEPLOY_VM_PROVIDER", "digitalocean")
        if provider not in ["digitalocean", "aws", "vultr"]:
            log(
                f"[WARN] Invalid DEPLOY_VM_PROVIDER '{provider}', using 'digitalocean'"
            )
            provider = "digitalocean"
    elif provider not in ["digitalocean", "aws", "vultr"]:
        error(f"Unknown provider: {provider}. Available: digitalocean, aws, vultr")

    if provider == "digitalocean":
        return DigitalOceanProvider(os_image=os_image, region=region, vm_size=vm_size)
    elif provider == "vultr":
        return VultrProvider(os_image=os_image, region=region, vm_size=vm_size)
    else:  # aws
        return AWSProvider(os_image=os_image, region=region, vm_size=vm_size, aws_profile=aws_profile)
