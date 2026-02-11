"""Cloud provider abstractions for DigitalOcean and AWS."""

import base64
import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Protocol

import boto3
from botocore.exceptions import ClientError, ProfileNotFound
from dotenv import load_dotenv

from .utils import error, log, run_cmd, run_cmd_json, warn

ProviderName = Literal["digitalocean", "aws"]

PROVIDER_OPTIONS = {
    "digitalocean": {
        "regions": [
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
        ],
        "vm_sizes": [
            "s-1vcpu-512mb",
            "s-1vcpu-1gb",
            "s-1vcpu-2gb",
            "s-2vcpu-2gb",
            "s-2vcpu-4gb",
            "s-4vcpu-8gb",
        ],
        "os_images": ["ubuntu-24-04-x64", "ubuntu-22-04-x64", "ubuntu-20-04-x64"],
    },
    "aws": {
        "regions": [
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
        ],
        "vm_sizes": [
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
        ],
        "os_images": [
            "ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*",
            "ubuntu/images/hvm-ssd/ubuntu-noble-24.04-amd64-server-*",
        ],
    },
}


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
            log(f"Using SSH key: {key_path}")
            return content, fingerprint

    error(f"No SSH key found in ~/.ssh/ (tried: {', '.join(key_names)})")


class Provider(Protocol):
    provider_name: ProviderName
    region: str
    os_image: str
    vm_size: str

    def validate_auth(self) -> None: ...

    def validate_config(self) -> None: ...

    def instance_exists(self, name: str) -> bool: ...

    def create_instance(
        self, name: str, region: str, vm_size: str, iam_role: str | None = None
    ) -> dict: ...

    def delete_instance(self, instance_id: str) -> None: ...

    def list_instances(self) -> list[dict]: ...

    def setup_dns(self, domain: str, ip: str) -> None: ...

    def cleanup_resources(self, *, dry_run: bool = True) -> None: ...


class DigitalOceanProvider:
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
        self.validate_config()

    def validate_auth(self) -> None:
        result = subprocess.run(
            ["doctl", "auth", "validate"], capture_output=True, text=True
        )
        if result.returncode != 0:
            error("doctl not authenticated. Run: doctl auth init")

    def validate_config(self) -> None:
        if (
            self.vm_size.startswith("t3.")
            or self.vm_size.startswith("t4g.")
            or self.vm_size.startswith("m5.")
        ):
            error(
                f"VM size '{self.vm_size}' is an AWS instance type, not DigitalOcean.\n"
                f"DigitalOcean sizes: s-1vcpu-1gb, s-2vcpu-2gb, s-4vcpu-8gb, etc.\n"
                f"See PROVIDER_COMPARISON.md for size mappings."
            )

    def instance_exists(self, name: str) -> bool:
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
        self.validate_auth()

        if self.instance_exists(name):
            error(f"Droplet '{name}' already exists")

        key_content, fingerprint = get_local_ssh_key()
        keys = run_cmd_json("doctl", "compute", "ssh-key", "list")

        existing = next((k for k in keys if k["fingerprint"] == fingerprint), None)
        if existing:
            ssh_key_id = str(existing["id"])
            log(f"Found matching SSH key in DigitalOcean: {existing['name']}")
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
            log(f"Uploaded SSH key: {key_name}")

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
        self.validate_auth()
        run_cmd("doctl", "compute", "droplet", "delete", str(instance_id), "--force")

    def list_instances(self) -> list[dict]:
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
    def __init__(
        self,
        os_image: str | None = None,
        region: str | None = None,
        vm_size: str | None = None,
    ):
        self.provider_name: ProviderName = "aws"
        self.os_image = (
            os_image or "ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"
        )
        self.vm_size = vm_size or "t3.micro"
        self.aws_config = AWSProvider.get_aws_config(is_raise_exception=False)

        if region:
            self.aws_config["region_name"] = region

        region = region or self.aws_config.get("region_name", "ap-southeast-2")
        self.region = self._validate_and_normalize_region(region)

        if not self.aws_config:
            error(
                "AWS credentials not configured. Please run:\n"
                "  aws configure\n"
                "Or set environment variables:\n"
                "  export AWS_PROFILE=your-profile\n"
                "  export AWS_REGION=ap-southeast-2"
            )

        self.validate_config()

    @staticmethod
    def get_aws_config(is_raise_exception: bool = True):
        """Get AWS configuration for boto3 client initialization.

        Searches AWS_PROFILE and AWS_REGION environment variables, validates
        credentials via STS GetCallerIdentity, and checks token expiration.

        :return: Dict with profile_name and region_name keys
        """
        load_dotenv()

        aws_config = {}

        profile_name = os.getenv("AWS_PROFILE")
        if profile_name:
            aws_config["profile_name"] = profile_name

        region = os.getenv("AWS_REGION")
        if region:
            aws_config["region_name"] = region

        try:
            aws_credentials_path = os.path.expanduser("~/.aws/credentials")
            if not os.path.exists(aws_credentials_path):
                log("No AWS credentials file at ~/.aws/credentials")
                return aws_config

            session = (
                boto3.Session(profile_name=profile_name)
                if profile_name
                else boto3.Session()
            )
            credentials = session.get_credentials()

            if not credentials or not credentials.access_key or not credentials.secret_key:
                return aws_config

            sts = session.client("sts")
            _ = sts.get_caller_identity()

            if hasattr(credentials, "token"):
                creds = credentials.get_frozen_credentials()
                if hasattr(creds, "expiry_time") and creds.expiry_time < datetime.now(
                    timezone.utc
                ):
                    warn(f"AWS credentials expired on {creds.expiry_time}")
                    return aws_config

        except ProfileNotFound:
            if is_raise_exception:
                raise
            warn(f"AWS profile '{profile_name}' not found")
        except ClientError as e:
            if is_raise_exception:
                raise
            error_code = e.response["Error"]["Code"]
            if error_code == "ExpiredToken":
                warn("AWS credentials have expired")
            elif error_code == "InvalidClientTokenId":
                warn("AWS credentials are invalid. Please reconfigure:\n  aws configure\n")
            else:
                warn(f"AWS API error: {error_code}")
        except Exception as e:
            if is_raise_exception:
                raise
            warn(f"AWS credential check failed: {e}")

        return aws_config

    def validate_auth(self) -> None:
        try:
            session = boto3.Session(**self.aws_config)
            sts = session.client("sts")
            sts.get_caller_identity()
        except Exception as e:
            error(f"AWS authentication failed: {e}")

    def _validate_and_normalize_region(self, region: str) -> str:
        """Validate and normalize AWS region (converts AZ to region if needed)."""
        valid_regions = PROVIDER_OPTIONS["aws"]["regions"]

        if region and region[-1].isalpha() and region[:-1] in valid_regions:
            normalized_region = region[:-1]
            log(
                f"Converted availability zone '{region}' to region '{normalized_region}'"
            )
            return normalized_region

        if region not in valid_regions:
            error(
                f"Invalid AWS region: '{region}'\n"
                f"Valid AWS regions: {', '.join(valid_regions[:6])}, ...\n"
                f"See PROVIDER_COMPARISON.md for full list."
            )

        return region

    def validate_config(self) -> None:
        if self.vm_size.startswith("s-"):
            error(
                f"VM size '{self.vm_size}' is a DigitalOcean size, not AWS.\n"
                f"AWS instance types: t3.micro, t3.small, t3.medium, t3.large, etc.\n"
                f"See PROVIDER_COMPARISON.md for size mappings."
            )

    def _get_ec2_client(self):
        session = boto3.Session(**self.aws_config)
        return session.client("ec2")

    def _get_route53_client(self):
        session = boto3.Session(**self.aws_config)
        return session.client("route53")

    def _validate_vpc(self, ec2, vpc_id: str) -> tuple[bool, str | None]:
        """:return: (is_valid, error_message)"""
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

    def _get_my_ip(self) -> str:
        try:
            import urllib.request

            response = urllib.request.urlopen("https://api.ipify.org", timeout=5)
            return response.read().decode("utf8")
        except Exception:
            log(
                "[WARN] Could not determine your public IP, using 0.0.0.0/0 for SSH access"
            )
            return None

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
            error(f"No AMI found matching pattern: {self.os_image}")

        images = sorted(
            response["Images"], key=lambda x: x["CreationDate"], reverse=True
        )
        return images[0]["ImageId"]

    def _get_iam_client(self):
        return boto3.client("iam", **self.aws_config)

    def _ensure_iam_role_and_profile(self, role_name: str) -> str:
        """Ensure IAM role and instance profile exist, return instance profile name.

        Creates:
        1. IAM role with EC2 trust policy
        2. Attaches AmazonBedrockFullAccess policy
        3. Instance profile with same name
        4. Adds role to instance profile

        Returns the instance profile name (same as role name).
        """
        iam = self._get_iam_client()

        # EC2 assume role trust policy
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

        # Create IAM role if it doesn't exist
        try:
            iam.get_role(RoleName=role_name)
            log(f"Using existing IAM role: {role_name}")
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                log(f"Creating IAM role: {role_name}")
                iam.create_role(
                    RoleName=role_name,
                    AssumeRolePolicyDocument=json.dumps(trust_policy),
                    Description=f"Role for deploy-vm managed instances (Bedrock access)",
                    Tags=[
                        {"Key": "ManagedBy", "Value": "deploy-vm"},
                        {"Key": "CreatedAt", "Value": datetime.now(timezone.utc).isoformat()},
                    ]
                )
                log(f"Created IAM role: {role_name}")
            else:
                raise

        # Attach AmazonBedrockFullAccess managed policy
        bedrock_policy_arn = "arn:aws:iam::aws:policy/AmazonBedrockFullAccess"
        try:
            iam.attach_role_policy(RoleName=role_name, PolicyArn=bedrock_policy_arn)
            log(f"Attached AmazonBedrockFullAccess policy to {role_name}")
        except ClientError as e:
            if e.response["Error"]["Code"] != "EntityAlreadyExists":
                # Policy might already be attached, that's fine
                pass

        # Create instance profile if it doesn't exist
        profile_name = role_name
        try:
            iam.get_instance_profile(InstanceProfileName=profile_name)
            log(f"Using existing instance profile: {profile_name}")
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                log(f"Creating instance profile: {profile_name}")
                iam.create_instance_profile(
                    InstanceProfileName=profile_name,
                    Tags=[
                        {"Key": "ManagedBy", "Value": "deploy-vm"},
                        {"Key": "CreatedAt", "Value": datetime.now(timezone.utc).isoformat()},
                    ]
                )
                log(f"Created instance profile: {profile_name}")
            else:
                raise

        # Add role to instance profile
        try:
            iam.add_role_to_instance_profile(
                InstanceProfileName=profile_name,
                RoleName=role_name
            )
            log(f"Added role {role_name} to instance profile")
        except ClientError as e:
            if e.response["Error"]["Code"] != "LimitExceeded":
                # Role might already be in profile, that's fine
                pass

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
        log(f"Using AMI: {ami_id}")

        # Setup IAM role if specified
        instance_profile_name = None
        if iam_role:
            instance_profile_name = self._ensure_iam_role_and_profile(iam_role)

        key_content, fingerprint = get_local_ssh_key()
        key_name = f"deploy-vm-{fingerprint[-8:]}"

        try:
            ec2.describe_key_pairs(KeyNames=[key_name])
            log(f"Using existing SSH key: {key_name}")
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidKeyPair.NotFound":
                log("Uploading SSH key to AWS...")
                ec2.import_key_pair(KeyName=key_name, PublicKeyMaterial=key_content)
                log(f"Uploaded SSH key: {key_name}")
            else:
                raise

        sg_name = "deploy-vm-web"
        try:
            response = ec2.describe_security_groups(
                Filters=[{"Name": "group-name", "Values": [sg_name]}]
            )
            if response["SecurityGroups"]:
                sg_id = response["SecurityGroups"][0]["GroupId"]
                log(f"Using existing security group: {sg_name}")
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
                    error(
                        "No VPC found in this region. Please create a VPC first:\n"
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

                log(f"Using VPC: {vpc_id}")

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
                    log(f"Restricting SSH access to your IP: {my_ip}")

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
                log(f"Created security group: {sg_name}")
            else:
                raise

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
            log(f"Attaching IAM instance profile: {instance_profile_name}")

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

        return {"id": instance_id, "ip": ip}

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
            error(f"No Route53 hosted zone found for domain: {domain}")

        log(f"Updating Route53 DNS records for {domain}...")

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

        log(f"Scanning for orphaned security groups in {region}...")

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
                        f"Security group {sg_name} ({sg_id}) in use by {instance_count} instance(s)"
                    )
                else:
                    if dry_run:
                        log(
                            f"[DRY RUN] Would delete unused security group: {sg_name} ({sg_id})"
                        )
                    else:
                        ec2.delete_security_group(GroupId=sg_id)
                        log(f"✓ Deleted security group: {sg_name} ({sg_id})")
            except ClientError as e:
                if "DependencyViolation" in str(e):
                    log(f"Security group {sg_name} ({sg_id}) is still in use")
                else:
                    log(f"[WARN] Could not process {sg_name}: {e}")

        if dry_run:
            log("\nRun with --no-dry-run to actually delete resources")


def get_provider(
    provider_name: ProviderName | None = None,
    *,
    region: str | None = None,
    os_image: str | None = None,
    vm_size: str | None = None,
) -> Provider:
    """Get a provider instance with defaults applied."""
    if provider_name is None:
        load_dotenv()
        provider_name = os.getenv("DEPLOY_VM_PROVIDER", "digitalocean")
        if provider_name not in ["digitalocean", "aws"]:
            log(
                f"[WARN] Invalid DEPLOY_VM_PROVIDER '{provider_name}', using 'digitalocean'"
            )
            provider_name = "digitalocean"
    elif provider_name not in ["digitalocean", "aws"]:
        error(f"Unknown provider: {provider_name}. Available: digitalocean, aws")

    if provider_name == "digitalocean":
        return DigitalOceanProvider(os_image=os_image, region=region, vm_size=vm_size)
    else:  # aws
        return AWSProvider(os_image=os_image, region=region, vm_size=vm_size)
