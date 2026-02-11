"""Type definitions for deploy-vm."""

from typing import Literal, TypedDict

ProviderName = Literal["digitalocean", "aws"]
AppType = Literal["nuxt", "fastapi"]


class AppInfo(TypedDict, total=False):
    """Application information stored in instance."""

    name: str
    type: AppType
    port: int


class InstanceData(TypedDict, total=False):
    """Instance data stored in .instance.json files."""

    id: str | int
    ip: str
    provider: ProviderName
    region: str
    os_image: str
    vm_size: str
    user: str
    iam_role: str  # AWS only: IAM role name for instance profile
    apps: list[AppInfo]


class InstanceResult(TypedDict):
    """Result from creating an instance."""

    id: str | int
    ip: str


class InstanceListItem(TypedDict):
    """Instance information in list results."""

    name: str
    ip: str
    status: str
    region: str
