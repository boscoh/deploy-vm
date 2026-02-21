"""Session-scoped fixture for integration tests against a real cloud instance."""

import pytest
from pathlib import Path
from uuid import uuid4

from deployvm.providers import get_provider
from deployvm.server import load_instance, save_instance, setup_server, wait_for_ssh
from deployvm.utils import get_ssh_user


def pytest_addoption(parser):
    parser.addoption(
        "--provider",
        default="vultr",
        help="Cloud provider for integration tests (default: vultr)",
    )


@pytest.fixture(scope="session")
def provider_name(request):
    return request.config.getoption("--provider")


@pytest.fixture(scope="session")
def live_instance(provider_name):
    """Create a real cloud instance, set it up, yield its name, delete on teardown."""
    name = f"test-deployvm-{uuid4().hex[:8]}"
    user = "deploy"

    p = get_provider(provider_name)
    p.validate_auth()

    result = p.create_instance(name, p.region, p.vm_size)
    ssh_user = get_ssh_user(provider_name)

    instance_data = {
        "id": result["id"],
        "ip": result["ip"],
        "provider": provider_name,
        "region": p.region,
        "vm_size": p.vm_size,
        "user": user,
        "apps": [],
    }
    save_instance(name, instance_data)

    wait_for_ssh(result["ip"], user=ssh_user)
    setup_server(result["ip"], user=user, ssh_user=ssh_user)

    try:
        yield name
    finally:
        try:
            current_data = load_instance(name)
            p2 = get_provider(provider_name)
            p2.delete_instance(current_data["id"])
        except (Exception, SystemExit):
            pass
        Path(f"{name}.instance.json").unlink(missing_ok=True)
