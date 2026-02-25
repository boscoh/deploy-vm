"""Session-scoped fixture for integration tests against a real cloud instance."""

import pytest
from pathlib import Path
from uuid import uuid4

from deployvm.providers import get_provider
from deployvm.server import load_instance, save_instance, setup_server, wait_for_ssh
from deployvm.utils import get_ssh_user

MAX_INSTANCE_RETRIES = 5
ALL_PROVIDERS = ["digitalocean", "vultr", "aws"]


def pytest_addoption(parser):
    parser.addoption(
        "--provider",
        default="vultr",
        help="Cloud provider for integration tests (default: vultr, use 'all' to run on all authenticated providers)",
    )


def _get_available_providers() -> list[str]:
    """Return providers that pass validate_auth."""
    available = []
    for name in ALL_PROVIDERS:
        try:
            p = get_provider(name)
            p.validate_auth()
            available.append(name)
        except (SystemExit, Exception):
            pass
    return available


def pytest_generate_tests(metafunc):
    if "provider_name" in metafunc.fixturenames:
        provider = metafunc.config.getoption("--provider")
        if provider == "all":
            providers = _get_available_providers()
            if not providers:
                pytest.skip("No authenticated providers found")
        else:
            providers = [provider]
        metafunc.parametrize("provider_name", providers, scope="session")


@pytest.fixture(scope="session")
def live_instance(provider_name):
    """Create a real cloud instance, set it up, yield its name, delete on teardown.

    Retries up to MAX_INSTANCE_RETRIES times if SSH setup fails (e.g. bad IP).
    """
    user = "deploy"
    ssh_user = get_ssh_user(provider_name)

    name = None
    instance_id = None

    for attempt in range(1, MAX_INSTANCE_RETRIES + 1):
        name = f"test-deployvm-{uuid4().hex[:8]}"
        p = get_provider(provider_name)
        p.validate_auth()

        print(f"\n[INFO] Creating instance (attempt {attempt}/{MAX_INSTANCE_RETRIES})...")
        result = p.create_instance(name, p.region, p.vm_size)
        instance_id = result["id"]

        instance_data = {
            "id": instance_id,
            "ip": result["ip"],
            "provider": provider_name,
            "region": p.region,
            "vm_size": p.vm_size,
            "user": user,
            "apps": [],
        }
        save_instance(name, instance_data)

        try:
            wait_for_ssh(result["ip"], user=ssh_user)
            setup_server(result["ip"], user=user, ssh_user=ssh_user)
            break  # success
        except SystemExit:
            print(f"[WARN] Instance {name} ({result['ip']}) failed SSH setup, deleting...")
            try:
                p2 = get_provider(provider_name)
                p2.delete_instance(instance_id)
            except (Exception, SystemExit):
                pass
            Path(f"{name}.instance.json").unlink(missing_ok=True)
            name = None
            if attempt == MAX_INSTANCE_RETRIES:
                pytest.fail(f"Failed to get a working instance after {MAX_INSTANCE_RETRIES} attempts")

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


@pytest.fixture(scope="session")
def npm_live_instance(provider_name):
    """Separate session-scoped instance for npm integration tests.

    Keeps npm tests isolated from test_integration.py's test_08_delete.
    """
    user = "deploy"
    ssh_user = get_ssh_user(provider_name)

    name = None
    instance_id = None

    for attempt in range(1, MAX_INSTANCE_RETRIES + 1):
        name = f"test-npm-{uuid4().hex[:8]}"
        p = get_provider(provider_name)
        p.validate_auth()

        print(f"\n[INFO] Creating npm instance (attempt {attempt}/{MAX_INSTANCE_RETRIES})...")
        result = p.create_instance(name, p.region, p.vm_size)
        instance_id = result["id"]

        instance_data = {
            "id": instance_id,
            "ip": result["ip"],
            "provider": provider_name,
            "region": p.region,
            "vm_size": p.vm_size,
            "user": user,
            "apps": [],
        }
        save_instance(name, instance_data)

        try:
            wait_for_ssh(result["ip"], user=ssh_user)
            setup_server(result["ip"], user=user, ssh_user=ssh_user)
            break
        except SystemExit:
            print(f"[WARN] Instance {name} ({result['ip']}) failed SSH setup, deleting...")
            try:
                p2 = get_provider(provider_name)
                p2.delete_instance(instance_id)
            except (Exception, SystemExit):
                pass
            Path(f"{name}.instance.json").unlink(missing_ok=True)
            name = None
            if attempt == MAX_INSTANCE_RETRIES:
                pytest.fail(f"Failed to get a working npm instance after {MAX_INSTANCE_RETRIES} attempts")

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
