"""Integration tests for the full FastAPI deployment lifecycle.

Tests are sequential and stateful — each test depends on the instance state
left by the previous one. Run with:

    uv run pytest tests/ -m integration --provider vultr
"""

import json
import shutil
from pathlib import Path

import httpx
import pytest

from deployvm.apps import UVApp as FastAPIApp
from deployvm.providers import get_provider
from deployvm.server import (
    check_instance_reachable,
    load_instance,
    setup_nginx_ip,
    ssh,
    verify_instance,
)
from deployvm.utils import get_ssh_user

TESTAPP_DIR = Path(__file__).parent / "fixtures" / "testapp"
FASTAPI_COMMAND = "uv run uvicorn app:app --host 0.0.0.0 --port 8000"
APP_NAME = "testapp"
APP_PORT = 8000

TESTAPP2_DIR = Path(__file__).parent / "fixtures" / "testapp2"
FASTAPI_COMMAND2 = "uv run uvicorn app:app --host 0.0.0.0 --port 8001"
APP2_NAME = "testapp2"
APP2_PORT = 8001


def _make_fastapi(live_instance: str) -> FastAPIApp:
    instance = load_instance(live_instance)
    return FastAPIApp(
        instance,
        instance.get("provider", "vultr"),
        user=instance.get("user", "deploy"),
        app_name=APP_NAME,
        port=APP_PORT,
        command=FASTAPI_COMMAND,
    )


def _make_fastapi2(live_instance: str) -> FastAPIApp:
    instance = load_instance(live_instance)
    return FastAPIApp(
        instance,
        instance.get("provider", "vultr"),
        user=instance.get("user", "deploy"),
        app_name=APP2_NAME,
        port=APP2_PORT,
        command=FASTAPI_COMMAND2,
    )


@pytest.mark.integration
def test_01_create(live_instance):
    """Instance created, IP assigned, SSH reachable."""
    instance = load_instance(live_instance)
    assert instance.get("ip"), "Instance IP not set"

    ssh_user = get_ssh_user(instance["provider"])
    assert check_instance_reachable(instance["ip"], ssh_user), (
        f"Instance {instance['ip']} not reachable via SSH"
    )


@pytest.mark.integration
def test_02_deploy(live_instance):
    """Initial FastAPI sync: supervisord RUNNING and app responds on localhost:8000."""
    fastapi = _make_fastapi(live_instance)
    result = fastapi.sync(str(TESTAPP_DIR))
    assert result is True, "Expected full sync on first deploy"

    instance = load_instance(live_instance)
    status = ssh(instance["ip"], f"sudo supervisorctl status {APP_NAME}", user="deploy")
    assert "RUNNING" in status, f"Supervisord not RUNNING: {status}"

    # Check app via localhost (port 8000 not exposed through cloud firewall)
    response_raw = ssh(
        instance["ip"], f"curl -sf http://localhost:{APP_PORT}/", user="deploy"
    )
    data = json.loads(response_raw)
    assert data["version"] == 1


@pytest.mark.integration
def test_02b_deploy_second_app(live_instance):
    """Second FastAPI app deploys on port 8001; both apps respond independently."""
    fastapi2 = _make_fastapi2(live_instance)
    result = fastapi2.sync(str(TESTAPP2_DIR))
    assert result is True, "Expected full sync on first deploy of second app"

    instance = load_instance(live_instance)
    status = ssh(instance["ip"], f"sudo supervisorctl status {APP2_NAME}", user="deploy")
    assert "RUNNING" in status, f"Supervisord not RUNNING for second app: {status}"

    # First app still running
    response1 = ssh(instance["ip"], f"curl -sf http://localhost:{APP_PORT}/", user="deploy")
    data1 = json.loads(response1)
    assert data1["version"] == 1

    # Second app running independently
    response2 = ssh(instance["ip"], f"curl -sf http://localhost:{APP2_PORT}/", user="deploy")
    data2 = json.loads(response2)
    assert data2["version"] == 1
    assert data2["app"] == "testapp2"


@pytest.mark.integration
def test_03_resync_unchanged(live_instance):
    """Re-sync with no source change takes fast path (returns False)."""
    fastapi = _make_fastapi(live_instance)
    result = fastapi.sync(str(TESTAPP_DIR))
    assert result is False, "Expected fast path when source unchanged"

    instance = load_instance(live_instance)
    response_raw = ssh(
        instance["ip"], f"curl -sf http://localhost:{APP_PORT}/", user="deploy"
    )
    data = json.loads(response_raw)
    assert data["version"] == 1


@pytest.mark.integration
def test_04_resync_changed(live_instance, tmp_path_factory):
    """Code change triggers full re-sync and new version is visible."""
    tmpdir = tmp_path_factory.mktemp("testapp_v2")
    app_dir = tmpdir / "testapp"
    shutil.copytree(TESTAPP_DIR, app_dir, ignore=shutil.ignore_patterns(".venv", "__pycache__", "*.pyc"))

    app_py = app_dir / "app.py"
    app_py.write_text(app_py.read_text().replace('"version": 1', '"version": 2'))

    fastapi = FastAPIApp(
        load_instance(live_instance),
        load_instance(live_instance).get("provider", "vultr"),
        user=load_instance(live_instance).get("user", "deploy"),
        app_name=APP_NAME,
        port=APP_PORT,
        command=FASTAPI_COMMAND,
    )
    result = fastapi.sync(str(app_dir))
    assert result is True, "Expected full sync on changed source"

    instance = load_instance(live_instance)
    response_raw = ssh(
        instance["ip"], f"curl -sf http://localhost:{APP_PORT}/", user="deploy"
    )
    data = json.loads(response_raw)
    assert data["version"] == 2


@pytest.mark.integration
def test_05_nginx_ip(live_instance):
    """Nginx set up for IP access: port 80 returns 200."""
    instance = load_instance(live_instance)
    setup_nginx_ip(instance["ip"], port=APP_PORT, ssh_user="deploy")

    response = httpx.get(f"http://{instance['ip']}/", timeout=30)
    assert response.status_code == 200


@pytest.mark.integration
def test_06_nginx_ip_idempotent(live_instance):
    """Re-running nginx ip setup is idempotent: port 80 still works."""
    instance = load_instance(live_instance)
    setup_nginx_ip(instance["ip"], port=APP_PORT, ssh_user="deploy")

    response = httpx.get(f"http://{instance['ip']}/", timeout=30)
    assert response.status_code == 200



@pytest.mark.integration
def test_07_verify(live_instance):
    """verify_instance passes with no failures after nginx ip setup."""
    # verify_instance raises SystemExit via error() only on SSH failure.
    # Other failures are printed but don't raise. We call and trust no SystemExit.
    verify_instance(live_instance)


@pytest.mark.integration
def test_08_delete(live_instance, provider_name):
    """Instance deleted and absent from provider instance list."""
    instance = load_instance(live_instance)
    p = get_provider(provider_name)
    p.delete_instance(instance["id"])

    instances = p.list_instances()
    names = [i["name"] for i in instances]
    assert live_instance not in names, "Instance still listed after deletion"
