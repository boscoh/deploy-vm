"""Integration tests for the npm (Nuxt/Next.js) deployment lifecycle via PM2.

Tests are sequential and stateful — each test depends on the instance state
left by the previous one. Run with:

    uv run pytest tests/test_npm_integration.py -m integration -v --provider vultr
"""

import json
from pathlib import Path

import pytest

from deployvm.apps import NpmApp
from deployvm.server import load_instance, ssh

NUXTAPP_DIR = Path(__file__).parent / "fixtures" / "nuxtapp"
NUXT_APP_NAME = "nuxtapp"
NUXT_PORT = 3000

NEXTAPP_DIR = Path(__file__).parent / "fixtures" / "nextapp"
NEXT_APP_NAME = "nextapp"
NEXT_PORT = 3001


def _make_nuxt(npm_live_instance: str) -> NpmApp:
    instance = load_instance(npm_live_instance)
    return NpmApp(
        instance,
        instance.get("provider", "vultr"),
        user=instance.get("user", "deploy"),
        app_name=NUXT_APP_NAME,
        port=NUXT_PORT,
        start_script=".output/server/index.mjs",
        dist_dir=".output",
        build_command="npm run build",
    )


def _make_next(npm_live_instance: str) -> NpmApp:
    instance = load_instance(npm_live_instance)
    return NpmApp(
        instance,
        instance.get("provider", "vultr"),
        user=instance.get("user", "deploy"),
        app_name=NEXT_APP_NAME,
        port=NEXT_PORT,
        start_script=".next/standalone/server.js",
        dist_dir=".next",
        build_command="npm run build",
    )


@pytest.mark.integration
def test_npm_01_deploy_nuxt(npm_live_instance):
    """Nuxt app deploys via PM2 and responds on localhost:3000."""
    nuxt = _make_nuxt(npm_live_instance)
    nuxt.sync(str(NUXTAPP_DIR))

    instance = load_instance(npm_live_instance)
    status = ssh(instance["ip"], f"pm2 describe {NUXT_APP_NAME}", user="deploy")
    assert "online" in status.lower(), f"PM2 not online for nuxtapp: {status}"

    response_raw = ssh(
        instance["ip"],
        f"curl -sf http://localhost:{NUXT_PORT}/api/health",
        user="deploy",
    )
    data = json.loads(response_raw)
    assert data["app"] == "nuxt"


@pytest.mark.integration
def test_npm_02_deploy_next(npm_live_instance):
    """Next.js app deploys via PM2 on port 3001 and responds on localhost:3001."""
    next_app = _make_next(npm_live_instance)
    next_app.sync(str(NEXTAPP_DIR))

    instance = load_instance(npm_live_instance)
    status = ssh(instance["ip"], f"pm2 describe {NEXT_APP_NAME}", user="deploy")
    assert "online" in status.lower(), f"PM2 not online for nextapp: {status}"

    # Next.js can take up to 60s to start on low-memory VMs
    response_raw = ssh(
        instance["ip"],
        f"for i in $(seq 1 30); do out=$(curl -sf http://localhost:{NEXT_PORT}/api/health 2>/dev/null) && echo \"$out\" && break || sleep 2; done",
        user="deploy",
    )
    if not response_raw.strip():
        ports = ssh(instance["ip"], "ss -tlnp 2>/dev/null | grep -E '300[0-9]' || echo 'no node ports'", user="deploy")
        logs = ssh(instance["ip"], f"pm2 logs {NEXT_APP_NAME} --lines 30 --nostream 2>/dev/null || echo 'no logs'", user="deploy")
        pm2_status = ssh(instance["ip"], f"pm2 describe {NEXT_APP_NAME}", user="deploy")
        pytest.fail(f"Next.js health check timed out after 60s.\nPM2:\n{pm2_status}\nPorts:\n{ports}\nLogs:\n{logs}")
    data = json.loads(response_raw.strip())
    assert data["app"] == "next"


@pytest.mark.integration
def test_npm_03_resync_unchanged_nuxt(npm_live_instance):
    """Re-sync nuxtapp with unchanged source takes fast path; app still responds."""
    nuxt = _make_nuxt(npm_live_instance)
    nuxt.sync(str(NUXTAPP_DIR))

    instance = load_instance(npm_live_instance)
    response_raw = ssh(
        instance["ip"],
        f"curl -sf http://localhost:{NUXT_PORT}/api/health",
        user="deploy",
    )
    data = json.loads(response_raw)
    assert data["app"] == "nuxt"
