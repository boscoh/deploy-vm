"""App deployment logic for Nuxt and FastAPI applications."""

import hashlib
import json
import subprocess
from pathlib import Path
from textwrap import dedent

from .server import (
    log,
    warn,
    error,
    ssh,
    ssh_script,
    ssh_write_file,
    ssh_as_user,
    rsync,
    get_ssh_user,
)
from .utils import get_sudo_prefix


def compute_hash(source: str, exclude: list[str] | None = None) -> str:
    """Compute MD5 hash of source directory.

    :param source: Path to source directory
    :param exclude: List of patterns to exclude
    :return: MD5 hash as hex string
    """
    source_path = Path(source)
    if exclude is None:
        exclude = [".git"]

    hasher = hashlib.md5()
    for f in sorted(source_path.rglob("*")):
        if f.is_file() and not any(ex in str(f) for ex in exclude):
            hasher.update(str(f.relative_to(source_path)).encode())
            hasher.update(f.read_bytes())
    return hasher.hexdigest()


class BaseApp:
    """Base class for app deployment."""

    def __init__(self, instance_data: dict, provider_name: str):
        """Initialize app.

        :param instance_data: Instance data from .instance.json
        :param provider_name: Cloud provider name
        """
        self.instance = instance_data
        self.ip = instance_data["ip"]
        self.provider_name = provider_name
        self.ssh_user = get_ssh_user(provider_name)

    def compute_source_hash(self, local_path: str, exclude: list[str] | None = None) -> str:
        """Compute hash of local source directory."""
        return compute_hash(local_path, exclude)

    def select_app(self, app_type: str, app_name: str | None = None) -> dict:
        """Select app from instance data.

        :param app_type: App type (nuxt or fastapi)
        :param app_name: App name (if multiple apps exist)
        :return: App data dict
        """
        apps = [app for app in self.instance.get("apps", []) if app["type"] == app_type]

        if app_name is None:
            if len(apps) == 1:
                return apps[0]
            elif len(apps) > 1:
                app_names = ", ".join(app["name"] for app in apps)
                error(f"Multiple {app_type} apps found: {app_names}. Use --app-name to specify.")
            else:
                # Fallback for old single-app instances
                return {"name": "app", "type": app_type}

        for app in apps:
            if app["name"] == app_name:
                return app

        error(f"App '{app_name}' not found in instance")


class NuxtApp(BaseApp):
    """Nuxt app deployment."""

    def __init__(
        self,
        instance_data: dict,
        provider_name: str,
        *,
        user: str,
        app_name: str = "nuxt",
        port: int = 3000,
        node_version: int = 20,
    ):
        super().__init__(instance_data, provider_name)
        self.user = user
        self.app_name = app_name
        self.port = port
        self.node_version = node_version
        self.app_dir = f"/home/{user}/{app_name}"

    def detect_node_version(self, source: str) -> int | None:
        """Detect Node.js version from project files.

        :param source: Path to source directory
        :return: Major Node.js version number
        """
        import re

        source_path = Path(source)

        for filename in [".nvmrc", ".node-version"]:
            version_file = source_path / filename
            if version_file.exists():
                content = version_file.read_text().strip().lstrip("v")
                try:
                    return int(content.split(".")[0])
                except ValueError:
                    pass

        package_json = source_path / "package.json"
        if package_json.exists():
            try:
                data = json.loads(package_json.read_text())
                node_constraint = data.get("engines", {}).get("node", "")
                match = re.search(r"(\d+)", node_constraint)
                if match:
                    return int(match.group(1))
            except (json.JSONDecodeError, ValueError):
                pass

        return None

    def generate_pm2_config(self) -> str:
        """Generate PM2 ecosystem config."""
        return dedent(f"""
            const fs = require('fs');
            const path = require('path');

            // Load .env file if it exists
            const envPath = path.join(__dirname, '.env');
            const envVars = {{}};
            if (fs.existsSync(envPath)) {{
              const content = fs.readFileSync(envPath, 'utf-8');
              content.split('\\n').forEach(line => {{
                const trimmed = line.trim();
                if (trimmed && !trimmed.startsWith('#')) {{
                  const [key, ...valueParts] = trimmed.split('=');
                  if (key && valueParts.length) {{
                    let value = valueParts.join('=').trim();
                    if ((value.startsWith('"') && value.endsWith('"')) ||
                        (value.startsWith("'") && value.endsWith("'"))) {{
                      value = value.slice(1, -1);
                    }}
                    envVars[key.trim()] = value;
                  }}
                }}
              }});
            }}

            module.exports = {{
              apps: [{{
                name: '{self.app_name}',
                script: './.output/server/index.mjs',
                cwd: '{self.app_dir}',
                instances: 'max',
                exec_mode: 'cluster',
                env: {{
                  NODE_ENV: 'production',
                  PORT: {self.port},
                  ...envVars
                }}
              }}]
            }};
        """).strip()

    def sync(
        self,
        source: str,
        *,
        local_build: bool = True,
        force: bool = False,
    ):
        """Sync Nuxt app to server.

        :param source: Local source directory
        :param local_build: Build locally instead of on server
        :param force: Force rebuild even if source unchanged
        """
        source = str(Path(source).resolve())

        if not Path(source).exists():
            error(f"Source directory not found: {source}")

        detected_version = self.detect_node_version(source)
        if detected_version:
            log(f"Detected Node.js version {detected_version} from project config")
            self.node_version = detected_version

        log(f"Deploying to {self.ip}...")

        log(f"Installing Node.js {self.node_version} and PM2...")
        node_script = dedent(f"""
            set -e
            if ! command -v node &> /dev/null; then
                curl -fsSL https://deb.nodesource.com/setup_{self.node_version}.x | bash -
                apt-get install -y nodejs
            fi
            node --version
            if ! command -v pm2 &> /dev/null; then
                npm install -g pm2
            fi
            mkdir -p {self.app_dir}
            chown -R {self.user}:{self.user} {self.app_dir}
        """).strip()
        ssh_script(self.ip, node_script, user=self.ssh_user)

        log("Generating PM2 ecosystem config...")
        ecosystem_config = self.generate_pm2_config()
        ssh_write_file(self.ip, f"{self.app_dir}/ecosystem.config.cjs", ecosystem_config, user=self.ssh_user)
        ssh(self.ip, f"chown {self.user}:{self.user} {self.app_dir}/ecosystem.config.cjs", user=self.ssh_user)

        nuxt_exclude = [
            "node_modules",
            ".git",
            ".output",
            ".nuxt",
            "public/projects",
            "data/scripts/models",
            "json/projects",
        ]
        local_hash = self.compute_source_hash(source, nuxt_exclude)
        try:
            remote_hash = ssh(
                self.ip,
                f"cat {self.app_dir}/.source_hash 2>/dev/null || echo ''",
                user=self.ssh_user,
            ).strip()
        except Exception:
            remote_hash = ""

        if not force and local_hash == remote_hash and remote_hash:
            log("Source unchanged, restarting app...")
            restart_script = dedent(f"""
                if ! su - {self.user} -c "pm2 reload {self.app_name}" 2>/dev/null; then
                    pkill -u {self.user} -f pm2 || true
                    rm -rf /home/{self.user}/.pm2 || true
                    rm -f /home/{self.user}/.pm2/*.sock /home/{self.user}/.pm2/pm2.pid 2>/dev/null || true
                    sleep 1
                    su - {self.user} -c "cd {self.app_dir} && pm2 start ecosystem.config.cjs && pm2 save"
                fi
            """).strip()
            ssh_script(self.ip, restart_script, user=self.ssh_user)
            log("App restarted")
            return

        if local_build:
            log("Building locally...")
            subprocess.run(["npm", "install"], cwd=source, check=True)
            subprocess.run(["npm", "run", "build"], cwd=source, check=True)

            if not Path(source, ".output").exists():
                error("Build failed - no .output directory")

        log("Uploading...")
        exclude = [
            "/node_modules",
            ".nuxt",
            ".git",
            "ecosystem.config.cjs",
            ".source_hash",
            "public/projects",
            "data/scripts/models",
            "json/projects",
        ]
        if not local_build:
            exclude.append(".output")
        rsync(source, self.ip, self.app_dir, exclude=exclude, user=self.ssh_user)

        if not local_build:
            log("Building on server...")
            build_script = dedent(f"""
                set -e
                cd {self.app_dir}
                export NODE_OPTIONS="--max-old-space-size=1024"
                su - {self.user} -c "cd {self.app_dir} && rm -rf package-lock.json .nuxt && npm install && npm run build"
            """).strip()
            ssh_script(self.ip, build_script, user=self.ssh_user)

        log("Starting app...")
        start_script = dedent(f"""
            set -e
            echo "{local_hash}" > {self.app_dir}/.source_hash
            # Legacy fallback: fix Nitro import.meta.url resolution for PM2
            # (nginx now serves .output/public directly, so this is rarely needed)
            sed -i 's/dirname(fileURLToPath(import.meta.url))/dirname(fileURLToPath(globalThis._importMeta_.url))/g' \
                {self.app_dir}/.output/server/chunks/nitro/nitro.mjs 2>/dev/null || true
            chown -R {self.user}:{self.user} {self.app_dir}
            pkill -u {self.user} -f pm2 || true
            pkill -u {self.user} -f "node.*index.mjs" || true
            rm -rf /home/{self.user}/.pm2 || true
            rm -f /home/{self.user}/.pm2/*.sock /home/{self.user}/.pm2/pm2.pid 2>/dev/null || true
            sleep 1
            su - {self.user} -c "cd {self.app_dir} && pm2 start ecosystem.config.cjs && pm2 save"
            pm2 startup systemd -u {self.user} --hp /home/{self.user} 2>/dev/null || true
        """).strip()
        ssh_script(self.ip, start_script, user=self.ssh_user)
        log("App deployed!")

    def restart(self):
        """Restart PM2 app."""
        log(f"Restarting {self.app_name}...")
        ssh_as_user(self.ip, self.user, f"pm2 reload {self.app_name}", ssh_user=self.ssh_user)
        log("App restarted")

    def status(self):
        """Show PM2 status."""
        return ssh_as_user(self.ip, self.user, "pm2 list", ssh_user=self.ssh_user)

    def logs(self, lines: int = 50):
        """Show PM2 logs."""
        return ssh_as_user(
            self.ip, self.user, f"pm2 logs {self.app_name} --lines {lines} --nostream", ssh_user=self.ssh_user
        )


class FastAPIApp(BaseApp):
    """FastAPI app deployment."""

    def __init__(
        self,
        instance_data: dict,
        provider_name: str,
        *,
        user: str,
        app_name: str = "fastapi",
        port: int = 8000,
        app_module: str = "app:app",
        workers: int = 2,
    ):
        super().__init__(instance_data, provider_name)
        self.user = user
        self.app_name = app_name
        self.port = port
        self.app_module = app_module
        self.workers = workers
        self.app_dir = f"/home/{user}/{app_name}"

    def sync(self, source: str, *, force: bool = False) -> bool:
        """Sync FastAPI app to server using supervisord.

        :param source: Local source directory
        :param force: Force rebuild even if source unchanged
        :return: True if full sync, False if source unchanged
        """
        source = str(Path(source).resolve())

        if not Path(source).exists():
            error(f"Source directory not found: {source}")

        if not (Path(source) / "pyproject.toml").exists():
            error(f"pyproject.toml not found in {source}")

        log(f"Deploying FastAPI to {self.ip}...")

        sudo = get_sudo_prefix(self.ssh_user)

        log("Installing uv and supervisor...")
        setup_script = dedent(f"""
            set -e
            {sudo}apt-get update
            {sudo}apt-get install -y supervisor curl

            {sudo}mkdir -p /home/{self.user}/{self.app_name}
            {sudo}mkdir -p /var/log/{self.app_name}
            {sudo}chown -R {self.user}:{self.user} /home/{self.user}/{self.app_name}
            {sudo}chown -R {self.user}:{self.user} /var/log/{self.app_name}

            {sudo}su - {self.user} -c "curl -LsSf https://astral.sh/uv/install.sh | sh"
        """).strip()
        ssh_script(self.ip, setup_script, user=self.ssh_user)

        python_exclude = [".venv", "__pycache__", ".git", "*.pyc"]
        local_hash = self.compute_source_hash(source, python_exclude)
        try:
            remote_hash = ssh(
                self.ip,
                f"cat /home/{self.user}/{self.app_name}/.source_hash 2>/dev/null || echo ''",
                user=self.ssh_user,
            ).strip()
        except Exception:
            remote_hash = ""

        if not force and local_hash == remote_hash and remote_hash:
            log("Source unchanged, restarting app...")
            ssh_script(self.ip, f"{sudo}supervisorctl restart {self.app_name}", user=self.ssh_user)
            log("App restarted")
            return False

        log("Uploading...")
        exclude = [".venv", "__pycache__", ".git", "*.pyc", ".source_hash"]
        rsync(source, self.ip, f"/home/{self.user}/{self.app_name}", exclude=exclude, user=self.ssh_user)

        log("Setting up Python environment...")
        venv_script = dedent(f"""
            set -e
            {sudo}chown -R {self.user}:{self.user} /home/{self.user}/{self.app_name}

            FROZEN=""
            if [ -f "/home/{self.user}/{self.app_name}/uv.lock" ]; then
                FROZEN="--frozen"
            fi

            {sudo}su - {self.user} -c "cd /home/{self.user}/{self.app_name} && ~/.local/bin/uv sync $FROZEN"
        """).strip()
        ssh_script(self.ip, venv_script, user=self.ssh_user)

        log("Configuring supervisord...")
        supervisor_config = dedent(f"""
            [program:{self.app_name}]
            directory=/home/{self.user}/{self.app_name}
            command=/home/{self.user}/{self.app_name}/.venv/bin/uvicorn {self.app_module} --host 0.0.0.0 --port {self.port} --workers {self.workers}
            user={self.user}
            autostart=true
            autorestart=true
            stopasgroup=true
            killasgroup=true
            stderr_logfile=/var/log/{self.app_name}/error.log
            stdout_logfile=/var/log/{self.app_name}/access.log
            environment=PATH="/home/{self.user}/{self.app_name}/.venv/bin:/home/{self.user}/.local/bin"
        """).strip()
        ssh_write_file(self.ip, f"/etc/supervisor/conf.d/{self.app_name}.conf", supervisor_config, user=self.ssh_user)

        if self.ssh_user == "root":
            hash_write_cmd = f'echo "{local_hash}" > /home/{self.user}/{self.app_name}/.source_hash'
        else:
            hash_write_cmd = f'echo "{local_hash}" | {sudo}tee /home/{self.user}/{self.app_name}/.source_hash > /dev/null'

        ssh_script(
            self.ip,
            f'{hash_write_cmd} && '
            f"{sudo}chown {self.user}:{self.user} /home/{self.user}/{self.app_name}/.source_hash && "
            f"{sudo}supervisorctl reread && {sudo}supervisorctl update && {sudo}supervisorctl restart {self.app_name}",
            user=self.ssh_user,
        )
        log("FastAPI app deployed!")
        return True

    def restart(self):
        """Restart supervisord app."""
        sudo = get_sudo_prefix(self.ssh_user)
        log(f"Restarting {self.app_name}...")
        ssh(self.ip, f"{sudo}supervisorctl restart {self.app_name}", user=self.ssh_user)
        log("App restarted")

    def status(self):
        """Show supervisord status."""
        sudo = get_sudo_prefix(self.ssh_user)
        return ssh(self.ip, f"{sudo}supervisorctl status", user=self.ssh_user)

    def logs(self, lines: int = 50):
        """Show supervisord logs."""
        log(f"Last {lines} lines of {self.app_name} logs:")
        return ssh(
            self.ip,
            f"tail -n {lines} /var/log/{self.app_name}/access.log /var/log/{self.app_name}/error.log 2>/dev/null || echo 'No logs found'",
            user=self.ssh_user,
        )
