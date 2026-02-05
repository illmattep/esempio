import json
import logging
import os
import re
import socket
import sqlite3
import subprocess
import sys
import threading
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, Optional

from flask import Flask, abort, flash, redirect, render_template, request, send_file, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from .themes import THEME_PRESETS

try:
    import psutil
except ImportError:  # pragma: no cover - optional dependency
    psutil = None

try:
    import docker
except ImportError:  # pragma: no cover - optional dependency
    docker = None

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = BASE_DIR / "uploads"
DB_PATH = DATA_DIR / "app.sqlite3"
THEME_FILE = DATA_DIR / "themes.json"
LOG_FILE = DATA_DIR / "app.log"

ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "zip", "tar", "gz", "py", "json", "html", "css", "js", "md"}
MAX_CONTENT_LENGTH = 1024 * 1024 * 1024

SERVICE_NAMES = {"monitor", "power", "docker", "terminal", "wol", "remote", "files", "logs", "auth", "tools"}
SERVICE_DEFAULTS: Dict[str, Dict[str, Any]] = {
    "terminal": {"terminal_url": ""},
}


class TunnelManager:
    def __init__(self):
        self.process = None
        self.url = None
        self.log_buffer = []
        self._stop_event = threading.Event()
        self._thread = None

    def start(self):
        if self.process and self.process.poll() is None:
            return
        
        self.stop() # Ensure clean state

        self.log_buffer = []
        self.url = None
        self._stop_event.clear()

        cmd = [sys.executable, "-m", "pycloudflared", "tunnel", "--url", "http://127.0.0.1:8000"]
        
        startupinfo = None
        creationflags = 0
        if os.name == 'nt':
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            creationflags = subprocess.CREATE_NO_WINDOW

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                startupinfo=startupinfo,
                creationflags=creationflags
            )
            
            self._thread = threading.Thread(target=self._monitor_output)
            self._thread.daemon = True
            self._thread.start()
        except Exception as e:
            self.log_buffer.append(f"Errore avvio tunnel: {e}")

    def stop(self):
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                 self.process.kill()
            self.process = None
        self._stop_event.set()
        self.url = None

    def _monitor_output(self):
        if not self.process:
            return
        
        # Regex per trovare https://xyz.trycloudflare.com
        url_pattern = re.compile(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com")
        
        while not self._stop_event.is_set() and self.process:
            line = self.process.stdout.readline()
            if not line:
                break
            
            self.log_buffer.append(line)
            if len(self.log_buffer) > 100:
                self.log_buffer.pop(0)
            
            if not self.url:
                match = url_pattern.search(line)
                if match:
                    self.url = match.group(0)

    def get_logs(self):
        return "".join(self.log_buffer)

    def get_status(self):
        if self.process and self.process.poll() is None:
            return "running"
        return "stopped"

tunnel_manager = TunnelManager()

THEME_FIELDS = [
    "bg",
    "bg_deep",
    "bg_light",
    "panel",
    "text",
    "muted",
    "accent",
    "accent_soft",
    "accent_strong",
    "border",
    "glow",
    "danger",
    "success",
    "ambient",
    "ambient_fade",
    "header_bg",
    "panel_bg",
    "panel_border_soft",
    "card_bg",
    "metric_bg",
    "meter_bg",
    "input_bg",
    "placeholder",
    "ghost_bg",
    "shadow_dark",
    "flash_error_bg",
    "flash_success_bg",
    "scanline",
    "scanline_gap",
    "swatch_border",
    "button_text",
]

RGBA_FIELDS = {
    "glow",
    "ambient",
    "ambient_fade",
    "header_bg",
    "panel_bg",
    "panel_border_soft",
    "card_bg",
    "metric_bg",
    "meter_bg",
    "input_bg",
    "placeholder",
    "ghost_bg",
    "shadow_dark",
    "flash_error_bg",
    "flash_success_bg",
    "scanline",
    "scanline_gap",
    "swatch_border",
}


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("APP_SECRET_KEY", "change-me")
    app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

    # Setup Logging
    logging.basicConfig(level=logging.INFO)
    handler = RotatingFileHandler(LOG_FILE, maxBytes=100000, backupCount=1)
    handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s in %(module)s: %(message)s"))
    app.logger.addHandler(handler)

    init_db()
    ensure_service_settings()
    ensure_theme_store()

    @app.context_processor
    def inject_theme():
        theme = get_active_theme()
        return {
            "theme_vars": theme_to_css(theme),
            "theme_name": theme.get("name", "Theme"),
        }

    @app.route("/")
    def index():
        if not is_logged_in():
            return redirect(url_for("login"))
        return redirect(url_for("dashboard"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        next_url = sanitize_next_url(request.args.get("next") or request.form.get("next"))
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            user = get_user(username)
            if user and check_password_hash(user["password_hash"], password):
                session["user"] = username
                return redirect(next_url or url_for("dashboard"))
            flash("Credenziali non valide", "error")
        return render_template("login.html", next_url=next_url)

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/dashboard")
    def dashboard():
        auth_response = require_login()
        if auth_response:
            return auth_response
        services = [
            {"name": "Monitoraggio Risorse", "endpoint": "monitor"},
            {"name": "Stato Batteria", "endpoint": "power"},
            {"name": "Docker", "endpoint": "docker_view"},
            {"name": "Terminale Web", "endpoint": "terminal"},
            {"name": "Wake-on-LAN", "endpoint": "wol"},
            {"name": "File Manager", "endpoint": "files"},
            {"name": "Log Sistema", "endpoint": "logs_view"},
            {"name": "Credenziali", "endpoint": "auth_manager"},
            {"name": "IT Tools", "endpoint": "tools_view"},
            {"name": "Accesso Remoto", "endpoint": "remote_view"},
        ]
        return render_template("dashboard.html", services=services)

    @app.route("/theme")
    def theme():
        auth_response = require_login()
        if auth_response:
            return auth_response
        store = load_theme_store()
        presets = store.get("presets", [])
        active = store.get("active", "")
        return render_template(
            "theme.html",
            presets=presets,
            active=active,
            fields=THEME_FIELDS,
            rgba_fields=RGBA_FIELDS,
        )

    @app.route("/theme/apply", methods=["POST"])
    def theme_apply():
        auth_response = require_login()
        if auth_response:
            return auth_response
        name = request.form.get("name", "").strip()
        if not name:
            flash("Nome tema mancante", "error")
            return redirect(url_for("theme"))
        store = load_theme_store()
        if not any(preset["name"] == name for preset in store.get("presets", [])):
            flash("Tema non trovato", "error")
            return redirect(url_for("theme"))
        store["active"] = name
        save_theme_store(store)
        flash("Tema applicato", "success")
        return redirect(url_for("theme"))

    @app.route("/theme/create", methods=["POST"])
    def theme_create():
        auth_response = require_login()
        if auth_response:
            return auth_response
        name = request.form.get("name", "").strip()
        if not name:
            flash("Nome tema richiesto", "error")
            return redirect(url_for("theme"))
        store = load_theme_store()
        if any(preset["name"].lower() == name.lower() for preset in store.get("presets", [])):
            flash("Esiste gia un tema con questo nome", "error")
            return redirect(url_for("theme"))

        colors: Dict[str, str] = {}
        for field in THEME_FIELDS:
            value = request.form.get(field, "").strip()
            if not value:
                flash(f"Colore mancante: {field}", "error")
                return redirect(url_for("theme"))
            if field in RGBA_FIELDS:
                if not value.startswith("rgba("):
                    flash(f"{field} deve essere in formato rgba(r, g, b, a)", "error")
                    return redirect(url_for("theme"))
                colors[field] = value
                continue
            if not is_hex_color(value):
                flash(f"Colore non valido: {field}", "error")
                return redirect(url_for("theme"))
            colors[field] = value

        store["presets"].append({"name": name, "colors": colors, "custom": True})
        store["active"] = name
        save_theme_store(store)
        flash("Tema creato", "success")
        return redirect(url_for("theme"))

    @app.route("/files", methods=["GET", "POST"])
    def files():
        auth_response = require_login() or require_service_access("files")
        if auth_response:
            return auth_response
        if request.method == "POST":
            file = request.files.get("file")
            if not file or file.filename == "":
                flash("Seleziona un file", "error")
                return redirect(url_for("files"))
            if not allowed_file(file.filename):
                flash("Estensione non consentita", "error")
                return redirect(url_for("files"))
            filename = secure_filename(file.filename)
            destination = UPLOAD_DIR / filename
            file.save(destination)
            flash("File caricato", "success")
            return redirect(url_for("files"))

        files_list = sorted(p.name for p in UPLOAD_DIR.iterdir() if p.is_file())
        settings = get_service_settings("files")
        return render_template("files.html", files=files_list, settings=settings)

    @app.route("/files/delete/<path:filename>", methods=["POST"])
    def delete_file_route(filename):
        auth_response = require_login() or require_service_access("files")
        if auth_response:
            return auth_response
        resolved = resolve_upload_path(filename)
        if not resolved or not resolved.exists():
            flash("File non trovato", "error")
        else:
            try:
                resolved.unlink()
                flash("File eliminato", "success")
            except Exception as e:
                flash(f"Errore eliminazione: {e}", "error")
        return redirect(url_for("files"))

        auth_response = require_login()
        if auth_response:
            return auth_response
        resolved = resolve_upload_path(filename)
        if not resolved or not resolved.exists():
            abort(404)
        return send_file(resolved, as_attachment=True)

    @app.route("/monitor")
    def monitor():
        auth_response = require_login() or require_service_access("monitor")
        if auth_response:
            return auth_response
        settings = get_service_settings("monitor")
        return render_template("monitor.html", settings=settings)

    @app.route("/api/monitor")
    def api_monitor():
        auth_response = require_login() or require_service_access("monitor")
        if auth_response:
            return auth_response
        if psutil is None:
            return {"error": "psutil_not_installed"}, 500

        cpu_percent = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage(str(BASE_DIR))
        temps = {}
        try:
            temps = psutil.sensors_temperatures()
        except (AttributeError, OSError):
            temps = {}

        temp_values = []
        for entries in temps.values():
            for entry in entries:
                if entry.current is not None:
                    temp_values.append(entry.current)

        return {
            "cpu_percent": cpu_percent,
            "mem_percent": mem.percent,
            "mem_used": mem.used,
            "mem_total": mem.total,
            "disk_percent": disk.percent,
            "disk_used": disk.used,
            "disk_total": disk.total,
            "temps": temp_values,
        }

    @app.route("/power")
    def power():
        auth_response = require_login() or require_service_access("power")
        if auth_response:
            return auth_response
        battery = None
        if psutil is not None:
            try:
                battery = psutil.sensors_battery()
            except (AttributeError, OSError):
                battery = None
        settings = get_service_settings("power")
        return render_template("power.html", battery=battery, settings=settings)

    @app.route("/docker")
    def docker_view():
        auth_response = require_login() or require_service_access("docker")
        if auth_response:
            return auth_response
        settings = get_service_settings("docker")
        containers = []
        error = None
        if docker is None:
            error = "Docker SDK non installato."
        else:
            try:
                client = docker.from_env()
                containers = client.containers.list(all=True)
            except Exception as exc:  # noqa: BLE001
                error = f"Errore Docker: {exc}"
        return render_template("docker.html", containers=containers, error=error, settings=settings)

    @app.route("/docker/action", methods=["POST"])
    def docker_action():
        auth_response = require_login() or require_service_access("docker")
        if auth_response:
            return auth_response
        container_id = request.form.get("container_id", "")
        action = request.form.get("action", "")
        if docker is None:
            flash("Docker SDK non installato", "error")
            return redirect(url_for("docker_view"))
        try:
            client = docker.from_env()
            container = client.containers.get(container_id)
            if action == "start":
                container.start()
            elif action == "stop":
                container.stop()
            elif action == "restart":
                container.restart()
            else:
                flash("Azione non valida", "error")
                return redirect(url_for("docker_view"))
            flash("Azione completata", "success")
        except Exception as exc:  # noqa: BLE001
            flash(f"Errore Docker: {exc}", "error")
        return redirect(url_for("docker_view"))

    @app.route("/terminal")
    def terminal():
        auth_response = require_login() or require_service_access("terminal")
        if auth_response:
            return auth_response
        settings = get_service_settings("terminal")
        terminal_url = settings["config"].get("terminal_url", "")
        return render_template("terminal.html", terminal_url=terminal_url, settings=settings)

    @app.route("/wol")
    def wol():
        auth_response = require_login() or require_service_access("wol")
        if auth_response:
            return auth_response
        settings = get_service_settings("wol")
        targets = list_wol_targets()
        return render_template("wol.html", targets=targets, settings=settings)

    @app.route("/wol/send", methods=["POST"])
    def wol_send():
        auth_response = require_login() or require_service_access("wol")
        if auth_response:
            return auth_response
        mac = request.form.get("mac", "").strip()
        host = request.form.get("host", "").strip() or None
        if not mac:
            flash("MAC richiesto", "error")
            return redirect(url_for("wol"))
        try:
            send_magic_packet(mac, host)
            flash("Pacchetto inviato", "success")
        except ValueError as exc:
            flash(str(exc), "error")
        return redirect(url_for("wol"))

    @app.route("/wol/targets", methods=["POST"])
    def wol_add_target():
        auth_response = require_login() or require_service_access("wol")
        if auth_response:
            return auth_response
        name = request.form.get("name", "").strip()
        mac = request.form.get("mac", "").strip()
        host = request.form.get("host", "").strip()
        if not name or not mac:
            flash("Nome e MAC sono richiesti", "error")
            return redirect(url_for("wol"))
        add_wol_target(name, mac, host)
        flash("Target salvato", "success")
        return redirect(url_for("wol"))

    @app.route("/wol/targets/<int:target_id>/delete", methods=["POST"])
    def wol_delete_target(target_id: int):
        auth_response = require_login() or require_service_access("wol")
        if auth_response:
            return auth_response
        delete_wol_target(target_id)
        flash("Target rimosso", "success")
        return redirect(url_for("wol"))

    @app.route("/services/<service>/auth", methods=["GET", "POST"])
    def service_auth(service: str):
        if service not in SERVICE_NAMES:
            abort(404)
        auth_response = require_login()
        if auth_response:
            return auth_response
            
        if request.method == "POST":
            password = request.form.get("password", "")
            user_data = get_user(session["user"])
            if user_data and check_password_hash(user_data["password_hash"], password):
                session[f"service_auth_{service}"] = True
                next_url = request.form.get("next") or url_for(service_endpoint(service))
                return redirect(next_url)
            flash("Password non valida", "error")
            
        next_url = request.args.get("next") or url_for(service_endpoint(service))
        return render_template("service_auth.html", service=service, next_url=next_url)

    @app.route("/services/<service>/settings", methods=["POST"])
    def service_settings(service: str):
        if service not in SERVICE_NAMES:
            abort(404)
        auth_response = require_login()
        if auth_response:
            return auth_response
        require_password = request.form.get("require_password") == "on"
        password = request.form.get("password", "")
        config_updates: Dict[str, Any] = {}
        if service == "terminal":
            config_updates["terminal_url"] = request.form.get("terminal_url", "").strip()
        try:
            update_service_settings(service, require_password, password, config_updates)
            flash("Impostazioni salvate", "success")
        except ValueError as exc:
            flash(str(exc), "error")
        next_url = request.form.get("next") or url_for(service_endpoint(service))
        return redirect(next_url)

    @app.route("/health")
    def health():
        return {"status": "ok"}

    @app.route("/auth_manager")
    def auth_manager():
        auth_response = require_login() or require_service_access("auth")
        if auth_response:
            return auth_response
        creds = list_credentials()
        settings = get_service_settings("auth")
        return render_template("auth_manager.html", credentials=creds, settings=settings)

    @app.route("/auth_manager/add", methods=["POST"])
    def auth_add():
        auth_response = require_login() or require_service_access("auth")
        if auth_response:
            return auth_response
        
        service = request.form.get("service")
        username = request.form.get("username")
        password = request.form.get("password")
        notes = request.form.get("notes")
        category = request.form.get("category")
        
        if service:
            add_credential(service, username, password, notes, category)
            flash("Credenziale salvata", "success")
        else:
            flash("Nome servizio richiesto", "error")
        return redirect(url_for("auth_manager"))

    @app.route("/auth_manager/delete/<int:id>", methods=["POST"])
    def auth_delete(id):
        auth_response = require_login() or require_service_access("auth")
        if auth_response:
            return auth_response
        delete_credential(id)
        flash("Credenziale eliminata", "success")
        return redirect(url_for("auth_manager"))

    @app.route("/logs")
    def logs_view():
        auth_response = require_login() or require_service_access("logs")
        if auth_response:
            return auth_response
        
        content = ""
        if LOG_FILE.exists():
            try:
                content = LOG_FILE.read_text(encoding="utf-8")
            except Exception as e:
                content = f"Errore lettura log: {e}"
        
        settings = get_service_settings("logs")
        return render_template("logs.html", log_content=content, settings=settings)

    @app.route("/logs/clear", methods=["POST"])
    def logs_clear():
        auth_response = require_login() or require_service_access("logs")
        if auth_response:
            return auth_response
        try:
            with open(LOG_FILE, 'w') as f:
                f.truncate(0)
            flash("Log cancellati", "success")
        except Exception as e:
            flash(f"Errore: {e}", "error")
        return redirect(url_for("logs_view"))

    @app.route("/tools")
    def tools_view():
        auth_response = require_login() or require_service_access("tools")
        if auth_response:
            return auth_response
        settings = get_service_settings("tools")
        return render_template("tools.html", settings=settings)

    @app.route("/remote")
    def remote_view():
        auth_response = require_login() or require_service_access("remote")
        if auth_response:
            return auth_response
        settings = get_service_settings("remote")
        return render_template(
            "remote.html", 
            tunnel_status=tunnel_manager.get_status(),
            tunnel_url=tunnel_manager.url,
            tunnel_logs=tunnel_manager.get_logs(),
            settings=settings
        )

    @app.route("/remote/start", methods=["POST"])
    def remote_start():
         auth_response = require_login() or require_service_access("remote")
         if auth_response:
             return auth_response
         tunnel_manager.start()
         flash("Tunnel avviato", "success")
         return redirect(url_for("remote_view"))

    @app.route("/remote/stop", methods=["POST"])
    def remote_stop():
         auth_response = require_login() or require_service_access("remote")
         if auth_response:
             return auth_response
         tunnel_manager.stop()
         flash("Tunnel arrestato", "success")
         return redirect(url_for("remote_view"))

    return app


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS service_settings (
                service TEXT PRIMARY KEY,
                require_password INTEGER NOT NULL DEFAULT 0,
                password_hash TEXT,
                config TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS wol_targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                mac TEXT NOT NULL,
                host TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service_name TEXT NOT NULL,
                username TEXT,
                encrypted_password TEXT,
                notes TEXT,
                category TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        try:
            conn.execute("ALTER TABLE credentials ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
        except sqlite3.OperationalError:
            pass # Colonna già esistente
        conn.commit()


def get_user(username: str) -> Optional[dict]:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if row:
            return dict(row)
        return None


def create_user(username: str, password: str) -> None:
    password_hash = generate_password_hash(password)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        conn.commit()


def is_logged_in() -> bool:
    return "user" in session


def require_login():
    if not is_logged_in():
        next_url = sanitize_next_url(request.path)
        return redirect(url_for("login", next=next_url))
    return None


def allowed_file(filename: str) -> bool:
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS


def resolve_upload_path(filename: str) -> Optional[Path]:
    safe_name = secure_filename(filename)
    candidate = (UPLOAD_DIR / safe_name).resolve()
    try:
        candidate.relative_to(UPLOAD_DIR.resolve())
    except ValueError:
        return None
    return candidate


def sanitize_next_url(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    if value.startswith("/") and not value.startswith("//"):
        return value
    return None


def ensure_theme_store() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if THEME_FILE.exists():
        store = load_theme_store()
        save_theme_store(store)
        return
    save_theme_store(default_theme_store())


def default_theme_store() -> Dict[str, Any]:
    return {
        "active": THEME_PRESETS[0]["name"],
        "presets": THEME_PRESETS,
    }


def load_theme_store() -> Dict[str, Any]:
    if not THEME_FILE.exists():
        return default_theme_store()
    try:
        with THEME_FILE.open("r", encoding="utf-8") as handle:
            store = json.load(handle)
    except (json.JSONDecodeError, OSError):
        return default_theme_store()

    presets = store.get("presets") or []
    merged = merge_presets(presets)
    active = store.get("active") or merged[0]["name"]
    if not any(preset["name"] == active for preset in merged):
        active = merged[0]["name"]
    return {"active": active, "presets": merged}


def save_theme_store(store: Dict[str, Any]) -> None:
    with THEME_FILE.open("w", encoding="utf-8") as handle:
        json.dump(store, handle, indent=2)


def merge_presets(presets: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
    preset_map = {preset["name"]: preset for preset in presets if "name" in preset}
    for preset in THEME_PRESETS:
        name = preset["name"]
        if name in preset_map:
            existing = preset_map[name]
            existing_colors = existing.get("colors", {})
            merged_colors = {**preset["colors"], **existing_colors}
            preset_map[name] = {**preset, **existing, "colors": merged_colors}
        else:
            preset_map[name] = preset

    defaults = THEME_PRESETS[0]["colors"]
    for name, preset in list(preset_map.items()):
        colors = preset.get("colors", {})
        merged_colors = {**defaults, **colors}
        preset_map[name] = {**preset, "colors": merged_colors}

    return list(preset_map.values())


def get_active_theme() -> Dict[str, Any]:
    store = load_theme_store()
    active = store.get("active")
    for preset in store.get("presets", []):
        if preset["name"] == active:
            return preset
    return store["presets"][0]


def theme_to_css(theme: Dict[str, Any]) -> str:
    colors = theme.get("colors", {})
    defaults = THEME_PRESETS[0]["colors"]
    parts = [f"--{key}: {colors.get(key) or defaults.get(key, '')};" for key in THEME_FIELDS]
    return " ".join(parts)


def is_hex_color(value: str) -> bool:
    if not value.startswith("#") or len(value) != 7:
        return False
    return all(ch in "0123456789abcdefABCDEF" for ch in value[1:])


def ensure_service_settings() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        for service in SERVICE_NAMES:
            conn.execute(
                """
                INSERT INTO service_settings (service, require_password, password_hash, config)
                VALUES (?, 0, NULL, '{}')
                ON CONFLICT(service) DO NOTHING
                """,
                (service,),
            )
        conn.commit()


def get_service_settings(service: str) -> Dict[str, Any]:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT service, require_password, password_hash, config FROM service_settings WHERE service = ?",
            (service,),
        ).fetchone()
        if not row:
            return {"service": service, "require_password": False, "password_hash": None, "config": {}}
        config = json.loads(row["config"] or "{}")
        defaults = SERVICE_DEFAULTS.get(service, {})
        merged = {**defaults, **config}
        return {
            "service": row["service"],
            "require_password": bool(row["require_password"]),
            "password_hash": row["password_hash"],
            "config": merged,
        }


def update_service_settings(
    service: str, require_password: bool, password: str, config_updates: Dict[str, Any]
) -> None:
    settings = get_service_settings(service)
    # Password argument is ignored now, we use the main admin password
    
    config = settings["config"].copy()
    config.update({k: v for k, v in config_updates.items() if v is not None})

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            UPDATE service_settings
            SET require_password = ?, config = ?
            WHERE service = ?
            """,
            (1 if require_password else 0, json.dumps(config), service),
        )
        conn.commit()


def require_service_access(service: str):
    settings = get_service_settings(service)
    if not settings["require_password"]:
        return None
    if session.get(f"service_auth_{service}"):
        return None
    return redirect(url_for("service_auth", service=service, next=request.path))


def service_endpoint(service: str) -> str:
    endpoints = {
        "monitor": "monitor",
        "power": "power",
        "docker": "docker_view",
        "terminal": "terminal",
        "wol": "wol",
        "remote": "remote_view", 
        "files": "files",
        "logs": "logs_view",
        "auth": "auth_manager",
        "tools": "tools_view"
    }
    return endpoints.get(service, "dashboard")


def list_wol_targets():
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT id, name, mac, host FROM wol_targets ORDER BY name").fetchall()
        return [dict(row) for row in rows]


def add_wol_target(name: str, mac: str, host: str) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO wol_targets (name, mac, host) VALUES (?, ?, ?)",
            (name, mac, host or None),
        )
        conn.commit()


def delete_wol_target(target_id: int) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM wol_targets WHERE id = ?", (target_id,))
        conn.commit()


def send_magic_packet(mac: str, host: Optional[str] = None, port: int = 9) -> None:
    mac_clean = mac.replace(":", "").replace("-", "").strip()
    if len(mac_clean) != 12 or not all(c in "0123456789abcdefABCDEF" for c in mac_clean):
        raise ValueError("MAC non valido")
    data = bytes.fromhex("FF" * 6 + mac_clean * 16)
    target_host = host or "255.255.255.255"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(data, (target_host, port))


def list_credentials():
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(row) for row in conn.execute("SELECT * FROM credentials ORDER BY service_name").fetchall()]


def add_credential(service_name, username, password, notes, category):
    import base64
    from datetime import datetime
    enc_pass = base64.b64encode(password.encode()).decode() if password else ""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO credentials (service_name, username, encrypted_password, notes, category, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            (service_name, username, enc_pass, notes, category, now)
        )
        conn.commit()


def delete_credential(cred_id):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM credentials WHERE id = ?", (cred_id,))
        conn.commit()

