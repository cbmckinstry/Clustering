# app.py
from flask import Flask, render_template, request, session, redirect, url_for
from flask_session import Session
import calculations
import os
import redis
from pathlib import Path
from datetime import datetime
from zoneinfo import ZoneInfo
import requests
import json
import time
import ipaddress
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "supersecretkey")

# Proxy awareness (Render / reverse proxies). Logging still uses XFF parsing below.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# ------------------------------
# Security: cookie hardening
# ------------------------------
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True,  # Render is HTTPS
)

# ------------------------------
# Sessions (Redis if available)
# ------------------------------
redis_url = os.environ.get("REDIS_URL")

# IMPORTANT:
# - SESSION_PERMANENT=False => session cookie dies when the BROWSER closes
# - Tab-close logout is handled by JS calling /logout/<role>
app.config["SESSION_PERMANENT"] = False  # browser-session cookie (ends when browser closes)
app.config["SESSION_USE_SIGNER"] = True

# IMPORTANT: isolate session keys between apps sharing Redis
app.config["SESSION_KEY_PREFIX"] = os.environ.get("SESSION_KEY_PREFIX", "session:clustering:")

if redis_url:
    app.config["SESSION_TYPE"] = "redis"
    app.config["SESSION_REDIS"] = redis.from_url(redis_url)
else:
    app.config["SESSION_TYPE"] = "filesystem"
    session_dir = Path(app.instance_path) / "flask_session"
    session_dir.mkdir(parents=True, exist_ok=True)
    app.config["SESSION_FILE_DIR"] = str(session_dir)

Session(app)

# ------------------------------
# Passwords
# ------------------------------
# /data (view/delete/wipe MAIN log)
DATA_PASSWORD = os.environ.get("DATA_PASSWORD", "change-me")
DATA_PASSWORD_VIEW = os.environ.get("DATA_PASSWORD_VIEW", DATA_PASSWORD)
DATA_PASSWORD_DELETE = os.environ.get("DATA_PASSWORD_DELETE", DATA_PASSWORD)
DATA_PASSWORD_WIPE = os.environ.get("DATA_PASSWORD_WIPE", DATA_PASSWORD)
DATA_PASSWORD_DELETE_IP = os.environ.get("DATA_PASSWORD_DELETE_IP", DATA_PASSWORD)

# /trainer (view-only MAIN log)
TRAINER_PASSWORD_VIEW = os.environ.get("TRAINER_PASSWORD_VIEW", "change-me")

# /carson (view-only ARCHIVE log)
ARCHIVE_PASSWORD_VIEW = os.environ.get("ARCHIVE_PASSWORD_VIEW", "change-me")

CARSON_PASSWORD = os.environ.get("CARSON_PASSWORD", "change-me")
CARSON_PASSWORD_VIEW = os.environ.get("CARSON_PASSWORD_VIEW", CARSON_PASSWORD)
CARSON_PASSWORD_DELETE = os.environ.get("CARSON_PASSWORD_DELETE", CARSON_PASSWORD)
CARSON_PASSWORD_WIPE = os.environ.get("CARSON_PASSWORD_WIPE", CARSON_PASSWORD)
CARSON_PASSWORD_DELETE_IP = os.environ.get("CARSON_PASSWORD_DELETE_IP", CARSON_PASSWORD)

# ------------------------------
# TTLs
# ------------------------------
# If 0 => requires delete password every delete
# If >0 => after entering delete password once, it stays unlocked for that many seconds
DELETE_TTL_SECONDS = int(os.environ.get("DELETE_TTL_SECONDS", "15"))


def _now() -> float:
    return time.time()


# ------------------------------
# Auth helpers (TAB-scoped like preclustering)
# ------------------------------
def is_admin_authed() -> bool:
    return bool(session.get("data_authed", False))


def require_admin() -> bool:
    if not is_admin_authed():
        session.pop("data_authed", None)
        session.pop("delete_unlocked_until", None)
        return False
    return True


def is_delete_unlocked() -> bool:
    return session.get("delete_unlocked_until", 0) > _now()


def is_trainer_authed() -> bool:
    return bool(session.get("trainer_authed", False))


def is_archive_authed() -> bool:
    return bool(session.get("archive_authed", False))


# /me auth (separate keys so it never intersects /data)
def is_carson_authed() -> bool:
    return bool(session.get("carson_authed", False))


def require_carson() -> bool:
    if not is_carson_authed():
        session.pop("carson_authed", None)
        session.pop("carson_delete_unlocked_until", None)
        return False
    return True


def is_carson_delete_unlocked() -> bool:
    return session.get("carson_delete_unlocked_until", 0) > _now()


# ------------------------------
# Logging keys (Redis)
# ------------------------------
# MAIN log (mutable): /data + /trainer see this
DATA_KEY_PREFIX = os.environ.get("DATA_KEY_PREFIX", "clustering:data_log_v2").strip() or "clustering:data_log_v2"
LOG_KEY = DATA_KEY_PREFIX
ID_KEY = f"{DATA_KEY_PREFIX}:id_counter"

# ARCHIVE log (immutable): /carson sees this; never wiped/deleted/edited
ARCHIVE_KEY_PREFIX = os.environ.get("ARCHIVE_KEY_PREFIX", "clustering:archive_v1").strip() or "clustering:archive_v1"
ARCHIVE_LOG_KEY = ARCHIVE_KEY_PREFIX
ARCHIVE_ID_KEY = f"{ARCHIVE_KEY_PREFIX}:id_counter"

# ME log (editable but independent)
CARSON_KEY_PREFIX = os.environ.get("CARSON_KEY_PREFIX", "clustering:carson_log_v1").strip() or "clustering:carson_log_v1"
CARSON_LOG_KEY = CARSON_KEY_PREFIX
CARSON_ID_KEY = f"{CARSON_KEY_PREFIX}:id_counter"

# HARD SAFETY CHECKS
if LOG_KEY == ARCHIVE_LOG_KEY:
    raise RuntimeError("FATAL CONFIG ERROR: DATA_KEY_PREFIX and ARCHIVE_KEY_PREFIX must be different.")
if len({LOG_KEY, ARCHIVE_LOG_KEY, CARSON_LOG_KEY}) != 3:
    raise RuntimeError("FATAL CONFIG ERROR: LOG_KEY / ARCHIVE_LOG_KEY / CARSON_LOG_KEY must all be different.")

# Local fallback storage (dev)
DATA_LOG = []
ARCHIVE_LOG = []
CARSON_LOG = []
LOG_COUNTER = 0
ARCHIVE_COUNTER = 0
CARSON_COUNTER = 0


def _get_redis():
    r = app.config.get("SESSION_REDIS")
    if r is None:
        return None
    try:
        r.ping()
        return r
    except Exception:
        return None


def _next_local_id():
    global LOG_COUNTER
    LOG_COUNTER += 1
    return LOG_COUNTER


def _next_archive_local_id():
    global ARCHIVE_COUNTER
    ARCHIVE_COUNTER += 1
    return ARCHIVE_COUNTER


def _next_carson_local_id():
    global CARSON_COUNTER
    CARSON_COUNTER += 1
    return CARSON_COUNTER


# ------------------------------
# IP helpers
# ------------------------------
def is_public_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_reserved or a.is_multicast or a.is_link_local)
    except ValueError:
        return False


def get_client_ip():
    """
    Returns (client_ip, xff_chain, ip_ok)

    - Prefer first PUBLIC IP in X-Forwarded-For chain.
    - If none, fall back to remote_addr.
    - ip_ok indicates whether the returned IP looks like a real public client IP.
    """
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        for ip in parts:  # leftmost-first
            if is_public_ip(ip):
                return ip, xff, True
        return (parts[0] if parts else (request.remote_addr or "")), xff, False

    ra = request.remote_addr or ""
    return ra, "", is_public_ip(ra)


# ------------------------------
# Log storage
# ------------------------------
def log_append(entry: dict):
    """
    Append to BOTH:
      - MAIN log (mutable)
      - ARCHIVE log (immutable)
    """
    r = _get_redis()
    entry = dict(entry)

    if r is not None:
        if "id" not in entry:
            entry["id"] = int(r.incr(ID_KEY))
        r.rpush(LOG_KEY, json.dumps(entry))

        archive_entry = dict(entry)
        archive_entry["archive_id"] = int(r.incr(ARCHIVE_ID_KEY))
        r.rpush(ARCHIVE_LOG_KEY, json.dumps(archive_entry))
    else:
        if "id" not in entry:
            entry["id"] = _next_local_id()
        DATA_LOG.append(entry)

        archive_entry = dict(entry)
        archive_entry["archive_id"] = _next_archive_local_id()
        ARCHIVE_LOG.append(archive_entry)


def carson_log_append(entry: dict):
    """Append ONLY to ME log (independent)."""
    r = _get_redis()
    entry = dict(entry)

    if r is not None:
        if "id" not in entry:
            entry["id"] = int(r.incr(CARSON_ID_KEY))
        r.rpush(CARSON_LOG_KEY, json.dumps(entry))
    else:
        if "id" not in entry:
            entry["id"] = _next_carson_local_id()
        CARSON_LOG.append(entry)


def log_get_all_main():
    r = _get_redis()
    if r is not None:
        raw = r.lrange(LOG_KEY, 0, -1)
        return [json.loads(x) for x in raw]
    return list(DATA_LOG)


def log_get_all_archive():
    r = _get_redis()
    if r is not None:
        raw = r.lrange(ARCHIVE_LOG_KEY, 0, -1)
        return [json.loads(x) for x in raw]
    return list(ARCHIVE_LOG)


def carson_log_get_all():
    r = _get_redis()
    if r is not None:
        raw = r.lrange(CARSON_LOG_KEY, 0, -1)
        return [json.loads(x) for x in raw]
    return list(CARSON_LOG)


def log_replace_all_main(entries):
    r = _get_redis()
    if r is not None:
        pipe = r.pipeline()
        pipe.delete(LOG_KEY)
        for e in entries:
            pipe.rpush(LOG_KEY, json.dumps(e))
        pipe.execute()
    else:
        global DATA_LOG
        DATA_LOG = list(entries)


def carson_log_replace_all(entries):
    r = _get_redis()
    if r is not None:
        pipe = r.pipeline()
        pipe.delete(CARSON_LOG_KEY)
        for e in entries:
            pipe.rpush(CARSON_LOG_KEY, json.dumps(e))
        pipe.execute()
    else:
        global CARSON_LOG
        CARSON_LOG = list(entries)


def log_clear_main():
    """Wipe ONLY MAIN log keys (archive untouched)."""
    r = _get_redis()
    if r is not None:
        r.delete(LOG_KEY)
        r.delete(ID_KEY)
    else:
        global DATA_LOG, LOG_COUNTER
        DATA_LOG.clear()
        LOG_COUNTER = 0


def carson_log_clear():
    """Wipe ONLY ME log keys (main + archive untouched)."""
    r = _get_redis()
    if r is not None:
        r.delete(CARSON_LOG_KEY)
        r.delete(CARSON_ID_KEY)
    else:
        global CARSON_LOG, CARSON_COUNTER
        CARSON_LOG.clear()
        CARSON_COUNTER = 0


def build_grouped_entries(entries):
    entries = list(reversed(entries))
    grouped = {}
    for e in entries:
        ip = e.get("ip", "Unknown IP")
        grouped.setdefault(ip, []).append(e)
    return grouped


def lookup_city(ip: str):
    try:
        if ip.startswith("127.") or ip == "::1":
            return {"city": "Localhost", "region": None, "country": None}

        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
        data = resp.json()

        if data.get("status") != "success":
            return None

        return {
            "city": data.get("city"),
            "region": data.get("regionName"),
            "country": data.get("country"),
        }
    except Exception:
        return None


# ------------------------------
# Main page
# ------------------------------
@app.route("/", methods=["GET", "POST"], strict_slashes=False)
def index():
    user_ip, xff_chain, ip_ok = get_client_ip()

    user_agent = request.headers.get("User-Agent", "").lower()
    is_bot = (
            "go-http-client/" in user_agent
            or "cron-job.org" in user_agent
            or "uptimerobot.com" in user_agent
            or user_agent.strip() == ""
    )

    geo = lookup_city(user_ip)

    # Only log GET views when IP looks like a real public client IP
    if request.method == "GET" and not is_bot and ip_ok:
        entry = {
            "ip": user_ip,
            "xff": xff_chain,
            "remote_addr": request.remote_addr,
            "geo": geo,
            "timestamp": datetime.now(ZoneInfo("America/Chicago")).strftime("%Y-%m-%d  %H:%M:%S"),
            "event": "view",
            "input": None,
        }
        log_append(entry)     # MAIN + ARCHIVE
        carson_log_append(entry)  # ME (independent)

    if request.method == "POST":
        try:
            int1 = int(request.form.get("int1") or 0)
            int2 = int(request.form.get("int2") or 0)
            int3 = int(request.form.get("int3") or 0)
            int4 = int(request.form.get("int4") or 0)
            int5 = int(request.form.get("int5") or 0)

            req = (request.form.get("int_list") or "").split(",")
            if req == [""]:
                req = [0]
            int_list = [int(x) for x in req if str(x).strip() != ""]

            log_entry = {
                "ip": user_ip,
                "xff": xff_chain,
                "remote_addr": request.remote_addr,
                "geo": geo,
                "timestamp": datetime.now(ZoneInfo("America/Chicago")).strftime("%Y-%m-%d  %H:%M:%S"),
                "event": "submit",
                "input": {
                    "int1": int1,
                    "int2": int2,
                    "int3": int3,
                    "int4": int4,
                    "int5": int5,
                    "int_list": int_list,
                },
            }

            log_append(log_entry)     # MAIN + ARCHIVE
            carson_log_append(log_entry)  # ME (independent)

            results = calculations.cluster(int1, int2, int3, int4, int5, int_list)

            session["int1"] = int1
            session["int2"] = int2
            session["int3"] = int3
            session["int4"] = int4
            session["int5"] = int5
            session["int_list"] = int_list

            return render_template("index.html", results=results, error_message=None)

        except Exception as e:
            return render_template("index.html", error_message=f"An error occurred: {str(e)}", results=None)

    return render_template("index.html", results=None, error_message=None)


# ==========================================================
# Logout beacon endpoints (TAB CLOSE)
# ==========================================================
@app.route("/logout/<role>", methods=["POST"], strict_slashes=False)
def logout_role(role: str):
    # Called by navigator.sendBeacon on tab close / pagehide
    if role == "data":
        session.pop("data_authed", None)
        session.pop("delete_unlocked_until", None)
    elif role == "trainer":
        session.pop("trainer_authed", None)
    elif role == "archive":
        session.pop("archive_authed", None)
    elif role == "carson":
        session.pop("carson_authed", None)
        session.pop("carson_delete_unlocked_until", None)
    return ("", 204)


# ==========================================================
# /data (EDITOR) — login + view + delete + wipe + delete_ip
# ==========================================================
@app.route("/data_login", methods=["GET", "POST"], strict_slashes=False)
def data_login():
    error = None
    if request.method == "POST":
        pwd = request.form.get("password", "")
        if pwd == DATA_PASSWORD_VIEW:
            session["data_authed"] = True
            session.pop("delete_unlocked_until", None)

            # Set tab-only flag so a NEW TAB must re-login (via set_tab_ok.html)
            return render_template(
                "set_tab_ok.html",
                tab_key="tab_ok_data",
                next_url=url_for("data_view"),
            )

        error = "Incorrect password."
    return render_template("data_login.html", error=error)


@app.route("/data", strict_slashes=False)
def data_view():
    if not require_admin():
        return redirect(url_for("data_login"))

    grouped_entries = build_grouped_entries(log_get_all_main())
    return render_template(
        "data.html",
        grouped_entries=grouped_entries,
        delete_unlocked=is_delete_unlocked(),
        delete_error=None,
        wipe_error=None,
    )


@app.route("/delete_entry", methods=["POST"], strict_slashes=False)
def delete_entry():
    if not require_admin():
        return redirect(url_for("data_login"))

    entry_id = request.form.get("entry_id", type=int)
    if entry_id is None:
        return redirect(url_for("data_view"))

    if not is_delete_unlocked():
        pwd = request.form.get("delete_password", "")
        if pwd != DATA_PASSWORD_DELETE:
            grouped_entries = build_grouped_entries(log_get_all_main())
            return render_template(
                "data.html",
                grouped_entries=grouped_entries,
                delete_unlocked=is_delete_unlocked(),
                delete_error="Incorrect delete password.",
                wipe_error=None,
            )
        session["delete_unlocked_until"] = _now() + DELETE_TTL_SECONDS

    entries = log_get_all_main()
    filtered = [e for e in entries if e.get("id") != entry_id]
    log_replace_all_main(filtered)
    return redirect(url_for("data_view"))


@app.route("/wipe_data", methods=["POST"], strict_slashes=False)
def wipe_data():
    if not require_admin():
        return redirect(url_for("data_login"))

    pwd = request.form.get("wipe_password", "")
    if pwd != DATA_PASSWORD_WIPE:
        grouped_entries = build_grouped_entries(log_get_all_main())
        return render_template(
            "data.html",
            grouped_entries=grouped_entries,
            delete_unlocked=is_delete_unlocked(),
            delete_error=None,
            wipe_error="Incorrect wipe password.",
        )

    log_clear_main()  # MAIN cleared; ARCHIVE untouched
    return redirect(url_for("data_view"))


@app.route("/delete_ip", methods=["POST"], strict_slashes=False)
def delete_ip():
    if not require_admin():
        return redirect(url_for("data_login"))

    ip_to_delete = (request.form.get("ip") or "").strip()
    if not ip_to_delete:
        return redirect(url_for("data_view"))

    # requires its own password EVERY TIME (no session unlock)
    pwd = request.form.get("delete_ip_password", "")
    if pwd != DATA_PASSWORD_DELETE_IP:
        grouped_entries = build_grouped_entries(log_get_all_main())
        return render_template(
            "data.html",
            grouped_entries=grouped_entries,
            delete_unlocked=is_delete_unlocked(),
            delete_error=None,
            wipe_error="Incorrect IP delete password.",
        )

    entries = log_get_all_main()
    filtered = [e for e in entries if e.get("ip", "Unknown IP") != ip_to_delete]
    log_replace_all_main(filtered)

    return redirect(url_for("data_view"))


# ==========================================================
# /trainer (VIEWER) — view-only MAIN (changes with /data)
# ==========================================================
@app.route("/trainer_login", methods=["GET", "POST"], strict_slashes=False)
def trainer_login():
    error = None
    if request.method == "POST":
        pwd = request.form.get("password", "")
        if pwd == TRAINER_PASSWORD_VIEW:
            session["trainer_authed"] = True

            return render_template(
                "set_tab_ok.html",
                tab_key="tab_ok_trainer",
                next_url=url_for("trainer_view"),
            )

        error = "Incorrect password."
    return render_template("trainer_login.html", error=error)


@app.route("/trainer", strict_slashes=False)
def trainer_view():
    if not is_trainer_authed():
        session.pop("trainer_authed", None)
        return redirect(url_for("trainer_login"))

    grouped_entries = build_grouped_entries(log_get_all_main())
    return render_template("trainer.html", grouped_entries=grouped_entries)


# ==========================================================
# /carson (IMMUTABLE VIEWER) — view-only ARCHIVE (tab-only, no TTL)
# ==========================================================
@app.route("/archive_login", methods=["GET", "POST"], strict_slashes=False)
def archive_login():
    error = None
    if request.method == "POST":
        pwd = request.form.get("password", "")
        if pwd == ARCHIVE_PASSWORD_VIEW:
            session["archive_authed"] = True

            return render_template(
                "set_tab_ok.html",
                tab_key="tab_ok_archive",
                next_url=url_for("archive_view"),
            )

        error = "Incorrect password."
    return render_template("archive_login.html", error=error)


@app.route("/archive", strict_slashes=False)
def archive_view():
    if not is_archive_authed():
        session.pop("archive_authed", None)
        return redirect(url_for("archive_login"))

    grouped_entries = build_grouped_entries(log_get_all_archive())
    return render_template("archive.html", grouped_entries=grouped_entries)


# ==========================================================
# /me (EDITOR) — independent editable log (like archive stream, but mutable)
# ==========================================================
@app.route("/carson_login", methods=["GET", "POST"], strict_slashes=False)
def carson_login():
    error = None
    if request.method == "POST":
        pwd = request.form.get("password", "")
        if pwd == CARSON_PASSWORD_VIEW:
            session["carson_authed"] = True
            session.pop("carson_delete_unlocked_until", None)

            return render_template(
                "set_tab_ok.html",
                tab_key="tab_ok_carson",
                next_url=url_for("carson_view"),
            )

        error = "Incorrect password."
    return render_template("carson_login.html", error=error)


@app.route("/carson", strict_slashes=False)
def carson_view():
    if not require_carson():
        return redirect(url_for("carson_login"))

    grouped_entries = build_grouped_entries(carson_log_get_all())
    return render_template(
        "carson.html",
        grouped_entries=grouped_entries,
        delete_unlocked=is_carson_delete_unlocked(),
        delete_error=None,
        wipe_error=None,
    )


@app.route("/carson_delete_entry", methods=["POST"], strict_slashes=False)
def carson_delete_entry():
    if not require_carson():
        return redirect(url_for("carson_login"))

    entry_id = request.form.get("entry_id", type=int)
    if entry_id is None:
        return redirect(url_for("carson_view"))

    if not is_carson_delete_unlocked():
        pwd = request.form.get("delete_password", "")
        if pwd != CARSON_PASSWORD_DELETE:
            grouped_entries = build_grouped_entries(carson_log_get_all())
            return render_template(
                "carson.html",
                grouped_entries=grouped_entries,
                delete_unlocked=is_carson_delete_unlocked(),
                delete_error="Incorrect delete password.",
                wipe_error=None,
            )
        session["carson_delete_unlocked_until"] = _now() + DELETE_TTL_SECONDS

    entries = carson_log_get_all()
    filtered = [e for e in entries if e.get("id") != entry_id]
    carson_log_replace_all(filtered)
    return redirect(url_for("carson_view"))


@app.route("/carson_wipe", methods=["POST"], strict_slashes=False)
def carson_wipe():
    if not require_carson():
        return redirect(url_for("carson_login"))

    pwd = request.form.get("wipe_password", "")
    if pwd != CARSON_PASSWORD_WIPE:
        grouped_entries = build_grouped_entries(carson_log_get_all())
        return render_template(
            "carson.html",
            grouped_entries=grouped_entries,
            delete_unlocked=is_carson_delete_unlocked(),
            delete_error=None,
            wipe_error="Incorrect wipe password.",
        )

    carson_log_clear()
    return redirect(url_for("carson_view"))


@app.route("/carson_delete_ip", methods=["POST"], strict_slashes=False)
def carson_delete_ip():
    if not require_carson():
        return redirect(url_for("carson_login"))

    ip_to_delete = (request.form.get("ip") or "").strip()
    if not ip_to_delete:
        return redirect(url_for("carson_view"))

    # requires its own password EVERY TIME (no session unlock)
    pwd = request.form.get("delete_ip_password", "")
    if pwd != CARSON_PASSWORD_DELETE_IP:
        grouped_entries = build_grouped_entries(carson_log_get_all())
        return render_template(
            "carson.html",
            grouped_entries=grouped_entries,
            delete_unlocked=is_carson_delete_unlocked(),
            delete_error=None,
            wipe_error="Incorrect IP delete password.",
        )

    entries = carson_log_get_all()
    filtered = [e for e in entries if e.get("ip", "Unknown IP") != ip_to_delete]
    carson_log_replace_all(filtered)

    return redirect(url_for("carson_view"))


if __name__ == "__main__":
    app.run()
