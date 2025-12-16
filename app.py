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

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "supersecretkey")

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

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_USE_SIGNER"] = True

# IMPORTANT: isolate session keys between apps sharing Redis
# Render env example:
#   SESSION_KEY_PREFIX=session:clustering:
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
# Admin passwords
# ------------------------------
DATA_PASSWORD = os.environ.get("DATA_PASSWORD", "change-me")
DATA_PASSWORD_VIEW = os.environ.get("DATA_PASSWORD_VIEW", DATA_PASSWORD)
DATA_PASSWORD_DELETE = os.environ.get("DATA_PASSWORD_DELETE", DATA_PASSWORD)
DATA_PASSWORD_WIPE = os.environ.get("DATA_PASSWORD_WIPE", DATA_PASSWORD)

# ------------------------------
# Admin TTL (seconds)
# ------------------------------
ADMIN_TTL_SECONDS = int(os.environ.get("ADMIN_TTL_SECONDS", "60"))

# If 0 => requires delete password every delete
# If >0 => after entering delete password once, it stays unlocked for that many seconds
DELETE_TTL_SECONDS = int(os.environ.get("DELETE_TTL_SECONDS", "0"))

def _now() -> float:
    return time.time()

def is_admin_authed() -> bool:
    return session.get("data_admin_until", 0) > _now()

def require_admin() -> bool:
    if not is_admin_authed():
        session.pop("data_admin_until", None)
        session.pop("delete_unlocked_until", None)
        return False
    return True

def is_delete_unlocked() -> bool:
    return session.get("delete_unlocked_until", 0) > _now()

# ------------------------------
# Logging keys (Redis)
# ------------------------------
# IMPORTANT: isolate log keys between apps sharing the same Redis
# Render env example:
#   DATA_KEY_PREFIX=clustering:data_log_v2
DATA_KEY_PREFIX = os.environ.get("DATA_KEY_PREFIX", "clustering:data_log_v2").strip() or "clustering:data_log_v2"
LOG_KEY = DATA_KEY_PREFIX
ID_KEY = f"{DATA_KEY_PREFIX}:id_counter"

# Local fallback storage (dev)
DATA_LOG = []
LOG_COUNTER = 0

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

def log_append(entry: dict):
    r = _get_redis()
    entry = dict(entry)

    if r is not None:
        if "id" not in entry:
            entry["id"] = int(r.incr(ID_KEY))
        r.rpush(LOG_KEY, json.dumps(entry))
    else:
        if "id" not in entry:
            entry["id"] = _next_local_id()
        DATA_LOG.append(entry)

def log_get_all():
    r = _get_redis()
    if r is not None:
        raw = r.lrange(LOG_KEY, 0, -1)
        return [json.loads(x) for x in raw]
    return list(DATA_LOG)

def log_replace_all(entries):
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

def log_clear_all():
    r = _get_redis()
    if r is not None:
        r.delete(LOG_KEY)
        r.delete(ID_KEY)
    else:
        global DATA_LOG, LOG_COUNTER
        DATA_LOG.clear()
        LOG_COUNTER = 0

def build_grouped_entries():
    entries = list(reversed(log_get_all()))
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

@app.route("/", methods=["GET", "POST"], strict_slashes=False)
def index():
    user_ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()
    user_agent = request.headers.get("User-Agent", "").lower()
    is_bot = (
            "go-http-client/" in user_agent
            or "cron-job.org" in user_agent
            or "uptimerobot.com" in user_agent
            or user_agent.strip() == ""
    )

    geo = lookup_city(user_ip)

    if request.method == "GET" and not is_bot:
        log_append({
            "ip": user_ip,
            "geo": geo,
            "timestamp": datetime.now(ZoneInfo("America/Chicago")).strftime("%Y-%m-%d  %H:%M:%S"),
            "event": "view",
            "input": None,
        })

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

            log_append({
                "ip": user_ip,
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
            })

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

@app.route("/data_login", methods=["GET", "POST"], strict_slashes=False)
def data_login():
    error = None
    if request.method == "POST":
        pwd = request.form.get("password", "")
        if pwd == DATA_PASSWORD_VIEW:
            session["data_admin_until"] = _now() + ADMIN_TTL_SECONDS
            session.pop("delete_unlocked_until", None)
            return redirect(url_for("data_view"))
        error = "Incorrect password."
    return render_template("data_login.html", error=error)

@app.route("/data", strict_slashes=False)
def data_view():
    if not require_admin():
        return redirect(url_for("data_login"))

    grouped_entries = build_grouped_entries()
    delete_unlocked = is_delete_unlocked()

    return render_template(
        "data.html",
        grouped_entries=grouped_entries,
        delete_unlocked=delete_unlocked,
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

    delete_unlocked = is_delete_unlocked()

    if not delete_unlocked:
        pwd = request.form.get("delete_password", "")
        if pwd != DATA_PASSWORD_DELETE:
            grouped_entries = build_grouped_entries()
            return render_template(
                "data.html",
                grouped_entries=grouped_entries,
                delete_unlocked=is_delete_unlocked(),
                delete_error="Incorrect delete password.",
                wipe_error=None,
            )
        session["delete_unlocked_until"] = _now() + DELETE_TTL_SECONDS
        delete_unlocked = is_delete_unlocked()

    entries = log_get_all()
    filtered = [e for e in entries if e.get("id") != entry_id]
    log_replace_all(filtered)
    return redirect(url_for("data_view"))

@app.route("/wipe_data", methods=["POST"], strict_slashes=False)
def wipe_data():
    if not require_admin():
        return redirect(url_for("data_login"))

    pwd = request.form.get("wipe_password", "")
    if pwd != DATA_PASSWORD_WIPE:
        grouped_entries = build_grouped_entries()
        return render_template(
            "data.html",
            grouped_entries=grouped_entries,
            delete_unlocked=is_delete_unlocked(),
            delete_error=None,
            wipe_error="Incorrect wipe password.",
        )

    log_clear_all()
    return redirect(url_for("data_view"))

if __name__ == "__main__":
    app.run()
