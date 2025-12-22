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

# Browser-session cookie (ends when browser closes)
app.config["SESSION_PERMANENT"] = False
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
# Trainer password (view-only)
# ------------------------------
TRAINER_PASSWORD_VIEW = os.environ.get("TRAINER_PASSWORD_VIEW", "change-me")

# ------------------------------
# Logging keys (Redis)
# ------------------------------
DATA_KEY_PREFIX = (os.environ.get("DATA_KEY_PREFIX", "clustering:trainer_log_v1").strip()
                   or "clustering:trainer_log_v1")
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


def lookup_city(ip: str):
    try:
        if ip.startswith("127.") or ip == "::1":
            return {"city": "Localhost", "region": None, "country": None}

        resp = requests.get(
            f"https://api.db-ip.com/v2/free/{ip}",
            timeout=2,
        )
        data = resp.json()

        return {
            "city": data.get("city"),
            "region": data.get("stateProv"),
            "country": data.get("countryName"),
        }
    except Exception:
        return None

def _format_loc(geo):
    if not geo:
        return "Location unknown"
    city = geo.get("city") or "Unknown city"
    region = geo.get("region") or "Unknown region"
    country = geo.get("country") or "Unknown country"
    return f"{city}, {region}, {country}"


def print_event(event: str, user_ip: str, geo, xff_chain: str, remote_addr: str, payload=None):
    ts = datetime.now(ZoneInfo("America/Chicago")).strftime("%Y-%m-%d %H:%M:%S")
    loc = _format_loc(geo)
    print(
        f"{event.upper()} {ts} | ip = {user_ip} | {loc} | inputs = {payload} | xff = {xff_chain} | ra = {remote_addr}",
        flush=True
    )


# ------------------------------
# Log storage (SUBMITS only)
# ------------------------------
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
        entries = [json.loads(x) for x in raw]
    else:
        entries = list(DATA_LOG)

    # ONLY keep real submit rows (no NULL/view legacy)
    return [
        e for e in entries
        if e.get("event") == "submit" and e.get("input") is not None
    ]

def build_grouped_entries(entries):
    # Most recent first
    entries = list(reversed(entries))
    grouped = {}
    for e in entries:
        ip = e.get("ip", "Unknown IP")
        grouped.setdefault(ip, []).append(e)
    return grouped


# ------------------------------
# Auth helpers
# ------------------------------
def is_trainer_authed() -> bool:
    return bool(session.get("trainer_authed", False))


# ------------------------------
# Shared request parsing
# ------------------------------
def parse_inputs_from_form():
    int1 = int(request.form.get("int1") or 0)
    int2 = int(request.form.get("int2") or 0)
    int3 = int(request.form.get("int3") or 0)
    int4 = int(request.form.get("int4") or 0)
    int5 = int(request.form.get("int5") or 0)

    req = (request.form.get("int_list") or "").split(",")
    if req == [""]:
        req = [0]
    int_list = [int(x) for x in req if str(x).strip() != ""]

    return int1, int2, int3, int4, int5, int_list

def describe_inputs(int1, int2, int3, int4, int5, int_list):
    return {
        "single_sites": int1,
        "double_sites": int2,
        "triple_sites": int3,
        "cars": int4,
        "vans": int5,
        "bus_capacities": int_list,
    }

def is_request_bot(user_agent: str) -> bool:
    ua = (user_agent or "").lower()
    return (
            "go-http-client/" in ua
            or "cron-job.org" in ua
            or "uptimerobot.com" in ua
            or ua.strip() == ""
    )


# ------------------------------
# Main page (REAL) — prints views, logs submits
# ------------------------------
@app.route("/", methods=["GET", "POST"], strict_slashes=False)
def index():
    user_ip, xff_chain, ip_ok = get_client_ip()
    is_bot = is_request_bot(request.headers.get("User-Agent", ""))

    geo = lookup_city(user_ip)

    # GET: print viewer info only (no stored log)
    if request.method == "GET" and (not is_bot) and ip_ok:
        print_event(
            event="view",
            user_ip=user_ip,
            geo=geo,
            xff_chain=xff_chain,
            remote_addr=request.remote_addr,
            payload=None,
        )
        return render_template("index.html", results=None, error_message=None)

    # POST: log submit to stored log + show results
    if request.method == "POST":
        try:
            int1, int2, int3, int4, int5, int_list = parse_inputs_from_form()

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
            log_append(log_entry)

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


# ------------------------------
# Test page — prints views + prints submits, logs nothing
# ------------------------------
@app.route("/test", methods=["GET", "POST"], strict_slashes=False)
def test_page():
    user_ip, xff_chain, ip_ok = get_client_ip()
    user_agent = request.headers.get("User-Agent", "")
    is_bot = is_request_bot(user_agent)

    geo = lookup_city(user_ip)

    # ------------------------------
    # GET: print viewer info only
    # ------------------------------
    if request.method == "GET":
        if (not is_bot) and ip_ok:
            print_event(
                event="view-test",
                user_ip=user_ip,
                geo=geo,
                xff_chain=xff_chain,
                remote_addr=request.remote_addr,
                payload=None,
            )
        return render_template("index.html", results=None, error_message=None)

    # ------------------------------
    # POST: print inputs only
    # ------------------------------
    try:
        int1 = int(request.form.get("int1") or 0)
        int2 = int(request.form.get("int2") or 0)
        int3 = int(request.form.get("int3") or 0)
        int4 = int(request.form.get("int4") or 0)
        int5 = int(request.form.get("int5") or 0)

        raw = (request.form.get("int_list") or "").split(",")
        if raw == [""]:
            raw = [0]
        int_list = [int(x) for x in raw if str(x).strip() != ""]

        summary = (
                "singlesites = " + str(int1) + ", "
                "doublesites = " + str(int2) + ", "
                "triplesites = " + str(int3) + ", "
                "cars = " + str(int4) + ", "
                "vans = " + str(int5) + ", "
                "buses = " + str(int_list)
        )

        print_event(
            event="submit-test",
            user_ip=user_ip,
            geo=geo,
            xff_chain=xff_chain,
            remote_addr=request.remote_addr,
            payload=summary,
        )

        results = calculations.cluster(int1, int2, int3, int4, int5, int_list)

        return render_template("index.html", results=results, error_message=None)

    except Exception as e:
        return render_template(
            "index.html",
            results=None,
            error_message="An error occurred: " + str(e),
        )

# ------------------------------
# /trainer (VIEW-ONLY)
# ------------------------------
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

    grouped_entries = build_grouped_entries(log_get_all())
    return render_template("trainer.html", grouped_entries=grouped_entries)

if __name__ == "__main__":
    app.run()
