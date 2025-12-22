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
MAX_LOG_ENTRIES = int(os.environ.get("MAX_LOG_ENTRIES", "20000"))

# ------------------------------
# Hidden IPs (do not log / do not show in trainer)
# Set in Render env as comma-separated:
#   HIDDEN_IPS=1.2.3.4,5.6.7.8
# ------------------------------
HIDDEN_IPS_RAW = os.environ.get("HIDDEN_IPS", "").strip()
HIDDEN_IPS = {x.strip() for x in HIDDEN_IPS_RAW.split(",") if x.strip()}

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
# Hidden IP helpers
# ------------------------------
def is_hidden_ip(ip: str) -> bool:
    return ip in HIDDEN_IPS


def filter_out_hidden_entries(entries):
    if not HIDDEN_IPS:
        return list(entries)
    return [e for e in entries if e.get("ip") not in HIDDEN_IPS]


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


def _format_loc(geo):
    if not geo:
        return "Location unknown"
    city = geo.get("city") or "Unknown city"
    region = geo.get("region") or "Unknown region"
    country = geo.get("country") or "Unknown country"
    return f"{city}, {region}, {country}"


def print_event(event: str, user_ip: str, geo, xff_chain: str, remote_addr: str, payload=None):
    loc = _format_loc(geo)
    print(
        f"{event.upper()} | ip= {user_ip} | {loc} | inputs= {payload} | xff= {xff_chain} | ra= {remote_addr}",
        flush=True
    )

def log_append(entry: dict):
    entry = dict(entry)

    # Skip hidden IPs entirely
    if is_hidden_ip(entry.get("ip", "")):
        return

    r = _get_redis()

    if r is not None:
        if "id" not in entry:
            entry["id"] = int(r.incr(ID_KEY))
        r.rpush(LOG_KEY, json.dumps(entry))
        r.ltrim(LOG_KEY, -MAX_LOG_ENTRIES, -1)
    else:
        if "id" not in entry:
            entry["id"] = _next_local_id()
        DATA_LOG.append(entry)


def log_get_all_raw():
    r = _get_redis()
    if r is not None:
        raw = r.lrange(LOG_KEY, 0, -1)
        return [json.loads(x) for x in raw]
    return list(DATA_LOG)


def log_get_all():
    # Hide IPs from display, too
    return filter_out_hidden_entries(log_get_all_raw())


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


def purge_hidden_ips_from_storage():
    """Remove already-stored entries for hidden IPs."""
    if not HIDDEN_IPS:
        return
    entries = log_get_all_raw()
    filtered = filter_out_hidden_entries(entries)
    if len(filtered) != len(entries):
        log_replace_all(filtered)
        print(f"PURGE-HIDDEN removed={len(entries) - len(filtered)}", flush=True)


def build_grouped_entries(entries):
    # Most recent first
    entries = list(reversed(entries))
    grouped = {}
    for e in entries:
        ip = e.get("ip", "Unknown IP")
        grouped.setdefault(ip, []).append(e)
    return grouped


def is_trainer_authed() -> bool:
    return bool(session.get("trainer_authed", False))


def parse_inputs_from_form():
    int1 = int(request.form.get("int1") or 0)
    int2 = int(request.form.get("int2") or 0)
    int3 = int(request.form.get("int3") or 0)
    int4 = int(request.form.get("int4") or 0)
    int5 = int(request.form.get("int5") or 0)

    raw = (request.form.get("int_list") or "").split(",")
    if raw == [""]:
        raw = [0]
    int_list = [int(x) for x in raw if str(x).strip() != ""]

    return int1, int2, int3, int4, int5, int_list


def is_request_bot(user_agent: str) -> bool:
    ua = (user_agent or "").lower()
    return (
            "go-http-client/" in ua
            or "cron-job.org" in ua
            or "uptimerobot.com" in ua
            or ua.strip() == ""
    )

purge_hidden_ips_from_storage()


@app.route("/", methods=["GET", "POST"], strict_slashes=False)
def index():
    user_ip, xff_chain, ip_ok = get_client_ip()
    is_bot = is_request_bot(request.headers.get("User-Agent", ""))

    geo = lookup_city(user_ip)

    # GET: print viewer info only (no stored log)
    if request.method == "GET":
        if (not is_bot) and ip_ok and (not is_hidden_ip(user_ip)):
            print_event(
                event="viewer",
                user_ip=user_ip,
                geo=geo,
                xff_chain=xff_chain,
                remote_addr=request.remote_addr,
                payload=None,
            )
        return render_template("index.html", results=None, error_message=None)

    # POST: log submit to stored log + show results
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
        return render_template("index.html", error_message="An error occurred: " + str(e), results=None)



def format_inputs_pretty(int1, int2, int3, int4, int5, int_list):
    # Nice, stable order; easy to scan in Render logs
    return (
        f"Single Sites={int1} | "
        f"Double Sites={int2} | "
        f"Triple Sites={int3} | "
        f"Cars={int4} | "
        f"Vans={int5} | "
        f"Bus Capacities={int_list}"
    )


def print_event(event: str, user_ip: str, geo, xff_chain: str, remote_addr: str, payload=None):
    loc = _format_loc(geo)

    # Render-friendly single line, consistent keys
    msg = f"{event.upper()} | ip= {user_ip} | loc= {loc} | xff= {xff_chain} | ra= {remote_addr}"
    if payload is not None:
        msg += f" | {payload}"

    print(msg, flush=True)

# ------------------------------
# Test page — prints views + prints submits, logs nothing
# ------------------------------
@app.route("/test", methods=["GET", "POST"], strict_slashes=False)
def test_page():
    user_ip, xff_chain, ip_ok = get_client_ip()
    is_bot = is_request_bot(request.headers.get("User-Agent", ""))

    geo = lookup_city(user_ip)

    # GET: print viewer info only
    if request.method == "GET":
        if (not is_bot) and ip_ok and (not is_hidden_ip(user_ip)):
            print_event(
                event="view-test",
                user_ip=user_ip,
                geo=geo,
                xff_chain=xff_chain,
                remote_addr=request.remote_addr,
                payload=None,
            )
        return render_template("index.html", results=None, error_message=None)

    # POST: print submit payload only (no stored log)
    try:
        int1, int2, int3, int4, int5, int_list = parse_inputs_from_form()

        pretty = format_inputs_pretty(int1, int2, int3, int4, int5, int_list)

        if not is_hidden_ip(user_ip):
            print_event(
                event="user-test",
                user_ip=user_ip,
                geo=geo,
                xff_chain=xff_chain,
                remote_addr=request.remote_addr,
                payload=pretty,
            )

        results = calculations.cluster(int1, int2, int3, int4, int5, int_list)
        return render_template("index.html", results=results, error_message=None)

    except Exception as e:
        return render_template("index.html", error_message="An error occurred: " + str(e), results=None)


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
