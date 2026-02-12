from __future__ import annotations

from flask import Flask, render_template, request, session, redirect, url_for, g
from flask_session import Session
import calculations
import os
import redis
from pathlib import Path
from datetime import datetime
from zoneinfo import ZoneInfo
import requests
import json
import uuid
import ipaddress
from werkzeug.middleware.proxy_fix import ProxyFix
from datetime import timedelta

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "supersecretkey")

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

IS_RENDER = bool(os.environ.get("RENDER")) or bool(os.environ.get("RENDER_SERVICE_ID"))
COOKIE_SECURE = True if IS_RENDER else False

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=COOKIE_SECURE,
)

redis_url = os.environ.get("REDIS_URL", "").strip()

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_USE_SIGNER"] = True

app.config["SESSION_KEY_PREFIX"] = os.environ.get("SESSION_KEY_PREFIX", "session:clustering:")

DEVICE_COOKIE_NAME = "device_id"
DEVICE_COOKIE_MAX_AGE = 60 * 60 * 24 * 365 * 2  # 2 years
LOG_RETENTION_DAYS = 365 * 2

def _valid_device_cookie(val: str | None) -> bool:
    if not val:
        return False
    val = val.strip()
    return 16 <= len(val) <= 80

def get_device_id() -> str:
    # Always stable within the request
    if hasattr(g, "device_id"):
        return g.device_id

    did = request.cookies.get(DEVICE_COOKIE_NAME)
    if _valid_device_cookie(did):
        g.device_id = did.strip()
        return g.device_id

    # no valid cookie -> generate once and cache for this request
    g.device_id = uuid.uuid4().hex
    return g.device_id

if redis_url:
    app.config["SESSION_TYPE"] = "redis"
    app.config["SESSION_REDIS"] = redis.Redis.from_url(redis_url)
else:
    app.config["SESSION_TYPE"] = "filesystem"
    session_dir = Path(app.instance_path) / "flask_session"
    session_dir.mkdir(parents=True, exist_ok=True)
    app.config["SESSION_FILE_DIR"] = str(session_dir)

Session(app)

TRAINER_PASSWORD_VIEW = os.environ.get("TRAINER_PASSWORD_VIEW", "change-me")
MAX_LOG_ENTRIES = int(os.environ.get("MAX_LOG_ENTRIES", "20000"))

HIDDEN_IPS_RAW = os.environ.get("HIDDEN_IPS", "").strip()
HIDDEN_IPS = {x.strip() for x in HIDDEN_IPS_RAW.split(",") if x.strip()}

DATA_KEY_PREFIX = (os.environ.get("DATA_KEY_PREFIX", "clustering:trainer_log_v1").strip()
                   or "clustering:trainer_log_v1")
LOG_KEY = DATA_KEY_PREFIX
ID_KEY = f"{DATA_KEY_PREFIX}:id_counter"

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

def is_hidden_ip(ip: str) -> bool:
    return ip in HIDDEN_IPS

def filter_out_hidden_entries(entries):
    if not HIDDEN_IPS:
        return list(entries)
    return [e for e in entries if e.get("ip") not in HIDDEN_IPS]


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

def build_user_map(entries: list[dict]) -> dict[str, int]:
    entries_oldest_first = sorted(entries, key=lambda e: e.get("timestamp", ""))
    first_seen: dict[str, str] = {}
    for e in entries_oldest_first:
        did = e.get("device_id")
        if not did:
            continue
        first_seen.setdefault(did, e.get("timestamp", ""))

    ordered = sorted(first_seen.items(), key=lambda x: (x[1], x[0]))
    return {did: i for i, (did, _) in enumerate(ordered, start=1)}

def _location_key_from_geo(geo: dict | None) -> str:
    if not geo:
        return "Location unknown"
    city = geo.get("city") or "Unknown city"
    region = geo.get("region") or "Unknown region"
    country = geo.get("country") or "Unknown country"
    return f"{city}, {region}, {country}"


def purge_old_entries():
    cutoff = datetime.now(ZoneInfo("America/Chicago")) - timedelta(days=LOG_RETENTION_DAYS)

    def is_recent(e: dict) -> bool:
        try:
            ts = datetime.strptime(e.get("timestamp", ""), "%Y-%m-%d  %H:%M:%S")
            ts = ts.replace(tzinfo=ZoneInfo("America/Chicago"))
            return ts >= cutoff
        except Exception:
            return False  # drop malformed timestamps

    r = _get_redis()
    if r is not None:
        raw = r.lrange(LOG_KEY, 0, -1)
        kept = []
        for s in raw:
            try:
                if isinstance(s, (bytes, bytearray)):
                    s = s.decode("utf-8", "ignore")
                e = json.loads(s)
                if is_recent(e):
                    kept.append(json.dumps(e))
            except Exception:
                pass

        pipe = r.pipeline()
        pipe.delete(LOG_KEY)
        if kept:
            pipe.rpush(LOG_KEY, *kept)
            pipe.ltrim(LOG_KEY, -MAX_LOG_ENTRIES, -1)
        pipe.execute()
    else:
        global DATA_LOG
        DATA_LOG = [e for e in DATA_LOG if is_recent(e)]

def build_grouped_entries_by_user_location(entries: list[dict]) -> dict[int, dict[str, list[dict]]]:
    user_map = build_user_map(entries)

    grouped: dict[int, dict[str, list[dict]]] = {}

    for e in entries:
        did = e.get("device_id") or ""
        user_num = user_map.get(did, 0)
        loc = _location_key_from_geo(e.get("geo"))
        grouped.setdefault(user_num, {}).setdefault(loc, []).append(e)

    # Sort entries newest-first within each location
    for u in grouped:
        for loc in grouped[u]:
            grouped[u][loc].sort(key=lambda e: e.get("timestamp", ""), reverse=True)

    # Sort locations newest-first within each user (based on newest entry in that loc)
    def loc_newest_ts(u: int, loc: str) -> str:
        return grouped[u][loc][0].get("timestamp", "") if grouped[u][loc] else ""

    ordered_grouped: dict[int, dict[str, list[dict]]] = {}
    for u in grouped:
        locs_sorted = sorted(grouped[u].keys(), key=lambda loc: loc_newest_ts(u, loc), reverse=True)
        ordered_grouped[u] = {loc: grouped[u][loc] for loc in locs_sorted}

    # Sort users newest-first (based on newest entry in their newest location)
    def user_newest_ts(u: int) -> str:
        first_loc = next(iter(ordered_grouped[u].keys()), "")
        if not first_loc:
            return ""
        return ordered_grouped[u][first_loc][0].get("timestamp", "")

    users_sorted = sorted(ordered_grouped.keys(), key=user_newest_ts, reverse=True)
    users_sorted = sorted(users_sorted, key=lambda u: (u == 0,))  # Unknown user to bottom

    return {u: ordered_grouped[u] for u in users_sorted}

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

def _now_ts():
    return datetime.now(ZoneInfo("America/Chicago")).strftime("%Y-%m-%d  %H:%M:%S")

def print_event(event: str, user_ip: str, device_id: str, geo, xff_chain: str, remote_addr: str, payload_lines: list[str] | None):
    if is_hidden_ip(user_ip):
        return

    print(f"\n{event.upper()} @ {_now_ts()}", flush=True)
    print(f"  Device: {device_id}", flush=True)
    print(f"  IP: {user_ip}", flush=True)
    print(f"  Location: {_format_loc(geo)}", flush=True)

    if xff_chain:
        print(f"  X-Forwarded-For: {xff_chain}", flush=True)
    if remote_addr:
        print(f"  Remote Addr: {remote_addr}", flush=True)

    if payload_lines:
        print("", flush=True)
        for line in payload_lines:
            print(line, flush=True)

    print("-" * 40, flush=True)

def build_payload_lines(int1, int2, int3, int4, int5, int_list) -> list[str]:
    pretty = (
        f"Single Sites={int1} | "
        f"Double Sites={int2} | "
        f"Triple Sites={int3} | "
        f"Cars={int4} | "
        f"Vans={int5} | "
        f"Bus Capacities={int_list}"
    )

    parts = [p.strip() for p in pretty.split("|") if p.strip()]
    lines = []

    for p in parts:
        if "=" in p:
            k, v = p.split("=", 1)
            lines.append(f"  {k.strip()}: {v.strip()}")
        else:
            lines.append(f"  {p}")

    return lines


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
        out = []
        for x in raw:
            try:
                if isinstance(x, (bytes, bytearray)):
                    x = x.decode("utf-8", "ignore")
                out.append(json.loads(x))
            except Exception:
                pass
        return out
    return list(DATA_LOG)

def log_get_all():
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
    if not HIDDEN_IPS:
        return
    entries = log_get_all_raw()
    filtered = filter_out_hidden_entries(entries)
    if len(filtered) != len(entries):
        log_replace_all(filtered)
        print(f"PURGE-HIDDEN removed={len(entries) - len(filtered)}", flush=True)

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
        raw = []
    int_list = [int(x) for x in raw if str(x).strip() != ""]

    return int1, int2, int3, int4, int5, int_list

WIPE_ALL_IPS_RAW = os.environ.get("WIPE_ALL_IPS", "").strip().lower()
WIPE_ALL_IPS = WIPE_ALL_IPS_RAW in {"1", "true", "yes", "y", "on"}

def wipe_all_ip_logs_from_storage():
    global DATA_LOG, LOG_COUNTER

    r = _get_redis()
    if r is not None:
        pipe = r.pipeline()
        pipe.delete(LOG_KEY)
        pipe.delete(ID_KEY)
        pipe.execute()
    else:
        DATA_LOG = []
        LOG_COUNTER = 0

if WIPE_ALL_IPS:
    wipe_all_ip_logs_from_storage()

purge_hidden_ips_from_storage()


def _render_index(results=None, error_message=None):
    return render_template(
        "index.html",
        results=results,
        error_message=error_message,
        int1=session.get("int1", ""),
        int2=session.get("int2", ""),
        int3=session.get("int3", ""),
        int4=session.get("int4", ""),
        int5=session.get("int5", ""),
        int_list=",".join(map(str, session.get("int_list", []))) if isinstance(session.get("int_list", []), list) else (session.get("int_list") or ""),
    )


@app.route("/", methods=["GET", "POST"], strict_slashes=False)
def index():
    user_ip, xff_chain, ip_ok = get_client_ip()
    device_id = get_device_id()

    geo = lookup_city(user_ip)

    if request.method == "GET":
        _ = get_device_id()
        return _render_index(results=None, error_message=None)


    try:
        int1, int2, int3, int4, int5, int_list = parse_inputs_from_form()


        log_entry = {
            "ip": user_ip,
            "device_id": device_id,
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

        return _render_index(results=results, error_message=None)

    except Exception as e:
        return _render_index(results=None, error_message="An error occurred: " + str(e))

@app.route("/test", methods=["GET", "POST"], strict_slashes=False)
def test_page():

    if request.method == "GET":
        _ = get_device_id()
        return _render_index(results=None, error_message=None)

    try:
        int1, int2, int3, int4, int5, int_list = parse_inputs_from_form()

        session["int1"] = int1
        session["int2"] = int2
        session["int3"] = int3
        session["int4"] = int4
        session["int5"] = int5
        session["int_list"] = int_list

        results = calculations.cluster(int1, int2, int3, int4, int5, int_list)
        return _render_index(results=results, error_message=None)

    except Exception as e:
        return _render_index(results=None, error_message="An error occurred: " + str(e))

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

    purge_old_entries()

    grouped_entries = build_grouped_entries_by_user_location(log_get_all())
    return render_template("trainer.html", grouped_entries=grouped_entries)

@app.route("/view_once", methods=["POST"], strict_slashes=False)
def view_once():
    user_ip, xff_chain, _ip_ok = get_client_ip()
    geo = lookup_city(user_ip)
    device_id = get_device_id()

    if is_hidden_ip(user_ip):
        return ("", 204)

    data = request.get_json(silent=True) or {}
    tab_id = (data.get("tab_id") or "").strip()
    if not tab_id or len(tab_id) > 80:
        return ("", 204)

    seen = session.get("view_once_seen_tabs", {})
    last_ip = seen.get(tab_id)

    if last_ip != user_ip:
        # include tab_id so the print output is actually useful
        print_event(
            event="view",
            user_ip=user_ip,
            device_id=device_id,
            geo=geo,
            xff_chain=xff_chain,
            remote_addr=request.remote_addr or "",
            payload_lines=[f"  Tab: {tab_id}"],
        )

        seen[tab_id] = user_ip

        # safety cap like your second app
        if len(seen) > 200:
            items = list(seen.items())[-200:]
            seen = dict(items)

        session["view_once_seen_tabs"] = seen

    return ("", 204)

@app.after_request
def after_request(resp):
    if request.path.startswith("/trainer"):
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"

    incoming = request.cookies.get(DEVICE_COOKIE_NAME)
    if not _valid_device_cookie(incoming):
        did = get_device_id()
        resp.set_cookie(
            DEVICE_COOKIE_NAME,
            did,
            max_age=DEVICE_COOKIE_MAX_AGE,
            httponly=True,
            samesite="Lax",
            secure=COOKIE_SECURE,
            path="/",
        )

    return resp

if __name__ == "__main__":
    app.run()
