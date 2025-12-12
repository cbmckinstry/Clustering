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

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "supersecretkey")

# -------------------------------------------------
# Sessions (matches your other file)
# -------------------------------------------------
redis_url = os.environ.get("REDIS_URL")

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_USE_SIGNER"] = True
app.config["SESSION_KEY_PREFIX"] = "session:"

if redis_url:
    app.config["SESSION_TYPE"] = "redis"
    app.config["SESSION_REDIS"] = redis.from_url(redis_url)
else:
    app.config["SESSION_TYPE"] = "filesystem"
    session_dir = Path(app.instance_path) / "flask_session"
    session_dir.mkdir(parents=True, exist_ok=True)
    app.config["SESSION_FILE_DIR"] = str(session_dir)

Session(app)

# -------------------------------------------------
# Logging storage (Redis + fallback)
# -------------------------------------------------
DATA_LOG = []
LOG_COUNTER = 0

DATA_PASSWORD = os.environ.get("DATA_PASSWORD", "change-me")
DATA_PASSWORD_VIEW = os.environ.get("DATA_PASSWORD_VIEW", DATA_PASSWORD)
DATA_PASSWORD_DELETE = os.environ.get("DATA_PASSWORD_DELETE", DATA_PASSWORD)
DATA_PASSWORD_WIPE = os.environ.get("DATA_PASSWORD_WIPE", DATA_PASSWORD)


def _get_redis():
    return app.config.get("SESSION_REDIS")


def _next_local_id():
    global LOG_COUNTER
    LOG_COUNTER += 1
    return LOG_COUNTER


def log_append(entry: dict):
    r = _get_redis()
    entry = dict(entry)

    if r is not None:
        if "id" not in entry:
            entry["id"] = int(r.incr("data_log_v2:id_counter"))
        r.rpush("data_log_v2", json.dumps(entry))
    else:
        if "id" not in entry:
            entry["id"] = _next_local_id()
        DATA_LOG.append(entry)


def log_get_all():
    r = _get_redis()
    if r is not None:
        raw = r.lrange("data_log_v2", 0, -1)
        return [json.loads(x) for x in raw]
    return list(DATA_LOG)


def log_replace_all(entries):
    r = _get_redis()
    if r is not None:
        pipe = r.pipeline()
        pipe.delete("data_log_v2")
        for e in entries:
            pipe.rpush("data_log_v2", json.dumps(e))
        pipe.execute()
    else:
        global DATA_LOG
        DATA_LOG = list(entries)


def log_clear_all():
    r = _get_redis()
    if r is not None:
        r.delete("data_log_v2")
        r.delete("data_log_v2:id_counter")
    else:
        global DATA_LOG, LOG_COUNTER
        DATA_LOG.clear()
        LOG_COUNTER = 0


def build_grouped_entries():
    entries = list(reversed(log_get_all()))  # newest first overall
    grouped = {}
    for e in entries:
        ip = e.get("ip", "Unknown IP")
        grouped.setdefault(ip, []).append(e)
    return grouped


# -------------------------------------------------
# Geo lookup (unchanged)
# -------------------------------------------------
def lookup_city(ip: str):
    try:
        if ip.startswith("127.") or ip == "::1":
            return {"city": "Localhost", "region": None, "country": None}

        url = f"http://ip-api.com/json/{ip}"
        resp = requests.get(url, timeout=2)
        data = resp.json()

        if data.get("status") != "success":
            print(f"Geo lookup failed for {ip}: {data.get('message')}")
            return None

        return {
            "city": data.get("city"),
            "region": data.get("regionName"),
            "country": data.get("country"),
        }

    except Exception as e:
        print("Geo lookup exception:", e)
        return None


# -------------------------------------------------
# Routes (same behavior as your simple app)
# -------------------------------------------------
@app.route("/", methods=["GET", "POST"])
def index():
    user_ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()
    user_agent = request.headers.get("User-Agent", "").lower()
    is_bot = (
            "go-http-client/" in user_agent
            or "cron-job.org" in user_agent
            or "uptimerobot.com" in user_agent
            or user_agent.strip() == ""
    )

    if str(user_ip) != "127.0.0.1" and not is_bot:
        print("Viewer IP:", user_ip)

    geo = lookup_city(user_ip)
    if geo:
        city_str = geo.get("city") or "Unknown city"
        region_str = geo.get("region") or ""
        country_str = geo.get("country") or ""
        location_print = ", ".join([s for s in [city_str, region_str, country_str] if s])
        print("Approx. location:", location_print)

    if request.method == "GET" and not is_bot:
        log_append(
            {
                "ip": user_ip,
                "geo": geo,
                "timestamp": datetime.now(ZoneInfo("America/Chicago")).strftime("%Y-%m-%d  %H:%M:%S"),
                "event": "view",
                "input": None,
            }
        )
        print("Logged viewer; entries:", len(log_get_all()))

    if request.method == "POST":
        try:
            int1 = int(request.form["int1"] if request.form["int1"] != "" else 0)
            int2 = int(request.form["int2"] if request.form["int2"] != "" else 0)
            int3 = int(request.form["int3"] if request.form["int3"] != "" else 0)
            int4 = int(request.form["int4"] if request.form["int4"] != "" else 0)
            int5 = int(request.form["int5"] if request.form["int5"] != "" else 0)

            req = request.form["int_list"].split(",")
            if req == [""]:
                req = [0]
            int_list = [int(x) for x in req]

            print(
                "User IP:", user_ip,
                ", Single Sites:", int1,
                ", Double Sites:", int2,
                ", Triple Sites:", int3,
                ", Cars:", int4,
                ", Vans:", int5,
                ", Bus Caps:", int_list,
            )

            log_append(
                {
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
                }
            )
            print("Logged submit; entries:", len(log_get_all()))

            results = calculations.cluster(int1, int2, int3, int4, int5, int_list)

            session["int1"] = int1
            session["int2"] = int2
            session["int3"] = int3
            session["int4"] = int4
            session["int5"] = int5
            session["int_list"] = int_list

            return render_template("index.html", results=results, error_message=None)

        except Exception as e:
            print("Error:", e)
            return render_template(
                "index.html",
                error_message=f"An error occurred: {str(e)}",
                results=None,
            )

    return render_template("index.html", results=None, error_message=None)


@app.route("/data_login", methods=["GET", "POST"])
def data_login():
    error = None
    if request.method == "POST":
        pwd = request.form.get("password", "")
        if pwd == DATA_PASSWORD_VIEW:
            session["data_admin"] = True
            session.pop("delete_unlocked", None)
            return redirect(url_for("data_view"))
        else:
            error = "Incorrect password."
    return render_template("data_login.html", error=error)


@app.route("/data")
def data_view():
    if not session.get("data_admin"):
        return redirect(url_for("data_login"))

    grouped_entries = build_grouped_entries()
    return render_template(
        "data.html",
        grouped_entries=grouped_entries,
        delete_error=None,
        wipe_error=None,
    )

@app.route("/delete_entry", methods=["POST"])
def delete_entry():
    if not session.get("data_admin"):
        return redirect(url_for("data_login"))

    entry_id = request.form.get("entry_id", type=int)
    if entry_id is None:
        return redirect(url_for("data_view"))

    delete_unlocked = session.get("delete_unlocked", False)

    if not delete_unlocked:
        pwd = request.form.get("delete_password", "")
        if pwd != DATA_PASSWORD_DELETE:
            grouped_entries = build_grouped_entries()
            return render_template(
                "data.html",
                grouped_entries=grouped_entries,
                delete_error="Incorrect delete password.",
                wipe_error=None,
            )
        session["delete_unlocked"] = True

    entries = log_get_all()
    filtered = [e for e in entries if e.get("id") != entry_id]
    log_replace_all(filtered)
    print(f"Deleted entry {entry_id}; remaining entries: {len(filtered)}")

    return redirect(url_for("data_view"))


@app.route("/wipe_data", methods=["POST"])
def wipe_data():
    if not session.get("data_admin"):
        return redirect(url_for("data_login"))

    pwd = request.form.get("wipe_password", "")
    if pwd != DATA_PASSWORD_WIPE:
        grouped_entries = build_grouped_entries()
        return render_template(
            "data.html",
            grouped_entries=grouped_entries,
            delete_error=None,
            wipe_error="Incorrect wipe password.",
        )

    log_clear_all()
    print("All entries wiped.")

    return redirect(url_for("data_view"))


if __name__ == "__main__":
    app.run()
