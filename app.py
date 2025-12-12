from flask import Flask, render_template, request, session, redirect, url_for
import calculations
import os
from datetime import datetime
from zoneinfo import ZoneInfo
import requests
import json
from pathlib import Path

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "supersecretkey")

# ============================================================
# PERSISTENT DATA LOG (disk-backed)
# ============================================================
DATA_DIR = Path(os.environ.get("DATA_DIR", Path(app.instance_path) / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

DATA_FILE = DATA_DIR / "data_log.jsonl"
ID_FILE = DATA_DIR / "data_log_id_counter.txt"

DATA_LOG = []
LOG_COUNTER = 0

DATA_PASSWORD = os.environ.get("DATA_PASSWORD", "change-me")
DATA_PASSWORD_VIEW = os.environ.get("DATA_PASSWORD_VIEW", DATA_PASSWORD)
DATA_PASSWORD_DELETE = os.environ.get("DATA_PASSWORD_DELETE", DATA_PASSWORD)
DATA_PASSWORD_WIPE = os.environ.get("DATA_PASSWORD_WIPE", DATA_PASSWORD)


def _load_log_from_disk():
    """Load DATA_LOG + LOG_COUNTER from disk on startup."""
    global DATA_LOG, LOG_COUNTER

    # Load log entries
    entries = []
    if DATA_FILE.exists():
        with DATA_FILE.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except Exception:
                    # Skip corrupted lines rather than crashing
                    continue
    DATA_LOG = entries

    # Load counter
    if ID_FILE.exists():
        try:
            LOG_COUNTER = int(ID_FILE.read_text(encoding="utf-8").strip() or "0")
        except Exception:
            LOG_COUNTER = 0
    else:
        LOG_COUNTER = 0

    # Ensure counter is at least max existing id
    try:
        max_id = max((int(e.get("id", 0)) for e in DATA_LOG), default=0)
        if LOG_COUNTER < max_id:
            LOG_COUNTER = max_id
            ID_FILE.write_text(str(LOG_COUNTER), encoding="utf-8")
    except Exception:
        pass


def _persist_counter():
    ID_FILE.write_text(str(int(LOG_COUNTER)), encoding="utf-8")


def _append_to_disk(entry: dict):
    with DATA_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def _rewrite_disk(entries):
    tmp = DATA_FILE.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
    tmp.replace(DATA_FILE)


# Load existing log as the app starts
_load_log_from_disk()


def lookup_city(ip: str):
    try:
        # Localhost / dev
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


def _next_log_id():
    """Return a unique, incrementing ID for each log entry (persisted)."""
    global LOG_COUNTER
    LOG_COUNTER += 1
    _persist_counter()
    return LOG_COUNTER


def _build_grouped_entries():
    entries = list(reversed(DATA_LOG))
    grouped = {}
    for e in entries:
        ip = e["ip"]
        grouped.setdefault(ip, []).append(e)
    return grouped


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

    # --- City lookup (for logging & /data) ---
    geo = lookup_city(user_ip)
    if geo:
        city_str = geo.get("city") or "Unknown city"
        region_str = geo.get("region") or ""
        country_str = geo.get("country") or ""
        location_print = ", ".join([s for s in [city_str, region_str, country_str] if s])
        print("Approx. location:", location_print)

    if request.method == "GET" and not is_bot:
        entry = {
            "id": _next_log_id(),
            "ip": user_ip,
            "geo": geo,
            "timestamp": datetime.now(ZoneInfo("America/Chicago")).strftime("%Y-%m-%d  %H:%M:%S"),
            "event": "view",
            "input": None,
        }
        DATA_LOG.append(entry)
        _append_to_disk(entry)
        print("Logged viewer; DATA_LOG size:", len(DATA_LOG))

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
                ", Bus Caps:", int_list
            )

            entry = {
                "id": _next_log_id(),
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
            DATA_LOG.append(entry)
            _append_to_disk(entry)
            print("Logged submit; DATA_LOG size:", len(DATA_LOG))

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

    grouped_entries = _build_grouped_entries()
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
            grouped_entries = _build_grouped_entries()
            return render_template(
                "data.html",
                grouped_entries=grouped_entries,
                delete_error="Incorrect delete password.",
                wipe_error=None,
            )
        session["delete_unlocked"] = True

    global DATA_LOG
    DATA_LOG = [e for e in DATA_LOG if e.get("id") != entry_id]
    _rewrite_disk(DATA_LOG)
    print(f"Deleted entry {entry_id}; DATA_LOG size now:", len(DATA_LOG))

    return redirect(url_for("data_view"))

@app.route("/wipe_data", methods=["POST"])
def wipe_data():
    if not session.get("data_admin"):
        return redirect(url_for("data_login"))

    pwd = request.form.get("wipe_password", "")
    if pwd != DATA_PASSWORD_WIPE:
        grouped_entries = _build_grouped_entries()
        return render_template(
            "data.html",
            grouped_entries=grouped_entries,
            delete_error=None,
            wipe_error="Incorrect wipe password.",
        )

    global LOG_COUNTER
    DATA_LOG.clear()
    _rewrite_disk(DATA_LOG)
    LOG_COUNTER = 0
    _persist_counter()
    print("DATA_LOG cleared by wipe_data")

    return redirect(url_for("data_view"))

if __name__ == "__main__":
    print("DATA_DIR:", DATA_DIR)
    print("DATA_FILE:", DATA_FILE)
    app.run()
