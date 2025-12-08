from flask import Flask, render_template, request, session, redirect, url_for
import calculations
import os
from datetime import datetime
from zoneinfo import ZoneInfo  # for Central Time
import requests

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "supersecretkey")

DATA_LOG = []
LOG_COUNTER = 0

DATA_PASSWORD = os.environ.get("DATA_PASSWORD", "change-me")

DATA_PASSWORD_VIEW = os.environ.get("DATA_PASSWORD_VIEW", DATA_PASSWORD)
DATA_PASSWORD_DELETE = os.environ.get("DATA_PASSWORD_DELETE", DATA_PASSWORD)
DATA_PASSWORD_WIPE = os.environ.get("DATA_PASSWORD_WIPE", DATA_PASSWORD)


# ------------------------------
# IP → City/Region/Country lookup
# ------------------------------
def lookup_city(ip: str):
    """
    Lookup using ip-api.com (no API key required).
    Returns dict {city, region, country} or None on failure.
    """
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
    """Return a unique, incrementing ID for each log entry."""
    global LOG_COUNTER
    LOG_COUNTER += 1
    return LOG_COUNTER


def _build_grouped_entries():
    """Group current DATA_LOG entries by IP (newest → oldest per IP)."""
    entries = list(reversed(DATA_LOG))  # newest first overall
    grouped = {}
    for e in entries:
        ip = e["ip"]
        grouped.setdefault(ip, []).append(e)
    return grouped


@app.route('/', methods=['GET', 'POST'])
def index():
    user_ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()
    user_agent = request.headers.get("User-Agent", "").lower()
    is_bot = (
            "go-http-client/" in user_agent
            or "cron-job.org" in user_agent
            or "uptimerobot.com" in user_agent
            or user_agent.strip() == ""
    )

    if str(user_ip) != '127.0.0.1' and not is_bot:
        print("Viewer IP:", user_ip)

    # --- City lookup (for logging & /data) ---
    geo = lookup_city(user_ip)
    if geo:
        city_str = geo.get("city") or "Unknown city"
        region_str = geo.get("region") or ""
        country_str = geo.get("country") or ""
        location_print = ", ".join([s for s in [city_str, region_str, country_str] if s])
        print("Approx. location:", location_print)

    # --- Log viewer (GET) with null input ---
    if request.method == "GET" and not is_bot:
        DATA_LOG.append(
            {
                "id": _next_log_id(),
                "ip": user_ip,
                "geo": geo,  # may be None if lookup failed
                "timestamp": datetime.now(ZoneInfo("America/Chicago")).strftime("%Y-%m-%d  %H:%M:%S"),
                "event": "view",
                "input": None,  # viewer: no inputs
            }
        )
        print("Logged viewer; DATA_LOG size:", len(DATA_LOG))

    if request.method == 'POST':
        try:
            # Get inputs from form
            int1 = int(request.form['int1'] if request.form['int1'] != '' else 0)
            int2 = int(request.form['int2'] if request.form['int2'] != '' else 0)
            int3 = int(request.form['int3'] if request.form['int3'] != '' else 0)
            int4 = int(request.form['int4'] if request.form['int4'] != '' else 0)
            int5 = int(request.form['int5'] if request.form['int5'] != '' else 0)

            req = request.form['int_list'].split(',')
            if req == ['']:
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

            # --- add to /data log (Central Time + location) ---
            DATA_LOG.append(
                {
                    "id": _next_log_id(),
                    "ip": user_ip,
                    "geo": geo,  # may be None if lookup failed
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
            print("Logged submit; DATA_LOG size:", len(DATA_LOG))

            # Run your existing calculations
            results = calculations.cluster(int1, int2, int3, int4, int5, int_list)

            # Remember last inputs in the session (for UX only)
            session['int1'] = int1
            session['int2'] = int2
            session['int3'] = int3
            session['int4'] = int4
            session['int5'] = int5
            session['int_list'] = int_list

            return render_template('index.html', results=results, error_message=None)

        except Exception as e:
            print('Error:', e)
            return render_template(
                'index.html',
                error_message=f"An error occurred: {str(e)}",
                results=None
            )

    # GET request (or after logging viewer)
    return render_template('index.html', results=None, error_message=None)


# ------------------------------
# View password for /data
# ------------------------------
@app.route("/data_login", methods=["GET", "POST"])
def data_login():
    error = None
    if request.method == "POST":
        pwd = request.form.get("password", "")
        if pwd == DATA_PASSWORD_VIEW:
            session["data_admin"] = True
            # reset delete unlock when (re)entering the data center
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


# ------------------------------
# Delete a single entry (2nd password, remembered after first success)
# ------------------------------
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
        # correct delete password: unlock for this session
        session["delete_unlocked"] = True

    # perform the deletion
    global DATA_LOG
    DATA_LOG = [e for e in DATA_LOG if e.get("id") != entry_id]
    print(f"Deleted entry {entry_id}; DATA_LOG size now:", len(DATA_LOG))

    return redirect(url_for("data_view"))


# ------------------------------
# Wipe all entries (3rd password, required every time)
# ------------------------------
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

    # correct wipe password → clear everything
    DATA_LOG.clear()
    print("DATA_LOG cleared by wipe_data")

    return redirect(url_for("data_view"))


if __name__ == '__main__':
    app.run()
