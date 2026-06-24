import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from flask import Flask, request, render_template, redirect, url_for, session
from database.logger import init_db, log_event

app = Flask(__name__, template_folder='../templates')
app.secret_key = "procurement_honeypot_secret_key_2026"

FAKE_CREDENTIALS = {
    "admin":       "admin123",
    "root":        "toor",
    "procurement": "proc2026",
    "manager":     "manager123",
}

FAKE_ORDERS = [
    {"id": "PO-2026-001", "vendor": "Raj Components Ltd",     "items": "Steel Rods x500",        "value": "₹12,40,000", "status": "Approved"},
    {"id": "PO-2026-002", "vendor": "Global Parts Inc",       "items": "Circuit Boards x200",    "value": "₹8,75,000",  "status": "Pending"},
    {"id": "PO-2026-003", "vendor": "Eastern Freight Co",     "items": "Packaging Material x1000","value": "₹3,20,000", "status": "Approved"},
    {"id": "PO-2026-004", "vendor": "Nexus Raw Materials",    "items": "Aluminium Sheets x300",  "value": "₹15,60,000", "status": "Under Review"},
    {"id": "PO-2026-005", "vendor": "Horizon Logistics Group","items": "Transport Services",      "value": "₹6,80,000",  "status": "Approved"},
]


@app.route("/", methods=["GET"])
def index():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", portal_name="Procurement Dashboard", error="")

    username   = request.form.get("username", "")
    password   = request.form.get("password", "")
    ip_address = request.remote_addr
    user_agent = request.headers.get("User-Agent", "")

    if FAKE_CREDENTIALS.get(username) == password:
        log_event(
            ip_address     = ip_address,
            portal         = "procurement",
            action         = "login_success",
            username_tried = username,
            password_tried = password,
            status         = "success",
            user_agent     = user_agent,
        )
        session["user"]   = username
        session["portal"] = "procurement"
        return redirect(url_for("dashboard"))
    else:
        log_event(
            ip_address     = ip_address,
            portal         = "procurement",
            action         = "login_failed",
            username_tried = username,
            password_tried = password,
            status         = "failed",
            user_agent     = user_agent,
        )
        return render_template(
            "login.html",
            portal_name = "Procurement Dashboard",
            error       = "Invalid credentials. Please try again."
        )


@app.route("/dashboard", methods=["GET"])
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))

    ip_address = request.remote_addr
    user_agent = request.headers.get("User-Agent", "")

    log_event(
        ip_address = ip_address,
        portal     = "procurement",
        action     = "dashboard_viewed",
        status     = "success",
        user_agent = user_agent,
    )

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Procurement Dashboard</title>
        <style>
            body  {{ background:#0d1117; color:#c9d1d9;
                     font-family:'Segoe UI',sans-serif; padding:40px; }}
            h1    {{ color:#e6edf3; margin-bottom:6px; }}
            p     {{ color:#8b949e; margin-bottom:30px; }}
            table {{ width:100%; border-collapse:collapse; }}
            th    {{ background:#161b22; color:#8b949e;
                     padding:12px; text-align:left;
                     border-bottom:1px solid #30363d; font-size:12px;
                     text-transform:uppercase; letter-spacing:1px; }}
            td    {{ padding:12px; border-bottom:1px solid #21262d; font-size:14px; }}
            tr:hover td  {{ background:#161b22; }}
            .Approved     {{ color:#3fb950; }}
            .Pending      {{ color:#d29922; }}
            .Under-Review {{ color:#388bfd; }}
            .logout {{ float:right; color:#f85149;
                       text-decoration:none; font-size:13px; }}
        </style>
    </head>
    <body>
        <a href="/logout" class="logout">Sign Out</a>
        <h1>📋 Procurement Dashboard</h1>
        <p>SupplyChain Corp — Purchase Order Management | Authorised Access Only</p>
        <table>
            <tr>
                <th>PO Number</th>
                <th>Vendor</th>
                <th>Items</th>
                <th>Value</th>
                <th>Status</th>
            </tr>
            {''.join(f"""
            <tr>
                <td>{o['id']}</td>
                <td>{o['vendor']}</td>
                <td>{o['items']}</td>
                <td>{o['value']}</td>
                <td class='{o["status"].replace(" ", "-")}'>{o['status']}</td>
            </tr>""" for o in FAKE_ORDERS)}
        </table>
    </body>
    </html>
    """


@app.route("/admin", methods=["GET"])
def admin():
    log_event(
        ip_address  = request.remote_addr,
        portal      = "procurement",
        action      = "bait_route_accessed",
        status      = "detected",
        user_agent  = request.headers.get("User-Agent", ""),
        attack_type = "reconnaissance",
    )
    return "403 Forbidden", 403


@app.route("/config", methods=["GET"])
def config():
    log_event(
        ip_address  = request.remote_addr,
        portal      = "procurement",
        action      = "bait_route_accessed",
        status      = "detected",
        user_agent  = request.headers.get("User-Agent", ""),
        attack_type = "reconnaissance",
    )
    return "403 Forbidden", 403


@app.route("/export", methods=["GET"])
def export():
    log_event(
        ip_address  = request.remote_addr,
        portal      = "procurement",
        action      = "bait_route_accessed",
        status      = "detected",
        user_agent  = request.headers.get("User-Agent", ""),
        attack_type = "reconnaissance",
    )
    return "403 Forbidden", 403


@app.route("/logout", methods=["GET"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.errorhandler(404)
def catch_all_probes(e):
    log_event(
        ip_address  = request.remote_addr,
        portal      = "procurement",
        action      = f"unknown_path_probed:{request.path}",
        status      = "detected",
        user_agent  = request.headers.get("User-Agent", ""),
        attack_type = "reconnaissance",
    )
    return "404 Not Found", 404


if __name__ == "__main__":
    init_db()
    print("Procurement Portal running on http://127.0.0.1:5002")
    app.run(host="0.0.0.0", port=5002, debug=False)