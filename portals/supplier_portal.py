import sys
import os

# ── This tells Python where to find logger.py ────────────────────────────────
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from flask import Flask, request, render_template, redirect, url_for, session
from database.logger import init_db, log_event

app = Flask(__name__, template_folder='../templates')
app.secret_key = "supplier_honeypot_secret_key_2026"

# ── Fake credentials — deliberately weak to let attackers "in" ───────────────
FAKE_CREDENTIALS = {
    "admin":    "admin123",
    "root":     "toor",
    "supplier": "supplier2026",
    "test":     "test123",
}

# ── Fake supplier data shown after login ─────────────────────────────────────
FAKE_SUPPLIERS = [
    {"id": "SUP001", "name": "Raj Components Ltd",      "status": "Active",   "contract": "₹42,00,000"},
    {"id": "SUP002", "name": "Global Parts Inc",         "status": "Active",   "contract": "₹18,50,000"},
    {"id": "SUP003", "name": "Eastern Freight Co",       "status": "Pending",  "contract": "₹9,75,000"},
    {"id": "SUP004", "name": "Nexus Raw Materials",      "status": "Active",   "contract": "₹31,20,000"},
    {"id": "SUP005", "name": "Horizon Logistics Group",  "status": "Inactive", "contract": "₹5,60,000"},
]


@app.route("/", methods=["GET"])
def index():
    """Redirect root URL to login page."""
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Handle login attempts.
    GET  → show the login form
    POST → check credentials, log the attempt, respond
    """
    if request.method == "GET":
        return render_template("login.html", portal_name="Supplier Portal", error="")

    # ── Grab what the attacker typed ─────────────────────────────────────────
    username   = request.form.get("username", "")
    password   = request.form.get("password", "")
    ip_address = request.remote_addr
    user_agent = request.headers.get("User-Agent", "")

    # ── Check against fake credentials ───────────────────────────────────────
    if FAKE_CREDENTIALS.get(username) == password:
        # Let them in — log it as a successful login
        log_event(
            ip_address     = ip_address,
            portal         = "supplier",
            action         = "login_success",
            username_tried = username,
            password_tried = password,
            status         = "success",
            user_agent     = user_agent,
        )
        session["user"]   = username
        session["portal"] = "supplier"
        return redirect(url_for("dashboard"))

    else:
        # Wrong credentials — log the failed attempt
        log_event(
            ip_address     = ip_address,
            portal         = "supplier",
            action         = "login_failed",
            username_tried = username,
            password_tried = password,
            status         = "failed",
            user_agent     = user_agent,
        )
        return render_template(
            "login.html",
            portal_name = "Supplier Portal",
            error       = "Invalid credentials. Please try again."
        )


@app.route("/dashboard", methods=["GET"])
def dashboard():
    """
    Fake supplier dashboard shown after successful login.
    Displays fake supplier data to keep the attacker engaged.
    """
    if "user" not in session:
        return redirect(url_for("login"))

    ip_address = request.remote_addr
    user_agent = request.headers.get("User-Agent", "")

    log_event(
        ip_address = ip_address,
        portal     = "supplier",
        action     = "dashboard_viewed",
        status     = "success",
        user_agent = user_agent,
    )

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Supplier Portal — Dashboard</title>
        <style>
            body {{ background:#0d1117; color:#c9d1d9;
                    font-family:'Segoe UI',sans-serif; padding:40px; }}
            h1   {{ color:#e6edf3; margin-bottom:6px; }}
            p    {{ color:#8b949e; margin-bottom:30px; }}
            table {{ width:100%; border-collapse:collapse; }}
            th   {{ background:#161b22; color:#8b949e;
                    padding:12px; text-align:left;
                    border-bottom:1px solid #30363d; font-size:12px;
                    text-transform:uppercase; letter-spacing:1px; }}
            td   {{ padding:12px; border-bottom:1px solid #21262d;
                    font-size:14px; }}
            tr:hover td {{ background:#161b22; }}
            .active   {{ color:#3fb950; }}
            .pending  {{ color:#d29922; }}
            .inactive {{ color:#f85149; }}
            .logout   {{ float:right; color:#f85149;
                         text-decoration:none; font-size:13px; }}
        </style>
    </head>
    <body>
        <a href="/logout" class="logout">Sign Out</a>
        <h1>🏭 Supplier Management Portal</h1>
        <p>SupplyChain Corp — Internal Vendor Registry | Authorised Access Only</p>

        <table>
            <tr>
                <th>Supplier ID</th>
                <th>Company Name</th>
                <th>Status</th>
                <th>Contract Value</th>
            </tr>
            {''.join(f"""
            <tr>
                <td>{s['id']}</td>
                <td>{s['name']}</td>
                <td class='{s['status'].lower()}'>{s['status']}</td>
                <td>{s['contract']}</td>
            </tr>""" for s in FAKE_SUPPLIERS)}
        </table>
    </body>
    </html>
    """


@app.route("/admin", methods=["GET"])
def admin():
    """
    Bait route — attackers always probe /admin.
    Log it as reconnaissance.
    """
    ip_address = request.remote_addr
    user_agent = request.headers.get("User-Agent", "")

    log_event(
        ip_address  = ip_address,
        portal      = "supplier",
        action      = "bait_route_accessed",
        status      = "detected",
        user_agent  = user_agent,
        attack_type = "reconnaissance",
    )
    return "403 Forbidden", 403


@app.route("/config", methods=["GET"])
def config():
    """Bait route — attackers probe /config looking for secrets."""
    ip_address = request.remote_addr
    user_agent = request.headers.get("User-Agent", "")

    log_event(
        ip_address  = ip_address,
        portal      = "supplier",
        action      = "bait_route_accessed",
        status      = "detected",
        user_agent  = user_agent,
        attack_type = "reconnaissance",
    )
    return "403 Forbidden", 403


@app.route("/export", methods=["GET"])
def export():
    """Bait route — attackers probe /export hoping to dump data."""
    ip_address = request.remote_addr
    user_agent = request.headers.get("User-Agent", "")

    log_event(
        ip_address  = ip_address,
        portal      = "supplier",
        action      = "bait_route_accessed",
        status      = "detected",
        user_agent  = user_agent,
        attack_type = "reconnaissance",
    )
    return "403 Forbidden", 403


@app.route("/logout", methods=["GET"])
def logout():
    """Clear the session and redirect to login."""
    session.clear()
    return redirect(url_for("login"))


@app.errorhandler(404)
def catch_all_probes(e):
    """
    Catch every unknown URL an attacker scans.
    Tools like DirBuster scan hundreds of paths — we log every single one.
    """
    ip_address = request.remote_addr
    user_agent = request.headers.get("User-Agent", "")
    path       = request.path

    log_event(
        ip_address  = ip_address,
        portal      = "supplier",
        action      = f"unknown_path_probed:{path}",
        status      = "detected",
        user_agent  = user_agent,
        attack_type = "reconnaissance",
    )
    return "404 Not Found", 404


# ── Run the portal ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    print("Supplier Portal running on http://127.0.0.1:5001")
    app.run(host="0.0.0.0", port=5001, debug=False)