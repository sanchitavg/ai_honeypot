import sys
import os

# ── Tell Python where to find the database/ folder ───────────────────────────
# __file__ is this file's path. We go one level up (..) to reach the project
# root, where the database/ package lives.
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from flask import Flask, request, render_template, redirect, url_for, session
from database.logger import init_db, log_event

# ── Create the Flask app ──────────────────────────────────────────────────────
# template_folder points Flask at the shared templates/ directory one level up.
app = Flask(__name__, template_folder='../templates')
app.secret_key = "inventory_honeypot_secret_key_2026"

# ── Fake credentials ──────────────────────────────────────────────────────────
# These are deliberately weak / common so attackers can successfully "break in".
# The point is not security — it is to lure them deeper and log every action.
FAKE_CREDENTIALS = {
    "admin":     "admin123",
    "root":      "toor",
    "inventory": "inv2026",
    "manager":   "manager1",
    "warehouse": "warehouse123",
}

# ── Fake inventory items shown on the dashboard ───────────────────────────────
# Realistic-looking industrial parts to make the portal convincing.
FAKE_ITEMS = [
    {"id": "ITM-3841", "name": "Industrial Bearing XR-200",  "qty": 450, "location": "Warehouse A", "value": "₹1,200"},
    {"id": "ITM-3842", "name": "Hydraulic Pump Model 7B",    "qty": 12,  "location": "Warehouse B", "value": "₹84,000"},
    {"id": "ITM-3843", "name": "Control Panel Unit CP-55",   "qty": 8,   "location": "Warehouse C", "value": "₹1,32,000"},
    {"id": "ITM-3844", "name": "Safety Valve SV-100",        "qty": 320, "location": "Warehouse A", "value": "₹3,400"},
    {"id": "ITM-3845", "name": "Pressure Gauge PG-40",       "qty": 75,  "location": "Warehouse D", "value": "₹2,100"},
    {"id": "ITM-3846", "name": "Electric Motor EM-750W",     "qty": 30,  "location": "Warehouse B", "value": "₹18,500"},
    {"id": "ITM-3847", "name": "Conveyor Belt CB-12M",       "qty": 5,   "location": "Warehouse C", "value": "₹67,000"},
]


# ── ROUTE 1: root — redirect to login ────────────────────────────────────────
@app.route("/", methods=["GET"])
def index():
    """Redirect visitors at the root URL straight to the login page."""
    return redirect(url_for("login"))


# ── ROUTE 2: /login ───────────────────────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    """
    The main entry point.

    GET  → Render the login form (same login.html Arya already built).
    POST → Read the submitted username and password, log the attempt to the
           database, then either grant access (if credentials match FAKE_CREDENTIALS)
           or show an error.

    Every single attempt — successful or not — is logged.
    That is the entire purpose of this portal.
    """
    if request.method == "GET":
        # Show the blank login form.
        # portal_name fills the {{ portal_name }} placeholder in login.html.
        # error="" means the red error box stays hidden.
        return render_template("login.html", portal_name="Inventory Portal", error="")

    # ── Someone submitted the form ────────────────────────────────────────────
    username   = request.form.get("username", "")   # text from the Username field
    password   = request.form.get("password", "")   # text from the Password field
    ip_address = request.remote_addr                 # attacker's IP address
    user_agent = request.headers.get("User-Agent", "")  # their browser / tool name

    if FAKE_CREDENTIALS.get(username) == password:
        # ── Correct credentials → log success, start session, show dashboard ─
        log_event(
            ip_address     = ip_address,
            portal         = "inventory",       # identifies which portal in the DB
            action         = "login_success",
            username_tried = username,
            password_tried = password,
            status         = "success",
            user_agent     = user_agent,
        )
        session["user"]   = username   # store who is logged in
        session["portal"] = "inventory"
        return redirect(url_for("dashboard"))

    else:
        # ── Wrong credentials → log failure, show error, stay on login page ──
        log_event(
            ip_address     = ip_address,
            portal         = "inventory",
            action         = "login_failed",
            username_tried = username,
            password_tried = password,
            status         = "failed",
            user_agent     = user_agent,
        )
        return render_template(
            "login.html",
            portal_name = "Inventory Portal",
            error       = "Invalid credentials. Please try again.",
        )


# ── ROUTE 3: /dashboard ───────────────────────────────────────────────────────
@app.route("/dashboard", methods=["GET"])
def dashboard():
    """
    The fake inventory dashboard — shown only after a successful login.

    Displays a table of fake stock items.  The attacker sees what looks like
    real company data, which encourages them to stay longer and take more
    actions — all of which we are logging.
    """
    # If there is no session (someone tried to visit /dashboard directly
    # without logging in), send them back to the login page.
    if "user" not in session:
        return redirect(url_for("login"))

    ip_address = request.remote_addr
    user_agent = request.headers.get("User-Agent", "")

    log_event(
        ip_address = ip_address,
        portal     = "inventory",
        action     = "dashboard_viewed",
        status     = "success",
        user_agent = user_agent,
    )

    # Build the dashboard HTML inline (same style as Arya's supplier dashboard).
    items_html = "".join(f"""
        <tr>
            <td>{item['id']}</td>
            <td>{item['name']}</td>
            <td>{item['qty']}</td>
            <td>{item['location']}</td>
            <td>{item['value']}</td>
        </tr>""" for item in FAKE_ITEMS)

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Inventory Portal — Dashboard</title>
        <style>
            body    {{ background:#0d1117; color:#c9d1d9;
                       font-family:'Segoe UI',sans-serif; padding:40px; }}
            h1      {{ color:#e6edf3; margin-bottom:6px; }}
            p       {{ color:#8b949e; margin-bottom:30px; }}
            table   {{ width:100%; border-collapse:collapse; }}
            th      {{ background:#161b22; color:#8b949e; padding:12px;
                       text-align:left; border-bottom:1px solid #30363d;
                       font-size:12px; text-transform:uppercase; letter-spacing:1px; }}
            td      {{ padding:12px; border-bottom:1px solid #21262d; font-size:14px; }}
            tr:hover td {{ background:#161b22; }}
            .logout {{ float:right; color:#f85149; text-decoration:none; font-size:13px; }}
        </style>
    </head>
    <body>
        <a href="/logout" class="logout">Sign Out</a>
        <h1>📦 Inventory Management Portal</h1>
        <p>SupplyChain Corp — Warehouse Stock System | Authorised Access Only</p>
        <table>
            <tr>
                <th>Item ID</th><th>Item Name</th><th>Quantity</th>
                <th>Location</th><th>Unit Value</th>
            </tr>
            {items_html}
        </table>
    </body>
    </html>
    """


# ── ROUTE 4: /admin — bait route ─────────────────────────────────────────────
@app.route("/admin", methods=["GET"])
def admin():
    """
    Attackers always probe /admin hoping to find an admin panel.
    We return 403 Forbidden (which looks realistic) and log the probe
    as reconnaissance.
    """
    log_event(
        ip_address  = request.remote_addr,
        portal      = "inventory",
        action      = "bait_route_accessed",
        status      = "detected",
        user_agent  = request.headers.get("User-Agent", ""),
        attack_type = "reconnaissance",
    )
    return "403 Forbidden", 403


# ── ROUTE 5: /export — bait route ────────────────────────────────────────────
@app.route("/export", methods=["GET"])
def export():
    """
    Attackers probe /export hoping to download a database dump or CSV.
    Log it and return 403.
    """
    log_event(
        ip_address  = request.remote_addr,
        portal      = "inventory",
        action      = "bait_route_accessed",
        status      = "detected",
        user_agent  = request.headers.get("User-Agent", ""),
        attack_type = "reconnaissance",
    )
    return "403 Forbidden", 403


# ── ROUTE 6: /config — bait route ────────────────────────────────────────────
@app.route("/config", methods=["GET"])
def config():
    """Attackers probe /config looking for API keys or database passwords."""
    log_event(
        ip_address  = request.remote_addr,
        portal      = "inventory",
        action      = "bait_route_accessed",
        status      = "detected",
        user_agent  = request.headers.get("User-Agent", ""),
        attack_type = "reconnaissance",
    )
    return "403 Forbidden", 403


# ── ROUTE 7: /logout ─────────────────────────────────────────────────────────
@app.route("/logout", methods=["GET"])
def logout():
    """Clear the session cookie and return to login."""
    session.clear()
    return redirect(url_for("login"))


# ── ROUTE 8: catch-all 404 handler ───────────────────────────────────────────
@app.errorhandler(404)
def catch_all_probes(e):
    """
    Directory-scanning tools (DirBuster, Gobuster, ffuf) probe hundreds of
    paths automatically.  This handler catches every unknown URL and logs it
    so we can see exactly what paths the attacker's tool tried.
    """
    path = request.path
    log_event(
        ip_address  = request.remote_addr,
        portal      = "inventory",
        action      = f"unknown_path_probed:{path}",
        status      = "detected",
        user_agent  = request.headers.get("User-Agent", ""),
        attack_type = "reconnaissance",
    )
    return "404 Not Found", 404


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()          # Create the attacker_logs table if it does not exist yet
    print("Inventory Portal running on http://127.0.0.1:5003")
    app.run(host="0.0.0.0", port=5003, debug=False)
