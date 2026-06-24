import sys
import os

# ── Tell Python where to find the database/ folder ───────────────────────────
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from flask import Flask, request, render_template, redirect, url_for, session
from database.logger import init_db, log_event

# ── Create the Flask app ──────────────────────────────────────────────────────
app = Flask(__name__, template_folder='../templates')
app.secret_key = "shipment_honeypot_secret_key_2026"

# ── Fake credentials ──────────────────────────────────────────────────────────
FAKE_CREDENTIALS = {
    "admin":    "admin123",
    "root":     "toor",
    "dispatch": "dispatch2026",
    "logistics": "log1stics",
    "driver":   "driver123",
}

# ── Fake shipment records shown on the dashboard ──────────────────────────────
# Realistic-looking data with high monetary values to attract attackers
# interested in supply-chain fraud or cargo theft.
FAKE_SHIPMENTS = [
    {"id": "SHP-10041", "origin": "Delhi",     "destination": "Mumbai",    "status": "Delivered",  "cargo": "Electronic Components", "value": "₹42,00,000"},
    {"id": "SHP-10042", "origin": "Chennai",   "destination": "Kolkata",   "status": "In Transit", "cargo": "Industrial Machinery",  "value": "₹18,50,000"},
    {"id": "SHP-10043", "origin": "Mumbai",    "destination": "Hyderabad", "status": "Processing", "cargo": "Pharmaceutical Goods",  "value": "₹87,50,000"},
    {"id": "SHP-10044", "origin": "Bangalore", "destination": "Pune",      "status": "In Transit", "cargo": "Auto Parts",            "value": "₹13,00,000"},
    {"id": "SHP-10045", "origin": "Kolkata",   "destination": "Delhi",     "status": "Delayed",    "cargo": "Chemical Supplies",     "value": "₹52,00,000"},
    {"id": "SHP-10046", "origin": "Hyderabad", "destination": "Chennai",   "status": "In Transit", "cargo": "Textile Goods",         "value": "₹9,75,000"},
]


# ── ROUTE 1: root — redirect to login ────────────────────────────────────────
@app.route("/", methods=["GET"])
def index():
    """Redirect the root URL to the login page."""
    return redirect(url_for("login"))


# ── ROUTE 2: /login ───────────────────────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Login page for the fake shipment portal.

    GET  → Render the login form.
    POST → Capture and log what the attacker typed, then either let them
           in (if credentials match FAKE_CREDENTIALS) or show an error.

    Shipment portals are particularly attractive to attackers because they
    can redirect high-value cargo by changing destination addresses.
    We want to draw them in and record everything they do.
    """
    if request.method == "GET":
        return render_template("login.html", portal_name="Shipment Portal", error="")

    username   = request.form.get("username", "")
    password   = request.form.get("password", "")
    ip_address = request.remote_addr
    user_agent = request.headers.get("User-Agent", "")

    if FAKE_CREDENTIALS.get(username) == password:
        log_event(
            ip_address     = ip_address,
            portal         = "shipment",
            action         = "login_success",
            username_tried = username,
            password_tried = password,
            status         = "success",
            user_agent     = user_agent,
        )
        session["user"]   = username
        session["portal"] = "shipment"
        return redirect(url_for("dashboard"))

    else:
        log_event(
            ip_address     = ip_address,
            portal         = "shipment",
            action         = "login_failed",
            username_tried = username,
            password_tried = password,
            status         = "failed",
            user_agent     = user_agent,
        )
        return render_template(
            "login.html",
            portal_name = "Shipment Portal",
            error       = "Invalid credentials. Please try again.",
        )


# ── ROUTE 3: /dashboard ───────────────────────────────────────────────────────
@app.route("/dashboard", methods=["GET"])
def dashboard():
    """
    The fake shipment dashboard — visible only after login.

    Shows a table of all active shipments with their cargo types, origins,
    destinations and values.  High-value entries like ₹87,50,000 in
    pharmaceutical goods are deliberate bait.
    """
    if "user" not in session:
        return redirect(url_for("login"))

    ip_address = request.remote_addr
    user_agent = request.headers.get("User-Agent", "")

    log_event(
        ip_address = ip_address,
        portal     = "shipment",
        action     = "dashboard_viewed",
        status     = "success",
        user_agent = user_agent,
    )

    # Build status-coloured rows — same visual style as supplier_portal.py
    status_colours = {
        "Delivered":  "active",
        "In Transit": "pending",
        "Processing": "pending",
        "Delayed":    "inactive",
    }

    rows_html = "".join(f"""
        <tr>
            <td>{s['id']}</td>
            <td>{s['origin']}</td>
            <td>{s['destination']}</td>
            <td class='{status_colours.get(s['status'], '')}'>{s['status']}</td>
            <td>{s['cargo']}</td>
            <td>{s['value']}</td>
        </tr>""" for s in FAKE_SHIPMENTS)

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Shipment Portal — Dashboard</title>
        <style>
            body     {{ background:#0d1117; color:#c9d1d9;
                        font-family:'Segoe UI',sans-serif; padding:40px; }}
            h1       {{ color:#e6edf3; margin-bottom:6px; }}
            p        {{ color:#8b949e; margin-bottom:30px; }}
            table    {{ width:100%; border-collapse:collapse; }}
            th       {{ background:#161b22; color:#8b949e; padding:12px;
                        text-align:left; border-bottom:1px solid #30363d;
                        font-size:12px; text-transform:uppercase; letter-spacing:1px; }}
            td       {{ padding:12px; border-bottom:1px solid #21262d; font-size:14px; }}
            tr:hover td  {{ background:#161b22; }}
            .active  {{ color:#3fb950; }}
            .pending {{ color:#d29922; }}
            .inactive {{ color:#f85149; }}
            .logout  {{ float:right; color:#f85149; text-decoration:none; font-size:13px; }}
        </style>
    </head>
    <body>
        <a href="/logout" class="logout">Sign Out</a>
        <h1>🚚 Shipment Management Portal</h1>
        <p>SupplyChain Corp — Logistics Tracking System | Authorised Access Only</p>
        <table>
            <tr>
                <th>Shipment ID</th><th>Origin</th><th>Destination</th>
                <th>Status</th><th>Cargo Type</th><th>Value</th>
            </tr>
            {rows_html}
        </table>
    </body>
    </html>
    """


# ── ROUTE 4: /track — bait route ─────────────────────────────────────────────
@app.route("/track", methods=["GET"])
def track():
    """
    Attackers look for tracking pages to enumerate shipment IDs.
    The tracking_id query parameter (e.g. /track?id=SHP-10043) is logged
    so we can see which shipments they are trying to locate.
    """
    tracking_id = request.args.get("id", "")
    ip_address  = request.remote_addr
    user_agent  = request.headers.get("User-Agent", "")

    log_event(
        ip_address     = ip_address,
        portal         = "shipment",
        action         = f"tracking_lookup:{tracking_id}" if tracking_id else "tracking_page_visited",
        status         = "detected",
        user_agent     = user_agent,
        attack_type    = "reconnaissance",
    )
    return "403 Forbidden", 403


# ── ROUTE 5: /admin — bait route ─────────────────────────────────────────────
@app.route("/admin", methods=["GET"])
def admin():
    """Standard bait — attackers always probe /admin."""
    log_event(
        ip_address  = request.remote_addr,
        portal      = "shipment",
        action      = "bait_route_accessed",
        status      = "detected",
        user_agent  = request.headers.get("User-Agent", ""),
        attack_type = "reconnaissance",
    )
    return "403 Forbidden", 403


# ── ROUTE 6: /export — bait route ────────────────────────────────────────────
@app.route("/export", methods=["GET"])
def export():
    """Attackers probe /export hoping to download shipment manifests."""
    log_event(
        ip_address  = request.remote_addr,
        portal      = "shipment",
        action      = "bait_route_accessed",
        status      = "detected",
        user_agent  = request.headers.get("User-Agent", ""),
        attack_type = "reconnaissance",
    )
    return "403 Forbidden", 403


# ── ROUTE 7: /manifest — bait route ──────────────────────────────────────────
@app.route("/manifest", methods=["GET"])
def manifest():
    """
    Cargo manifests are high-value targets in supply-chain attacks.
    Attackers who reach /manifest are flagged as higher-intent threats.
    """
    log_event(
        ip_address  = request.remote_addr,
        portal      = "shipment",
        action      = "bait_route_accessed",
        status      = "detected",
        user_agent  = request.headers.get("User-Agent", ""),
        attack_type = "reconnaissance",
    )
    return "403 Forbidden", 403


# ── ROUTE 8: /logout ─────────────────────────────────────────────────────────
@app.route("/logout", methods=["GET"])
def logout():
    """Clear the session and return to the login page."""
    session.clear()
    return redirect(url_for("login"))


# ── ROUTE 9: catch-all 404 handler ───────────────────────────────────────────
@app.errorhandler(404)
def catch_all_probes(e):
    """
    Log every path a scanner probes that is not an explicit route above.
    The path itself (e.g. /wp-admin, /.env, /api/v1/users) tells us what
    kind of attack or tool the attacker is using.
    """
    path = request.path
    log_event(
        ip_address  = request.remote_addr,
        portal      = "shipment",
        action      = f"unknown_path_probed:{path}",
        status      = "detected",
        user_agent  = request.headers.get("User-Agent", ""),
        attack_type = "reconnaissance",
    )
    return "404 Not Found", 404


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()         # Create attacker_logs table if it does not exist yet
    print("Shipment Portal running on http://127.0.0.1:5003")
    app.run(host="0.0.0.0", port=5003, debug=False)
