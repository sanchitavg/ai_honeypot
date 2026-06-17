import sys
import os

# This lets Python find the database/ folder from inside the portals/ folder
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from flask import Flask, request, render_template, redirect, url_for, session
from database.logger import log_action
import secrets

# ── App setup ──────────────────────────────────────────────────────────────────
app = Flask(__name__, template_folder="../templates")
app.secret_key = secrets.token_hex(16)   # needed for session management

PORTAL_NAME = "Supplier"
PORT        = 5001

# Deliberately weak fake credentials — attackers will eventually "crack" these
# This makes the honeypot feel real when they succeed
FAKE_CREDENTIALS = {
    "admin":    "admin123",
    "supplier": "supplier2024",
    "root":     "toor",
}


def get_ip():
    """Get the real IP address even if behind a proxy."""
    return (
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or request.remote_addr
        or "unknown"
    )


def get_user_agent():
    """Get the browser or tool the attacker is using."""
    return request.headers.get("User-Agent", "unknown")


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET", "POST"])
def login():
    """
    Main login page.
    GET  → show the login form
    POST → check credentials, log the attempt, respond
    """
    ip         = get_ip()
    user_agent = get_user_agent()

    if request.method == "GET":
        # Log that they visited the login page
        log_action(ip, PORTAL_NAME, "visited_login_page",
                   status="info", user_agent=user_agent)
        return render_template("login.html", portal_name=PORTAL_NAME, error=None)

    # POST — they submitted the login form
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()

    if FAKE_CREDENTIALS.get(username) == password:
        # Let them in — they "cracked" the fake login
        log_action(ip, PORTAL_NAME, "login_success",
                   username_tried=username, password_tried=password,
                   status="success", user_agent=user_agent)
        session["user"]   = username
        session["portal"] = PORTAL_NAME
        return redirect(url_for("dashboard"))
    else:
        # Wrong credentials — still log it (this is the most common attacker action)
        log_action(ip, PORTAL_NAME, "login_failed",
                   username_tried=username, password_tried=password,
                   status="failed", user_agent=user_agent)
        return render_template("login.html", portal_name=PORTAL_NAME,
                               error="Invalid credentials. Access denied.")


@app.route("/dashboard")
def dashboard():
    """Fake supplier dashboard shown after successful login."""
    ip         = get_ip()
    user_agent = get_user_agent()

    log_action(ip, PORTAL_NAME, "viewed_dashboard",
               status="success", user_agent=user_agent)

    # Fake supplier data — makes the honeypot look real
    fake_suppliers = [
        {"id": "SUP-001", "name": "GlobalParts Ltd.",     "status": "Active",  "orders": 142},
        {"id": "SUP-002", "name": "FastShip Co.",         "status": "Active",  "orders": 87},
        {"id": "SUP-003", "name": "SecureComponents Inc.","status": "Pending", "orders": 23},
    ]

    return f"""
    <html>
    <head>
      <title>Supplier Dashboard — SupplyChain Pro</title>
      <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background:#0d1117;
                color:#c9d1d9; padding:40px; }}
        h1   {{ color:#e6edf3; margin-bottom:8px; }}
        p    {{ color:#8b949e; margin-bottom:32px; }}
        table {{ border-collapse:collapse; width:100%; max-width:700px; }}
        th   {{ background:#161b22; color:#8b949e; font-size:12px;
                text-transform:uppercase; padding:10px 16px; text-align:left;
                border-bottom:1px solid #30363d; }}
        td   {{ padding:12px 16px; border-bottom:1px solid #21262d;
                font-size:14px; }}
        .active  {{ color:#3fb950; }} .pending {{ color:#d29922; }}
        a    {{ color:#58a6ff; text-decoration:none; font-size:13px; }}
        a:hover {{ text-decoration:underline; }}
      </style>
    </head>
    <body>
      <h1>Supplier Management</h1>
      <p>Welcome back. You have 3 active supplier records.</p>
      <table>
        <tr><th>ID</th><th>Supplier</th><th>Status</th><th>Orders</th></tr>
        {''.join(f"""<tr>
          <td>{s['id']}</td><td>{s['name']}</td>
          <td class="{'active' if s['status']=='Active' else 'pending'}">{s['status']}</td>
          <td>{s['orders']}</td></tr>""" for s in fake_suppliers)}
      </table>
      <br/>
      <a href="/admin">⚙ Admin Panel</a> &nbsp;|&nbsp;
      <a href="/config">🔧 System Config</a> &nbsp;|&nbsp;
      <a href="/export">📦 Export Data</a>
    </body>
    </html>
    """


@app.route("/admin")
def admin():
    """
    Fake admin panel — highly tempting to attackers.
    Real attackers always probe /admin first.
    """
    ip         = get_ip()
    user_agent = get_user_agent()

    log_action(ip, PORTAL_NAME, "probed_admin_panel",
               status="probed", user_agent=user_agent)

    return """
    <html>
    <head>
      <title>Admin — SupplyChain Pro</title>
      <style>
        body {{ font-family:'Segoe UI',Arial,sans-serif; background:#0d1117;
                color:#c9d1d9; padding:40px; }}
        .box {{ background:#161b22; border:1px solid #f85149; border-radius:8px;
                padding:32px; max-width:480px; }}
        h2   {{ color:#f85149; margin-bottom:12px; }}
        p    {{ color:#8b949e; font-size:14px; }}
      </style>
    </head>
    <body>
      <div class="box">
        <h2>⛔ Access Restricted</h2>
        <p>Administrator access requires two-factor authentication.<br/>
           Contact your system administrator to request elevated access.</p>
      </div>
    </body>
    </html>
    """, 403


@app.route("/config")
def config():
    """Fake config page — logs attackers who probe system configuration."""
    ip         = get_ip()
    user_agent = get_user_agent()

    log_action(ip, PORTAL_NAME, "probed_config_page",
               status="probed", user_agent=user_agent)

    return """
    <html>
    <head>
      <title>Config — SupplyChain Pro</title>
      <style>
        body {{ font-family:'Segoe UI',Arial,sans-serif; background:#0d1117;
                color:#c9d1d9; padding:40px; }}
        .box {{ background:#161b22; border:1px solid #30363d; border-radius:8px;
                padding:32px; max-width:480px; }}
        h2   {{ color:#e6edf3; margin-bottom:12px; }}
        p    {{ color:#8b949e; font-size:14px; }}
      </style>
    </head>
    <body>
      <div class="box">
        <h2>🔧 System Configuration</h2>
        <p>Configuration management is restricted to on-site engineers.<br/>
           Remote access to this panel has been disabled.</p>
      </div>
    </body>
    </html>
    """, 403


@app.route("/export")
def export():
    """Fake export page — logs data exfiltration attempts."""
    ip         = get_ip()
    user_agent = get_user_agent()

    log_action(ip, PORTAL_NAME, "attempted_data_export",
               status="probed", user_agent=user_agent)

    return """
    <html>
    <head>
      <title>Export — SupplyChain Pro</title>
      <style>
        body {{ font-family:'Segoe UI',Arial,sans-serif; background:#0d1117;
                color:#c9d1d9; padding:40px; }}
        .box {{ background:#161b22; border:1px solid #d29922; border-radius:8px;
                padding:32px; max-width:480px; }}
        h2   {{ color:#d29922; margin-bottom:12px; }}
        p    {{ color:#8b949e; font-size:14px; }}
      </style>
    </head>
    <body>
      <div class="box">
        <h2>📦 Export Restricted</h2>
        <p>Bulk data export requires manager approval.<br/>
           Submit a request via the internal ticketing system.</p>
      </div>
    </body>
    </html>
    """, 403


@app.route("/<path:unknown_path>")
def catch_all(unknown_path):
    """
    Catches ANY path the attacker tries that doesn't exist.
    e.g. /wp-admin, /shell.php, /.env, /api/v1/users
    All of these are logged as scan attempts.
    """
    ip         = get_ip()
    user_agent = get_user_agent()

    log_action(ip, PORTAL_NAME, f"probed_unknown_path:/{unknown_path}",
               status="404", user_agent=user_agent)

    return """
    <html>
    <head>
      <title>404 — SupplyChain Pro</title>
      <style>
        body {{ font-family:'Segoe UI',Arial,sans-serif; background:#0d1117;
                color:#c9d1d9; padding:40px; text-align:center; margin-top:80px; }}
        h1   {{ font-size:72px; color:#30363d; margin-bottom:8px; }}
        p    {{ color:#8b949e; }}
      </style>
    </head>
    <body>
      <h1>404</h1>
      <p>The page you're looking for doesn't exist.</p>
    </body>
    </html>
    """, 404


# ── Run ────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print(f"[*] Supplier Portal running on http://localhost:{PORT}")
    print(f"[*] Logging to database/honeypot.db")
    app.run(host="0.0.0.0", port=PORT, debug=False)