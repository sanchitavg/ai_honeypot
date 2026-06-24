import sqlite3
import datetime
import os
import logging

# ── Logging setup so we can see what the logger itself is doing ──────────────
logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# ── Path to the database file ─────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(BASE_DIR, "honeypot.db")


def get_connection() -> sqlite3.Connection:
    """
    Open a connection to the SQLite database.
    WAL mode allows all 4 portals to write simultaneously without conflicts.
    """
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def init_db() -> None:
    """
    Create the attacker_logs table if it does not already exist.
    Also creates indexes for fast querying by IP, portal, and time.
    Call this once when any portal starts up.
    """
    create_table_sql = """
        CREATE TABLE IF NOT EXISTS attacker_logs (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address     TEXT    NOT NULL,
            portal         TEXT    NOT NULL,
            action         TEXT    NOT NULL,
            username_tried TEXT,
            password_tried TEXT,
            status         TEXT,
            timestamp      TEXT    NOT NULL,
            user_agent     TEXT,
            attack_type    TEXT    DEFAULT 'unknown'
        );
    """
    create_index_ip       = "CREATE INDEX IF NOT EXISTS idx_ip        ON attacker_logs(ip_address);"
    create_index_portal   = "CREATE INDEX IF NOT EXISTS idx_portal    ON attacker_logs(portal);"
    create_index_ts       = "CREATE INDEX IF NOT EXISTS idx_timestamp ON attacker_logs(timestamp);"

    try:
        with get_connection() as conn:
            conn.execute(create_table_sql)
            conn.execute(create_index_ip)
            conn.execute(create_index_portal)
            conn.execute(create_index_ts)
            conn.commit()
        log.info("Database initialised successfully at %s", DB_PATH)
    except sqlite3.Error as e:
        log.error("Failed to initialise database: %s", e)
        raise


def detect_attack_type(username: str, password: str, user_agent: str) -> str:
    """
    Inspect the login attempt for known attack patterns.
    Returns a string label identifying the attack type.
    """
    # Combine fields into one string for easy scanning
    combined = f"{username} {password} {user_agent}".lower()

    sql_patterns       = ["'", '"', " or ", " and ", "--", ";", "1=1",
                          "drop ", "select ", "union ", "insert ", "delete "]
    xss_patterns       = ["<script", "javascript:", "onerror=", "onload=",
                          "alert(", "<img", "<svg"]
    path_patterns      = ["../", "..\\", "/etc/passwd", "/etc/shadow",
                          "boot.ini", "win.ini"]
    recon_agents       = ["sqlmap", "nmap", "nikto", "masscan", "zgrab",
                          "dirbuster", "gobuster", "hydra", "burpsuite"]
    brute_force_agents = ["python-requests", "curl", "wget", "go-http"]

    if any(p in combined for p in sql_patterns):
        return "sql_injection"
    if any(p in combined for p in xss_patterns):
        return "xss"
    if any(p in combined for p in path_patterns):
        return "path_traversal"
    if any(p in combined for p in recon_agents):
        return "reconnaissance"
    if any(p in combined for p in brute_force_agents):
        return "brute_force"

    return "unknown"


def log_event(
    ip_address:     str,
    portal:         str,
    action:         str,
    username_tried: str  = "",
    password_tried: str  = "",
    status:         str  = "",
    user_agent:     str  = "",
    attack_type:    str  = ""
) -> None:
    """
    Write one attacker event to the database.
    This is the main function every portal will call.

    Parameters:
        ip_address     : attacker IP e.g. '192.168.1.1'
        portal         : which fake portal e.g. 'supplier'
        action         : what happened e.g. 'login_failed'
        username_tried : username the attacker typed
        password_tried : password the attacker typed
        status         : 'success' or 'failed'
        user_agent     : browser or tool string e.g. 'sqlmap/1.7'
        attack_type    : override auto-detection if already known
    """
    # Auto-detect attack type if not provided
    if not attack_type:
        attack_type = detect_attack_type(username_tried, password_tried, user_agent)

    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    insert_sql = """
        INSERT INTO attacker_logs
            (ip_address, portal, action, username_tried, password_tried,
             status, timestamp, user_agent, attack_type)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
    """
    values = (
        ip_address,
        portal,
        action,
        username_tried,
        password_tried,
        status,
        timestamp,
        user_agent,
        attack_type
    )

    try:
        with get_connection() as conn:
            conn.execute(insert_sql, values)
            conn.commit()
        log.info("[%s] %s | %s | %s | %s", timestamp, ip_address, portal, action, attack_type)
    except sqlite3.Error as e:
        log.error("Failed to log event: %s", e)


def get_all_logs() -> list:
    """
    Fetch every row from attacker_logs.
    Used by the dashboard and AI engine.
    Returns a list of dictionaries — one dict per log row.
    """
    try:
        with get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM attacker_logs ORDER BY timestamp DESC;")
            rows   = cursor.fetchall()
            return [dict(row) for row in rows]
    except sqlite3.Error as e:
        log.error("Failed to fetch logs: %s", e)
        return []


def get_logs_by_ip(ip_address: str) -> list:
    """
    Fetch all logs for one specific IP address.
    Used by the AI engine to analyse a single attacker session.
    """
    try:
        with get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT * FROM attacker_logs WHERE ip_address = ? ORDER BY timestamp ASC;",
                (ip_address,)
            )
            return [dict(row) for row in cursor.fetchall()]
    except sqlite3.Error as e:
        log.error("Failed to fetch logs for IP %s: %s", ip_address, e)
        return []


def get_logs_by_portal(portal: str) -> list:
    """
    Fetch all logs for one specific portal.
    Used by the dashboard to show per-portal attack statistics.
    """
    try:
        with get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT * FROM attacker_logs WHERE portal = ? ORDER BY timestamp DESC;",
                (portal,)
            )
            return [dict(row) for row in cursor.fetchall()]
    except sqlite3.Error as e:
        log.error("Failed to fetch logs for portal %s: %s", portal, e)
        return []


# ── Self-test: run this file directly to verify everything works ──────────────
if __name__ == "__main__":
    print("Initialising database...")
    init_db()

    print("Writing a test log entry...")
    log_event(
        ip_address     = "192.168.1.100",
        portal         = "supplier",
        action         = "login_failed",
        username_tried = "admin",
        password_tried = "admin' OR '1'='1",
        status         = "failed",
        user_agent     = "sqlmap/1.7"
    )

    print("Fetching all logs...")
    logs = get_all_logs()
    for entry in logs:
        print(entry)