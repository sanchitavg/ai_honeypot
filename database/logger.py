import sqlite3
import datetime
import os
import logging

# ── Path to the database file (always saved inside the database/ folder) ──
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "honeypot.db")

# ── Python's built-in logger (prints errors to terminal if anything goes wrong) ──
logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


def get_connection():
    """Open and return a database connection with safe settings turned on."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row          # lets you access columns by name, e.g. row["ip_address"]
    conn.execute("PRAGMA journal_mode=WAL") # allows multiple portals to write at the same time without conflict
    conn.execute("PRAGMA foreign_keys=ON")  # enforces data integrity rules
    return conn


def init_db():
    """Create the attacker_logs table if it doesn't already exist."""
    with get_connection() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS attacker_logs (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address      TEXT    NOT NULL,
                portal          TEXT    NOT NULL,
                action          TEXT    NOT NULL,
                username_tried  TEXT    DEFAULT '',
                password_tried  TEXT    DEFAULT '',
                status          TEXT    DEFAULT 'unknown',
                timestamp       TEXT    NOT NULL,
                user_agent      TEXT    DEFAULT ''
            )
        ''')
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ip      ON attacker_logs(ip_address)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_portal  ON attacker_logs(portal)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_time    ON attacker_logs(timestamp)")
        conn.commit()
    log.info("Database initialised at %s", DB_PATH)


def log_action(ip_address: str, portal: str, action: str,
               username_tried: str = "", password_tried: str = "",
               status: str = "unknown", user_agent: str = "") -> bool:
    """
    Save one attacker action to the database.
    Returns True on success, False if something went wrong.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with get_connection() as conn:
            conn.execute('''
                INSERT INTO attacker_logs
                    (ip_address, portal, action, username_tried,
                     password_tried, status, timestamp, user_agent)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (ip_address, portal, action, username_tried,
                  password_tried, status, timestamp, user_agent))
            conn.commit()
        return True
    except sqlite3.Error as e:
        log.error("Failed to log action: %s", e)
        return False


def get_all_logs() -> list:
    """Return all logs, newest first, as a list of Row objects."""
    with get_connection() as conn:
        cursor = conn.execute("SELECT * FROM attacker_logs ORDER BY id DESC")
        return cursor.fetchall()


def get_logs_by_ip(ip_address: str) -> list:
    """Return all logs for one specific IP address."""
    with get_connection() as conn:
        cursor = conn.execute(
            "SELECT * FROM attacker_logs WHERE ip_address = ? ORDER BY id DESC",
            (ip_address,)
        )
        return cursor.fetchall()


def get_logs_by_portal(portal: str) -> list:
    """Return all logs for one specific portal (e.g. 'supplier')."""
    with get_connection() as conn:
        cursor = conn.execute(
            "SELECT * FROM attacker_logs WHERE portal = ? ORDER BY id DESC",
            (portal,)
        )
        return cursor.fetchall()


def get_recent_logs(limit: int = 50) -> list:
    """Return the most recent N logs. Default is 50."""
    with get_connection() as conn:
        cursor = conn.execute(
            "SELECT * FROM attacker_logs ORDER BY id DESC LIMIT ?",
            (limit,)
        )
        return cursor.fetchall()


# ── Auto-initialise the database the moment any portal imports this file ──
init_db()