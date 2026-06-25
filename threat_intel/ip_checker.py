"""
threat_intel/ip_checker.py
──────────────────────────
Enriches every unique attacker IP address captured by the portals with
external threat intelligence from two public APIs:

  • AbuseIPDB  — reports whether an IP has been flagged for malicious
                 activity by the global security community, and gives it
                 an abuse confidence score from 0–100.

  • VirusTotal — scans the IP against 90+ security vendor databases and
                 reports how many vendors flag it as malicious or suspicious.

Results are written back into the existing attacker_logs table as a new
column called `threat_intel` (added by this module's init function).
The dashboard (dashboard/app.py) will later read that column to show
enriched attack data alongside the portal logs.

How it fits in the architecture (from the screenshot):
    logger.py → portals → [YOUR CODE HERE] → dashboard/app.py
                              ip_checker.py
"""

import os
import sys
import json
import sqlite3
import logging
import requests
import datetime

# ── Tell Python where to find database/logger.py ─────────────────────────────
# This file lives in threat_intel/ip_checker.py
# Going one level up (..) reaches the project root where database/ lives.
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from database.logger import get_connection

# ── Module-level logger ───────────────────────────────────────────────────────
# This lets us see what ip_checker is doing in the Terminal when it runs.
# It prints lines like: INFO:threat_intel.ip_checker:Checking IP 1.2.3.4
logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# ── API keys — loaded from environment variables, NEVER hardcoded ─────────────
# You will set these in your Terminal before running this file (see guide).
# os.getenv() reads the value from the environment; if the variable is not
# set it returns the default (empty string here), and we handle that gracefully.
ABUSEIPDB_API_KEY  = os.getenv("ABUSEIPDB_API_KEY",  "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

# ── API endpoint URLs ─────────────────────────────────────────────────────────
ABUSEIPDB_URL  = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"

# ── Request timeout in seconds ────────────────────────────────────────────────
# If the API server takes longer than this to respond, we stop waiting and
# record an error instead of hanging forever.
REQUEST_TIMEOUT = 10


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 1 — DATABASE SETUP
# Add the threat_intel column to attacker_logs if it does not exist yet.
# We never recreate the table — we only add to it so Arya's data is preserved.
# ─────────────────────────────────────────────────────────────────────────────

def init_threat_intel_column() -> None:
    """
    Add a `threat_intel` TEXT column to attacker_logs.

    SQLite does not support ALTER TABLE ADD COLUMN IF NOT EXISTS, so we
    attempt the ALTER and silently ignore the error if the column already
    exists (which happens on every run after the first).

    The column stores a JSON string, for example:
        '{"abuseipdb": {...}, "virustotal": {...}}'
    Storing JSON as text is standard SQLite practice for flexible data.
    """
    try:
        with get_connection() as conn:
            conn.execute(
                "ALTER TABLE attacker_logs ADD COLUMN threat_intel TEXT DEFAULT NULL;"
            )
            conn.commit()
        log.info("threat_intel column added to attacker_logs.")
    except sqlite3.OperationalError as e:
        # "duplicate column name: threat_intel" → already exists, that's fine
        if "duplicate column" in str(e).lower():
            log.info("threat_intel column already exists — skipping.")
        else:
            # Any other OperationalError is unexpected — re-raise it
            raise


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 2 — ABUSEIPDB LOOKUP
# ─────────────────────────────────────────────────────────────────────────────

def check_abuseipdb(ip: str) -> dict:
    """
    Ask AbuseIPDB whether this IP address has been reported for abuse.

    What AbuseIPDB is:
        A free public database where security researchers worldwide submit
        IPs they have seen attacking their systems. When you check an IP,
        you get a confidence score (0–100) indicating how likely it is to
        be malicious, plus the number of reports and the country.

    Why we use it:
        Our portals capture IPs, but they do not know if those IPs are
        known attackers. AbuseIPDB tells us whether 127.0.0.1 or any
        real IP has been flagged by the global security community before.

    Free tier limits:
        1,000 checks per day — more than enough for a student project.

    Parameters:
        ip : the IP address string to look up, e.g. "1.2.3.4"

    Returns:
        A dict with the fields we care about, or an error dict.
    """
    # If no API key is configured, return a clear placeholder rather than
    # crashing — this lets the rest of the code continue working.
    if _is_private_ip(ip):
        return {
            "abuse_confidence_score": 0,
            "total_reports":          0,
            "country_code":           "LOCAL",
            "domain":                 "localhost",
            "is_tor":                 False,
            "note":                   "Private/local IP — not checked against AbuseIPDB"
        }

    # Skip private / loopback addresses first — they never appear on the
    # public internet, so external APIs cannot know anything about them.
    # This check runs BEFORE the API key check so private IPs always get
    # a clean local note regardless of whether keys are configured.
    if _is_private_ip(ip):
        return {
            "abuse_confidence_score": 0,
            "total_reports":          0,
            "country_code":           "LOCAL",
            "domain":                 "localhost",
            "is_tor":                 False,
            "note":                   "Private/local IP — not checked against AbuseIPDB"
        }

    if not ABUSEIPDB_API_KEY:
        log.warning("ABUSEIPDB_API_KEY not set — skipping AbuseIPDB check.")
        return {"error": "API key not configured"}

    try:
        # requests.get() makes an HTTP GET request to the AbuseIPDB API.
        # headers=  : sends our API key in the request headers (required by their API)
        # params=   : URL query parameters (?ipAddress=...&maxAgeInDays=90&verbose=)
        # timeout=  : stop waiting after REQUEST_TIMEOUT seconds
        response = requests.get(
            ABUSEIPDB_URL,
            headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params  = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            timeout = REQUEST_TIMEOUT,
        )

        # raise_for_status() raises an exception if the server returned an
        # error status code (4xx or 5xx). Without this, a 401 Unauthorised
        # would silently return an empty-looking response.
        response.raise_for_status()

        # .json() converts the raw JSON text from the API into a Python dict.
        data = response.json().get("data", {})

        # Extract only the fields we need and rename them for clarity.
        return {
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "total_reports":          data.get("totalReports", 0),
            "country_code":           data.get("countryCode", "Unknown"),
            "domain":                 data.get("domain", "Unknown"),
            "is_tor":                 data.get("isTor", False),
            "last_reported":          data.get("lastReportedAt", "Never"),
            "usage_type":             data.get("usageType", "Unknown"),
        }

    except requests.exceptions.Timeout:
        log.error("AbuseIPDB request timed out for IP %s", ip)
        return {"error": "Request timed out"}

    except requests.exceptions.HTTPError as e:
        log.error("AbuseIPDB HTTP error for IP %s: %s", ip, e)
        return {"error": f"HTTP {response.status_code}"}

    except requests.exceptions.RequestException as e:
        log.error("AbuseIPDB connection error for IP %s: %s", ip, e)
        return {"error": "Connection failed"}


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 3 — VIRUSTOTAL LOOKUP
# ─────────────────────────────────────────────────────────────────────────────

def check_virustotal(ip: str) -> dict:
    """
    Ask VirusTotal whether this IP is flagged by any security vendors.

    What VirusTotal is:
        A Google-owned service that aggregates results from 90+ antivirus
        and security vendor databases. When you submit an IP, it returns
        how many of those vendors flag it as malicious, suspicious, or clean.

    Why we use it alongside AbuseIPDB:
        AbuseIPDB = community reports (people who got attacked by this IP)
        VirusTotal = vendor databases (professional security companies flagging it)
        Together they give a much more complete picture of an IP's threat level.

    Free tier limits:
        500 requests per day — sufficient for a student project.

    Parameters:
        ip : the IP address string to look up, e.g. "1.2.3.4"

    Returns:
        A dict with vendor vote counts, or an error dict.
    """
    if _is_private_ip(ip):
        return {
            "malicious":  0,
            "suspicious": 0,
            "harmless":   0,
            "undetected": 0,
            "note":       "Private/local IP — not checked against VirusTotal"
        }

    if not VIRUSTOTAL_API_KEY:
        log.warning("VIRUSTOTAL_API_KEY not set — skipping VirusTotal check.")
        return {"error": "API key not configured"}

    try:
        # VirusTotal uses the IP address directly in the URL path, not as a
        # query parameter. We use .format(ip=ip) to insert the IP into the URL.
        url = VIRUSTOTAL_URL.format(ip=ip)

        response = requests.get(
            url,
            headers = {"x-apikey": VIRUSTOTAL_API_KEY},
            timeout = REQUEST_TIMEOUT,
        )
        response.raise_for_status()

        data = response.json()

        # VirusTotal nests the counts we want inside:
        # response → data → attributes → last_analysis_stats → {malicious, suspicious, ...}
        stats = (
            data
            .get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )

        # Also grab the country and AS (Autonomous System / internet provider) info
        attributes = data.get("data", {}).get("attributes", {})

        return {
            "malicious":    stats.get("malicious",  0),
            "suspicious":   stats.get("suspicious", 0),
            "harmless":     stats.get("harmless",   0),
            "undetected":   stats.get("undetected", 0),
            "country":      attributes.get("country", "Unknown"),
            "as_owner":     attributes.get("as_owner", "Unknown"),
            "reputation":   attributes.get("reputation", 0),
        }

    except requests.exceptions.Timeout:
        log.error("VirusTotal request timed out for IP %s", ip)
        return {"error": "Request timed out"}

    except requests.exceptions.HTTPError as e:
        log.error("VirusTotal HTTP error for IP %s: %s", ip, e)
        return {"error": f"HTTP {response.status_code}"}

    except requests.exceptions.RequestException as e:
        log.error("VirusTotal connection error for IP %s: %s", ip, e)
        return {"error": "Connection failed"}


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 4 — THREAT SCORE CALCULATOR
# Combine both API results into a single human-readable verdict.
# ─────────────────────────────────────────────────────────────────────────────

def calculate_threat_level(abuseipdb_result: dict, virustotal_result: dict) -> str:
    """
    Combine the AbuseIPDB and VirusTotal results into a single threat label.

    This function is pure Python logic — no API calls, no database access.
    It gives the dashboard (and your mentor) a simple one-word verdict
    instead of raw numbers.

    Thresholds (chosen to match typical honeypot research standards):
        CRITICAL  : AbuseIPDB score >= 80  OR  VirusTotal malicious >= 5
        HIGH      : AbuseIPDB score >= 50  OR  VirusTotal malicious >= 2
        MEDIUM    : AbuseIPDB score >= 20  OR  VirusTotal suspicious >= 1
        LOW       : IP has any reports but below all the above thresholds
        CLEAN     : No reports from either source
        UNKNOWN   : API errors prevented us from checking
    """
    # If both results are errors, we cannot determine threat level
    if "error" in abuseipdb_result and "error" in virustotal_result:
        return "UNKNOWN"

    abuse_score = abuseipdb_result.get("abuse_confidence_score", 0)
    vt_malicious  = virustotal_result.get("malicious",  0)
    vt_suspicious = virustotal_result.get("suspicious", 0)
    abuse_reports = abuseipdb_result.get("total_reports", 0)

    if abuse_score >= 80 or vt_malicious >= 5:
        return "CRITICAL"
    if abuse_score >= 50 or vt_malicious >= 2:
        return "HIGH"
    if abuse_score >= 20 or vt_suspicious >= 1:
        return "MEDIUM"
    if abuse_reports > 0 or vt_malicious > 0:
        return "LOW"
    return "CLEAN"


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 5 — MAIN ENRICHMENT FUNCTION
# Reads unique IPs from the DB, checks each one, writes results back.
# ─────────────────────────────────────────────────────────────────────────────

def enrich_all_ips() -> list:
    """
    The main function of this module.

    Steps:
    1. Read every distinct IP address from attacker_logs.
    2. For each IP, call check_abuseipdb() and check_virustotal().
    3. Build a combined result dict.
    4. Write that dict (as JSON) into the threat_intel column.
    5. Return the full list of results so callers can print or log them.

    Why distinct IPs?
        The same IP may appear in dozens of rows (one per login attempt).
        We only need to call the APIs once per unique IP — not once per row.
        After enrichment, every row for that IP gets the same threat_intel value.

    Returns:
        A list of dicts, one per unique IP, containing the full enrichment result.
    """
    results = []

    # ── Step 1: get distinct IPs ──────────────────────────────────────────────
    try:
        with get_connection() as conn:
            cursor = conn.execute(
                "SELECT DISTINCT ip_address FROM attacker_logs ORDER BY ip_address;"
            )
            unique_ips = [row[0] for row in cursor.fetchall()]
    except sqlite3.Error as e:
        log.error("Failed to fetch IPs from database: %s", e)
        return []

    if not unique_ips:
        log.info("No IPs found in attacker_logs — nothing to enrich.")
        return []

    log.info("Found %d unique IP(s) to enrich: %s", len(unique_ips), unique_ips)

    # ── Step 2 & 3: check each IP ────────────────────────────────────────────
    for ip in unique_ips:
        log.info("Checking IP: %s", ip)

        abuseipdb_data  = check_abuseipdb(ip)
        virustotal_data = check_virustotal(ip)
        threat_level    = calculate_threat_level(abuseipdb_data, virustotal_data)

        # Build the full enrichment record
        enrichment = {
            "ip_address":   ip,
            "threat_level": threat_level,
            "checked_at":   datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "abuseipdb":    abuseipdb_data,
            "virustotal":   virustotal_data,
        }

        # ── Step 4: write back to the database ───────────────────────────────
        # json.dumps() converts our Python dict into a JSON string for storage.
        # We update ALL rows that have this IP address so every log entry for
        # this attacker carries the enrichment data.
        try:
            with get_connection() as conn:
                conn.execute(
                    """
                    UPDATE attacker_logs
                    SET    threat_intel = ?
                    WHERE  ip_address   = ?;
                    """,
                    (json.dumps(enrichment), ip)
                )
                conn.commit()
            log.info(
                "IP %s enriched → threat_level=%s, abuse_score=%s, vt_malicious=%s",
                ip,
                threat_level,
                abuseipdb_data.get("abuse_confidence_score", "N/A"),
                virustotal_data.get("malicious", "N/A"),
            )
        except sqlite3.Error as e:
            log.error("Failed to write threat_intel for IP %s: %s", ip, e)

        results.append(enrichment)

    return results


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 6 — SINGLE-IP LOOKUP (used by dashboard/app.py)
# ─────────────────────────────────────────────────────────────────────────────

def enrich_single_ip(ip: str) -> dict:
    """
    Check and enrich one specific IP address.

    This is a convenience function for the dashboard — when it wants
    to look up a single IP on demand rather than re-checking all of them.

    Parameters:
        ip : the IP address string to look up

    Returns:
        The enrichment dict for that IP.
    """
    abuseipdb_data  = check_abuseipdb(ip)
    virustotal_data = check_virustotal(ip)
    threat_level    = calculate_threat_level(abuseipdb_data, virustotal_data)

    enrichment = {
        "ip_address":   ip,
        "threat_level": threat_level,
        "checked_at":   datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "abuseipdb":    abuseipdb_data,
        "virustotal":   virustotal_data,
    }

    # Write the result back to the database for all rows with this IP
    try:
        with get_connection() as conn:
            conn.execute(
                "UPDATE attacker_logs SET threat_intel = ? WHERE ip_address = ?;",
                (json.dumps(enrichment), ip)
            )
            conn.commit()
    except sqlite3.Error as e:
        log.error("Failed to write threat_intel for IP %s: %s", ip, e)

    return enrichment


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 7 — READ ENRICHMENT RESULTS BACK FROM THE DATABASE
# Used by dashboard/app.py to display results without recalling the APIs.
# ─────────────────────────────────────────────────────────────────────────────

def get_enriched_logs() -> list:
    """
    Fetch all attacker_logs rows that have been enriched with threat intel.

    The dashboard calls this to show a combined view of:
      - what the attacker did (from the portal logs)
      - what the external APIs say about their IP

    Returns a list of dicts. Each dict has all the attacker_logs columns
    plus the parsed threat_intel dict (not the raw JSON string).
    """
    try:
        with get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                """
                SELECT * FROM attacker_logs
                WHERE  threat_intel IS NOT NULL
                ORDER  BY timestamp DESC;
                """
            )
            rows = cursor.fetchall()

        results = []
        for row in rows:
            entry = dict(row)
            # Parse the JSON string back into a Python dict for easy use
            if entry.get("threat_intel"):
                try:
                    entry["threat_intel"] = json.loads(entry["threat_intel"])
                except json.JSONDecodeError:
                    entry["threat_intel"] = {}
            results.append(entry)

        return results

    except sqlite3.Error as e:
        log.error("Failed to fetch enriched logs: %s", e)
        return []


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 8 — PRIVATE IP HELPER
# ─────────────────────────────────────────────────────────────────────────────

def _is_private_ip(ip: str) -> bool:
    """
    Return True if the IP is a private, loopback, or reserved address
    that should not be sent to external APIs.

    Private ranges (RFC 1918):
        10.0.0.0/8       — corporate networks
        172.16.0.0/12    — corporate networks
        192.168.0.0/16   — home networks
    Loopback:
        127.x.x.x        — localhost (this is what all our test traffic shows as)

    We use Python's built-in ipaddress module so we do not have to write
    our own IP range comparison logic.
    """
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_reserved
    except ValueError:
        # If ip is not a valid IP string at all, treat it as private to be safe
        return True


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 9 — SELF-TEST (run this file directly to test it)
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import pprint

    print("=" * 60)
    print("ip_checker.py — self-test")
    print("=" * 60)

    # Step 1: ensure the threat_intel column exists
    print("\n[1] Initialising threat_intel column...")
    init_threat_intel_column()

    # Step 2: enrich all IPs in the database
    print("\n[2] Enriching all unique IPs in attacker_logs...")
    results = enrich_all_ips()

    if not results:
        print("    No IPs found in the database.")
    else:
        print(f"\n[3] Enrichment complete — {len(results)} unique IP(s) processed:\n")
        for r in results:
            print(f"  IP: {r['ip_address']}")
            print(f"  Threat Level : {r['threat_level']}")
            print(f"  Checked At   : {r['checked_at']}")
            print()
            print("  AbuseIPDB result:")
            pprint.pprint(r["abuseipdb"], indent=4)
            print()
            print("  VirusTotal result:")
            pprint.pprint(r["virustotal"], indent=4)
            print("-" * 60)

    # Step 3: read enriched logs back from DB to confirm they were saved
    print("\n[4] Reading enriched logs back from the database...")
    enriched = get_enriched_logs()
    print(f"    {len(enriched)} row(s) in attacker_logs now have threat_intel data.")

    if enriched:
        # Show the first row as a sample
        sample = enriched[0]
        print(f"\n    Sample row (id={sample['id']}):")
        print(f"      portal       : {sample['portal']}")
        print(f"      ip_address   : {sample['ip_address']}")
        print(f"      action       : {sample['action']}")
        threat = sample.get("threat_intel", {})
        print(f"      threat_level : {threat.get('threat_level', 'N/A')}")

    print("\nSelf-test complete.")
