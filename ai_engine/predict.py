"""
ai_engine/predict.py
====================
PURPOSE:
    Loads the trained models (random_forest.pkl, isolation_forest.pkl,
    scaler.pkl) and uses them to analyse live honeypot log entries from
    honeypot.db.

    Two modes:
      1. predict_one(log_row)  — analyse a single log dictionary
                                 (called by dashboard/app.py in real time)
      2. predict_all()         — analyse every row currently in honeypot.db
                                 (run manually to batch-score existing logs)

RUN (batch mode):
    python ai_engine/predict.py
"""

import os
import sys
import logging
import pickle

import numpy  as np
import pandas as pd

# ── Tell Python where to find database/logger.py ─────────────────────────────
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database.logger import get_all_logs

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level  = logging.INFO,
    format = "%(asctime)s  %(levelname)s  %(message)s"
)
log = logging.getLogger(__name__)

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR  = os.path.join(BASE_DIR, "models")
RF_PATH     = os.path.join(MODELS_DIR, "random_forest.pkl")
IF_PATH     = os.path.join(MODELS_DIR, "isolation_forest.pkl")
SCALER_PATH = os.path.join(MODELS_DIR, "scaler.pkl")

# ── Label decoding (must match generate_data.py and train_model.py) ───────────
LABEL_NAMES = {
    0: "benign",
    1: "brute_force",
    2: "path_traversal",
    3: "reconnaissance",
    4: "sql_injection",
    5: "xss",
}

# ── Risk level thresholds ─────────────────────────────────────────────────────
# Confidence from Random Forest is a probability between 0.0 and 1.0
# Anomaly score from Isolation Forest: more negative = more anomalous
RISK_RULES = {
    "CRITICAL" : dict(min_confidence=0.85, attack_types={"sql_injection", "xss", "path_traversal"}),
    "HIGH"     : dict(min_confidence=0.70, attack_types={"brute_force", "reconnaissance"}),
    "MEDIUM"   : dict(min_confidence=0.50, attack_types=set()),   # any attack, lower confidence
    "LOW"      : dict(min_confidence=0.00, attack_types=set()),   # everything else
}


# ══════════════════════════════════════════════════════════════════════════════
# STEP 1 — Load models from disk (done once at startup)
# ══════════════════════════════════════════════════════════════════════════════

def load_models() -> tuple:
    """
    Load the 3 saved model files from models/.

    Returns:
        (rf, iso, scaler) — ready to use for prediction
    """
    for path in (RF_PATH, IF_PATH, SCALER_PATH):
        if not os.path.exists(path):
            log.error("Model file not found: %s", path)
            log.error("Run ai_engine/train_model.py first.")
            sys.exit(1)

    log.info("Loading models from %s ...", MODELS_DIR)

    with open(RF_PATH,     "rb") as f: rf     = pickle.load(f)
    with open(IF_PATH,     "rb") as f: iso    = pickle.load(f)
    with open(SCALER_PATH, "rb") as f: scaler = pickle.load(f)

    log.info("Models loaded successfully.")
    return rf, iso, scaler


# ══════════════════════════════════════════════════════════════════════════════
# STEP 2 — Convert a log row into a numeric feature vector
# ══════════════════════════════════════════════════════════════════════════════

def _encode_portal(portal: str) -> float:
    """Convert portal name to a number the model understands."""
    mapping = {
        "supplier"    : 0.0,
        "procurement" : 1.0,
        "inventory"   : 2.0,
        "shipment"    : 3.0,
    }
    return mapping.get(portal.lower(), -1.0)


def _encode_action(action: str) -> float:
    """
    Convert action string to a numeric severity score.
    Higher number = more suspicious action.
    """
    action = action.lower()
    if "login_success"     in action: return 0.2
    if "dashboard_viewed"  in action: return 0.3
    if "login_failed"      in action: return 0.6
    if "bait_route"        in action: return 0.8
    if "unknown_path"      in action: return 0.7
    if "tracking_lookup"   in action: return 0.75
    return 0.5   # default for unknown actions


def _encode_attack_type(attack_type: str) -> float:
    """Convert the logger's detected attack_type to a number."""
    mapping = {
        "unknown"        : 0.0,
        "benign"         : 0.1,
        "brute_force"    : 0.5,
        "reconnaissance" : 0.6,
        "xss"            : 0.7,
        "path_traversal" : 0.8,
        "sql_injection"  : 0.9,
    }
    return mapping.get(attack_type.lower(), 0.0)


def _encode_user_agent(user_agent: str) -> float:
    """
    Detect known attack tools and browsers.
    Returns a suspicion score between 0.0 and 1.0.
    """
    ua = user_agent.lower()
    # Known attack tools get high scores
    if any(tool in ua for tool in ["sqlmap", "nikto", "nmap", "hydra",
                                    "masscan", "gobuster", "dirbuster",
                                    "burpsuite", "zgrab", "nuclei"]):
        return 1.0
    # Scripted tools — suspicious but could be legitimate
    if any(tool in ua for tool in ["python-requests", "curl", "wget",
                                    "go-http", "java/", "libwww"]):
        return 0.7
    # Normal browsers
    if any(b in ua for b in ["mozilla", "chrome", "safari", "firefox", "edge"]):
        return 0.1
    # Empty or unknown
    return 0.5


def _count_failed_logins(ip: str, all_logs: list) -> int:
    """
    Count how many failed login attempts this IP has made.
    High number = brute force indicator.
    """
    return sum(
        1 for row in all_logs
        if row.get("ip_address") == ip and row.get("action") == "login_failed"
    )


def _count_portals_hit(ip: str, all_logs: list) -> int:
    """
    Count how many different portals this IP has touched.
    Hitting multiple portals = coordinated attack indicator.
    """
    portals = set(
        row.get("portal") for row in all_logs
        if row.get("ip_address") == ip
    )
    return len(portals)


def log_to_features(log_row: dict, all_logs: list) -> np.ndarray:
    """
    Convert one log dictionary into a numeric feature vector.

    The feature vector has 13 values — same number as the training data
    (generate_data.py used 13 CICIDS feature columns).

    Features:
        0  portal_encoded       — which portal was hit
        1  action_severity      — how suspicious the action is
        2  attack_type_encoded  — what logger.py detected
        3  user_agent_score     — how suspicious the tool is
        4  failed_login_count   — brute force indicator
        5  portals_hit          — lateral movement indicator
        6  username_len         — long usernames can be injections
        7  password_len         — long passwords can be injections
        8  has_sql_chars        — SQL characters in username/password
        9  has_xss_chars        — XSS characters in username/password
        10 has_path_chars       — path traversal in username/password
        11 is_bait_route        — did they hit a honeypot trap?
        12 is_unknown_path      — did a scanner probe unknown paths?

    Parameters:
        log_row  : one row from get_all_logs() — a dictionary
        all_logs : all rows from the database — used for IP context

    Returns:
        numpy array of shape (13,)
    """
    ip          = log_row.get("ip_address",     "")
    portal      = log_row.get("portal",          "")
    action      = log_row.get("action",          "")
    username    = log_row.get("username_tried",  "") or ""
    password    = log_row.get("password_tried",  "") or ""
    user_agent  = log_row.get("user_agent",      "") or ""
    attack_type = log_row.get("attack_type",     "") or ""

    combined = (username + " " + password).lower()

    features = [
        _encode_portal(portal),                          # feat_0
        _encode_action(action),                          # feat_1
        _encode_attack_type(attack_type),                # feat_2
        _encode_user_agent(user_agent),                  # feat_3
        min(_count_failed_logins(ip, all_logs), 50)      # feat_4  cap at 50
            / 50.0,
        min(_count_portals_hit(ip, all_logs), 4)         # feat_5  cap at 4
            / 4.0,
        min(len(username), 100) / 100.0,                 # feat_6
        min(len(password), 100) / 100.0,                 # feat_7
        float(any(c in combined for c in               # feat_8  SQL chars
                  ["'", '"', " or ", "--", "1=1",
                   "select", "union", "drop"])),
        float(any(c in combined for c in               # feat_9  XSS chars
                  ["<script", "javascript:", "onerror",
                   "alert(", "<img", "<svg"])),
        float(any(c in combined for c in               # feat_10 path chars
                  ["../", "..\\", "/etc/", "boot.ini"])),
        float("bait_route" in action),                  # feat_11
        float("unknown_path" in action),                # feat_12
    ]

    return np.array(features, dtype=np.float64)


# ══════════════════════════════════════════════════════════════════════════════
# STEP 3 — Determine risk level
# ══════════════════════════════════════════════════════════════════════════════

def _get_risk_level(predicted_attack: str, confidence: float, is_anomaly: bool) -> str:
    """
    Combine Random Forest prediction + Isolation Forest anomaly flag
    to assign a human-readable risk level.

    CRITICAL : high-confidence web attack (SQLi, XSS, path traversal)
               OR any anomaly with high confidence
    HIGH     : high-confidence brute force or reconnaissance
    MEDIUM   : any attack with moderate confidence
    LOW      : low confidence or benign traffic
    """
    if predicted_attack == "benign" and not is_anomaly:
        return "LOW"

    if predicted_attack in {"sql_injection", "xss", "path_traversal"}:
        if confidence >= 0.75 or is_anomaly:
            return "CRITICAL"
        return "HIGH"

    if predicted_attack in {"brute_force", "reconnaissance"}:
        if confidence >= 0.70:
            return "HIGH"
        return "MEDIUM"

    if is_anomaly and confidence >= 0.60:
        return "HIGH"

    if confidence >= 0.50:
        return "MEDIUM"

    return "LOW"


# ══════════════════════════════════════════════════════════════════════════════
# STEP 4 — Core prediction function
# ══════════════════════════════════════════════════════════════════════════════

def predict_one(
    log_row  : dict,
    all_logs : list,
    rf,
    iso,
    scaler,
) -> dict:
    """
    Analyse a single log row and return a full prediction result.

    This is the function the dashboard calls for every log entry.

    Parameters:
        log_row  : one log dictionary from honeypot.db
        all_logs : all logs (needed for IP context features)
        rf       : loaded RandomForestClassifier
        iso      : loaded IsolationForest
        scaler   : loaded StandardScaler

    Returns:
        Dictionary with prediction results — see example below:
        {
            "log_id"           : 42,
            "ip_address"       : "192.168.1.100",
            "portal"           : "supplier",
            "action"           : "login_failed",
            "predicted_attack" : "sql_injection",
            "confidence"       : 0.94,
            "is_anomaly"       : True,
            "anomaly_score"    : -0.15,
            "risk_level"       : "CRITICAL",
            "all_probs"        : {label: prob, ...}
        }
    """
    # Build feature vector — shape (13,)
    features = log_to_features(log_row, all_logs)

    # Scale using the same scaler used during training
    features_scaled = scaler.transform(features.reshape(1, -1))

    # ── Random Forest prediction ──────────────────────────────────────────────
    rf_label      = rf.predict(features_scaled)[0]            # integer label
    rf_proba      = rf.predict_proba(features_scaled)[0]      # array of probs
    confidence    = float(rf_proba[rf_label])
    predicted_atk = LABEL_NAMES.get(rf_label, "unknown")

    # All class probabilities as a readable dict
    all_probs = {
        LABEL_NAMES[i]: round(float(p), 4)
        for i, p in enumerate(rf_proba)
    }

    # ── Isolation Forest anomaly detection ────────────────────────────────────
    iso_pred     = iso.predict(features_scaled)[0]   # 1=normal, -1=anomaly
    is_anomaly   = bool(iso_pred == -1)
    anomaly_score = float(iso.decision_function(features_scaled)[0])
    # anomaly_score: more negative = more anomalous
    # typical range: -0.5 (very anomalous) to +0.5 (very normal)

    # ── Risk level ────────────────────────────────────────────────────────────
    risk_level = _get_risk_level(predicted_atk, confidence, is_anomaly)

    return {
        "log_id"           : log_row.get("id",          ""),
        "ip_address"       : log_row.get("ip_address",  ""),
        "portal"           : log_row.get("portal",      ""),
        "action"           : log_row.get("action",      ""),
        "timestamp"        : log_row.get("timestamp",   ""),
        "predicted_attack" : predicted_atk,
        "confidence"       : round(confidence, 4),
        "is_anomaly"       : is_anomaly,
        "anomaly_score"    : round(anomaly_score, 4),
        "risk_level"       : risk_level,
        "all_probs"        : all_probs,
    }


# ══════════════════════════════════════════════════════════════════════════════
# STEP 5 — Batch predict all logs in the database
# ══════════════════════════════════════════════════════════════════════════════

def predict_all() -> list:
    """
    Load every row from honeypot.db and run predict_one() on each.

    Returns:
        List of prediction result dictionaries, sorted by risk level.
    """
    log.info("Fetching all logs from honeypot.db ...")
    all_logs = get_all_logs()

    if not all_logs:
        log.warning("No logs found in honeypot.db.")
        log.warning("Start the portals and trigger some login attempts first.")
        return []

    log.info("Found %d log entries. Loading models ...", len(all_logs))
    rf, iso, scaler = load_models()

    log.info("Running predictions ...")
    results = []
    for i, row in enumerate(all_logs):
        result = predict_one(row, all_logs, rf, iso, scaler)
        results.append(result)
        if (i + 1) % 100 == 0:
            log.info("  Processed %d / %d rows ...", i + 1, len(all_logs))

    # Sort by risk level: CRITICAL first
    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    results.sort(key=lambda r: risk_order.get(r["risk_level"], 4))

    # ── Summary ───────────────────────────────────────────────────────────────
    log.info("=" * 50)
    log.info("PREDICTION SUMMARY")
    log.info("=" * 50)
    log.info("Total logs analysed : %d", len(results))

    # Count by risk level
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = sum(1 for r in results if r["risk_level"] == level)
        log.info("  %-10s : %d", level, count)

    # Count by predicted attack
    log.info("Attack type breakdown:")
    from collections import Counter
    attack_counts = Counter(r["predicted_attack"] for r in results)
    for attack, count in attack_counts.most_common():
        log.info("  %-20s : %d", attack, count)

    # Top 5 most suspicious IPs
    ip_risk = {}
    for r in results:
        ip = r["ip_address"]
        if ip not in ip_risk:
            ip_risk[ip] = 0
        ip_risk[ip] += {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(r["risk_level"], 0)

    top_ips = sorted(ip_risk.items(), key=lambda x: x[1], reverse=True)[:5]
    log.info("Top suspicious IPs:")
    for ip, score in top_ips:
        log.info("  %-20s risk score: %d", ip, score)

    return results


# ══════════════════════════════════════════════════════════════════════════════
# MAIN — batch mode
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    log.info("=" * 60)
    log.info("predict.py  —  AI Honeypot Live Threat Analyser")
    log.info("=" * 60)

    results = predict_all()

    if results:
        log.info("=" * 60)
        log.info("TOP 10 HIGHEST RISK EVENTS:")
        log.info("=" * 60)
        for r in results[:10]:
            log.info(
                "[%s] IP=%-18s Portal=%-12s Attack=%-16s Conf=%.2f Anomaly=%s",
                r["risk_level"],
                r["ip_address"],
                r["portal"],
                r["predicted_attack"],
                r["confidence"],
                r["is_anomaly"],
            )

    log.info("=" * 60)
    log.info("DONE. predict_one() is ready to be called by dashboard/app.py")
    log.info("=" * 60)
