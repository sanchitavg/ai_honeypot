"""
ai_engine/predict.py
====================
PURPOSE:
    Loads the trained models and uses them to analyse live honeypot log
    entries from honeypot.db.

    The 13 features extracted here are IDENTICAL to the 13 features
    used to generate training data in generate_data.py. This is critical —
    the model must see the same feature format at prediction time as it
    saw during training.

    Two modes:
      1. predict_one(log_row, all_logs, rf, iso, scaler)
             — analyse one log dict, called by dashboard in real time
      2. predict_all()
             — batch analyse every row in honeypot.db

RUN (batch mode):
    python ai_engine/predict.py
"""

import os
import sys
import logging
import pickle

import numpy as np

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

# ── Label decoding — must match generate_data.py and train_model.py ───────────
LABEL_NAMES = {
    0: "benign",
    1: "brute_force",
    2: "path_traversal",
    3: "reconnaissance",
    4: "sql_injection",
    5: "xss",
}


# ══════════════════════════════════════════════════════════════════════════════
# Feature extraction — 13 features, identical to generate_data.py
# ══════════════════════════════════════════════════════════════════════════════

def _encode_portal(portal: str) -> float:
    """feat_0: which portal was hit"""
    return {"supplier": 0.0, "procurement": 1.0,
            "inventory": 2.0, "shipment": 3.0}.get(portal.lower(), 0.0)


def _encode_action(action: str) -> float:
    """feat_1: how suspicious the action is"""
    a = action.lower()
    if "login_success"    in a: return 0.2
    if "dashboard_viewed" in a: return 0.3
    if "login_failed"     in a: return 0.6
    if "bait_route"       in a: return 0.8
    if "unknown_path"     in a: return 0.75
    if "tracking_lookup"  in a: return 0.75
    return 0.5


def _encode_attack_type(attack_type: str) -> float:
    """feat_2: attack type detected by logger.py"""
    return {
        "unknown"        : 0.0,
        "benign"         : 0.0,
        "brute_force"    : 0.7,
        "reconnaissance" : 0.75,
        "xss"            : 0.85,
        "path_traversal" : 0.9,
        "sql_injection"  : 1.0,
    }.get(attack_type.lower(), 0.0)


def _encode_user_agent(user_agent: str) -> float:
    """feat_3: how suspicious the browser/tool is"""
    ua = user_agent.lower()
    if any(t in ua for t in ["sqlmap", "nikto", "nmap", "hydra", "masscan",
                               "gobuster", "dirbuster", "burpsuite", "zgrab",
                               "nuclei", "metasploit"]):
        return 1.0
    if any(t in ua for t in ["python-requests", "curl", "wget",
                               "go-http", "java/", "libwww", "scrapy"]):
        return 0.7
    if any(t in ua for t in ["mozilla", "chrome", "safari",
                               "firefox", "edge"]):
        return 0.1
    return 0.5


def _failed_login_count(ip: str, all_logs: list) -> float:
    """feat_4: number of failed logins from this IP, normalised 0-1 (cap 50)"""
    count = sum(1 for r in all_logs
                if r.get("ip_address") == ip and r.get("action") == "login_failed")
    return min(count, 50) / 50.0


def _portals_hit(ip: str, all_logs: list) -> float:
    """feat_5: how many different portals this IP hit, normalised 0-1 (cap 4)"""
    portals = set(r.get("portal") for r in all_logs if r.get("ip_address") == ip)
    return min(len(portals), 4) / 4.0


def log_to_features(log_row: dict, all_logs: list) -> np.ndarray:
    """
    Convert one honeypot log dictionary into a 13-element numeric feature vector.
    This function is the bridge between raw log data and the AI model.
    Every feature here corresponds exactly to a column in training_data.csv.
    """
    ip          = log_row.get("ip_address",    "")
    portal      = log_row.get("portal",         "")
    action      = log_row.get("action",         "")
    username    = log_row.get("username_tried", "") or ""
    password    = log_row.get("password_tried", "") or ""
    user_agent  = log_row.get("user_agent",     "") or ""
    attack_type = log_row.get("attack_type",    "") or ""

    combined = (username + " " + password).lower()

    features = [
        _encode_portal(portal),                                          # feat_0
        _encode_action(action),                                          # feat_1
        _encode_attack_type(attack_type),                                # feat_2
        _encode_user_agent(user_agent),                                  # feat_3
        _failed_login_count(ip, all_logs),                               # feat_4
        _portals_hit(ip, all_logs),                                      # feat_5
        min(len(username), 100) / 100.0,                                 # feat_6
        min(len(password),  100) / 100.0,                                # feat_7
        float(any(p in combined for p in                                 # feat_8 SQL
                  ["'", '"', " or ", " and ", "--", "1=1",
                   "drop ", "select ", "union ", "insert "])),
        float(any(p in combined for p in                                 # feat_9 XSS
                  ["<script", "javascript:", "onerror=",
                   "alert(", "<img", "<svg"])),
        float(any(p in combined for p in                                 # feat_10 path
                  ["../", "..\\", "/etc/passwd", "/etc/shadow",
                   "boot.ini", "win.ini"])),
        float("bait_route"    in action.lower()),                        # feat_11
        float("unknown_path"  in action.lower()),                        # feat_12
    ]

    return np.array(features, dtype=np.float64)


# ══════════════════════════════════════════════════════════════════════════════
# Risk level
# ══════════════════════════════════════════════════════════════════════════════

def _get_risk_level(predicted_attack: str, confidence: float, is_anomaly: bool) -> str:
    """Assign a risk level based on attack type, confidence and anomaly flag."""
    if predicted_attack == "benign" and not is_anomaly:
        return "LOW"
    if predicted_attack in {"sql_injection", "xss", "path_traversal"}:
        return "CRITICAL" if confidence >= 0.60 or is_anomaly else "HIGH"
    if predicted_attack in {"brute_force", "reconnaissance"}:
        return "HIGH" if confidence >= 0.60 else "MEDIUM"
    if is_anomaly:
        return "HIGH"
    return "MEDIUM" if confidence >= 0.50 else "LOW"


# ══════════════════════════════════════════════════════════════════════════════
# Load models
# ══════════════════════════════════════════════════════════════════════════════

def load_models() -> tuple:
    """Load all 3 model files. Called once at startup."""
    for path in (RF_PATH, IF_PATH, SCALER_PATH):
        if not os.path.exists(path):
            log.error("Model not found: %s — run train_model.py first.", path)
            sys.exit(1)

    log.info("Loading models from %s ...", MODELS_DIR)
    with open(RF_PATH,     "rb") as f: rf     = pickle.load(f)
    with open(IF_PATH,     "rb") as f: iso    = pickle.load(f)
    with open(SCALER_PATH, "rb") as f: scaler = pickle.load(f)
    log.info("Models loaded successfully.")
    return rf, iso, scaler


# ══════════════════════════════════════════════════════════════════════════════
# Core prediction function — called by dashboard for every log row
# ══════════════════════════════════════════════════════════════════════════════

def predict_one(log_row: dict, all_logs: list, rf, iso, scaler) -> dict:
    """
    Analyse one log row and return a full prediction result dict.

    Returns:
        {
            log_id, ip_address, portal, action, timestamp,
            predicted_attack, confidence, is_anomaly,
            anomaly_score, risk_level, all_probs
        }
    """
    features        = log_to_features(log_row, all_logs)
    features_scaled = scaler.transform(features.reshape(1, -1))

    # Random Forest
    rf_label      = rf.predict(features_scaled)[0]
    rf_proba      = rf.predict_proba(features_scaled)[0]
    confidence    = float(rf_proba[rf_label])
    predicted_atk = LABEL_NAMES.get(int(rf_label), "unknown")

    all_probs = {
        LABEL_NAMES[i]: round(float(p), 4)
        for i, p in enumerate(rf_proba)
    }

    # Isolation Forest
    iso_raw       = iso.predict(features_scaled)[0]
    is_anomaly    = bool(iso_raw == -1)
    anomaly_score = float(iso.decision_function(features_scaled)[0])

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
# Batch predict all logs
# ══════════════════════════════════════════════════════════════════════════════

def predict_all() -> list:
    """Fetch all logs from honeypot.db and run predict_one on each."""
    log.info("Fetching all logs from honeypot.db ...")
    all_logs = get_all_logs()

    if not all_logs:
        log.warning("No logs found. Start a portal and trigger some activity first.")
        return []

    log.info("Found %d log entries. Loading models ...", len(all_logs))
    rf, iso, scaler = load_models()

    log.info("Running predictions ...")
    results = []
    for i, row in enumerate(all_logs):
        results.append(predict_one(row, all_logs, rf, iso, scaler))
        if (i + 1) % 50 == 0:
            log.info("  Processed %d / %d ...", i + 1, len(all_logs))

    # Sort: CRITICAL first
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    results.sort(key=lambda r: order.get(r["risk_level"], 4))

    # Summary
    from collections import Counter
    log.info("=" * 50)
    log.info("PREDICTION SUMMARY — %d logs analysed", len(results))
    log.info("=" * 50)
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        log.info("  %-10s : %d", level,
                 sum(1 for r in results if r["risk_level"] == level))
    log.info("Attack type breakdown:")
    for atk, cnt in Counter(r["predicted_attack"] for r in results).most_common():
        log.info("  %-20s : %d", atk, cnt)

    # Top suspicious IPs
    ip_score = {}
    score_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    for r in results:
        ip_score[r["ip_address"]] = (
            ip_score.get(r["ip_address"], 0) + score_map.get(r["risk_level"], 0)
        )
    log.info("Top suspicious IPs:")
    for ip, sc in sorted(ip_score.items(), key=lambda x: x[1], reverse=True)[:5]:
        log.info("  %-20s risk score: %d", ip, sc)

    return results


# ══════════════════════════════════════════════════════════════════════════════
# Main
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
