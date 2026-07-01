"""
dashboard/app.py
=================
PURPOSE:
    The final module of the AI Honeypot project. This Flask app is the
    "control room" — it reads everything the other modules have produced
    and shows it on one screen:

        database/logger.py          → raw attacker events (who, what, when)
        ai_engine/predict.py        → AI verdict per event (attack type,
                                       confidence, anomaly flag, risk level)
        explainability/shap_explainer.py → WHY the AI reached that verdict
        threat_intel/ip_checker.py  → is this IP known-bad on the open internet?

    Nothing in this file re-implements logic that already exists elsewhere.
    It only calls functions from the other modules and arranges the results
    into a webpage.

RUN:
    python dashboard/app.py
    then open http://127.0.0.1:5000 in a browser.
"""

import os
import sys
import logging

# ── Tell Python where to find database/, ai_engine/, threat_intel/, etc. ─────
# This file lives in dashboard/app.py, so going one level up (..) reaches
# the project root — the same pattern used in every portal and in
# ip_checker.py / predict.py / shap_explainer.py.
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from flask import Flask, render_template, jsonify, request, send_from_directory

from database.logger import init_db, get_all_logs, get_logs_by_ip, get_logs_by_portal
from ai_engine.predict import load_models, predict_one
from explainability.shap_explainer import explain_one
from threat_intel.ip_checker import (
    init_threat_intel_column,
    get_enriched_logs,
    enrich_all_ips,
)

# ── Logging setup — same style as every other module in this project ────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)s  %(message)s")
log = logging.getLogger(__name__)

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, "models")

# ── Flask app ─────────────────────────────────────────────────────────────────
app = Flask(__name__, template_folder="../templates")
app.secret_key = "dashboard_honeypot_secret_key_2026"

# ── Load the AI models ONCE when the server starts ────────────────────────────
# predict_one() needs rf (Random Forest), iso (Isolation Forest) and scaler
# for every single log row. Loading a 17 MB pickle file on every web request
# would make the dashboard painfully slow, so we load them one time here and
# reuse the same objects for every request that comes in afterwards.
log.info("Starting dashboard — loading AI models into memory ...")
RF_MODEL, ISO_MODEL, SCALER = load_models()
log.info("AI models loaded. Dashboard ready.")


# ══════════════════════════════════════════════════════════════════════════════
# HELPER 1 — Combine raw logs + AI predictions + threat intel into one list
# ══════════════════════════════════════════════════════════════════════════════

def build_enriched_log_list() -> list:
    """
    This is the central function of the whole dashboard.

    It takes the raw attacker_logs rows from the database and, for every
    row, attaches two extra things:
      1. The AI's verdict  (from ai_engine.predict.predict_one)
      2. The IP's threat intel, if it has been checked already
         (read from the same row — ip_checker.py already wrote it into
         the 'threat_intel' column of attacker_logs)

    Why we don't call get_enriched_logs() alone:
        get_enriched_logs() ONLY returns rows that already have threat_intel
        filled in. If threat_intel/ip_checker.py has not been run yet, that
        list would be empty and the dashboard would show nothing. Instead we
        start from get_all_logs() (every row, always present) and merge in
        threat_intel when it exists.

    Returns:
        A list of dicts, newest first, each containing the original log
        fields PLUS: predicted_attack, confidence, is_anomaly, risk_level,
        all_probs, and threat_level.
    """
    import json

    all_logs = get_all_logs()

    if not all_logs:
        return []

    enriched = []
    for row in all_logs:
        # ── 1. AI prediction for this single row ─────────────────────────────
        # predict_one() also needs the full all_logs list because two of its
        # 13 features (failed_login_count, portals_hit) depend on the
        # attacker's ENTIRE history, not just this one row.
        prediction = predict_one(row, all_logs, RF_MODEL, ISO_MODEL, SCALER)

        # ── 2. Threat intel, if this row already has it ──────────────────────
        threat_level = "NOT CHECKED"
        raw_intel = row.get("threat_intel")
        if raw_intel:
            try:
                threat_level = json.loads(raw_intel).get("threat_level", "NOT CHECKED")
            except (json.JSONDecodeError, TypeError):
                threat_level = "NOT CHECKED"

        merged = dict(row)                       # copy original log fields
        merged.update(prediction)                # add predicted_attack, confidence, etc.
        merged["threat_level"] = threat_level
        enriched.append(merged)

    return enriched


# ══════════════════════════════════════════════════════════════════════════════
# HELPER 2 — Turn the enriched log list into dashboard summary statistics
# ══════════════════════════════════════════════════════════════════════════════

def build_summary(enriched_logs: list) -> dict:
    """
    Compute the numbers shown in the summary cards at the top of the
    dashboard: total events, unique attacker IPs, risk-level counts,
    attack-type counts, and the top 5 most suspicious IPs.

    This is plain Python counting — no AI, no database calls. It just
    summarises the list that build_enriched_log_list() already produced,
    so we do not repeat any work.
    """
    from collections import Counter

    total_events  = len(enriched_logs)
    unique_ips    = sorted(set(r["ip_address"] for r in enriched_logs))
    portals_hit   = sorted(set(r["portal"] for r in enriched_logs))

    risk_counts   = Counter(r["risk_level"]       for r in enriched_logs)
    attack_counts = Counter(r["predicted_attack"] for r in enriched_logs)
    anomaly_count = sum(1 for r in enriched_logs if r["is_anomaly"])

    # ── Risk score per IP, same scoring used in predict.py's predict_all() ──
    score_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    ip_scores = {}
    for r in enriched_logs:
        ip_scores[r["ip_address"]] = (
            ip_scores.get(r["ip_address"], 0) + score_map.get(r["risk_level"], 0)
        )
    top_ips = sorted(ip_scores.items(), key=lambda x: x[1], reverse=True)[:5]

    return {
        "total_events":   total_events,
        "unique_ip_count": len(unique_ips),
        "portals_hit":    portals_hit,
        "risk_counts":    dict(risk_counts),
        "attack_counts":  dict(attack_counts),
        "anomaly_count":  anomaly_count,
        "top_ips":        top_ips,
    }


# ══════════════════════════════════════════════════════════════════════════════
# ROUTE 1 — Main dashboard page
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/", methods=["GET"])
def dashboard_home():
    """
    The main page. Shows:
      - summary cards (total events, unique IPs, risk breakdown, anomalies)
      - the top 5 riskiest IPs
      - a table of every event with its AI verdict and threat intel
      - a link to the global SHAP feature-importance chart

    All the heavy lifting (querying the DB, running the AI, reading threat
    intel) happens in the two helper functions above. This route just calls
    them and hands the results to the HTML template.
    """
    enriched_logs = build_enriched_log_list()
    summary       = build_summary(enriched_logs)

    return render_template(
        "dashboard.html",
        logs          = enriched_logs,
        summary       = summary,
    )


# ══════════════════════════════════════════════════════════════════════════════
# ROUTE 2 — SHAP explanation for ONE log row (called by JavaScript, not a link)
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/explain/<int:log_id>", methods=["GET"])
def api_explain(log_id):
    """
    Returns a JSON explanation of WHY the AI made its prediction for one
    specific log row. The dashboard page calls this with JavaScript's
    fetch() when the analyst clicks an "Explain" button, instead of
    reloading the whole page.

    Why JSON and not HTML:
        Running SHAP is slower than a normal database read (it has to
        replay the Random Forest's decision path). We only want to pay
        that cost for the ONE row the analyst is currently interested in,
        not for all 47+ rows every time the dashboard loads.
    """
    all_logs = get_all_logs()
    target_row = next((r for r in all_logs if r["id"] == log_id), None)

    if target_row is None:
        return jsonify({"error": f"Log id {log_id} not found"}), 404

    explanation = explain_one(target_row, all_logs, RF_MODEL, SCALER)
    return jsonify(explanation)


# ══════════════════════════════════════════════════════════════════════════════
# ROUTE 3 — Manually trigger threat-intel enrichment for all IPs
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/refresh-threat-intel", methods=["POST"])
def api_refresh_threat_intel():
    """
    Calls threat_intel.ip_checker.enrich_all_ips(), which contacts the
    AbuseIPDB and VirusTotal APIs for every unique IP in the database and
    writes the result back into attacker_logs.threat_intel.

    This is a POST route triggered by a button on the dashboard, NOT run
    automatically on every page load. Reasons:
      - It calls external APIs, which is slow (network round trips).
      - Free-tier API keys have daily limits (AbuseIPDB: 1000/day,
        VirusTotal: 500/day) — we don't want to burn through them just
        because the dashboard was refreshed.
    """
    results = enrich_all_ips()
    return jsonify({
        "message": f"Enriched {len(results)} unique IP(s).",
        "results": results,
    })


# ══════════════════════════════════════════════════════════════════════════════
# ROUTE 4 — Serve the global SHAP summary chart image
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/shap-summary-chart", methods=["GET"])
def shap_summary_chart():
    """
    Serves models/shap_summary.png — the bar chart generated by
    explainability/shap_explainer.py's explain_all() function.
    This shows which of the 13 features matter most across ALL predictions
    (the "global" picture), as opposed to /api/explain/<id> which explains
    just ONE prediction (the "local" picture).
    """
    return send_from_directory(MODELS_DIR, "shap_summary.png")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN — run the dashboard
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    init_db()                      # make sure attacker_logs table exists
    init_threat_intel_column()     # make sure threat_intel column exists
    print("AI Honeypot Dashboard running on http://127.0.0.1:5050")
    app.run(host="0.0.0.0", port=5050, debug=False)
