"""
explainability/shap_explainer.py
================================
PURPOSE:
    Uses SHAP to explain WHY the Random Forest made each prediction.

    Two functions:
      1. explain_one(log_row, all_logs, rf, scaler)
             Returns {feature_name: shap_value} for one log row.
             Called by dashboard/app.py.

      2. explain_all(sample_size=500)
             Runs SHAP on training data and saves a bar chart to
             models/shap_summary.png

RUN:
    python explainability/shap_explainer.py
"""

import os
import sys
import logging
import pickle

import numpy  as np
import pandas as pd
import shap
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ai_engine.predict import log_to_features, load_models

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)s  %(message)s")
log = logging.getLogger(__name__)

BASE_DIR        = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRAINING_DATA   = os.path.join(BASE_DIR, "data",   "training_data.csv")
MODELS_DIR      = os.path.join(BASE_DIR, "models")
SHAP_CHART_PATH = os.path.join(MODELS_DIR, "shap_summary.png")

FEATURE_NAMES = [
    "Portal Targeted",
    "Action Severity",
    "Attack Type (Logger)",
    "User Agent Suspicion",
    "Failed Login Count",
    "Portals Hit (Lateral)",
    "Username Length",
    "Password Length",
    "SQL Chars in Input",
    "XSS Chars in Input",
    "Path Traversal in Input",
    "Bait Route Accessed",
    "Unknown Path Probed",
]


# ══════════════════════════════════════════════════════════════════════════════
# FUNCTION 1 — Explain one log row
# ══════════════════════════════════════════════════════════════════════════════

def explain_one(log_row: dict, all_logs: list, rf, scaler) -> dict:
    """
    Generate SHAP explanation for one honeypot log row.
    Returns a dict of feature names → shap values, sorted by impact.
    """
    features        = log_to_features(log_row, all_logs)
    features_scaled = scaler.transform(features.reshape(1, -1))
    predicted_label = int(rf.predict(features_scaled)[0])

    explainer   = shap.TreeExplainer(rf)
    shap_values = explainer.shap_values(features_scaled)

    # shap_values is a list (one array per class) — pick predicted class
    class_shap = np.array(shap_values[predicted_label]).flatten()

    feature_impacts = {
        name: round(float(val), 4)
        for name, val in zip(FEATURE_NAMES, class_shap)
    }

    # Sort by absolute impact descending
    feature_impacts = dict(
        sorted(feature_impacts.items(), key=lambda x: abs(x[1]), reverse=True)
    )

    top_reason = list(feature_impacts.keys())[0]

    ev = explainer.expected_value
    base_value = float(ev[predicted_label]) if hasattr(ev, '__len__') else float(ev)

    log.info("SHAP explanation for log_id=%s: top_reason='%s'",
             log_row.get("id", "?"), top_reason)

    return {
        "feature_impacts" : feature_impacts,
        "top_reason"      : top_reason,
        "predicted_class" : str(predicted_label),
        "base_value"      : round(base_value, 4),
    }


# ══════════════════════════════════════════════════════════════════════════════
# FUNCTION 2 — Generate summary chart
# ══════════════════════════════════════════════════════════════════════════════

def explain_all(sample_size: int = 500) -> None:
    """
    Run SHAP on a sample of training data.
    Saves a feature importance bar chart to models/shap_summary.png.
    """
    log.info("Loading models ...")
    rf, iso, scaler = load_models()

    log.info("Loading training data ...")
    if not os.path.exists(TRAINING_DATA):
        log.error("training_data.csv not found. Run generate_data.py first.")
        sys.exit(1)

    df = pd.read_csv(TRAINING_DATA)
    feature_cols = [c for c in df.columns if c.startswith("feat_")]
    log.info("Loaded %d rows with %d features.", len(df), len(feature_cols))

    # Sample for speed
    sample = df[feature_cols].sample(min(sample_size, len(df)), random_state=42)
    sample_scaled = scaler.transform(sample.values)

    log.info("Running SHAP TreeExplainer on %d samples ...", len(sample))
    explainer   = shap.TreeExplainer(rf)
    shap_values = explainer.shap_values(sample_scaled)

    # shap_values is list of arrays shape (n_samples, n_features), one per class
    # Stack into shape (n_classes, n_samples, n_features)
    stacked = np.array(shap_values)   # shape: (n_classes, n_samples, n_features)

    # Mean absolute SHAP value per feature across all classes and samples
    mean_abs_shap = np.abs(stacked).mean(axis=(0, 1))  # shape: (n_features,)

    log.info("mean_abs_shap shape: %s", mean_abs_shap.shape)
    log.info("FEATURE_NAMES count: %d", len(FEATURE_NAMES))

    # Use only as many names as we have values
    n = min(len(mean_abs_shap), len(FEATURE_NAMES))
    names  = FEATURE_NAMES[:n]
    values = mean_abs_shap[:n]

    # Sort descending
    order         = np.argsort(values)[::-1]
    sorted_names  = [names[i]  for i in order]
    sorted_values = [values[i] for i in order]

    # ── Bar chart ─────────────────────────────────────────────────────────────
    log.info("Generating SHAP summary bar chart ...")

    fig, ax = plt.subplots(figsize=(10, 7))
    fig.patch.set_facecolor("#0d1117")
    ax.set_facecolor("#0d1117")

    colors = ["#f85149" if v > 0.05 else "#388bfd" for v in sorted_values]

    bars = ax.barh(range(len(sorted_names)), sorted_values,
                   color=colors, edgecolor="none", height=0.6)

    ax.set_yticks(range(len(sorted_names)))
    ax.set_yticklabels(sorted_names, fontsize=11, color="#c9d1d9")
    ax.set_xlabel("Mean |SHAP Value| — Average Impact on Prediction",
                  fontsize=11, color="#8b949e")
    ax.set_title(
        "AI Honeypot — Feature Importance (SHAP)\nWhich signals drive attack detection?",
        fontsize=13, color="#e6edf3", pad=15
    )
    ax.tick_params(colors="#8b949e")
    for spine in ["top", "right"]:
        ax.spines[spine].set_visible(False)
    ax.spines["left"].set_color("#30363d")
    ax.spines["bottom"].set_color("#30363d")

    for bar, val in zip(bars, sorted_values):
        ax.text(val + 0.001, bar.get_y() + bar.get_height() / 2,
                f"{val:.3f}", va="center", ha="left",
                fontsize=9, color="#8b949e")

    plt.tight_layout()
    os.makedirs(MODELS_DIR, exist_ok=True)
    plt.savefig(SHAP_CHART_PATH, dpi=150, bbox_inches="tight", facecolor="#0d1117")
    plt.close()

    log.info("Chart saved to: %s", SHAP_CHART_PATH)
    log.info("Top 5 most important features:")
    for i in range(min(5, len(sorted_names))):
        log.info("  %d. %-30s %.4f", i + 1, sorted_names[i], sorted_values[i])


# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    log.info("=" * 60)
    log.info("shap_explainer.py  —  AI Honeypot Explainability Engine")
    log.info("=" * 60)

    explain_all(sample_size=500)

    log.info("=" * 60)
    log.info("DONE. Chart saved to models/shap_summary.png")
    log.info("=" * 60)
