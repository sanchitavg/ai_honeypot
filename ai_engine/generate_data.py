"""
ai_engine/generate_data.py
==========================
PURPOSE:
    Generates synthetic honeypot log data using the EXACT same 13 features
    that predict.py will extract from real honeypot logs.

    Every row in the training data represents one honeypot log entry,
    encoded into 13 numeric features that match predict.py's log_to_features().

    The 13 features (in order) are:
        feat_0  portal_encoded        0=supplier,1=procurement,2=inventory,3=shipment
        feat_1  action_severity       how suspicious the action is (0.0-1.0)
        feat_2  attack_type_encoded   what logger.py detected (0.0-1.0)
        feat_3  user_agent_score      how suspicious the tool is (0.0-1.0)
        feat_4  failed_login_count    brute force indicator, normalised 0-1
        feat_5  portals_hit           lateral movement indicator, normalised 0-1
        feat_6  username_len          normalised 0-1
        feat_7  password_len          normalised 0-1
        feat_8  has_sql_chars         1 if SQL injection chars found, else 0
        feat_9  has_xss_chars         1 if XSS chars found, else 0
        feat_10 has_path_chars        1 if path traversal chars found, else 0
        feat_11 is_bait_route         1 if bait route was hit, else 0
        feat_12 is_unknown_path       1 if unknown path was probed, else 0

RUN ONCE before train_model.py:
    python ai_engine/generate_data.py
"""

import os
import sys
import random
import logging

import numpy  as np
import pandas as pd

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level  = logging.INFO,
    format = "%(asctime)s  %(levelname)s  %(message)s"
)
log = logging.getLogger(__name__)

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_PATH = os.path.join(BASE_DIR, "data", "training_data.csv")

# ── Constants ─────────────────────────────────────────────────────────────────
RANDOM_SEED    = 42
TOTAL_ROWS     = 20_000   # total synthetic rows to generate

# Label encoding — alphabetical order, must match train_model.py and predict.py
LABEL_MAP = {
    "benign"         : 0,
    "brute_force"    : 1,
    "path_traversal" : 2,
    "reconnaissance" : 3,
    "sql_injection"  : 4,
    "xss"            : 5,
}

LABEL_NAMES = {v: k for k, v in LABEL_MAP.items()}

# 13 feature column names — must match predict.py's log_to_features() exactly
FEATURE_COLS = [
    "feat_0_portal",
    "feat_1_action_severity",
    "feat_2_attack_type",
    "feat_3_user_agent",
    "feat_4_failed_logins",
    "feat_5_portals_hit",
    "feat_6_username_len",
    "feat_7_password_len",
    "feat_8_sql_chars",
    "feat_9_xss_chars",
    "feat_10_path_chars",
    "feat_11_bait_route",
    "feat_12_unknown_path",
]


# ══════════════════════════════════════════════════════════════════════════════
# Feature value ranges for each attack type
# These ranges are designed to match exactly what predict.py's
# log_to_features() would produce for each attack type.
# ══════════════════════════════════════════════════════════════════════════════

def make_row(attack_type: str, rng: np.random.Generator) -> list:
    """
    Generate one synthetic feature vector for a given attack type.
    Every value here mirrors what predict.py extracts from a real log.

    feat_0  portal: random 0-3 (all portals are equally targeted)
    feat_1  action_severity: depends on what action the attacker took
    feat_2  attack_type_encoded: directly reflects the attack type
    feat_3  user_agent_score: attackers use tools, benign use browsers
    feat_4  failed_login_count: brute force = many failures
    feat_5  portals_hit: recon = hits many portals
    feat_6  username_len: SQL injection = long usernames
    feat_7  password_len: SQL injection = long passwords
    feat_8  has_sql_chars: 1 for sql_injection, 0 otherwise
    feat_9  has_xss_chars: 1 for xss, 0 otherwise
    feat_10 has_path_chars: 1 for path_traversal, 0 otherwise
    feat_11 is_bait_route: recon hits bait routes
    feat_12 is_unknown_path: recon scans unknown paths
    """

    if attack_type == "benign":
        return [
            float(rng.integers(0, 4)),          # feat_0 any portal
            rng.choice([0.2, 0.3]),              # feat_1 login_success or dashboard
            0.0,                                 # feat_2 attack_type=unknown/benign
            rng.uniform(0.0, 0.15),             # feat_3 normal browser
            rng.uniform(0.0, 0.04),             # feat_4 0-2 failed logins / 50
            rng.uniform(0.25, 0.5),             # feat_5 hits 1-2 portals / 4
            rng.uniform(0.03, 0.10),            # feat_6 short normal username
            rng.uniform(0.06, 0.15),            # feat_7 short normal password
            0.0,                                 # feat_8 no SQL chars
            0.0,                                 # feat_9 no XSS chars
            0.0,                                 # feat_10 no path chars
            0.0,                                 # feat_11 no bait route
            0.0,                                 # feat_12 no unknown path
        ]

    elif attack_type == "sql_injection":
        return [
            float(rng.integers(0, 4)),           # feat_0 any portal
            rng.choice([0.6, 0.6]),              # feat_1 login_failed
            1.0,                                 # feat_2 sql_injection = 1.0
            rng.uniform(0.6, 1.0),              # feat_3 tool or script
            rng.uniform(0.02, 0.20),            # feat_4 1-10 failed logins / 50
            rng.uniform(0.25, 0.5),             # feat_5 1-2 portals
            rng.uniform(0.20, 0.80),            # feat_6 long username with SQL
            rng.uniform(0.10, 0.50),            # feat_7 medium password
            1.0,                                 # feat_8 SQL chars present
            0.0,                                 # feat_9 no XSS
            0.0,                                 # feat_10 no path chars
            0.0,                                 # feat_11 no bait route
            0.0,                                 # feat_12 no unknown path
        ]

    elif attack_type == "xss":
        return [
            float(rng.integers(0, 4)),           # feat_0 any portal
            rng.choice([0.6, 0.6]),              # feat_1 login_failed
            0.85,                                # feat_2 xss = 0.85
            rng.uniform(0.5, 1.0),              # feat_3 tool or script
            rng.uniform(0.02, 0.15),            # feat_4 few failed logins
            rng.uniform(0.25, 0.5),             # feat_5 1-2 portals
            rng.uniform(0.15, 0.70),            # feat_6 medium username with XSS
            rng.uniform(0.05, 0.30),            # feat_7 short password
            0.0,                                 # feat_8 no SQL chars
            1.0,                                 # feat_9 XSS chars present
            0.0,                                 # feat_10 no path chars
            0.0,                                 # feat_11 no bait route
            0.0,                                 # feat_12 no unknown path
        ]

    elif attack_type == "path_traversal":
        return [
            float(rng.integers(0, 4)),           # feat_0 any portal
            rng.choice([0.6, 0.7]),              # feat_1 login_failed or bait
            0.9,                                 # feat_2 path_traversal = 0.9
            rng.uniform(0.5, 1.0),              # feat_3 tool
            rng.uniform(0.0, 0.10),             # feat_4 few failed logins
            rng.uniform(0.25, 0.75),            # feat_5 1-3 portals
            rng.uniform(0.10, 0.60),            # feat_6 medium username with path
            rng.uniform(0.05, 0.20),            # feat_7 short password
            0.0,                                 # feat_8 no SQL
            0.0,                                 # feat_9 no XSS
            1.0,                                 # feat_10 path chars present
            rng.choice([0.0, 1.0]),             # feat_11 may hit bait route
            0.0,                                 # feat_12 no unknown path
        ]

    elif attack_type == "reconnaissance":
        return [
            float(rng.integers(0, 4)),           # feat_0 any portal
            rng.choice([0.7, 0.8, 0.75]),       # feat_1 bait_route or unknown_path
            0.75,                                # feat_2 reconnaissance = 0.75
            rng.uniform(0.6, 1.0),              # feat_3 scanner tool
            rng.uniform(0.0, 0.06),             # feat_4 few failed logins
            rng.uniform(0.5, 1.0),              # feat_5 hits many portals
            rng.uniform(0.0, 0.10),             # feat_6 short username
            rng.uniform(0.0, 0.10),             # feat_7 short password
            0.0,                                 # feat_8 no SQL
            0.0,                                 # feat_9 no XSS
            0.0,                                 # feat_10 no path
            rng.choice([0.0, 1.0, 1.0]),        # feat_11 often hits bait routes
            rng.choice([0.0, 1.0, 1.0]),        # feat_12 often hits unknown paths
        ]

    elif attack_type == "brute_force":
        return [
            float(rng.integers(0, 4)),           # feat_0 any portal
            0.6,                                 # feat_1 login_failed
            0.7,                                 # feat_2 brute_force = 0.7
            rng.uniform(0.6, 1.0),              # feat_3 tool (hydra, curl etc.)
            rng.uniform(0.20, 1.0),             # feat_4 many failed logins
            rng.uniform(0.25, 0.5),             # feat_5 1-2 portals
            rng.uniform(0.03, 0.15),            # feat_6 short username (common ones)
            rng.uniform(0.06, 0.20),            # feat_7 short password (common ones)
            0.0,                                 # feat_8 no SQL
            0.0,                                 # feat_9 no XSS
            0.0,                                 # feat_10 no path
            0.0,                                 # feat_11 no bait route
            0.0,                                 # feat_12 no unknown path
        ]

    # fallback — should never reach here
    return [0.0] * 13


# ══════════════════════════════════════════════════════════════════════════════
# Generate the full dataset
# ══════════════════════════════════════════════════════════════════════════════

def generate(total_rows: int) -> pd.DataFrame:
    """
    Generate total_rows synthetic honeypot log entries.

    Distribution:
        40% benign         — normal employee usage
        20% brute_force    — most common real attack
        15% reconnaissance — scanners and probers
        10% sql_injection
        8%  xss
        7%  path_traversal
    """
    rng = np.random.default_rng(RANDOM_SEED)
    random.seed(RANDOM_SEED)

    counts = {
        "benign"         : int(total_rows * 0.40),
        "brute_force"    : int(total_rows * 0.20),
        "reconnaissance" : int(total_rows * 0.15),
        "sql_injection"  : int(total_rows * 0.10),
        "xss"            : int(total_rows * 0.08),
        "path_traversal" : int(total_rows * 0.07),
    }

    log.info("Generating %d synthetic honeypot log rows ...", total_rows)
    log.info("Distribution: %s", counts)

    rows        = []
    labels      = []
    attack_types = []

    for attack_type, count in counts.items():
        for _ in range(count):
            row = make_row(attack_type, rng)
            # Add small Gaussian noise so rows are not identical
            noisy = [max(0.0, min(1.0 if i > 0 else 3.0, v + rng.normal(0, 0.02)))
                     for i, v in enumerate(row)]
            rows.append(noisy)
            labels.append(LABEL_MAP[attack_type])
            attack_types.append(attack_type)

    df = pd.DataFrame(rows, columns=FEATURE_COLS)
    df["attack_type"] = attack_types
    df["label"]       = labels
    df["source"]      = "synthetic"

    # Shuffle
    df = df.sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)

    log.info("Generated shape: %s", df.shape)
    log.info("Label distribution:\n%s", df["attack_type"].value_counts().to_string())
    return df


# ══════════════════════════════════════════════════════════════════════════════
# Save
# ══════════════════════════════════════════════════════════════════════════════

def save(df: pd.DataFrame) -> None:
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    df.to_csv(OUTPUT_PATH, index=False)
    log.info("Saved training data to: %s", OUTPUT_PATH)
    log.info("Total rows: %d | Total columns: %d", *df.shape)


# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    log.info("=" * 60)
    log.info("generate_data.py  —  Honeypot Training Data Builder")
    log.info("=" * 60)

    df = generate(TOTAL_ROWS)
    save(df)

    log.info("=" * 60)
    log.info("DONE. Run ai_engine/train_model.py next.")
    log.info("=" * 60)


if __name__ == "__main__":
    main()
