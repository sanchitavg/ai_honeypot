"""
ai_engine/generate_data.py
==========================
PURPOSE:
    Prepares the training dataset for the AI model by doing 3 things:
      1. Loads the CICIDS2017 cleaned CSV and maps its attack labels
         to the 5 attack types your honeypot uses.
      2. Generates synthetic honeypot logs that look exactly like what
         your 4 portals produce.
      3. Combines both and saves data/training_data.csv

RUN THIS FILE ONCE before running train_model.py:
    python ai_engine/generate_data.py
"""

import os
import sys
import random
import logging

import numpy  as np
import pandas as pd

# ── Logging setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level  = logging.INFO,
    format = "%(asctime)s  %(levelname)s  %(message)s"
)
log = logging.getLogger(__name__)

# ── Paths ─────────────────────────────────────────────────────────────────────
# __file__ is ai_engine/generate_data.py
# BASE_DIR goes one level up to the project root (ai_honeypot/)
BASE_DIR      = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CICIDS_PATH   = os.path.join(BASE_DIR, "data", "CICIDS2017", "cicids2017_cleaned.csv")
OUTPUT_PATH   = os.path.join(BASE_DIR, "data", "training_data.csv")

# ── Constants ─────────────────────────────────────────────────────────────────
RANDOM_SEED        = 42          # makes results reproducible every run
SYNTHETIC_ROWS     = 5_000       # synthetic honeypot rows to generate
CICIDS_SAMPLE_SIZE = 50_000      # how many CICIDS rows to use (keeps memory low)

# The 5 attack types your honeypot detects + 1 for normal traffic
ATTACK_TYPES = [
    "benign",
    "sql_injection",
    "xss",
    "path_traversal",
    "reconnaissance",
    "brute_force",
]

# Map every CICIDS2017 label → your honeypot's attack_type labels
# The cleaned dataset by Eric Anacleto Ribeiro uses these label values:
CICIDS_LABEL_MAP = {
    "Normal Traffic" : "benign",
    "Port Scanning"  : "reconnaissance",
    "Web Attacks"    : "sql_injection",
    "Brute Force"    : "brute_force",
    "DDoS"           : "brute_force",
    "Bots"           : "reconnaissance",
    "DoS"            : "brute_force",
}

# The numeric feature columns present in the cleaned CICIDS CSV.
# These are standard network-flow features — we pick 15 that are most
# meaningful for detecting the attack types your honeypot sees.
CICIDS_FEATURE_COLS = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Bwd Packet Length Max",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Fwd IAT Mean",
    "Bwd IAT Mean",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Packet Length Mean",
]

# Your 4 honeypot portals
PORTALS = ["supplier", "procurement", "inventory", "shipment"]


# ══════════════════════════════════════════════════════════════════════════════
# PART 1 — Load and clean the CICIDS2017 dataset
# ══════════════════════════════════════════════════════════════════════════════

def load_cicids(path: str, sample_size: int) -> pd.DataFrame:
    """
    Read the CICIDS2017 cleaned CSV, keep only the columns we need,
    map labels to your attack types, and return a tidy dataframe.

    Parameters:
        path        : full path to cicids2017_cleaned.csv
        sample_size : how many rows to load (to save RAM)

    Returns:
        pd.DataFrame with columns: feature_1..feature_N + attack_type + source
    """
    log.info("Loading CICIDS2017 from %s ...", path)

    if not os.path.exists(path):
        log.error("CICIDS file not found at: %s", path)
        log.error("Please place cicids2017_cleaned.csv in data/CICIDS2017/")
        sys.exit(1)

    # Read the full CSV — it is ~700 MB so this may take 20-30 seconds
    df_raw = pd.read_csv(path, low_memory=False)
    log.info("Raw CICIDS shape: %s rows x %s columns", *df_raw.shape)

    # ── Find the label column ─────────────────────────────────────────────────
    # Different versions of the cleaned CSV name it slightly differently
    label_col = None
    for col in df_raw.columns:
        if col.strip().lower() in ("label", "attack type"):
            label_col = col
            break

    if label_col is None:
        log.error("Could not find 'Label' column. Columns found: %s", df_raw.columns.tolist())
        sys.exit(1)

    log.info("Label column found: '%s'", label_col)
    log.info("Unique labels: %s", df_raw[label_col].unique().tolist())

    # ── Keep only the feature columns that exist in this CSV ─────────────────
    # Some cleaned versions rename columns slightly, so we do a fuzzy match
    available_features = []
    for wanted in CICIDS_FEATURE_COLS:
        # exact match first
        if wanted in df_raw.columns:
            available_features.append(wanted)
            continue
        # case-insensitive match
        for col in df_raw.columns:
            if col.strip().lower() == wanted.lower():
                available_features.append(col)
                break

    if len(available_features) < 5:
        log.error("Too few feature columns found (%d). Check CSV column names.", len(available_features))
        log.error("Available columns: %s", df_raw.columns.tolist())
        sys.exit(1)

    log.info("Using %d feature columns: %s", len(available_features), available_features)

    # ── Build clean dataframe ─────────────────────────────────────────────────
    df = df_raw[available_features + [label_col]].copy()
    df.columns = [f"feat_{i}" for i in range(len(available_features))] + ["raw_label"]

    # Map CICIDS labels → your attack types
    df["attack_type"] = df["raw_label"].str.strip().map(CICIDS_LABEL_MAP)

    # Drop rows whose label isn't in our map (rare edge cases)
    unknown_mask = df["attack_type"].isna()
    if unknown_mask.sum() > 0:
        log.warning("Dropping %d rows with unmapped labels", unknown_mask.sum())
    df = df[~unknown_mask].drop(columns=["raw_label"])

    # ── Replace inf / -inf with NaN then drop those rows ─────────────────────
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    before = len(df)
    df.dropna(inplace=True)
    log.info("Dropped %d rows with NaN/inf values", before - len(df))

    # ── Sample to keep memory usage reasonable ────────────────────────────────
    if len(df) > sample_size:
        groups = []
        for attack, group in df.groupby("attack_type"):
            n = max(1, int(sample_size * len(group) / len(df)))
            groups.append(group.sample(min(len(group), n), random_state=RANDOM_SEED))
        df = pd.concat(groups).reset_index(drop=True)
        log.info("Sampled down to %d rows (stratified)", len(df))

    # Tag the source so we know which rows came from CICIDS
    df["source"] = "cicids2017"

    log.info("CICIDS2017 loaded. Shape: %s", df.shape)
    log.info("Attack type distribution:\n%s", df["attack_type"].value_counts().to_string())
    return df.reset_index(drop=True)


# ══════════════════════════════════════════════════════════════════════════════
# PART 2 — Generate synthetic honeypot logs
# ══════════════════════════════════════════════════════════════════════════════

def _make_feature_vector(attack_type: str, n_features: int) -> list:
    """
    Generate one row of realistic-looking numeric features
    for a given attack type.

    Real attackers produce different network traffic patterns:
    - sql_injection : short bursts, small payloads, fast
    - xss           : medium bursts, slightly larger payloads
    - brute_force   : many packets, high frequency, low payload size
    - reconnaissance: very many packets, tiny payloads, very fast
    - path_traversal: few packets, medium payload
    - benign        : normal spread, moderate everything
    """
    rng = np.random.default_rng()   # fresh RNG each call for variety

    profiles = {
        "benign": dict(
            duration   = rng.uniform(1_000, 500_000),
            fwd_pkts   = rng.integers(5, 200),
            bwd_pkts   = rng.integers(5, 150),
            fwd_len    = rng.uniform(200, 5_000),
            bwd_len    = rng.uniform(200, 5_000),
            pkt_mean   = rng.uniform(100, 800),
            flow_bps   = rng.uniform(1_000, 100_000),
            flow_pps   = rng.uniform(1, 500),
        ),
        "sql_injection": dict(
            duration   = rng.uniform(500, 50_000),
            fwd_pkts   = rng.integers(2, 30),
            bwd_pkts   = rng.integers(1, 20),
            fwd_len    = rng.uniform(500, 3_000),   # larger — payload has SQL
            bwd_len    = rng.uniform(100, 1_000),
            pkt_mean   = rng.uniform(200, 1_200),
            flow_bps   = rng.uniform(5_000, 200_000),
            flow_pps   = rng.uniform(5, 100),
        ),
        "xss": dict(
            duration   = rng.uniform(500, 40_000),
            fwd_pkts   = rng.integers(2, 25),
            bwd_pkts   = rng.integers(1, 20),
            fwd_len    = rng.uniform(400, 2_500),
            bwd_len    = rng.uniform(100, 800),
            pkt_mean   = rng.uniform(150, 900),
            flow_bps   = rng.uniform(4_000, 180_000),
            flow_pps   = rng.uniform(5, 80),
        ),
        "path_traversal": dict(
            duration   = rng.uniform(300, 30_000),
            fwd_pkts   = rng.integers(1, 15),
            bwd_pkts   = rng.integers(1, 10),
            fwd_len    = rng.uniform(100, 800),
            bwd_len    = rng.uniform(50, 400),
            pkt_mean   = rng.uniform(80, 500),
            flow_bps   = rng.uniform(2_000, 80_000),
            flow_pps   = rng.uniform(2, 50),
        ),
        "reconnaissance": dict(
            duration   = rng.uniform(100, 10_000),   # short — just probing
            fwd_pkts   = rng.integers(50, 500),      # many packets
            bwd_pkts   = rng.integers(50, 500),
            fwd_len    = rng.uniform(40, 200),        # tiny payloads
            bwd_len    = rng.uniform(40, 200),
            pkt_mean   = rng.uniform(40, 150),
            flow_bps   = rng.uniform(50_000, 500_000),  # very fast
            flow_pps   = rng.uniform(200, 2_000),
        ),
        "brute_force": dict(
            duration   = rng.uniform(1_000, 100_000),
            fwd_pkts   = rng.integers(100, 1_000),   # lots of attempts
            bwd_pkts   = rng.integers(80, 900),
            fwd_len    = rng.uniform(100, 500),
            bwd_len    = rng.uniform(100, 400),
            pkt_mean   = rng.uniform(80, 400),
            flow_bps   = rng.uniform(20_000, 300_000),
            flow_pps   = rng.uniform(100, 1_500),
        ),
    }

    p = profiles.get(attack_type, profiles["benign"])

    # Build a feature vector with the same number of features as CICIDS
    # We cycle through our profile values to fill all n_features slots,
    # adding small random noise so no two rows are identical
    base_values = [
        p["duration"],
        p["fwd_pkts"],
        p["bwd_pkts"],
        p["fwd_len"],
        p["bwd_len"],
        p["fwd_len"] * rng.uniform(0.5, 1.5),   # fwd max
        p["bwd_len"] * rng.uniform(0.5, 1.5),   # bwd max
        p["flow_bps"],
        p["flow_pps"],
        p["duration"] / max(p["fwd_pkts"] + p["bwd_pkts"], 1),  # IAT mean
        p["duration"] / max(p["fwd_pkts"], 1),                   # fwd IAT
        p["duration"] / max(p["bwd_pkts"], 1),                   # bwd IAT
        p["flow_pps"] * rng.uniform(0.4, 0.8),  # fwd pps
        p["flow_pps"] * rng.uniform(0.2, 0.6),  # bwd pps
        p["pkt_mean"],
    ]

    # If CICIDS had more or fewer features, pad / trim to match
    if len(base_values) < n_features:
        extra = [v * rng.uniform(0.8, 1.2) for v in base_values]
        base_values = (base_values + extra * 10)[:n_features]
    else:
        base_values = base_values[:n_features]

    # Add small Gaussian noise so the synthetic rows aren't too uniform
    noise  = rng.normal(0, 0.05, size=len(base_values))
    result = [max(0.0, v * (1 + n)) for v, n in zip(base_values, noise)]
    return result


def generate_synthetic(n_rows: int, n_features: int) -> pd.DataFrame:
    """
    Generate n_rows of synthetic honeypot traffic.

    The distribution is:
        50% benign  (normal employees using the portals)
        50% attacks (split across 5 attack types)

    Parameters:
        n_rows     : total number of synthetic rows to create
        n_features : must match the number of feature columns in CICIDS

    Returns:
        pd.DataFrame with same column structure as load_cicids()
    """
    log.info("Generating %d synthetic honeypot rows ...", n_rows)

    random.seed(RANDOM_SEED)
    np.random.seed(RANDOM_SEED)

    # How many rows per attack type
    # 50% benign, 10% each for 5 attack types
    counts = {
        "benign"        : int(n_rows * 0.50),
        "sql_injection" : int(n_rows * 0.10),
        "xss"           : int(n_rows * 0.10),
        "path_traversal": int(n_rows * 0.10),
        "reconnaissance": int(n_rows * 0.10),
        "brute_force"   : int(n_rows * 0.10),
    }

    rows = []
    for attack_type, count in counts.items():
        for _ in range(count):
            features = _make_feature_vector(attack_type, n_features)
            rows.append(features + [attack_type])

    # Column names must match what load_cicids() produces
    feat_cols = [f"feat_{i}" for i in range(n_features)]
    df = pd.DataFrame(rows, columns=feat_cols + ["attack_type"])

    # Shuffle so attack types aren't grouped together
    df = df.sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)

    df["source"] = "synthetic"

    log.info("Synthetic data generated. Shape: %s", df.shape)
    log.info("Distribution:\n%s", df["attack_type"].value_counts().to_string())
    return df


# ══════════════════════════════════════════════════════════════════════════════
# PART 3 — Combine and save
# ══════════════════════════════════════════════════════════════════════════════

def combine_and_save(df_cicids: pd.DataFrame, df_synthetic: pd.DataFrame) -> None:
    """
    Stack both dataframes, shuffle, and save to data/training_data.csv

    Parameters:
        df_cicids    : output of load_cicids()
        df_synthetic : output of generate_synthetic()
    """
    log.info("Combining CICIDS2017 + synthetic data ...")

    # Both dataframes must have the same columns — verify
    cicids_feat_cols    = [c for c in df_cicids.columns    if c.startswith("feat_")]
    synthetic_feat_cols = [c for c in df_synthetic.columns if c.startswith("feat_")]

    if len(cicids_feat_cols) != len(synthetic_feat_cols):
        log.error(
            "Feature column count mismatch: CICIDS=%d, synthetic=%d",
            len(cicids_feat_cols), len(synthetic_feat_cols)
        )
        sys.exit(1)

    # Stack vertically
    df_combined = pd.concat([df_cicids, df_synthetic], ignore_index=True)

    # Shuffle the whole thing one more time
    df_combined = df_combined.sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)

    log.info("Combined shape: %s", df_combined.shape)
    log.info("Final attack_type distribution:\n%s",
             df_combined["attack_type"].value_counts().to_string())

    # Encode attack_type as an integer label for sklearn
    # benign=0, brute_force=1, path_traversal=2, reconnaissance=3,
    # sql_injection=4, xss=5  (alphabetical)
    label_map = {a: i for i, a in enumerate(sorted(ATTACK_TYPES))}
    df_combined["label"] = df_combined["attack_type"].map(label_map)

    log.info("Label encoding: %s", label_map)

    # Save
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    df_combined.to_csv(OUTPUT_PATH, index=False)
    log.info("Saved training data to: %s", OUTPUT_PATH)
    log.info("Total rows: %d | Total columns: %d", *df_combined.shape)


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    log.info("=" * 60)
    log.info("generate_data.py  —  AI Honeypot Training Data Builder")
    log.info("=" * 60)

    # Step 1: Load CICIDS
    df_cicids = load_cicids(CICIDS_PATH, CICIDS_SAMPLE_SIZE)

    # Step 2: Generate synthetic data
    # n_features must match CICIDS so both dataframes align
    n_features   = len([c for c in df_cicids.columns if c.startswith("feat_")])
    df_synthetic = generate_synthetic(SYNTHETIC_ROWS, n_features)

    # Step 3: Combine and save
    combine_and_save(df_cicids, df_synthetic)

    log.info("=" * 60)
    log.info("DONE. Run ai_engine/train_model.py next.")
    log.info("=" * 60)


if __name__ == "__main__":
    main()
