"""
ai_engine/train_model.py
========================
PURPOSE:
    Reads data/training_data.csv (built by generate_data.py) and trains
    two AI models:

      1. Random Forest    — classifies known attack types
      2. Isolation Forest — detects unknown / zero-day anomalies

    Saves 3 files into models/:
        models/random_forest.pkl
        models/isolation_forest.pkl
        models/scaler.pkl

RUN:
    python ai_engine/train_model.py
"""

import os
import sys
import logging
import pickle

import numpy  as np
import pandas as pd

from sklearn.ensemble        import RandomForestClassifier, IsolationForest
from sklearn.preprocessing   import StandardScaler
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics         import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    roc_auc_score,
)

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level  = logging.INFO,
    format = "%(asctime)s  %(levelname)s  %(message)s"
)
log = logging.getLogger(__name__)

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR        = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRAINING_DATA   = os.path.join(BASE_DIR, "data",   "training_data.csv")
MODELS_DIR      = os.path.join(BASE_DIR, "models")
RF_PATH         = os.path.join(MODELS_DIR, "random_forest.pkl")
IF_PATH         = os.path.join(MODELS_DIR, "isolation_forest.pkl")
SCALER_PATH     = os.path.join(MODELS_DIR, "scaler.pkl")

# ── Reproducibility ───────────────────────────────────────────────────────────
RANDOM_SEED = 42

# Label encoding (must match generate_data.py)
# benign=0, brute_force=1, path_traversal=2, reconnaissance=3,
# sql_injection=4, xss=5
LABEL_NAMES = {
    0: "benign",
    1: "brute_force",
    2: "path_traversal",
    3: "reconnaissance",
    4: "sql_injection",
    5: "xss",
}


# ══════════════════════════════════════════════════════════════════════════════
# STEP 1 — Load and prepare the training data
# ══════════════════════════════════════════════════════════════════════════════

def load_data(path: str):
    """
    Read training_data.csv, separate features from labels,
    and return X (features) and y (labels).

    Returns:
        X : numpy array of shape (n_samples, n_features)
        y : numpy array of shape (n_samples,)  — integer labels
        feature_cols : list of feature column names
    """
    log.info("Loading training data from %s ...", path)

    if not os.path.exists(path):
        log.error("training_data.csv not found. Run generate_data.py first.")
        sys.exit(1)

    df = pd.read_csv(path)
    log.info("Loaded shape: %s rows x %s columns", *df.shape)

    # Feature columns are all columns starting with "feat_"
    feature_cols = [c for c in df.columns if c.startswith("feat_")]

    if not feature_cols:
        log.error("No feature columns found. Check generate_data.py output.")
        sys.exit(1)

    if "label" not in df.columns:
        log.error("No 'label' column found. Check generate_data.py output.")
        sys.exit(1)

    X = df[feature_cols].values   # shape: (55000, 13)
    y = df["label"].values         # shape: (55000,)

    log.info("Features: %d columns", len(feature_cols))
    log.info("Label distribution:\n%s",
             df["attack_type"].value_counts().to_string() if "attack_type" in df.columns else "N/A")

    return X, y, feature_cols


# ══════════════════════════════════════════════════════════════════════════════
# STEP 2 — Scale the features
# ══════════════════════════════════════════════════════════════════════════════

def scale_features(X_train: np.ndarray, X_test: np.ndarray):
    """
    Fit a StandardScaler on the training data and transform both
    training and test sets.

    WHY SCALING?
    Features like 'Flow Duration' can be 500,000 while 'Total Fwd Packets'
    might be 5. Without scaling, the big numbers dominate and the model
    ignores the small ones. Scaling brings everything to the same range.

    The scaler is fitted ONLY on X_train — never on X_test — to prevent
    data leakage (the model should not peek at test data during training).

    Returns:
        X_train_scaled, X_test_scaled, scaler
    """
    log.info("Scaling features with StandardScaler ...")
    scaler        = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)   # fit + transform train
    X_test_scaled  = scaler.transform(X_test)         # transform only (no fit)
    log.info("Scaling done.")
    return X_train_scaled, X_test_scaled, scaler


# ══════════════════════════════════════════════════════════════════════════════
# STEP 3 — Train the Random Forest
# ══════════════════════════════════════════════════════════════════════════════

def train_random_forest(X_train: np.ndarray, y_train: np.ndarray) -> RandomForestClassifier:
    """
    Train a Random Forest classifier.

    WHAT IS RANDOM FOREST?
    It builds 200 decision trees, each trained on a random subset of the data.
    Every tree votes on what attack type a sample is. The majority vote wins.
    200 trees gives much better accuracy than a single tree, and is less
    likely to overfit (memorise the training data).

    Parameters:
        n_estimators  = 200   → number of trees
        max_depth     = 20    → how deep each tree can grow
        class_weight  = balanced → treats rare classes (xss, path_traversal)
                                   with more importance so they aren't ignored
        n_jobs        = -1    → use all CPU cores for speed
        random_state  = 42    → reproducible results

    Returns:
        Trained RandomForestClassifier
    """
    log.info("Training Random Forest (200 trees) ...")

    rf = RandomForestClassifier(
        n_estimators  = 200,
        max_depth     = 20,
        min_samples_split = 5,
        min_samples_leaf  = 2,
        class_weight  = "balanced",
        n_jobs        = -1,
        random_state  = RANDOM_SEED,
    )
    rf.fit(X_train, y_train)
    log.info("Random Forest training complete.")
    return rf


# ══════════════════════════════════════════════════════════════════════════════
# STEP 4 — Evaluate the Random Forest
# ══════════════════════════════════════════════════════════════════════════════

def evaluate_random_forest(
    rf: RandomForestClassifier,
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test:  np.ndarray,
    y_test:  np.ndarray,
) -> None:
    """
    Print accuracy, classification report, and 5-fold cross-validation score.

    WHAT THESE NUMBERS MEAN:
    - Accuracy    : % of predictions that were correct overall
    - Precision   : of all times we said "sql_injection", how many were right?
    - Recall      : of all actual sql_injection attacks, how many did we catch?
    - F1-score    : harmonic mean of precision and recall — the main metric
    - Cross-val   : we split data into 5 parts, train on 4, test on 1,
                    repeat 5 times — gives a reliable estimate of real accuracy
    """
    log.info("Evaluating Random Forest ...")

    y_pred = rf.predict(X_test)

    accuracy = accuracy_score(y_test, y_pred)
    log.info("Test Accuracy: %.4f (%.2f%%)", accuracy, accuracy * 100)

    log.info("Classification Report:\n%s",
             classification_report(
                 y_test, y_pred,
                 target_names=[LABEL_NAMES[i] for i in sorted(LABEL_NAMES)],
                 zero_division=0
             ))

    log.info("Confusion Matrix:\n%s", confusion_matrix(y_test, y_pred))

    # 5-fold cross validation on training data
    log.info("Running 5-fold cross-validation (this takes ~30 seconds) ...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_SEED)
    cv_scores = cross_val_score(rf, X_train, y_train, cv=cv, scoring="f1_weighted", n_jobs=-1)
    log.info("Cross-val F1 scores: %s", [f"{s:.4f}" for s in cv_scores])
    log.info("Mean CV F1: %.4f ± %.4f", cv_scores.mean(), cv_scores.std())

    # Feature importance — which features matter most
    feature_importance = rf.feature_importances_
    top_indices = np.argsort(feature_importance)[::-1][:5]
    log.info("Top 5 most important features (by index): %s",
             [(f"feat_{i}", f"{feature_importance[i]:.4f}") for i in top_indices])


# ══════════════════════════════════════════════════════════════════════════════
# STEP 5 — Train the Isolation Forest
# ══════════════════════════════════════════════════════════════════════════════

def train_isolation_forest(X_train: np.ndarray, y_train: np.ndarray) -> IsolationForest:
    """
    Train an Isolation Forest for anomaly detection.

    WHAT IS ISOLATION FOREST?
    Unlike Random Forest, this model is NOT told what the labels are.
    It learns what NORMAL traffic looks like.
    When a new sample comes in that looks unusual, it gets a low anomaly
    score — flagged as suspicious even if it's a brand new attack type
    we've never seen before.

    We train it ONLY on benign samples (label=0) so it learns the
    shape of normal traffic perfectly.

    contamination = 0.05 means "expect ~5% of new traffic to be anomalous"

    Returns:
        Trained IsolationForest
    """
    log.info("Training Isolation Forest (anomaly detector) ...")

    # Train only on normal/benign traffic
    X_benign = X_train[y_train == 0]
    log.info("Isolation Forest training on %d benign samples only.", len(X_benign))

    iso = IsolationForest(
        n_estimators  = 200,
        contamination = 0.05,   # expect 5% anomalies in live traffic
        max_samples   = "auto",
        n_jobs        = -1,
        random_state  = RANDOM_SEED,
    )
    iso.fit(X_benign)
    log.info("Isolation Forest training complete.")
    return iso


# ══════════════════════════════════════════════════════════════════════════════
# STEP 6 — Evaluate the Isolation Forest
# ══════════════════════════════════════════════════════════════════════════════

def evaluate_isolation_forest(
    iso:    IsolationForest,
    X_test: np.ndarray,
    y_test: np.ndarray,
) -> None:
    """
    Evaluate the Isolation Forest.

    Isolation Forest returns:
         1 = normal (inlier)
        -1 = anomaly (outlier)

    We convert this to:
         0 = normal
         1 = anomaly (any non-benign label)

    Then we measure how well it detects attacks vs normal traffic.
    """
    log.info("Evaluating Isolation Forest ...")

    # Predict: 1 = normal, -1 = anomaly
    iso_preds_raw = iso.predict(X_test)

    # Convert to binary: 0 = normal, 1 = anomaly
    iso_preds = np.where(iso_preds_raw == -1, 1, 0)

    # Ground truth binary: 0 = benign, 1 = any attack
    y_binary = np.where(y_test == 0, 0, 1)

    log.info("Isolation Forest — Anomaly Detection Report:\n%s",
             classification_report(
                 y_binary, iso_preds,
                 target_names=["normal", "anomaly"],
                 zero_division=0
             ))

    # Anomaly scores (lower = more anomalous)
    scores = iso.decision_function(X_test)
    log.info("Anomaly score range: min=%.4f, max=%.4f, mean=%.4f",
             scores.min(), scores.max(), scores.mean())


# ══════════════════════════════════════════════════════════════════════════════
# STEP 7 — Save models to disk
# ══════════════════════════════════════════════════════════════════════════════

def save_models(
    rf:     RandomForestClassifier,
    iso:    IsolationForest,
    scaler: StandardScaler,
) -> None:
    """
    Save all 3 objects to the models/ directory using pickle.

    WHAT IS PICKLE?
    Python's built-in way of saving any object to a file.
    We can load these .pkl files later in predict.py without
    retraining — training takes minutes, prediction takes milliseconds.
    """
    os.makedirs(MODELS_DIR, exist_ok=True)

    with open(RF_PATH,     "wb") as f: pickle.dump(rf,     f)
    with open(IF_PATH,     "wb") as f: pickle.dump(iso,    f)
    with open(SCALER_PATH, "wb") as f: pickle.dump(scaler, f)

    log.info("Saved: %s", RF_PATH)
    log.info("Saved: %s", IF_PATH)
    log.info("Saved: %s", SCALER_PATH)


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    log.info("=" * 60)
    log.info("train_model.py  —  AI Honeypot Model Trainer")
    log.info("=" * 60)

    # Step 1: Load data
    X, y, feature_cols = load_data(TRAINING_DATA)

    # Step 2: Split into train (80%) and test (20%)
    # stratify=y ensures both splits have the same class distribution
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size    = 0.20,
        random_state = RANDOM_SEED,
        stratify     = y,
    )
    log.info("Train size: %d | Test size: %d", len(X_train), len(X_test))

    # Step 3: Scale
    X_train_scaled, X_test_scaled, scaler = scale_features(X_train, X_test)

    # Step 4: Train Random Forest
    rf = train_random_forest(X_train_scaled, y_train)

    # Step 5: Evaluate Random Forest
    evaluate_random_forest(rf, X_train_scaled, y_train, X_test_scaled, y_test)

    # Step 6: Train Isolation Forest
    iso = train_isolation_forest(X_train_scaled, y_train)

    # Step 7: Evaluate Isolation Forest
    evaluate_isolation_forest(iso, X_test_scaled, y_test)

    # Step 8: Save everything
    save_models(rf, iso, scaler)

    log.info("=" * 60)
    log.info("DONE. All models saved to models/")
    log.info("Run ai_engine/predict.py next.")
    log.info("=" * 60)


if __name__ == "__main__":
    main()
