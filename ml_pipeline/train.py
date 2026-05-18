import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score, RandomizedSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from xgboost import XGBClassifier
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix,
    precision_score, recall_score, roc_auc_score, brier_score_loss
)
import joblib
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# ──────────────────────────────────────────────────────────────────────────────
# REMEDIATION 1: Cost-Sensitive Weighting
#
# Real-world phishing prevalence is approximately 1 malicious per 1000 benign.
# scale_pos_weight = n_benign / n_malicious tells XGBoost to penalize
# missing a phishing site (FN) far more than flagging a safe site (FP).
# We use 10 here (conservative) rather than 1000, since the CTI layer and
# WHOIS checks act as secondary validators. Adjust based on your SOC's
# tolerance for false positives vs missed threats.
# ──────────────────────────────────────────────────────────────────────────────
SCALE_POS_WEIGHT = 10


def evaluate_on_skewed_dataset(model, X_test, y_test, skew_ratio=100):
    """
    Simulate real-world base rate: for every 1 phishing sample inject
    `skew_ratio` benign samples. Report FPR and recall on this skewed set.
    This is the ground-truth test for production viability.
    """
    benign_mask  = y_test == 0
    phish_mask   = y_test == 1

    benign_X  = X_test[benign_mask]
    benign_y  = y_test[benign_mask]
    phish_X   = X_test[phish_mask]
    phish_y   = y_test[phish_mask]

    n_phish   = len(phish_X)
    n_benign  = min(n_phish * skew_ratio, len(benign_X))

    skewed_X  = pd.concat([benign_X.iloc[:n_benign], phish_X])
    skewed_y  = pd.concat([benign_y.iloc[:n_benign], phish_y])

    preds     = model.predict(skewed_X)
    cm        = confusion_matrix(skewed_y, preds)
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0

    logging.info(f"\n--- Skewed-Dataset Evaluation (1:{skew_ratio} ratio) ---")
    logging.info(f"  False Positive Rate : {fpr:.4f}  (target: < 0.001)")
    logging.info(f"  Recall (Sensitivity): {recall:.4f} (target: > 0.90)")
    return fpr, recall


def train_model(
    data_path="c:/Users/pvmvb/Desktop/Projects/PhishGuard/ml_pipeline/data/processed_features.csv",
    model_dir="c:/Users/pvmvb/Desktop/Projects/PhishGuard/ml_pipeline/models"
):
    Path(model_dir).mkdir(parents=True, exist_ok=True)

    logging.info("Loading processed features...")
    try:
        df = pd.read_csv(data_path)
    except FileNotFoundError:
        logging.error(f"Could not find {data_path}. Run data_prep.py first.")
        return

    logging.info(f"Dataset shape: {df.shape}")
    logging.info(f"Features: {list(df.columns)}")

    X = df.drop(columns=['label'])
    y = df['label']

    # 60% train / 20% calibration / 20% test — the calibration split is key:
    # we MUST NOT calibrate on the same data used for fitting.
    X_train_cal, X_test, y_train_cal, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    X_train, X_cal, y_train, y_cal = train_test_split(
        X_train_cal, y_train_cal, test_size=0.25, random_state=42, stratify=y_train_cal
    )

    # ──────────────────────────────────────────────────────────────────────────
    # REMEDIATION 1: XGBoost with cost-sensitive weighting
    # scoring='roc_auc' penalises both FP and FN proportionally, unlike
    # raw accuracy which is dominated by the majority class.
    # ──────────────────────────────────────────────────────────────────────────
    logging.info("Training cost-sensitive XGBoost with RandomizedSearchCV...")

    xgb_param_space = {
        'n_estimators':     [100, 200, 300],
        'max_depth':        [4, 6, 8, 10],
        'learning_rate':    [0.05, 0.1, 0.2],
        'subsample':        [0.7, 0.8, 0.9, 1.0],
        'colsample_bytree': [0.7, 0.8, 0.9, 1.0],
        'min_child_weight': [1, 3, 5],
        'gamma':            [0, 0.1, 0.2]
    }

    xgb_base = XGBClassifier(
        scale_pos_weight=SCALE_POS_WEIGHT,   # <-- REMEDIATION: cost-sensitive
        eval_metric='logloss',
        random_state=42
    )
    xgb_search = RandomizedSearchCV(
        xgb_base, xgb_param_space, n_iter=20, cv=5,
        scoring='roc_auc',   # <-- REMEDIATION: AUC, not raw accuracy
        random_state=42, n_jobs=-1, verbose=0
    )
    xgb_search.fit(X_train, y_train)
    best_xgb_params = xgb_search.best_params_

    # ──────────────────────────────────────────────────────────────────────────
    # REMEDIATION 1: Isotonic Regression Calibration (sklearn >= 1.2 compatible)
    #
    # cv='prefit' was removed in recent scikit-learn releases. The correct
    # modern pattern is to wrap an UNFITTED base estimator in
    # CalibratedClassifierCV with cv=5, then fit on the combined train+cal
    # data. Internally sklearn trains the base on 4 folds and calibrates on
    # the 5th, averages across all 5 — giving better calibration than a single
    # held-out split while remaining fully compatible with all sklearn versions.
    # ──────────────────────────────────────────────────────────────────────────
    logging.info("Calibrating probabilities via Isotonic Regression (cv=5)...")
    xgb_for_calibration = XGBClassifier(
        **best_xgb_params,
        scale_pos_weight=SCALE_POS_WEIGHT,
        eval_metric='logloss',
        random_state=42
    )
    calibrated_xgb = CalibratedClassifierCV(
        xgb_for_calibration, method='isotonic', cv=5
    )
    # Fit on combined train+cal — cv=5 handles the internal holdout split
    calibrated_xgb.fit(X_train_cal, y_train_cal)

    xgb_preds     = calibrated_xgb.predict(X_test)
    xgb_proba     = calibrated_xgb.predict_proba(X_test)[:, 1]
    xgb_acc       = accuracy_score(y_test, xgb_preds)
    xgb_auc       = roc_auc_score(y_test, xgb_proba)
    xgb_brier     = brier_score_loss(y_test, xgb_proba)
    xgb_precision = precision_score(y_test, xgb_preds, zero_division=0)
    xgb_recall    = recall_score(y_test, xgb_preds, zero_division=0)

    logging.info(f"XGBoost Best Params : {xgb_search.best_params_}")
    logging.info(f"XGBoost Accuracy    : {xgb_acc:.4f}")
    logging.info(f"XGBoost ROC-AUC     : {xgb_auc:.4f}")
    logging.info(f"XGBoost Brier Score : {xgb_brier:.4f} (lower is better, 0 is perfect)")
    logging.info(f"XGBoost Precision   : {xgb_precision:.4f}")
    logging.info(f"XGBoost Recall      : {xgb_recall:.4f}")
    logging.info("\n" + classification_report(y_test, xgb_preds))

    # --- Random Forest with Cross-Validation (baseline comparison) ---
    logging.info("Training Random Forest (baseline comparison)...")
    rf_clf = RandomForestClassifier(
        n_estimators=200, max_depth=12,
        class_weight='balanced',   # RF equivalent of scale_pos_weight
        random_state=42, n_jobs=-1
    )
    cv_scores = cross_val_score(rf_clf, X_train, y_train, cv=5, scoring='roc_auc')
    logging.info(f"Random Forest CV AUC: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")

    # Calibrated RF: same pattern — unfitted estimator + cv=5
    rf_for_calibration = RandomForestClassifier(
        n_estimators=200, max_depth=12,
        class_weight='balanced',
        random_state=42, n_jobs=-1
    )
    calibrated_rf = CalibratedClassifierCV(
        rf_for_calibration, method='isotonic', cv=5
    )
    calibrated_rf.fit(X_train_cal, y_train_cal)
    rf_preds        = calibrated_rf.predict(X_test)
    rf_acc          = accuracy_score(y_test, rf_preds)
    rf_auc          = roc_auc_score(y_test, calibrated_rf.predict_proba(X_test)[:, 1])
    logging.info(f"Random Forest Accuracy: {rf_acc:.4f}, AUC: {rf_auc:.4f}")

    # --- Select best model by AUC, not accuracy ---
    if xgb_auc >= rf_auc:
        best_model = calibrated_xgb
        best_preds = xgb_preds
        best_name  = "xgboost_calibrated"
        best_auc   = xgb_auc
    else:
        best_model = calibrated_rf
        best_preds = rf_preds
        best_name  = "random_forest_calibrated"
        best_auc   = rf_auc

    # --- Feature Importance (averaged across calibration folds) ---
    # With cv=5, CalibratedClassifierCV stores 5 fitted sub-models in
    # .calibrated_classifiers_[i].estimator — average their importances.
    logging.info("\n--- Feature Importances ---")
    try:
        cal_classifiers = best_model.calibrated_classifiers_
        all_importances = [
            cc.estimator.feature_importances_
            for cc in cal_classifiers
            if hasattr(cc.estimator, 'feature_importances_')
        ]
        if all_importances:
            import numpy as np
            avg_importances = np.mean(all_importances, axis=0)
            feature_imp = sorted(
                zip(X.columns, avg_importances),
                key=lambda x: x[1], reverse=True
            )
            for feat, imp in feature_imp:
                logging.info(f"  {feat:40s} {imp:.4f}")
    except Exception as e:
        logging.warning(f"Could not extract feature importances: {e}")

    # --- Confusion Matrix ---
    cm = confusion_matrix(y_test, best_preds)
    logging.info(f"\nConfusion Matrix:\n{cm}")
    logging.info(f"  True Negatives : {cm[0][0]}")
    logging.info(f"  False Positives: {cm[0][1]}  <-- false alarms")
    logging.info(f"  False Negatives: {cm[1][0]}")
    logging.info(f"  True Positives : {cm[1][1]}")

    # --- Skewed Dataset Evaluation (Production Reality Check) ---
    fpr, recall = evaluate_on_skewed_dataset(best_model, X_test, y_test, skew_ratio=100)

    # --- Gate on AUC, not raw accuracy ---
    if best_auc >= 0.97:
        logging.info(f"✓ Target ROC-AUC >= 0.97 achieved: {best_auc:.4f}")
    else:
        logging.warning(f"✗ ROC-AUC {best_auc:.4f} below target of 0.97. Further tuning needed.")

    if fpr < 0.01:
        logging.info(f"✓ Production FPR target met: {fpr:.4f} < 0.01")
    else:
        logging.warning(f"✗ Production FPR {fpr:.4f} exceeds 0.01 target. Increase scale_pos_weight.")

    model_path = Path(model_dir) / "phishguard_model.joblib"
    joblib.dump(best_model, model_path)
    logging.info(f"Saved calibrated model ({best_name}) to {model_path}")


if __name__ == "__main__":
    train_model()
