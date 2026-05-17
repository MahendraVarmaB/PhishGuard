import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score, RandomizedSearchCV
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def train_model(data_path="c:/Users/pvmvb/Desktop/Projects/PhishGuard/ml_pipeline/data/processed_features.csv", 
                model_dir="c:/Users/pvmvb/Desktop/Projects/PhishGuard/ml_pipeline/models"):
    
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
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # --- XGBoost with Hyperparameter Tuning ---
    logging.info("Training XGBoost with RandomizedSearchCV (hyperparameter tuning)...")
    
    xgb_param_space = {
        'n_estimators': [100, 200, 300],
        'max_depth': [4, 6, 8, 10],
        'learning_rate': [0.05, 0.1, 0.2],
        'subsample': [0.7, 0.8, 0.9, 1.0],
        'colsample_bytree': [0.7, 0.8, 0.9, 1.0],
        'min_child_weight': [1, 3, 5],
        'gamma': [0, 0.1, 0.2]
    }
    
    xgb_base = XGBClassifier(eval_metric='logloss', random_state=42)
    xgb_search = RandomizedSearchCV(
        xgb_base, xgb_param_space, n_iter=20, cv=5,
        scoring='accuracy', random_state=42, n_jobs=-1, verbose=0
    )
    xgb_search.fit(X_train, y_train)
    xgb_clf = xgb_search.best_estimator_
    
    xgb_preds = xgb_clf.predict(X_test)
    xgb_acc = accuracy_score(y_test, xgb_preds)
    
    logging.info(f"XGBoost Best Params: {xgb_search.best_params_}")
    logging.info(f"XGBoost Accuracy: {xgb_acc:.4f}")
    logging.info(f"XGBoost CV Score: {xgb_search.best_score_:.4f}")
    logging.info("\n" + classification_report(y_test, xgb_preds))
    
    # --- Random Forest with Cross-Validation ---
    logging.info("Training Random Forest with 5-fold Cross-Validation...")
    rf_clf = RandomForestClassifier(n_estimators=200, max_depth=12, random_state=42, n_jobs=-1)
    
    cv_scores = cross_val_score(rf_clf, X_train, y_train, cv=5, scoring='accuracy')
    logging.info(f"Random Forest CV Scores: {cv_scores}")
    logging.info(f"Random Forest CV Mean: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
    
    rf_clf.fit(X_train, y_train)
    rf_preds = rf_clf.predict(X_test)
    rf_acc = accuracy_score(y_test, rf_preds)
    
    logging.info(f"Random Forest Test Accuracy: {rf_acc:.4f}")
    
    # --- Feature Importance Analysis ---
    logging.info("\n--- Feature Importances (Top Model) ---")
    best_model = xgb_clf if xgb_acc >= rf_acc else rf_clf
    best_name = "xgboost" if xgb_acc >= rf_acc else "random_forest"
    
    importances = best_model.feature_importances_
    feature_imp = sorted(zip(X.columns, importances), key=lambda x: x[1], reverse=True)
    for feat, imp in feature_imp:
        logging.info(f"  {feat:35s} {imp:.4f}")
    
    # --- Confusion Matrix ---
    best_preds = xgb_preds if xgb_acc >= rf_acc else rf_preds
    cm = confusion_matrix(y_test, best_preds)
    logging.info(f"\nConfusion Matrix:\n{cm}")
    logging.info(f"  True Negatives:  {cm[0][0]}")
    logging.info(f"  False Positives: {cm[0][1]} <-- These are the false alarms we want to minimize")
    logging.info(f"  False Negatives: {cm[1][0]}")
    logging.info(f"  True Positives:  {cm[1][1]}")
    
    if max(xgb_acc, rf_acc) >= 0.95:
        logging.info("Target metric of >= 95% accuracy achieved!")
    else:
        logging.warning("Target metric of 95% not reached. Further tuning needed.")
        
    model_path = Path(model_dir) / "phishguard_model.joblib"
    joblib.dump(best_model, model_path)
    logging.info(f"Saved best model ({best_name}) to {model_path}")

if __name__ == "__main__":
    train_model()
