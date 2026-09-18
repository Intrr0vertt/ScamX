"""
Train Logistic Regression (baseline) and Random Forest classifiers
on the Credit Card Fraud Detection dataset.

Methodology:
  1. Split: 70% train / 15% validation / 15% test (stratified)
  2. Fit preprocessing on training data only
  3. Train both models on training data
  4. Evaluate both models on the VALIDATION set
  5. Select the best model by PR-AUC on validation
  6. Evaluate the selected model exactly once on the untouched TEST set
  7. Save all artifacts

The test set never influences model selection.

Usage (from project root):
    python backend/ml/train_model.py
"""
import os
import sys
import json
import time
import platform
import logging

import numpy as np
import joblib
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    precision_score, recall_score, f1_score,
    average_precision_score, confusion_matrix, accuracy_score,
)

# Allow execution from project root
_DIR = os.path.dirname(os.path.abspath(__file__))
if _DIR not in sys.path:
    sys.path.insert(0, _DIR)

from preprocessing import (
    load_dataset, split_data, build_preprocessing_pipeline,
    get_feature_names, RANDOM_STATE,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("scamx.ml")

MODEL_DIR = os.path.join(_DIR, "model")
DATASET_NAME = "Credit Card Fraud Detection (Kaggle/ULB)"
DATASET_SOURCE = "https://www.kaggle.com/datasets/mlg-ulb/creditcardfraud"


def _compute_metrics(model, X_pre, y_true, train_time, pred_time):
    """Compute real evaluation metrics from the trained model."""
    y_pred = model.predict(X_pre)
    y_proba = model.predict_proba(X_pre)[:, 1]
    cm = confusion_matrix(y_true, y_pred)
    return {
        "precision": round(float(precision_score(y_true, y_pred)), 6),
        "recall": round(float(recall_score(y_true, y_pred)), 6),
        "f1": round(float(f1_score(y_true, y_pred)), 6),
        "pr_auc": round(float(average_precision_score(y_true, y_proba)), 6),
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 6),
        "confusion_matrix": cm.tolist(),
        "training_time_s": round(float(train_time), 3),
        "prediction_time_ms": round(float(pred_time) * 1000, 3),
    }


def _train_model(model, X_train_pre, y_train):
    """Train a single model and measure time."""
    t0 = time.perf_counter()
    model.fit(X_train_pre, y_train)
    train_time = time.perf_counter() - t0
    return model, train_time


def _measure_pred_time(model, X_pre):
    t0 = time.perf_counter()
    model.predict(X_pre)
    return time.perf_counter() - t0


def train():
    os.makedirs(MODEL_DIR, exist_ok=True)

    log.info("Loading dataset...")
    df = load_dataset()
    n_total = len(df)
    n_fraud = int(df["Class"].sum())
    n_legit = n_total - n_fraud
    log.info("Records: %d | Fraud: %d (%.4f%%) | Legitimate: %d",
             n_total, n_fraud, n_fraud / n_total * 100, n_legit)

    log.info("Splitting data (stratified 70/15/15)...")
    X_train, X_val, X_test, y_train, y_val, y_test = split_data(df)
    log.info("Train: %d (fraud: %d) | Val: %d (fraud: %d) | Test: %d (fraud: %d)",
             len(X_train), int(y_train.sum()),
             len(X_val), int(y_val.sum()),
             len(X_test), int(y_test.sum()))

    log.info("Fitting preprocessing pipeline on training data...")
    pre = build_preprocessing_pipeline()
    pre.fit(X_train)
    X_train_pre = pre.transform(X_train)
    X_val_pre = pre.transform(X_val)
    X_test_pre = pre.transform(X_test)

    # --- Train both models ---
    log.info("Training Logistic Regression...")
    lr = LogisticRegression(class_weight="balanced", max_iter=1000, random_state=RANDOM_STATE)
    lr, train_time_lr = _train_model(lr, X_train_pre, y_train)
    pred_time_lr = _measure_pred_time(lr, X_val_pre)
    val_metrics_lr = _compute_metrics(lr, X_val_pre, y_val, train_time_lr, pred_time_lr)
    log.info("LR validation → P=%.4f R=%.4f F1=%.4f PR-AUC=%.4f",
             val_metrics_lr["precision"], val_metrics_lr["recall"],
             val_metrics_lr["f1"], val_metrics_lr["pr_auc"])

    log.info("Training Random Forest...")
    rf = RandomForestClassifier(
        n_estimators=100, class_weight="balanced",
        random_state=RANDOM_STATE, n_jobs=-1, max_depth=15,
    )
    rf, train_time_rf = _train_model(rf, X_train_pre, y_train)
    pred_time_rf = _measure_pred_time(rf, X_val_pre)
    val_metrics_rf = _compute_metrics(rf, X_val_pre, y_val, train_time_rf, pred_time_rf)
    log.info("RF validation → P=%.4f R=%.4f F1=%.4f PR-AUC=%.4f",
             val_metrics_rf["precision"], val_metrics_rf["recall"],
             val_metrics_rf["f1"], val_metrics_rf["pr_auc"])

    validation_results = {
        "logistic_regression": val_metrics_lr,
        "random_forest": val_metrics_rf,
    }

    # --- Select best model by PR-AUC on VALIDATION set ---
    best_name = max(validation_results, key=lambda k: validation_results[k]["pr_auc"])
    best_model = rf if best_name == "random_forest" else lr
    log.info("Selected model (by validation PR-AUC): %s (%.4f)",
             best_name, validation_results[best_name]["pr_auc"])

    # --- Evaluate selected model on the UNTOUCHED TEST set ---
    log.info("Evaluating selected model on untouched test set...")
    test_pred_time = _measure_pred_time(best_model, X_test_pre)
    # Re-measure train time from stored values
    best_train_time = train_time_rf if best_name == "random_forest" else train_time_lr
    final_test_metrics = _compute_metrics(
        best_model, X_test_pre, y_test, best_train_time, test_pred_time
    )
    log.info("FINAL TEST → P=%.4f R=%.4f F1=%.4f PR-AUC=%.4f Acc=%.4f",
             final_test_metrics["precision"], final_test_metrics["recall"],
             final_test_metrics["f1"], final_test_metrics["pr_auc"],
             final_test_metrics["accuracy"])
    cm = final_test_metrics["confusion_matrix"]
    log.info("Confusion Matrix: TN=%d FP=%d FN=%d TP=%d",
             cm[0][0], cm[0][1], cm[1][0], cm[1][1])

    # --- Save artifacts ---
    joblib.dump(best_model, os.path.join(MODEL_DIR, "fraud_model.joblib"))
    joblib.dump(pre, os.path.join(MODEL_DIR, "scaler.joblib"))

    # Collect library versions
    import sklearn
    import pandas as pd2
    import numpy as np2
    import joblib as jb2

    feature_info = {
        "features": get_feature_names(),
        "n_features": len(get_feature_names()),
        "dataset_name": DATASET_NAME,
        "dataset_source": DATASET_SOURCE,
        "n_total_records": n_total,
        "n_fraud": n_fraud,
        "n_legitimate": n_legit,
        "fraud_pct": round(n_fraud / n_total * 100, 4),
        "n_train": len(X_train),
        "n_val": len(X_val),
        "n_test": len(X_test),
        "n_train_fraud": int(y_train.sum()),
        "n_val_fraud": int(y_val.sum()),
        "n_test_fraud": int(y_test.sum()),
        "selected_model": best_name,
        "random_state": RANDOM_STATE,
        "training_date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "python_version": platform.python_version(),
        "scikit_learn_version": sklearn.__version__,
        "pandas_version": pd2.__version__,
        "numpy_version": np2.__version__,
        "joblib_version": jb2.__version__,
        "class_balance_strategy": "class_weight=balanced (no SMOTE)",
        "selection_metric": "PR-AUC (average_precision_score) on validation set",
        "evaluation_methodology": "70/15/15 stratified split — validation for selection, test for final evaluation",
    }
    with open(os.path.join(MODEL_DIR, "feature_info.json"), "w") as f:
        json.dump(feature_info, f, indent=2)

    metrics = {
        "selected_model": best_name,
        "validation_metrics": validation_results,
        "final_test_metrics": final_test_metrics,
        "feature_info": feature_info,
    }
    with open(os.path.join(MODEL_DIR, "metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)

    log.info("=" * 60)
    log.info("TRAINING SUMMARY")
    log.info("=" * 60)
    log.info("Dataset: %s", DATASET_NAME)
    log.info("Records: %d (Fraud: %d, Legitimate: %d)", n_total, n_fraud, n_legit)
    log.info("Train: %d | Validation: %d | Test: %d", len(X_train), len(X_val), len(X_test))
    log.info("")
    log.info("VALIDATION METRICS (used for model selection):")
    for name, m in validation_results.items():
        log.info("  %s → P=%.4f R=%.4f F1=%.4f PR-AUC=%.4f",
                 name, m["precision"], m["recall"], m["f1"], m["pr_auc"])
    log.info("")
    log.info("SELECTED: %s (best validation PR-AUC=%.4f)",
             best_name, validation_results[best_name]["pr_auc"])
    log.info("")
    log.info("FINAL TEST METRICS (untouched, reported once):")
    fm = final_test_metrics
    log.info("  Precision:      %.6f", fm["precision"])
    log.info("  Recall:         %.6f", fm["recall"])
    log.info("  F1-Score:       %.6f", fm["f1"])
    log.info("  PR-AUC:         %.6f", fm["pr_auc"])
    log.info("  Accuracy:       %.6f", fm["accuracy"])
    log.info("  Confusion:      TN=%d FP=%d FN=%d TP=%d", cm[0][0], cm[0][1], cm[1][0], cm[1][1])
    log.info("  Training time:  %.3fs", fm["training_time_s"])
    log.info("  Pred time:      %.3fms", fm["prediction_time_ms"])
    log.info("")
    log.info("Saved: fraud_model.joblib, scaler.joblib, feature_info.json, metrics.json")
    log.info("=" * 60)

    return metrics


if __name__ == "__main__":
    train()
