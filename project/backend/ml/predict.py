"""
Prediction module — loads the trained model and scaler, applies the same
preprocessing learned during training, and returns fraud probability.

The probability comes from the model's predict_proba(). It is NOT modified.

Usage (from project root):
    The fraud route imports this module. No direct execution needed.
"""
import os
import sys
import json
import math
import logging
import numpy as np
import joblib

_DIR = os.path.dirname(os.path.abspath(__file__))
if _DIR not in sys.path:
    sys.path.insert(0, _DIR)

log = logging.getLogger("scamx.ml.predict")

MODEL_DIR = os.path.join(_DIR, "model")
MODEL_PATH = os.path.join(MODEL_DIR, "fraud_model.joblib")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.joblib")
FEATURE_INFO_PATH = os.path.join(MODEL_DIR, "feature_info.json")

_model = None
_scaler = None
_feature_info = None
_load_error = None


def _load():
    """Lazily load model, scaler, and feature info. Returns True if loaded."""
    global _model, _scaler, _feature_info, _load_error
    if _model is not None:
        return True
    if _load_error is not None:
        return False
    if not os.path.exists(MODEL_PATH) or not os.path.exists(SCALER_PATH):
        _load_error = "MODEL_NOT_TRAINED"
        return False
    if not os.path.exists(FEATURE_INFO_PATH):
        _load_error = "MODEL_NOT_TRAINED"
        return False
    try:
        _model = joblib.load(MODEL_PATH)
        _scaler = joblib.load(SCALER_PATH)
        with open(FEATURE_INFO_PATH) as f:
            _feature_info = json.load(f)
        log.info("Loaded model: %s", _feature_info.get("selected_model", "unknown"))
        return True
    except Exception as e:
        log.error("Failed to load model: %s", e)
        _load_error = "MODEL_LOAD_ERROR"
        return False


def is_model_available() -> bool:
    return _load()


def get_model_error() -> str | None:
    """Return the error code if model failed to load."""
    return _load_error


def get_feature_info() -> dict | None:
    if not _load():
        return None
    return _feature_info


def get_metrics() -> dict | None:
    """Load metrics.json for model-info endpoint."""
    metrics_path = os.path.join(MODEL_DIR, "metrics.json")
    if not os.path.exists(metrics_path):
        return None
    try:
        with open(metrics_path) as f:
            return json.load(f)
    except Exception as e:
        log.error("Failed to load metrics: %s", e)
        return None


def predict_transaction(features: dict) -> dict:
    """
    Accept a dict of feature_name -> numeric_value.
    Returns: {"prediction": 0/1, "label": "Legitimate"/"Fraud", "fraud_probability": float}
    """
    if not _load():
        raise RuntimeError("Fraud detection model is not trained. Run the training script first.")

    expected = _feature_info["features"]

    # Validate: all required features present and numeric
    values = []
    for feat in expected:
        if feat not in features:
            raise ValueError(f"Missing required feature: {feat}")
        val = features[feat]
        try:
            num_val = float(val)
        except (TypeError, ValueError):
            raise ValueError(f"Feature {feat} must be numeric, got: {type(val).__name__}")
        # Reject NaN and Infinity
        if math.isnan(num_val) or math.isinf(num_val):
            raise ValueError(f"Feature {feat} must be a finite number (NaN/Infinity not allowed).")
        values.append(num_val)

    arr = np.array([values], dtype=np.float64)
    arr_pre = _scaler.transform(arr)
    prediction = int(_model.predict(arr_pre)[0])
    probability = float(_model.predict_proba(arr_pre)[0, 1])

    # Sanity check: probability must be between 0 and 1
    if not (0.0 <= probability <= 1.0):
        raise RuntimeError("Model returned invalid probability.")

    return {
        "prediction": prediction,
        "label": "Fraud" if prediction == 1 else "Legitimate",
        "fraud_probability": round(probability, 6),
    }


def get_demo_transaction() -> dict:
    """
    Return a fixed demonstration vector based on the dataset feature format.
    This is NOT a real transaction — it is a synthetic example for UI testing.
    """
    if not _load():
        raise RuntimeError("Model not trained")
    demo = {}
    for i in range(1, 29):
        demo[f"V{i}"] = 0.0
    demo["Time"] = 100000.0
    demo["Amount"] = 50.0
    return demo
