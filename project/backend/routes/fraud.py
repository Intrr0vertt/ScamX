"""
Fraud Detection API — Flask Blueprint
POST /api/fraud/predict       — predict fraud from transaction features
GET  /api/fraud/model-info    — return model metadata and evaluation metrics
GET  /api/fraud/demo-transaction — return a fixed demo feature vector
"""
import logging
from flask import Blueprint, request, jsonify

import sys
import os

_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ml")
if _DIR not in sys.path:
    sys.path.insert(0, _DIR)

from predict import (
    predict_transaction, is_model_available, get_model_error,
    get_feature_info, get_metrics, get_demo_transaction,
)

fraud_bp = Blueprint("fraud", __name__)
log = logging.getLogger("scamx.fraud")


@fraud_bp.route("/model-info", methods=["GET"])
def model_info():
    if not is_model_available():
        err = get_model_error() or "MODEL_NOT_TRAINED"
        msg = ("Fraud detection model is not trained. Run the training script first."
               if err == "MODEL_NOT_TRAINED"
               else "Failed to load the fraud detection model. Please retrain.")
        return jsonify({
            "success": False,
            "error": {"code": err, "message": msg}
        }), 503

    fi = get_feature_info()
    metrics = get_metrics()
    if not fi or not metrics:
        return jsonify({
            "success": False,
            "error": {"code": "MODEL_INFO_MISSING", "message": "Model metadata not found."}
        }), 500

    selected = metrics.get("selected_model", "unknown")
    fm = metrics.get("final_test_metrics", {})
    val_metrics = metrics.get("validation_metrics", {})

    return jsonify({
        "success": True,
        "data": {
            "model_name": selected.replace("_", " ").title(),
            "dataset_name": fi["dataset_name"],
            "dataset_source": fi["dataset_source"],
            "n_train_samples": fi["n_train"],
            "n_val_samples": fi.get("n_val", 0),
            "n_test_samples": fi["n_test"],
            "n_features": fi["n_features"],
            "features": fi["features"],
            "training_date": fi.get("training_date", ""),
            "class_balance_strategy": fi.get("class_balance_strategy", ""),
            "selection_metric": fi.get("selection_metric", ""),
            "evaluation_methodology": fi.get("evaluation_methodology", ""),
            "python_version": fi.get("python_version", ""),
            "scikit_learn_version": fi.get("scikit_learn_version", ""),
            # Final test metrics (from untouched test set)
            "precision": fm.get("precision", 0),
            "recall": fm.get("recall", 0),
            "f1": fm.get("f1", 0),
            "pr_auc": fm.get("pr_auc", 0),
            "accuracy": fm.get("accuracy", 0),
            "confusion_matrix": fm.get("confusion_matrix", []),
            "training_time_s": fm.get("training_time_s", 0),
            "prediction_time_ms": fm.get("prediction_time_ms", 0),
            # Validation metrics (used for model selection)
            "validation_metrics": {
                name: {
                    "precision": v["precision"],
                    "recall": v["recall"],
                    "f1": v["f1"],
                    "pr_auc": v["pr_auc"],
                    "training_time_s": v["training_time_s"],
                    "prediction_time_ms": v["prediction_time_ms"],
                }
                for name, v in val_metrics.items()
            },
        }
    })


@fraud_bp.route("/predict", methods=["POST"])
def predict():
    if not is_model_available():
        err = get_model_error() or "MODEL_NOT_TRAINED"
        msg = ("Fraud detection model is not trained. Run the training script first."
               if err == "MODEL_NOT_TRAINED"
               else "Failed to load the fraud detection model. Please retrain.")
        return jsonify({
            "success": False,
            "error": {"code": err, "message": msg}
        }), 503

    data = request.get_json(silent=True)
    if not data:
        return jsonify({
            "success": False,
            "error": {"code": "BAD_REQUEST",
                       "message": "JSON body with transaction features is required."}
        }), 400

    try:
        result = predict_transaction(data)
    except ValueError as e:
        return jsonify({
            "success": False,
            "error": {"code": "VALIDATION_ERROR", "message": str(e)}
        }), 400
    except RuntimeError as e:
        return jsonify({
            "success": False,
            "error": {"code": "MODEL_NOT_TRAINED", "message": str(e)}
        }), 503
    except Exception:
        log.exception("Fraud prediction failed")
        return jsonify({
            "success": False,
            "error": {"code": "INTERNAL_ERROR",
                       "message": "An unexpected error occurred during prediction."}
        }), 500

    # Store prediction in SQLite (no sensitive payment data)
    stored = False
    try:
        from db.database import get_conn
        conn = get_conn()
        model_name = get_feature_info().get("selected_model", "unknown")
        conn.execute(
            "INSERT INTO ml_predictions (prediction, fraud_probability, model_name) VALUES (?, ?, ?)",
            (result["prediction"], result["fraud_probability"], model_name)
        )
        conn.commit()
        conn.close()
        stored = True
    except Exception:
        log.warning("Failed to store ML prediction in database", exc_info=True)

    return jsonify({"success": True, "data": {**result, "stored": stored}})


@fraud_bp.route("/demo-transaction", methods=["GET"])
def demo_transaction():
    if not is_model_available():
        err = get_model_error() or "MODEL_NOT_TRAINED"
        msg = ("Fraud detection model is not trained. Run the training script first."
               if err == "MODEL_NOT_TRAINED"
               else "Failed to load the fraud detection model. Please retrain.")
        return jsonify({
            "success": False,
            "error": {"code": err, "message": msg}
        }), 503
    try:
        demo = get_demo_transaction()
    except Exception:
        log.exception("Demo transaction failed")
        return jsonify({
            "success": False,
            "error": {"code": "INTERNAL_ERROR",
                       "message": "Could not generate demo transaction."}
        }), 500
    return jsonify({
        "success": True,
        "data": demo,
        "note": "Fixed demonstration vector — not a real transaction.",
    })
