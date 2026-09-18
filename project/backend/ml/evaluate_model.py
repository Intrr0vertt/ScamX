"""
Standalone evaluation script — prints detailed metrics from the saved model.
Run after training: python backend/ml/evaluate_model.py
"""
import json
import os
import sys

_DIR = os.path.dirname(os.path.abspath(__file__))
if _DIR not in sys.path:
    sys.path.insert(0, _DIR)

METRICS_PATH = os.path.join(_DIR, "model", "metrics.json")


def main():
    if not os.path.exists(METRICS_PATH):
        print("metrics.json not found. Run train_model.py first.")
        return

    with open(METRICS_PATH) as f:
        m = json.load(f)

    print("=" * 60)
    print("MODEL EVALUATION REPORT")
    print("=" * 60)
    print(f"Selected model: {m['selected_model']}")
    fi = m["feature_info"]
    print(f"Dataset: {fi['dataset_name']}")
    print(f"Records: {fi['n_total_records']}")
    print(f"Train/Val/Test: {fi['n_train']}/{fi['n_val']}/{fi['n_test']}")
    print(f"Methodology: {fi['evaluation_methodology']}")
    print()

    print("VALIDATION METRICS (used for model selection):")
    print("-" * 60)
    for name, metrics in m.get("validation_metrics", {}).items():
        print(f"  {name}:")
        print(f"    Precision: {metrics['precision']:.6f}")
        print(f"    Recall:    {metrics['recall']:.6f}")
        print(f"    F1-Score:  {metrics['f1']:.6f}")
        print(f"    PR-AUC:    {metrics['pr_auc']:.6f}")
        print()
    print(f"Selected: {m['selected_model']} (best validation PR-AUC)")
    print()

    print("FINAL TEST METRICS (untouched, reported once):")
    print("-" * 60)
    fm = m["final_test_metrics"]
    print(f"  Precision:      {fm['precision']:.6f}")
    print(f"  Recall:         {fm['recall']:.6f}")
    print(f"  F1-Score:       {fm['f1']:.6f}")
    print(f"  PR-AUC:         {fm['pr_auc']:.6f}")
    print(f"  Accuracy:       {fm['accuracy']:.6f}")
    cm = fm["confusion_matrix"]
    print(f"  Confusion Matrix: TN={cm[0][0]} FP={cm[0][1]} FN={cm[1][0]} TP={cm[1][1]}")
    print(f"  Training time:   {fm['training_time_s']:.3f}s")
    print(f"  Prediction time: {fm['prediction_time_ms']:.3f}ms")
    print()
    print("=" * 60)


if __name__ == "__main__":
    main()
