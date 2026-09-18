"""
Preprocessing for the Credit Card Fraud Detection dataset.

Uses sklearn Pipeline + StandardScaler so the exact same preprocessing
learned during training is applied during prediction.

Split methodology: 70% train / 15% validation / 15% test (stratified).
The validation set is used for model selection. The test set is untouched
until final evaluation.
"""
import os
import sys
import math
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

# Allow both `python backend/ml/preprocessing.py` and imports from train_model.py
_DIR = os.path.dirname(os.path.abspath(__file__))
if _DIR not in sys.path:
    sys.path.insert(0, _DIR)

DATA_PATH = os.path.join(_DIR, "data", "creditcard.csv")
TARGET_COL = "Class"
FEATURE_COLS = [f"V{n}" for n in range(1, 29)] + ["Time", "Amount"]
RANDOM_STATE = 42


def load_dataset(path: str | None = None) -> pd.DataFrame:
    """Load the raw CSV, validating expected columns."""
    p = path or DATA_PATH
    if not os.path.exists(p):
        raise FileNotFoundError(
            f"Dataset not found at {p}. Run: python backend/ml/download_data.py"
        )
    df = pd.read_csv(p)
    expected = FEATURE_COLS + [TARGET_COL]
    missing = [c for c in expected if c not in df.columns]
    if missing:
        raise ValueError(f"Dataset missing columns: {missing}")
    # Check for NaN/Inf in features
    X = df[FEATURE_COLS]
    if X.isnull().any().any():
        raise ValueError("Dataset contains NaN values in features. Please check the data.")
    if np.isinf(X.select_dtypes(include=[np.number])).any().any():
        raise ValueError("Dataset contains Infinity values in features. Please check the data.")
    return df


def split_data(df: pd.DataFrame):
    """
    Stratified 70/15/15 train/validation/test split.
    Returns (X_train, X_val, X_test, y_train, y_val, y_test).
    """
    X = df[FEATURE_COLS].copy()
    y = df[TARGET_COL].copy()

    # First split: 70% train, 30% temp (val+test)
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.30, stratify=y, random_state=RANDOM_STATE
    )
    # Second split: 50% of temp → 15% val, 15% test
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, stratify=y_temp, random_state=RANDOM_STATE
    )
    return X_train, X_val, X_test, y_train, y_val, y_test


def build_preprocessing_pipeline() -> Pipeline:
    """StandardScaler on all numeric features."""
    return Pipeline([("scaler", StandardScaler())])


def get_feature_names() -> list[str]:
    """Return the ordered feature names the model expects."""
    return FEATURE_COLS.copy()


def validate_features(values: list[float]) -> None:
    """Reject NaN, Infinity, or -Infinity in feature values."""
    for i, v in enumerate(values):
        if math.isnan(v) or math.isinf(v):
            raise ValueError(
                f"Feature value at index {i} is not finite (NaN/Infinity not allowed)."
            )
