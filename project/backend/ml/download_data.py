"""
Download the Credit Card Fraud Detection dataset (Kaggle) via a public mirror.
If the download fails, prints instructions for manual download.

Source: https://www.kaggle.com/datasets/mlg-ulb/creditcardfraud
License: Open Database License (ODbL)

Usage (from project root):
    python backend/ml/download_data.py
"""
import os
import sys
import csv
import urllib.request
import urllib.error

MIRROR_URLS = [
    "https://storage.googleapis.com/download.tensorflow.org/data/creditcard.csv",
]

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
TARGET = os.path.join(DATA_DIR, "creditcard.csv")

EXPECTED_COLUMNS = [f"V{n}" for n in range(1, 29)] + ["Time", "Amount", "Class"]
MIN_ROWS = 280000
MAX_ROWS = 290000
EXPECTED_NUM_COLUMNS = 31


def _validate_csv(path: str) -> bool:
    """Validate the downloaded file is a proper CSV with expected structure."""
    if not os.path.exists(path):
        return False
    size = os.path.getsize(path)
    if size < 1_000_000:
        print(f"  File too small ({size} bytes) — likely not the real dataset.")
        return False

    try:
        with open(path, "r", newline="") as f:
            reader = csv.reader(f)
            header = next(reader, None)
            if not header:
                print("  Empty CSV header.")
                return False
            # Check for HTML error page
            first_col = header[0].lower() if header else ""
            if "<html" in first_col or "<!doctype" in first_col or "<!DOCTYPE" in first_col:
                print("  File appears to be an HTML error page, not CSV.")
                return False
            missing = [c for c in EXPECTED_COLUMNS if c not in header]
            if missing:
                print(f"  Missing expected columns: {missing}")
                return False
            if len(header) != EXPECTED_NUM_COLUMNS:
                print(f"  Expected {EXPECTED_NUM_COLUMNS} columns, got {len(header)}.")
                return False
            # Count rows
            row_count = sum(1 for _ in reader)
            if row_count < MIN_ROWS or row_count > MAX_ROWS:
                print(f"  Expected ~{MIN_ROWS}-{MAX_ROWS} rows, got {row_count}.")
                return False
            print(f"  Validated: {len(header)} columns, {row_count} rows.")
            return True
    except Exception as e:
        print(f"  CSV validation error: {e}")
        return False


def download():
    os.makedirs(DATA_DIR, exist_ok=True)

    # Check if already exists and is valid
    if os.path.exists(TARGET):
        print(f"Checking existing file: {TARGET}")
        if _validate_csv(TARGET):
            print("Dataset already present and valid. Skipping download.")
            return True
        else:
            print("Existing file is invalid. Removing and re-downloading.")
            os.remove(TARGET)

    for url in MIRROR_URLS:
        tmp_path = TARGET + ".tmp"
        try:
            print(f"Downloading from: {url}")
            urllib.request.urlretrieve(url, tmp_path)
            # Validate before renaming
            os.rename(tmp_path, TARGET)
            if _validate_csv(TARGET):
                size = os.path.getsize(TARGET)
                print(f"Downloaded {size:,} bytes → {TARGET}")
                return True
            else:
                print("Downloaded file failed validation. Removing.")
                if os.path.exists(TARGET):
                    os.remove(TARGET)
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
        except Exception as e:
            print(f"Download failed: {e}")
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    print("\n" + "=" * 60)
    print("AUTOMATIC DOWNLOAD FAILED")
    print("=" * 60)
    print("Manual download instructions:")
    print("1. Go to https://www.kaggle.com/datasets/mlg-ulb/creditcardfraud")
    print("2. Download creditcard.csv")
    print(f"3. Place it at: {TARGET}")
    print("4. Re-run: python backend/ml/train_model.py")
    print("=" * 60)
    return False


if __name__ == "__main__":
    ok = download()
    sys.exit(0 if ok else 1)
