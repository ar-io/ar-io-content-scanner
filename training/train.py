from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone

import numpy as np
import xgboost as xgb
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import GridSearchCV, train_test_split

# Import feature extraction from the production module — single source of truth.
# No separate training copy exists; any change to features requires retraining.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from src.ml.features import extract_features


# Max file size for training samples (10MB). Larger files are likely not
# HTML phishing pages and would waste memory during feature extraction.
_MAX_TRAINING_FILE_BYTES = 10 * 1024 * 1024


def process_file(filename):
    size = os.path.getsize(filename)
    if size > _MAX_TRAINING_FILE_BYTES:
        raise ValueError(f"File too large ({size} bytes, max {_MAX_TRAINING_FILE_BYTES})")
    if size == 0:
        raise ValueError("Empty file")
    with open(filename, "r", encoding="utf-8") as file:
        content = file.read()
    features = extract_features(content)
    return content, features.to_vector()


def process_files(folder, label):
    filenames = [
        os.path.join(folder, f)
        for f in os.listdir(folder)
        if os.path.isfile(os.path.join(folder, f))
    ]
    print(f"Processing {len(filenames)} files from {folder}...")
    contents = []
    features = []
    for i, filename in enumerate(filenames):
        if (i + 1) % 100 == 0:
            print(f"  Processed {i + 1}/{len(filenames)} files")
        try:
            content, feature = process_file(filename)
            contents.append(content)
            features.append(feature)
        except Exception as e:
            print(f"  WARNING: Skipping {filename}: {e}")
    labels = [label] * len(features)
    return filenames[: len(features)], contents, features, labels


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

print("=" * 60)
print("Starting phishing detection model training")
print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("=" * 60)

neutral_folder = "data/neutral/"
phishing_folder = "data/phishing/"

if not os.path.isdir(neutral_folder) or not os.path.isdir(phishing_folder):
    print(
        f"ERROR: Training data not found. Expected directories:\n"
        f"  {neutral_folder}\n  {phishing_folder}\n\n"
        f"Copy training data from the content-scanner container:\n"
        f"  docker cp ar-io-content-scanner:/app/data/training/phishing ./data/phishing\n"
        f"  docker cp ar-io-content-scanner:/app/data/training/neutral ./data/neutral"
    )
    sys.exit(1)

print("\n[Step 1/5] Loading and processing dataset...")
start_time = time.time()

neutral_filenames, neutral_contents, neutral_features, neutral_labels = process_files(
    neutral_folder, 0
)
phishing_filenames, phishing_contents, phishing_features, phishing_labels = process_files(
    phishing_folder, 1
)

filenames_all_ordered = neutral_filenames + phishing_filenames

# Combine the neutral and phishing datasets
X = neutral_features + phishing_features
y = neutral_labels + phishing_labels

processing_time = time.time() - start_time
print(f"\nDataset loaded successfully!")
print(f"  Total samples: {len(X)}")
print(f"  Neutral samples: {len(neutral_features)}")
print(f"  Phishing samples: {len(phishing_features)}")
print(f"  Processing time: {processing_time:.2f} seconds")

if len(X) < 10:
    print("ERROR: Not enough training data. Need at least 10 samples.")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Hyperparameter tuning
# ---------------------------------------------------------------------------

param_grid = {
    "learning_rate": [0.1, 0.01, 0.001],
    "max_depth": [3, 5, 7],
    "n_estimators": [100, 200, 300],
}

print(f"\n[Step 2/5] Performing hyperparameter tuning...")
print(f"  Parameters to test:")
print(f"    Learning rates: {param_grid['learning_rate']}")
print(f"    Max depths: {param_grid['max_depth']}")
print(f"    N estimators: {param_grid['n_estimators']}")
total_combos = (
    len(param_grid["learning_rate"])
    * len(param_grid["max_depth"])
    * len(param_grid["n_estimators"])
)
print(f"  Total combinations: {total_combos}")
print(f"  Cross-validation folds: 5")

start_time = time.time()
model = xgb.XGBClassifier(eval_metric="logloss")
grid_search = GridSearchCV(
    model, param_grid, scoring="accuracy", cv=5, n_jobs=1, verbose=3
)
grid_search.fit(X, y)

grid_search_time = time.time() - start_time
print(f"\nGrid search completed in {grid_search_time:.2f} seconds")
print(f"Best parameters found:")
print(f"  Learning rate: {grid_search.best_params_['learning_rate']}")
print(f"  Max depth: {grid_search.best_params_['max_depth']}")
print(f"  N estimators: {grid_search.best_params_['n_estimators']}")
print(f"  Best cross-validation score: {grid_search.best_score_:.4f}")

# ---------------------------------------------------------------------------
# Train final model
# ---------------------------------------------------------------------------

best_model = grid_search.best_estimator_

print(f"\n[Step 3/5] Training final model on entire dataset...")
start_time = time.time()
best_model.fit(X, y)
training_time = time.time() - start_time
print(f"Final model trained in {training_time:.2f} seconds")

# ---------------------------------------------------------------------------
# Save model + verify production format
# ---------------------------------------------------------------------------

print(f"\n[Step 4/5] Saving XGBoost model to disk...")
best_model.save_model("xgboost_model.pkl")
print(f"XGBoost model saved to 'xgboost_model.pkl'")

# Verify it loads in the production Booster format
test_booster = xgb.Booster()
test_booster.load_model("xgboost_model.pkl")
print("Model verified: loads correctly in production Booster format")

# ---------------------------------------------------------------------------
# Evaluate on holdout test set
# ---------------------------------------------------------------------------

print(f"\n[Step 5/5] Evaluating model performance on test set...")
print("=" * 60)

combined_data = list(zip(filenames_all_ordered, X, y))
combined_train, combined_test = train_test_split(
    combined_data, test_size=0.2, random_state=42
)

X_test = [features for _, features, _ in combined_test]
y_test = [label for _, _, label in combined_test]
filenames_test = [fn for fn, _, _ in combined_test]

print(f"Test set size: {len(X_test)} samples")
print("Running predictions on test set...")
y_pred = best_model.predict(X_test)

xgb_accuracy = accuracy_score(y_test, y_pred)
xgb_report = classification_report(y_test, y_pred, output_dict=True)

print(f"\nAccuracy: {xgb_accuracy:.4f}")
print("\nClassification Report:")
print(classification_report(y_test, y_pred))
print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# Misclassified samples
incorrect_indices = np.where(np.array(y_test) != np.array(y_pred))[0]
print(
    f"\nMisclassified: {len(incorrect_indices)} / {len(y_test)} "
    f"({len(incorrect_indices) / len(y_test) * 100:.2f}%)"
)

feature_names = [
    "num_input_fields", "num_buttons", "num_forms", "num_tags_within_body",
    "has_form_with_post", "has_form_with_action", "has_password_field",
    "has_obfuscated_script", "all_flagged_keywords", "whitelisted_keywords",
    "title_length", "has_password_in_title", "has_signin_in_title",
    "has_suspicious_title", "crypto_keywords", "wallet_keywords", "has_generic_title",
]

for i, index in enumerate(incorrect_indices, 1):
    predicted = "phishing" if y_pred[index] == 1 else "neutral"
    actual = "phishing" if y_test[index] == 1 else "neutral"
    print(f"\n[{i}/{len(incorrect_indices)}] {filenames_test[index]}")
    print(f"  Predicted: {predicted}, Actual: {actual}")
    feats = X_test[index]
    for j, name in enumerate(feature_names):
        if j < len(feats):
            print(f"    {name}: {feats[j]}")

# ---------------------------------------------------------------------------
# Generate model manifest
# ---------------------------------------------------------------------------

print("\nGenerating model manifest...")

with open("xgboost_model.pkl", "rb") as f:
    model_hash = hashlib.sha256(f.read()).hexdigest()

manifest = {
    "version": "2",
    "trained_at": datetime.now(timezone.utc).isoformat(),
    "xgboost_version": xgb.__version__,
    "features_count": 17,
    "training_data": {
        "phishing_samples": len(phishing_features),
        "neutral_samples": len(neutral_features),
        "total_samples": len(X),
    },
    "best_params": grid_search.best_params_,
    "metrics": {
        "accuracy": float(xgb_accuracy),
        "cv_best_score": float(grid_search.best_score_),
        "phishing_precision": float(xgb_report["1"]["precision"]),
        "phishing_recall": float(xgb_report["1"]["recall"]),
        "phishing_f1": float(xgb_report["1"]["f1-score"]),
    },
    "model_file": "xgboost_model.pkl",
    "model_sha256": model_hash,
}

with open("model-manifest.json", "w") as f:
    json.dump(manifest, f, indent=2)
print("Model manifest saved to 'model-manifest.json'")

print("\n" + "=" * 60)
print("Training completed successfully!")
print(f"Final timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("=" * 60)
