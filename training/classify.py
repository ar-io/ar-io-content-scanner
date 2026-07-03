from __future__ import annotations

import os
import sys

import numpy as np
import xgboost as xgb

# Import feature extraction from the production module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from src.ml.features import extract_features

model = xgb.XGBClassifier()
model.load_model("xgboost_model.pkl")

unknown_folder = "data/uncategorized/html/"
if not os.path.isdir(unknown_folder):
    print(f"No uncategorized data found at {unknown_folder}")
    sys.exit(0)

unknown_files = os.listdir(unknown_folder)
if not unknown_files:
    print("No files to classify.")
    sys.exit(0)

X_unknown = []
for file in unknown_files:
    with open(os.path.join(unknown_folder, file), "r", encoding="utf-8") as f:
        content = f.read()
    features = extract_features(content)
    X_unknown.append(features.to_vector())

X_unknown = np.array(X_unknown)

y_pred = model.predict(X_unknown)

class_labels = ["neutral", "phishing"]
phishing_count = 0

for file, prediction in zip(unknown_files, y_pred):
    label = class_labels[prediction]
    if label == "phishing":
        print(f"PHISHING: {file}")
        phishing_count += 1

print(f"\n{phishing_count} phishing / {len(unknown_files)} total files")
