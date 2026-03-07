import os
import numpy as np
import xgboost as xgb
from extract_features import extract_features

model = xgb.XGBClassifier()
model.load_model("xgboost_model.pkl")

# Load the model from disk
# with open('xgboost_model.pkl', 'rb') as file:
#     model = pickle.load(file)

# Prepare the unseen data
unknown_folder = "data/uncategorized/html/"
unknown_files = os.listdir(unknown_folder)

# Extract features for each unseen file
X_unknown = []
for file in unknown_files:
    with open(os.path.join(unknown_folder, file), 'r', encoding='utf-8') as f:
        content = f.read()
    features = extract_features(content)
    X_unknown.append(features)

X_unknown = np.array(X_unknown)

# Make predictions on the unseen data
y_pred = model.predict(X_unknown)

# Analyze the predictions
# Replace these labels with the actual class names you used when training the model
class_labels = ['neutral', 'phishing']

for file, prediction in zip(unknown_files, y_pred):
  if class_labels[prediction] == 'phishing':
    print(f"File: {file}")
    print(f"Predicted class: {class_labels[prediction]}\n")
