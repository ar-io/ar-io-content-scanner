import os
import numpy as np
import xgboost as xgb
from sklearn.model_selection import GridSearchCV, train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.naive_bayes import MultinomialNB
from sklearn.feature_extraction.text import TfidfVectorizer
from extract_features import extract_features
import pickle
import time
from datetime import datetime


def process_file(filename):
    with open(filename, 'r', encoding='utf-8') as file:
        content = file.read()
    return content, extract_features(content)


def process_files(folder, label):
    filenames = [os.path.join(folder, f) for f in os.listdir(
        folder) if os.path.isfile(os.path.join(folder, f))]
    print(f"Processing {len(filenames)} files from {folder}...")
    contents = []
    features = []
    for i, filename in enumerate(filenames):
        if (i + 1) % 100 == 0:
            print(f"  Processed {i + 1}/{len(filenames)} files")
        content, feature = process_file(filename)
        contents.append(content)
        features.append(feature)
    labels = [label] * len(filenames)
    return filenames, contents, features, labels


print("=" * 60)
print("Starting phishing detection model training")
print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("=" * 60)

neutral_folder = "data/neutral/"
phishing_folder = "data/phishing/"

print("\n[Step 1/5] Loading and processing dataset...")
start_time = time.time()

neutral_filenames, neutral_contents, neutral_features, neutral_labels = process_files(
    neutral_folder, 0)
phishing_filenames, phishing_contents, phishing_features, phishing_labels = process_files(
    phishing_folder, 1)

filenames_all_ordered = neutral_filenames + phishing_filenames
contents_all = neutral_contents + phishing_contents

# Combine the neutral and phishing datasets
X = neutral_features + phishing_features
y = neutral_labels + phishing_labels

processing_time = time.time() - start_time
print(f"\nDataset loaded successfully!")
print(f"  Total samples: {len(X)}")
print(f"  Neutral samples: {len(neutral_features)}")
print(f"  Phishing samples: {len(phishing_features)}")
print(f"  Processing time: {processing_time:.2f} seconds")


# Fine-tune hyperparameters using cross-validation
param_grid = {
    'learning_rate': [0.1, 0.01, 0.001],
    'max_depth': [3, 5, 7],
    'n_estimators': [100, 200, 300],
}

print(f"\n[Step 2/5] Performing hyperparameter tuning...")
print(f"  Parameters to test:")
print(f"    Learning rates: {param_grid['learning_rate']}")
print(f"    Max depths: {param_grid['max_depth']}")
print(f"    N estimators: {param_grid['n_estimators']}")
print(f"  Total combinations: {len(param_grid['learning_rate']) * len(param_grid['max_depth']) * len(param_grid['n_estimators'])}")
print(f"  Cross-validation folds: 5")

# Train the XGBoost classifier
start_time = time.time()
model = xgb.XGBClassifier(use_label_encoder=False, eval_metric='logloss')
grid_search = GridSearchCV(
    model, param_grid, scoring='accuracy', cv=5, n_jobs=1, verbose=3)
grid_search.fit(X, y)

grid_search_time = time.time() - start_time
print(f"\nGrid search completed in {grid_search_time:.2f} seconds")
print(f"Best parameters found:")
print(f"  Learning rate: {grid_search.best_params_['learning_rate']}")
print(f"  Max depth: {grid_search.best_params_['max_depth']}")
print(f"  N estimators: {grid_search.best_params_['n_estimators']}")
print(f"  Best cross-validation score: {grid_search.best_score_:.4f}")

# Get the best model from the grid search
best_model = grid_search.best_estimator_

# Train the model on the entire dataset
print(f"\n[Step 3/5] Training final model on entire dataset...")
start_time = time.time()
best_model.fit(X, y)
training_time = time.time() - start_time
print(f"Final model trained in {training_time:.2f} seconds")

print(f"\n[Step 4/5] Saving XGBoost model to disk...")
best_model.save_model("xgboost_model.pkl")
print(f"XGBoost model saved successfully to 'xgboost_model.pkl'")

# Train Text-based Naive Bayes with TF-IDF for comparison
print(f"\n[Step 4.5/5] Training Text-based Naive Bayes with TF-IDF...")
start_time = time.time()

# Vectorize HTML content
print("  Vectorizing HTML content with TF-IDF...")
tfidf_vectorizer = TfidfVectorizer(max_features=5000, stop_words='english',
                                   min_df=2, max_df=0.95)
X_tfidf = tfidf_vectorizer.fit_transform(contents_all)
print(f"  TF-IDF vocabulary size: {len(tfidf_vectorizer.vocabulary_)}")

# Train MultinomialNB on TF-IDF features
print("  Training MultinomialNB...")
nb_text_model = MultinomialNB()
nb_text_model.fit(X_tfidf, y)
nb_text_training_time = time.time() - start_time
print(f"Text-based Naive Bayes model trained in {nb_text_training_time:.2f} seconds")

# Save text-based model and vectorizer
print(f"Saving text-based Naive Bayes model to disk...")
with open('naive_bayes_text_model.pkl', 'wb') as file:
    pickle.dump(nb_text_model, file)
with open('tfidf_vectorizer.pkl', 'wb') as file:
    pickle.dump(tfidf_vectorizer, file)
print(f"Text-based model saved to 'naive_bayes_text_model.pkl'")
print(f"TF-IDF vectorizer saved to 'tfidf_vectorizer.pkl'")


# THIS HERE IS OPTIONAL AND IS USED TO TEST THE MODEL ON THE TEST SET
# ANYTHING BELOW THIS IS NOT NEEDED FOR THE MODEL TO WORK

print(f"\n[Step 5/5] Evaluating model performance on test set...")
print("=" * 60)

# Combining filenames, contents, features, and labels into a single list of tuples
combined_data = list(zip(filenames_all_ordered, contents_all, X, y))

# Splitting the combined data into training and test sets
combined_train, combined_test = train_test_split(
    combined_data, test_size=0.2, random_state=42)

# Unpacking the training and test sets
X_train, y_train = zip(*[(features, label)
                       for _, _, features, label in combined_train])
X_test, y_test = zip(*[(features, label)
                     for _, _, features, label in combined_test])
contents_test = [content for _, content, _, _ in combined_test]
filenames_test = [filename for filename, _, _, _ in combined_test]

print(f"Test set size: {len(X_test)} samples")

# # Convert X_train, X_test, y_train, y_test back to lists if necessary
# X_train = list(X_train)
# X_test = list(X_test)
# y_train = list(y_train)
# y_test = list(y_test)


# # Split the dataset into training and testing sets
# X_train, X_test, y_train, y_test = train_test_split(
#     X, y, test_size=0.2, random_state=42)

print("Running predictions on test set...")
y_pred_xgb = best_model.predict(X_test)

# Transform test content and predict with text-based NB
X_test_tfidf = tfidf_vectorizer.transform(contents_test)
y_pred_nb_text = nb_text_model.predict(X_test_tfidf)

# Get probability predictions for ensemble
y_pred_xgb_proba = best_model.predict_proba(X_test)[:, 1]
y_pred_nb_text_proba = nb_text_model.predict_proba(X_test_tfidf)[:, 1]

# Ensemble method
print("Creating ensemble predictions...")

# XGBoost + Text NB ensemble (soft voting)
y_pred_ensemble = ((y_pred_xgb_proba + y_pred_nb_text_proba) / 2 >= 0.5).astype(int)

# Calculate metrics for all models
xgb_accuracy = accuracy_score(y_test, y_pred_xgb)
nb_text_accuracy = accuracy_score(y_test, y_pred_nb_text)
ensemble_accuracy = accuracy_score(y_test, y_pred_ensemble)

# Get detailed reports
xgb_report = classification_report(y_test, y_pred_xgb, output_dict=True)
nb_text_report = classification_report(y_test, y_pred_nb_text, output_dict=True)
ensemble_report = classification_report(y_test, y_pred_ensemble, output_dict=True)

# Print side-by-side comparison
print(f"\n*** MODEL COMPARISON ***")
print("=" * 80)
print(f"\n{'Metric':<30} {'XGBoost':<15} {'NB (Text)':<15} {'Ensemble':<15}")
print("-" * 80)
print(f"{'Accuracy':<30} {xgb_accuracy:<15.4f} {nb_text_accuracy:<15.4f} {ensemble_accuracy:<15.4f}")
print(f"{'Phishing Precision':<30} {xgb_report['1']['precision']:<15.4f} {nb_text_report['1']['precision']:<15.4f} {ensemble_report['1']['precision']:<15.4f}")
print(f"{'Phishing Recall':<30} {xgb_report['1']['recall']:<15.4f} {nb_text_report['1']['recall']:<15.4f} {ensemble_report['1']['recall']:<15.4f}")
print(f"{'Phishing F1-Score':<30} {xgb_report['1']['f1-score']:<15.4f} {nb_text_report['1']['f1-score']:<15.4f} {ensemble_report['1']['f1-score']:<15.4f}")
print(f"{'Neutral Precision':<30} {xgb_report['0']['precision']:<15.4f} {nb_text_report['0']['precision']:<15.4f} {ensemble_report['0']['precision']:<15.4f}")
print(f"{'Neutral Recall':<30} {xgb_report['0']['recall']:<15.4f} {nb_text_report['0']['recall']:<15.4f} {ensemble_report['0']['recall']:<15.4f}")
print(f"{'Training Time (seconds)':<30} {training_time:<15.2f} {nb_text_training_time:<15.2f} {'N/A':<15}")
print("=" * 80)

print(f"\n*** NOTES ***")
print("XGBoost: Engineered features (17 features)")
print("NB (Text): TF-IDF vectorization with MultinomialNB")
print("Ensemble: Soft voting (XGBoost + NB Text)")
print("=" * 80)

# Evaluate the XGBoost classifier in detail
print(f"\n*** XGBoost Detailed Performance ***")
print(f"Accuracy: {xgb_accuracy:.2f}")

print("\nClassification Report:")
print(classification_report(y_test, y_pred_xgb))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred_xgb))

incorrect_indices = np.where(y_test != y_pred_xgb)[0]

# Print the incorrect predictions
print(f"\n*** Misclassified Samples Analysis ***")
print(f"Total misclassified: {len(incorrect_indices)} out of {len(y_test)} ({len(incorrect_indices)/len(y_test)*100:.2f}%)")
print("\nDetailed breakdown of incorrectly predicted instances:")
print("-" * 60)
featurs_titles = [
    "num_input_fields",
    "num_buttons",
    "num_forms",
    "num_tags_within_body",
    "has_form_with_post",
    "has_form_with_action",
    "has_password_field",
    "has_obfuscated_script",
    "all_flagged_keywords",
    "whitelisted_keywords",
    "title_length",
    "has_password_in_title",
    "has_signin_in_title",
    "has_suspicious_title",
    "crypto_keywords",
    "wallet_keywords",
    "has_generic_title"
]
for i, index in enumerate(incorrect_indices, 1):
    predicted_label = "phishing" if y_pred_xgb[index] == 1 else "neutral"
    actual_label = "phishing" if y_test[index] == 1 else "neutral"
    print(f"\n[{i}/{len(incorrect_indices)}] Misclassification:")
    print(f"  Predicted: {predicted_label} (class {y_pred_xgb[index]})")
    print(f"  Actual: {actual_label} (class {y_test[index]})")
    print(f"  File: {filenames_test[index]}")
    current_features = X_test[index]
    features_pretty = [
        str(featurs_titles[j] + ": " + str(current_features[j])) for j in range(min(len(featurs_titles), len(current_features)))]
    features_pretty_2 = "\n    ".join(features_pretty)
    print(f"  Features:\n    {features_pretty_2}")
    
print("\n" + "=" * 60)
print("Training completed successfully!")
print(f"Final timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("=" * 60)


# Save the trained model to a file
# with open('xgboost_model.pkl', 'wb') as file:
#     pickle.dump(model, file)
