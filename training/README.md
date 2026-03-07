# ML Model Training Pipeline

Scripts for training and managing the XGBoost phishing detection model.

## Training Data

Training data is stored in S3 (`s3://ario-infra-ml-training-data/`) with this structure:

```
data/
  neutral/       # Legitimate HTML files
  phishing/      # Confirmed phishing HTML files
  uncategorized/  # New samples awaiting classification
    html/
    jpeg/
```

### S3 Scripts

- `s3sync.sh` — Download training data from S3
- `s3move.sh` — Move categorized files from uncategorized to their target folder
- `s3remove.sh` — Remove a specific TX ID from uncategorized data

## Training

```bash
# 1. Download training data
./s3sync.sh

# 2. Train the model (outputs xgboost_model.pkl)
python3 train.py

# 3. Copy the model to the project root
cp xgboost_model.pkl ../xgboost_model.pkl
```

`train.py` performs GridSearchCV over learning rate, max depth, and n_estimators, then trains the final model on the full dataset. It also trains a Naive Bayes text model for comparison (not used in production).

## Classifying New Samples

```bash
# Classify uncategorized HTML files
python3 classify.py
```

## Feature Vector

The model uses 17 engineered features (defined in `extract_features.py`). These must stay in sync with `src/ml/features.py` in the main codebase — any changes to features require retraining.

| # | Feature | Description |
|---|---------|-------------|
| 0 | num_input_fields | Total `<input>` elements |
| 1 | num_buttons | Total `<button>` elements |
| 2 | num_forms | Total `<form>` elements |
| 3 | num_tags_within_body | Tags in `<body>` (excluding header) |
| 4 | has_form_with_post | Any form with method=POST |
| 5 | has_form_with_action | Any form with an action attribute |
| 6 | has_password_field | Password input present |
| 7 | has_obfuscated_script | document.write + unescape in scripts |
| 8 | all_flagged_keywords | Count of known phishing indicators |
| 9 | whitelisted_keywords | Count of known legitimate indicators |
| 10 | title_length | Length of `<title>` text |
| 11 | has_password_in_title | Password-related words in title |
| 12 | has_signin_in_title | Sign-in/login words in title |
| 13 | has_suspicious_title | Urgency/verification words in title |
| 14 | crypto_keywords | Count of crypto/seed phrase terms |
| 15 | wallet_keywords | Count of wallet brand names |
| 16 | has_generic_title | Title is very short or generic |
