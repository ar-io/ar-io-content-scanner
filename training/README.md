# ML Model Retraining

## Training Data

Training data accumulates in the content-scanner's Docker volume when operators
use Slack buttons or the admin dashboard:

```
/app/data/training/
├── phishing/     ← "Confirm & Block" button
└── neutral/      ← "Classify Neutral" button
```

### Collecting training data

Copy from the running scanner to your local machine:

```bash
# From the node running the content-scanner
docker cp ar-io-content-scanner:/app/data/training/phishing ./data/phishing
docker cp ar-io-content-scanner:/app/data/training/neutral ./data/neutral
```

Or place existing labeled HTML files directly in `data/phishing/` and `data/neutral/`.

## Retraining

```bash
cd training
python3 train.py
```

This will:
1. Load HTML files from `data/phishing/` and `data/neutral/`
2. Extract 17 features using the production module (`src/ml/features.py`)
3. Perform GridSearchCV hyperparameter tuning (27 combinations, 5-fold CV)
4. Train the final model on the full dataset
5. Evaluate on a 20% holdout test set
6. Save `xgboost_model.pkl` and `model-manifest.json`
7. Verify the model loads correctly in the production Booster format

## Deploying the new model

```bash
# Copy to project root
cp xgboost_model.pkl ../xgboost_model.pkl
cp model-manifest.json ../model-manifest.json

# Rebuild and deploy the container image
# The classifier logs the manifest on startup so you can verify the new model
```

## Classifying uncategorized samples

```bash
# Place HTML files in data/uncategorized/html/
python3 classify.py
# Prints predictions for suspected phishing files
```

## Feature vector

The model uses 17 engineered features defined in `src/ml/features.py`. The training
script imports directly from this production module — there is no separate training
copy. Any change to features requires retraining.

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
