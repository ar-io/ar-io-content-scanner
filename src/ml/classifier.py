from __future__ import annotations

import logging

import numpy as np
import xgboost as xgb

from src.ml.features import HtmlFeatures

logger = logging.getLogger("scanner.ml")


class PhishingClassifier:
    def __init__(self, model_path: str):
        self._model = xgb.Booster()
        self._model.load_model(model_path)
        logger.info("XGBoost model loaded", extra={"model_path": model_path})

    def predict_score(self, features: HtmlFeatures) -> float:
        vector = np.array([features.to_vector()])
        dmat = xgb.DMatrix(vector)
        score = self._model.predict(dmat)
        return float(score[0])
