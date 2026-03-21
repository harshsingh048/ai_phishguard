"""
PhishGuard AI - ML Model Service
Loads trained models once and provides prediction interface.
"""
import os
import pickle
import logging
import numpy as np

from config import Config
from utils.url_features import get_feature_vector, get_rule_based_score as url_rules, extract_url_features
from utils.text_features import get_rule_based_score as text_rules, extract_text_features

logger = logging.getLogger(__name__)


class ModelService:
    """Singleton ML model service. Load once, predict many."""

    _instance = None
    _url_model = None
    _url_scaler = None
    _text_model = None
    _text_vectorizer = None
    _models_loaded = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def load_models(self):
        """Load all models from disk."""
        if self._models_loaded:
            return True

        success = True

        # Load URL model
        try:
            if os.path.exists(Config.URL_MODEL_PATH):
                with open(Config.URL_MODEL_PATH, 'rb') as f:
                    self._url_model = pickle.load(f)
                with open(Config.URL_SCALER_PATH, 'rb') as f:
                    self._url_scaler = pickle.load(f)
                logger.info("URL model loaded successfully")
            else:
                logger.warning("URL model not found - using rule-based only")
                success = False
        except Exception as e:
            logger.error(f"Failed to load URL model: {e}")
            success = False

        # Load text model
        try:
            if os.path.exists(Config.TEXT_MODEL_PATH):
                with open(Config.TEXT_MODEL_PATH, 'rb') as f:
                    self._text_model = pickle.load(f)
                with open(Config.TEXT_VECTORIZER_PATH, 'rb') as f:
                    self._text_vectorizer = pickle.load(f)
                logger.info("Text model loaded successfully")
            else:
                logger.warning("Text model not found - using rule-based only")
                success = False
        except Exception as e:
            logger.error(f"Failed to load text model: {e}")
            success = False

        self._models_loaded = True
        return success

    def predict_url(self, url: str) -> dict:
        """
        Predict phishing probability for a URL.
        Returns dict with ml_score, rule_score, features, explanations.
        """
        # Rule-based score (always available)
        rule_score, rule_triggers = url_rules(url)
        features = extract_url_features(url)

        ml_score = None
        ml_confidence = None

        # ML model prediction
        if self._url_model and self._url_scaler:
            try:
                feature_vector = np.array(get_feature_vector(url)).reshape(1, -1)
                scaled = self._url_scaler.transform(feature_vector)
                proba = self._url_model.predict_proba(scaled)[0]
                # proba[1] = probability of phishing class
                ml_score = float(proba[1]) * 100
                ml_confidence = float(max(proba))

                # Feature importance (if RandomForest)
                if hasattr(self._url_model, 'feature_importances_'):
                    importances = self._url_model.feature_importances_
                    feature_names = list(features.keys())
                    top_features = sorted(
                        zip(feature_names, importances, get_feature_vector(url)),
                        key=lambda x: x[1], reverse=True
                    )[:5]
                    importance_list = [
                        {"feature": f, "importance": round(i, 3), "value": v}
                        for f, i, v in top_features
                    ]
                else:
                    importance_list = []

            except Exception as e:
                logger.error(f"URL ML prediction failed: {e}")
                ml_score = None
                importance_list = []
        else:
            importance_list = []

        # Ensemble score
        if ml_score is not None:
            final_score = 0.55 * ml_score + 0.45 * rule_score
        else:
            final_score = rule_score

        return {
            "ml_score": round(ml_score, 2) if ml_score else None,
            "rule_score": round(rule_score, 2),
            "final_score": round(min(100, final_score), 2),
            "triggered_rules": rule_triggers,
            "top_features": importance_list,
            "ml_available": ml_score is not None
        }

    def predict_text(self, text: str) -> dict:
        """
        Predict phishing probability for text message.
        Returns dict with ml_score, rule_score, highlights.
        """
        rule_score, rule_triggers, highlights = text_rules(text)
        features = extract_text_features(text)

        ml_score = None

        if self._text_model and self._text_vectorizer:
            try:
                vec = self._text_vectorizer.transform([text])
                proba = self._text_model.predict_proba(vec)[0]
                ml_score = float(proba[1]) * 100
            except Exception as e:
                logger.error(f"Text ML prediction failed: {e}")
                ml_score = None

        # Ensemble
        if ml_score is not None:
            final_score = 0.55 * ml_score + 0.45 * rule_score
        else:
            final_score = rule_score

        return {
            "ml_score": round(ml_score, 2) if ml_score else None,
            "rule_score": round(rule_score, 2),
            "final_score": round(min(100, final_score), 2),
            "triggered_rules": rule_triggers,
            "highlighted_phrases": highlights,
            "ml_available": ml_score is not None
        }

    def models_loaded(self) -> bool:
        return self._models_loaded


# Global singleton
model_service = ModelService()
