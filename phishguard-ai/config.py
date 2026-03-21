"""
PhishGuard AI - Configuration
"""
import os
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    # Flask
    SECRET_KEY = os.environ.get('SECRET_KEY', 'phishguard-secret-key-2024-change-in-production')
    DEBUG = False

    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL',
        f'sqlite:///{os.path.join(BASE_DIR, "database", "phishguard.db")}'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"connect_args": {"check_same_thread": False}}

    # JWT
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'jwt-phishguard-secret-2024')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)

    # Models
    MODELS_DIR = os.path.join(BASE_DIR, 'models')
    URL_MODEL_PATH = os.path.join(MODELS_DIR, 'url_model.pkl')
    URL_SCALER_PATH = os.path.join(MODELS_DIR, 'url_scaler.pkl')
    TEXT_MODEL_PATH = os.path.join(MODELS_DIR, 'text_model.pkl')
    TEXT_VECTORIZER_PATH = os.path.join(MODELS_DIR, 'text_vectorizer.pkl')

    # Reports
    REPORTS_DIR = os.path.join(BASE_DIR, 'reports')

    # Rate limiting
    RATE_LIMIT_PER_MINUTE = 30

    # External APIs (optional - fallback logic built in)
    PHISHTANK_API_KEY = os.environ.get('PHISHTANK_API_KEY', '')
    GOOGLE_SAFE_BROWSING_KEY = os.environ.get('GOOGLE_SAFE_BROWSING_KEY', '')
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')

    # Scan settings
    MAX_INPUT_LENGTH = 5000
    BERT_MAX_TOKENS = 512
    CACHE_MAX_SIZE = 1000

    # Risk thresholds
    SAFE_THRESHOLD = 30
    SUSPICIOUS_THRESHOLD = 60


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False
