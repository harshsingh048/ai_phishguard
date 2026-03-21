"""
PhishGuard AI - Database Models
"""
import os
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

    scans = db.relationship('Scan', backref='user', lazy='dynamic')

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "created_at": self.created_at.isoformat(),
            "scan_count": self.scans.count()
        }

    def __repr__(self):
        return f'<User {self.username}>'


class Scan(db.Model):
    __tablename__ = 'scans'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    input_text = db.Column(db.Text, nullable=False)
    input_type = db.Column(db.String(20), nullable=False)  # 'url' or 'text'
    risk_score = db.Column(db.Float, nullable=False)
    classification = db.Column(db.String(20), nullable=False)  # safe/suspicious/dangerous
    scan_mode = db.Column(db.String(10), default='fast')  # fast/deep
    explanation = db.Column(db.Text, nullable=True)
    features = db.Column(db.Text, nullable=True)  # JSON string
    ip_address = db.Column(db.String(45), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "input_text": self.input_text[:100] + "..." if len(self.input_text) > 100 else self.input_text,
            "input_type": self.input_type,
            "risk_score": self.risk_score,
            "classification": self.classification,
            "scan_mode": self.scan_mode,
            "timestamp": self.timestamp.isoformat()
        }

    def __repr__(self):
        return f'<Scan {self.id} - {self.classification}>'


class ThreatFeed(db.Model):
    __tablename__ = 'threat_feeds'

    id = db.Column(db.Integer, primary_key=True)
    indicator = db.Column(db.String(500), nullable=False, index=True)
    indicator_type = db.Column(db.String(20), nullable=False)  # url/domain/ip
    threat_type = db.Column(db.String(50), nullable=False)
    source = db.Column(db.String(100), nullable=True)
    confidence = db.Column(db.Float, default=1.0)
    added_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "indicator": self.indicator,
            "type": self.indicator_type,
            "threat": self.threat_type,
            "confidence": self.confidence
        }


def init_db():
    """Initialize database tables and seed threat feed."""
    os.makedirs(os.path.dirname('database/'), exist_ok=True)
    db.create_all()
    _seed_threat_feed()


def _seed_threat_feed():
    """Seed known phishing domains."""
    if ThreatFeed.query.count() > 0:
        return

    known_threats = [
        ("paypa1.com", "domain", "phishing", "manual"),
        ("amazon-security-alert.com", "domain", "phishing", "manual"),
        ("secure-banking-update.com", "domain", "phishing", "manual"),
        ("login-facebook-verify.com", "domain", "phishing", "manual"),
        ("apple-id-suspended.com", "domain", "phishing", "manual"),
        ("netflix-billing-update.net", "domain", "phishing", "manual"),
        ("account-google-security.com", "domain", "phishing", "manual"),
        ("microsoft-security-alert.xyz", "domain", "phishing", "manual"),
        ("irs-tax-refund-2024.com", "domain", "phishing", "manual"),
        ("verify-your-paypal-account.com", "domain", "phishing", "manual"),
    ]

    for indicator, itype, threat, source in known_threats:
        feed = ThreatFeed(
            indicator=indicator,
            indicator_type=itype,
            threat_type=threat,
            source=source,
            confidence=0.95
        )
        db.session.add(feed)

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
