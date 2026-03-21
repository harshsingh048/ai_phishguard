"""
PhishGuard AI - Authentication Service
"""
import re
import logging
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token

from database.db import db, User

logger = logging.getLogger(__name__)


class AuthService:

    @staticmethod
    def register(username: str, email: str, password: str) -> dict:
        """Register a new user."""
        # Validate inputs
        if not username or len(username) < 3:
            return {"success": False, "error": "Username must be at least 3 characters"}

        if not email or not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            return {"success": False, "error": "Invalid email address"}

        if not password or len(password) < 6:
            return {"success": False, "error": "Password must be at least 6 characters"}

        # Check existing
        if User.query.filter_by(username=username).first():
            return {"success": False, "error": "Username already taken"}

        if User.query.filter_by(email=email).first():
            return {"success": False, "error": "Email already registered"}

        try:
            user = User(
                username=username.strip().lower(),
                email=email.strip().lower(),
                password_hash=generate_password_hash(password),
                created_at=datetime.utcnow()
            )
            db.session.add(user)
            db.session.commit()

            token = create_access_token(identity=str(user.id))
            return {
                "success": True,
                "token": token,
                "user": user.to_dict()
            }
        except Exception as e:
            db.session.rollback()
            logger.error(f"Registration error: {e}")
            return {"success": False, "error": "Registration failed"}

    @staticmethod
    def login(username_or_email: str, password: str) -> dict:
        """Authenticate user."""
        if not username_or_email or not password:
            return {"success": False, "error": "Credentials required"}

        try:
            # Try username or email
            user = User.query.filter(
                (User.username == username_or_email.lower()) |
                (User.email == username_or_email.lower())
            ).first()

            if not user:
                return {"success": False, "error": "Invalid credentials"}

            if not check_password_hash(user.password_hash, password):
                return {"success": False, "error": "Invalid credentials"}

            if not user.is_active:
                return {"success": False, "error": "Account disabled"}

            token = create_access_token(identity=str(user.id))
            return {
                "success": True,
                "token": token,
                "user": user.to_dict()
            }
        except Exception as e:
            logger.error(f"Login error: {e}")
            return {"success": False, "error": "Login failed"}

    @staticmethod
    def get_user_by_id(user_id: int) -> User:
        """Get user by ID."""
        try:
            return User.query.get(user_id)
        except Exception:
            return None
