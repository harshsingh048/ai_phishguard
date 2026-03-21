"""
PhishGuard AI - Auth Routes
"""
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from auth.auth_service import AuthService

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/register', methods=['POST'])
def register():
    """
    Register new user.
    POST /api/auth/register
    Body: {"username": ..., "email": ..., "password": ...}
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    result = AuthService.register(
        username=data.get('username', ''),
        email=data.get('email', ''),
        password=data.get('password', '')
    )

    if result.get('success'):
        return jsonify(result), 201
    return jsonify(result), 400


@auth_bp.route('/login', methods=['POST'])
def login():
    """
    Login user.
    POST /api/auth/login
    Body: {"username": ..., "password": ...}
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    result = AuthService.login(
        username_or_email=data.get('username', data.get('email', '')),
        password=data.get('password', '')
    )

    if result.get('success'):
        return jsonify(result), 200
    return jsonify(result), 401


@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def me():
    """Get current user profile."""
    user_id = int(get_jwt_identity())
    user = AuthService.get_user_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"user": user.to_dict()}), 200


@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """Logout (client should delete token)."""
    return jsonify({"success": True, "message": "Logged out successfully"}), 200
