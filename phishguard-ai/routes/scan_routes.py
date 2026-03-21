"""
PhishGuard AI - Scan Routes
"""
import logging
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity, verify_jwt_in_request

from services.scan_service import scan_input, scan_batch
from services.report_service import generate_json_report, generate_pdf_report
from services.cache import scan_cache
from config import Config

logger = logging.getLogger(__name__)

scan_bp = Blueprint('scan', __name__)

# Simple in-memory rate limiter
from collections import defaultdict
import time
_rate_limit_store = defaultdict(list)

def check_rate_limit(ip: str, limit: int = 30) -> bool:
    """Check if IP exceeds rate limit (per minute)."""
    now = time.time()
    window = 60  # 1 minute
    _rate_limit_store[ip] = [t for t in _rate_limit_store[ip] if now - t < window]
    if len(_rate_limit_store[ip]) >= limit:
        return False
    _rate_limit_store[ip].append(now)
    return True


@scan_bp.route('/scan', methods=['POST'])
def scan():
    """
    Main scan endpoint.
    POST /api/scan
    Body: {"input": "url or message", "mode": "fast|deep"}
    """
    # Get client IP
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)

    # Rate limiting
    if not check_rate_limit(ip):
        return jsonify({"error": "Rate limit exceeded. Please wait."}), 429

    # Optional JWT (scan works without auth)
    user_id = None
    try:
        verify_jwt_in_request(optional=True)
        identity = get_jwt_identity()
        if identity:
            user_id = int(identity)
    except Exception:
        pass

    # Parse request
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON body"}), 400

    input_text = data.get('input', '').strip()
    mode = data.get('mode', 'fast').lower()

    if not input_text:
        return jsonify({"error": "Input is required"}), 400

    if len(input_text) > Config.MAX_INPUT_LENGTH:
        return jsonify({"error": f"Input too long (max {Config.MAX_INPUT_LENGTH} chars)"}), 400

    if mode not in ('fast', 'deep'):
        mode = 'fast'

    try:
        result = scan_input(input_text, mode=mode, user_id=user_id, ip=ip)
        if 'error' in result:
            return jsonify(result), 400
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Scan error: {e}")
        return jsonify({"error": "Scan failed. Please try again."}), 500


@scan_bp.route('/batch', methods=['POST'])
@jwt_required()
def batch_scan():
    """
    Batch scan endpoint (requires auth).
    POST /api/batch
    Body: {"inputs": ["url1", "msg1", ...], "mode": "fast|deep"}
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    inputs = data.get('inputs', [])
    mode = data.get('mode', 'fast')
    user_id = int(get_jwt_identity())

    if not inputs or not isinstance(inputs, list):
        return jsonify({"error": "inputs must be a non-empty array"}), 400

    if len(inputs) > 20:
        return jsonify({"error": "Maximum 20 inputs per batch"}), 400

    try:
        results = scan_batch(inputs, mode=mode, user_id=user_id)
        return jsonify({
            "total": len(results),
            "results": results
        }), 200
    except Exception as e:
        logger.error(f"Batch scan error: {e}")
        return jsonify({"error": "Batch scan failed"}), 500


@scan_bp.route('/report', methods=['POST'])
def generate_report():
    """Generate downloadable report for a scan result."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    report_type = data.get('type', 'json').lower()
    scan_result = data.get('scan_result', {})

    if not scan_result:
        return jsonify({"error": "scan_result is required"}), 400

    try:
        if report_type == 'pdf':
            result = generate_pdf_report(scan_result)
        else:
            result = generate_json_report(scan_result)

        if result.get('success'):
            return jsonify({
                "success": True,
                "filename": result['filename'],
                "message": f"{report_type.upper()} report generated"
            }), 200
        else:
            return jsonify({"success": False, "error": result.get('error')}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@scan_bp.route('/cache/stats', methods=['GET'])
def cache_stats():
    """Get cache statistics."""
    return jsonify(scan_cache.stats()), 200
