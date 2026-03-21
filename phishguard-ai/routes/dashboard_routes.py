"""
PhishGuard AI - Dashboard Routes
"""
import logging
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity, verify_jwt_in_request

from database.db import db, Scan, User

logger = logging.getLogger(__name__)
dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/dashboard', methods=['GET'])
def dashboard():
    """
    Get dashboard statistics.
    GET /api/dashboard
    Optional JWT for user-specific stats.
    """
    user_id = None
    try:
        verify_jwt_in_request(optional=True)
        identity = get_jwt_identity()
        if identity:
            user_id = int(identity)
    except Exception:
        pass

    try:
        # Global stats
        total_scans = Scan.query.count()
        dangerous = Scan.query.filter_by(classification='Dangerous').count()
        suspicious = Scan.query.filter_by(classification='Suspicious').count()
        safe = Scan.query.filter_by(classification='Safe').count()

        dangerous_pct = round((dangerous / total_scans * 100), 1) if total_scans > 0 else 0
        suspicious_pct = round((suspicious / total_scans * 100), 1) if total_scans > 0 else 0
        safe_pct = round((safe / total_scans * 100), 1) if total_scans > 0 else 0

        # Recent scans (last 10)
        recent_scans = Scan.query.order_by(Scan.timestamp.desc()).limit(10).all()

        # Last 7 days trend
        seven_days_ago = datetime.utcnow() - timedelta(days=7)
        trend_data = []
        for i in range(7):
            day = seven_days_ago + timedelta(days=i)
            day_start = day.replace(hour=0, minute=0, second=0)
            day_end = day_start + timedelta(days=1)
            count = Scan.query.filter(
                Scan.timestamp >= day_start,
                Scan.timestamp < day_end
            ).count()
            trend_data.append({
                "date": day.strftime('%m/%d'),
                "count": count
            })

        # URL vs text breakdown
        url_count = Scan.query.filter_by(input_type='url').count()
        text_count = Scan.query.filter_by(input_type='text').count()

        # Average risk score
        from sqlalchemy import func
        avg_score = db.session.query(func.avg(Scan.risk_score)).scalar()
        avg_score = round(float(avg_score), 1) if avg_score else 0

        # User-specific stats
        user_stats = None
        if user_id:
            user_scans = Scan.query.filter_by(user_id=user_id).count()
            user_dangerous = Scan.query.filter_by(user_id=user_id, classification='Dangerous').count()
            user_recent = Scan.query.filter_by(user_id=user_id).order_by(Scan.timestamp.desc()).limit(5).all()
            user_stats = {
                "total_scans": user_scans,
                "dangerous": user_dangerous,
                "recent": [s.to_dict() for s in user_recent]
            }

        # Attack map data (recent scans with timestamps for visualization)
        attack_map = []
        for scan in recent_scans:
            if scan.classification in ('Dangerous', 'Suspicious'):
                attack_map.append({
                    "id": scan.id,
                    "type": scan.input_type,
                    "classification": scan.classification,
                    "risk_score": scan.risk_score,
                    "timestamp": scan.timestamp.isoformat()
                })

        return jsonify({
            "stats": {
                "total_scans": total_scans,
                "dangerous": dangerous,
                "suspicious": suspicious,
                "safe": safe,
                "dangerous_pct": dangerous_pct,
                "suspicious_pct": suspicious_pct,
                "safe_pct": safe_pct,
                "avg_risk_score": avg_score
            },
            "breakdown": {
                "url_scans": url_count,
                "text_scans": text_count
            },
            "trend": trend_data,
            "recent_scans": [s.to_dict() for s in recent_scans],
            "attack_map": attack_map,
            "user_stats": user_stats
        }), 200

    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return jsonify({"error": "Failed to load dashboard"}), 500


@dashboard_bp.route('/history', methods=['GET'])
@jwt_required()
def scan_history():
    """Get paginated scan history for authenticated user."""
    user_id = int(get_jwt_identity())
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    per_page = min(per_page, 100)

    try:
        pagination = Scan.query.filter_by(user_id=user_id)\
            .order_by(Scan.timestamp.desc())\
            .paginate(page=page, per_page=per_page, error_out=False)

        return jsonify({
            "scans": [s.to_dict() for s in pagination.items],
            "total": pagination.total,
            "pages": pagination.pages,
            "current_page": page
        }), 200
    except Exception as e:
        logger.error(f"History error: {e}")
        return jsonify({"error": "Failed to load history"}), 500
