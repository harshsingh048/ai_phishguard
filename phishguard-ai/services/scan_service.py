"""
PhishGuard AI - Scan Orchestrator
Combines all detection modules into unified scan result.
"""
import time
import json
import logging
from datetime import datetime

from services.cache import scan_cache
from services.model_service import model_service
from utils.text_features import detect_input_type, highlight_text_spans
from utils.url_features import highlight_url_parts
from config import Config

logger = logging.getLogger(__name__)


def classify_risk(score: float) -> dict:
    """Convert numeric score to classification with emoji and color."""
    if score < Config.SAFE_THRESHOLD:
        return {
            "label": "Safe",
            "emoji": "✅",
            "color": "green",
            "css_class": "safe",
            "description": "This content appears to be safe."
        }
    elif score < Config.SUSPICIOUS_THRESHOLD:
        return {
            "label": "Suspicious",
            "emoji": "⚠️",
            "color": "yellow",
            "css_class": "suspicious",
            "description": "This content shows some suspicious characteristics. Proceed with caution."
        }
    else:
        return {
            "label": "Dangerous",
            "emoji": "🚨",
            "color": "red",
            "css_class": "dangerous",
            "description": "This content is likely malicious. Do not click or respond."
        }


def get_safety_suggestions(score: float, input_type: str, triggered_rules: list) -> list:
    """Generate contextual safety suggestions based on risk level."""
    suggestions = []

    if score >= Config.SUSPICIOUS_THRESHOLD:
        if input_type == 'url':
            suggestions.extend([
                {"icon": "🚫", "action": "Do not visit this URL", "priority": "critical"},
                {"icon": "🛡️", "action": "Report as phishing to your browser", "priority": "high"},
                {"icon": "🔒", "action": "Check site certificate before proceeding", "priority": "high"},
            ])
        else:
            suggestions.extend([
                {"icon": "🗑️", "action": "Delete this message immediately", "priority": "critical"},
                {"icon": "🚫", "action": "Do not click any links in this message", "priority": "critical"},
                {"icon": "🚨", "action": "Report as spam/phishing", "priority": "high"},
                {"icon": "🔇", "action": "Block the sender", "priority": "high"},
            ])

        # Rule-specific suggestions
        if any("credential" in r.lower() for r in triggered_rules):
            suggestions.append({"icon": "🔑", "action": "Never share passwords or personal info", "priority": "critical"})
        if any("brand" in r.lower() or "impersonat" in r.lower() for r in triggered_rules):
            suggestions.append({"icon": "✉️", "action": "Contact the real company directly via official website", "priority": "high"})

    elif score >= Config.SAFE_THRESHOLD:
        suggestions.extend([
            {"icon": "⚠️", "action": "Proceed with caution", "priority": "medium"},
            {"icon": "🔍", "action": "Verify sender identity independently", "priority": "medium"},
            {"icon": "🔒", "action": "Don't provide sensitive information", "priority": "medium"},
        ])
    else:
        suggestions.extend([
            {"icon": "✅", "action": "Content appears safe", "priority": "info"},
            {"icon": "💡", "action": "Always stay vigilant online", "priority": "info"},
        ])

    return suggestions


def scan_input(input_text: str, mode: str = 'fast', user_id: int = None, ip: str = None) -> dict:
    """
    Main scan function. Orchestrates all detection modules.

    Args:
        input_text: URL or text message to scan
        mode: 'fast' (ML + rules) or 'deep' (+ WHOIS + BERT)
        user_id: Optional authenticated user ID
        ip: Client IP for logging

    Returns:
        Complete scan result dict
    """
    start_time = time.time()

    # Input validation
    if not input_text or not input_text.strip():
        return {"error": "Empty input provided"}

    input_text = input_text.strip()[:Config.MAX_INPUT_LENGTH]

    # Check cache
    cached = scan_cache.get(input_text, mode)
    if cached:
        cached['from_cache'] = True
        _save_scan_to_db(input_text, cached, user_id, ip, mode)
        return cached

    # Auto-detect input type
    input_type = detect_input_type(input_text)

    # Load models if not loaded
    if not model_service.models_loaded():
        model_service.load_models()

    result = {
        "input": input_text,
        "input_type": input_type,
        "mode": mode,
        "timestamp": datetime.utcnow().isoformat(),
        "from_cache": False
    }

    # ─── FAST MODE: ML + Rules ─────────────────────────────────────────
    if input_type == 'url':
        prediction = model_service.predict_url(input_text)
        highlights = highlight_url_parts(input_text)
        result['url_highlights'] = highlights
    else:
        prediction = model_service.predict_text(input_text)
        result['text_highlights'] = highlight_text_spans(input_text)

    base_score = prediction['final_score']
    triggered_rules = prediction.get('triggered_rules', [])

    # ─── DEEP MODE: + WHOIS + Threat Intel + BERT ─────────────────────
    domain_boost = 0
    domain_info = {}
    bert_result = {}

    if mode == 'deep':
        if input_type == 'url':
            try:
                from services.domain_intel import run_deep_domain_analysis
                domain_analysis = run_deep_domain_analysis(input_text)
                domain_boost = domain_analysis.get('score_boost', 0)
                domain_info = domain_analysis.get('domain_data', {})
                triggered_rules.extend(domain_analysis.get('reasons', []))
            except Exception as e:
                logger.error(f"Domain analysis failed: {e}")

        # BERT analysis for text
        if input_type == 'text':
            try:
                from bert_model import predict_bert, load_bert_model, _bert_available
                if not _bert_available:
                    load_bert_model()
                bert_result = predict_bert(input_text)
                if bert_result.get('available') and bert_result.get('score') is not None:
                    # Blend BERT score
                    base_score = 0.4 * base_score + 0.35 * bert_result['score'] + 0.25 * prediction['rule_score']
            except Exception as e:
                logger.error(f"BERT analysis failed: {e}")

    # Final score with domain boost
    final_score = max(0, min(100, base_score + domain_boost))
    classification = classify_risk(final_score)
    suggestions = get_safety_suggestions(final_score, input_type, triggered_rules)

    # Build explanation
    explanation_parts = []
    if triggered_rules:
        explanation_parts.append("Detected issues: " + "; ".join(triggered_rules[:5]))
    if not triggered_rules:
        explanation_parts.append("No significant threats detected.")
    if prediction.get('ml_available'):
        explanation_parts.append(f"ML model confidence: {abs(final_score - 50):.0f}% confident in {classification['label']} classification.")

    elapsed_ms = round((time.time() - start_time) * 1000, 1)

    result.update({
        "risk_score": round(final_score, 1),
        "classification": classification,
        "explanation": " ".join(explanation_parts),
        "triggered_rules": triggered_rules[:10],
        "suggestions": suggestions,
        "top_features": prediction.get('top_features', []),
        "ml_scores": {
            "ml_score": prediction.get('ml_score'),
            "rule_score": prediction.get('rule_score'),
            "bert_score": bert_result.get('score') if bert_result else None,
            "ml_available": prediction.get('ml_available', False)
        },
        "domain_info": domain_info,
        "response_time_ms": elapsed_ms
    })

    # Cache result
    scan_cache.set(input_text, mode, result)

    # Save to database
    _save_scan_to_db(input_text, result, user_id, ip, mode)

    return result


def scan_batch(inputs: list, mode: str = 'fast', user_id: int = None) -> list:
    """Scan multiple inputs in sequence."""
    results = []
    for item in inputs[:20]:  # Limit batch to 20
        try:
            r = scan_input(item, mode, user_id)
            results.append(r)
        except Exception as e:
            results.append({"input": item, "error": str(e)})
    return results


def _save_scan_to_db(input_text: str, result: dict, user_id: int, ip: str, mode: str):
    """Save scan result to database."""
    try:
        from database.db import db, Scan
        scan = Scan(
            user_id=user_id,
            input_text=input_text[:1000],
            input_type=result.get('input_type', 'unknown'),
            risk_score=result.get('risk_score', 0),
            classification=result.get('classification', {}).get('label', 'Unknown'),
            scan_mode=mode,
            explanation=result.get('explanation', '')[:500],
            features=json.dumps(result.get('ml_scores', {}))[:500],
            ip_address=ip
        )
        db.session.add(scan)
        db.session.commit()
    except Exception as e:
        try:
            db.session.rollback()
        except Exception:
            pass
        logger.error(f"Failed to save scan to DB: {e}")
