"""
PhishGuard AI - BERT Model Service (Deep Mode Only)
Uses DistilBERT for deep text classification.
"""
import logging
import re

logger = logging.getLogger(__name__)

_bert_pipeline = None
_bert_loaded = False
_bert_available = False


def load_bert_model():
    """Load DistilBERT model (lazy loading)."""
    global _bert_pipeline, _bert_loaded, _bert_available

    if _bert_loaded:
        return _bert_available

    _bert_loaded = True

    try:
        from transformers import pipeline
        logger.info("Loading DistilBERT model... (this may take a minute)")
        _bert_pipeline = pipeline(
            "text-classification",
            model="distilbert-base-uncased-finetuned-sst-2-english",
            truncation=True,
            max_length=512
        )
        _bert_available = True
        logger.info("DistilBERT loaded successfully")
        return True
    except ImportError:
        logger.warning("transformers library not installed. BERT disabled.")
        _bert_available = False
        return False
    except Exception as e:
        logger.error(f"Failed to load BERT model: {e}")
        _bert_available = False
        return False


def predict_bert(text: str) -> dict:
    """
    Run DistilBERT on text.
    Returns dict with score and confidence.
    Note: Base model used as proxy; in production, fine-tune on phishing data.
    """
    global _bert_pipeline

    if not _bert_available or _bert_pipeline is None:
        return {"available": False, "score": None}

    try:
        # Truncate to BERT limit
        words = text.split()
        if len(words) > 400:
            text = ' '.join(words[:400])

        # Remove URLs for cleaner text analysis
        text_clean = re.sub(r'http\S+', '[URL]', text)

        result = _bert_pipeline(text_clean)[0]

        # Map sentiment to phishing score
        # NEGATIVE sentiment = potentially malicious/alarming language
        label = result['label']
        confidence = result['score']

        if label == 'NEGATIVE':
            # High negative sentiment correlates with threatening/urgent phishing language
            bert_score = confidence * 70  # scale to 0-70
        else:
            bert_score = (1 - confidence) * 30  # low positive still has some risk

        return {
            "available": True,
            "score": round(bert_score, 2),
            "label": label,
            "confidence": round(confidence, 3),
            "raw_label": label
        }

    except Exception as e:
        logger.error(f"BERT prediction failed: {e}")
        return {"available": False, "score": None, "error": str(e)}
