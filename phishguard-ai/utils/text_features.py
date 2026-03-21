"""
PhishGuard AI - Text Feature Extractor
Analyzes messages and emails for phishing/scam patterns.
"""
import re
import logging

logger = logging.getLogger(__name__)

# Phishing/scam indicators
URGENCY_PHRASES = [
    'act now', 'urgent', 'immediately', 'limited time', 'expires soon',
    'within 24 hours', 'account suspended', 'verify now', 'click immediately',
    'respond now', 'action required', 'your account will be', 'last chance',
    'final notice', 'time sensitive', 'don\'t delay', 'as soon as possible'
]

REWARD_PHRASES = [
    'you have won', 'congratulations', 'you\'ve been selected', 'free gift',
    'claim your prize', 'lucky winner', 'cash prize', 'unclaimed funds',
    'lottery winner', 'you are winner', '$1000', '$500', 'million dollars',
    'guaranteed', 'no risk', '100% free', 'risk-free', 'you qualify'
]

THREAT_PHRASES = [
    'account will be suspended', 'account has been compromised', 'suspicious activity',
    'unauthorized access', 'your password has been', 'security breach',
    'your account may be', 'we have detected', 'unusual sign-in', 'verify your identity'
]

CREDENTIAL_PHRASES = [
    'enter your password', 'confirm your details', 'update your information',
    'verify your account', 'provide your credit card', 'social security number',
    'bank account number', 'billing information', 'payment details',
    'confirm your identity', 'validate your account'
]

BRAND_IMPERSONATION = [
    'paypal', 'amazon', 'google', 'microsoft', 'apple', 'netflix', 'facebook',
    'instagram', 'bank of america', 'chase bank', 'wells fargo', 'citibank',
    'irs', 'social security', 'medicare', 'fedex', 'ups', 'usps', 'dhl'
]

SUSPICIOUS_LINKS = [
    'click here', 'click the link', 'visit this link', 'follow this link',
    'tap here', 'open this link', 'go to', 'navigate to'
]


def extract_text_features(text: str) -> dict:
    """Extract features from message text."""
    features = {}
    text_lower = text.lower()
    words = re.findall(r'\b\w+\b', text_lower)
    sentences = re.split(r'[.!?]+', text)

    # Feature 1: Text length
    features['text_length'] = len(text)

    # Feature 2: Urgency score
    urgency_count = sum(1 for phrase in URGENCY_PHRASES if phrase in text_lower)
    features['urgency_score'] = urgency_count

    # Feature 3: Reward/bait phrases
    reward_count = sum(1 for phrase in REWARD_PHRASES if phrase in text_lower)
    features['reward_score'] = reward_count

    # Feature 4: Threat phrases
    threat_count = sum(1 for phrase in THREAT_PHRASES if phrase in text_lower)
    features['threat_score'] = threat_count

    # Feature 5: Credential request
    cred_count = sum(1 for phrase in CREDENTIAL_PHRASES if phrase in text_lower)
    features['credential_request'] = cred_count

    # Feature 6: Brand impersonation
    brand_count = sum(1 for brand in BRAND_IMPERSONATION if brand in text_lower)
    features['brand_impersonation'] = brand_count

    # Feature 7: URL count in text
    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
    features['url_count'] = len(urls)

    # Feature 8: Suspicious link phrases
    link_phrases = sum(1 for phrase in SUSPICIOUS_LINKS if phrase in text_lower)
    features['suspicious_link_phrases'] = link_phrases

    # Feature 9: Exclamation marks
    features['exclamation_count'] = text.count('!')

    # Feature 10: ALL CAPS words
    caps_words = [w for w in words if w.isupper() and len(w) > 2]
    features['caps_word_count'] = len(caps_words)

    # Feature 11: Money symbols/mentions
    money_pattern = r'\$[\d,]+|\d+\s*dollars?|€[\d,]+|£[\d,]+'
    features['money_mentions'] = len(re.findall(money_pattern, text_lower))

    # Feature 12: Phone number presence
    phone_pattern = r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'
    features['has_phone'] = 1 if re.search(phone_pattern, text) else 0

    # Feature 13: Unusual greeting
    impersonal_greetings = ['dear customer', 'dear user', 'dear account holder',
                            'dear valued member', 'hello friend', 'dear beneficiary']
    features['impersonal_greeting'] = 1 if any(g in text_lower for g in impersonal_greetings) else 0

    # Feature 14: Grammar quality (rough heuristic)
    # Count repeated punctuation or common grammar errors
    grammar_issues = len(re.findall(r'[!?]{2,}|\s{3,}|[A-Z]{5,}', text))
    features['grammar_issues'] = grammar_issues

    # Feature 15: Sender spoofing indicators
    spoofing = ['no-reply', 'noreply', 'donotreply', 'do-not-reply', 'support@', 'security@']
    features['spoofing_indicator'] = 1 if any(s in text_lower for s in spoofing) else 0

    return features


def get_rule_based_score(text: str) -> tuple[float, list, list]:
    """
    Pure rule-based text scoring.
    Returns (score, triggered_rules, highlighted_phrases).
    """
    score = 0.0
    triggered = []
    highlights = []
    text_lower = text.lower()
    features = extract_text_features(text)

    if features['urgency_score'] > 0:
        score += min(25, features['urgency_score'] * 10)
        triggered.append(f"Urgency language detected ({features['urgency_score']} phrases)")
        highlights.extend([p for p in URGENCY_PHRASES if p in text_lower])

    if features['reward_score'] > 0:
        score += min(25, features['reward_score'] * 10)
        triggered.append(f"Reward/bait language detected ({features['reward_score']} phrases)")
        highlights.extend([p for p in REWARD_PHRASES if p in text_lower])

    if features['threat_score'] > 0:
        score += min(20, features['threat_score'] * 10)
        triggered.append(f"Threat/fear language detected ({features['threat_score']} phrases)")
        highlights.extend([p for p in THREAT_PHRASES if p in text_lower])

    if features['credential_request'] > 0:
        score += min(25, features['credential_request'] * 12)
        triggered.append(f"Credential request detected")
        highlights.extend([p for p in CREDENTIAL_PHRASES if p in text_lower])

    if features['brand_impersonation'] > 0:
        score += 15
        triggered.append(f"Brand impersonation detected")

    if features['url_count'] > 0:
        score += min(15, features['url_count'] * 5)
        triggered.append(f"Contains {features['url_count']} URL(s)")

    if features['impersonal_greeting']:
        score += 10
        triggered.append("Impersonal greeting (mass phishing indicator)")

    if features['caps_word_count'] > 5:
        score += 8
        triggered.append(f"Excessive capitalization ({features['caps_word_count']} caps words)")

    if features['exclamation_count'] > 3:
        score += 5
        triggered.append(f"Multiple exclamation marks ({features['exclamation_count']})")

    if features['money_mentions'] > 0:
        score += 8
        triggered.append(f"Financial lure detected ({features['money_mentions']} money mentions)")

    if features['grammar_issues'] > 2:
        score += 5
        triggered.append("Poor grammar/formatting (common in scam messages)")

    return min(100.0, score), triggered, list(set(highlights[:10]))


def highlight_text_spans(text: str) -> list:
    """
    Return list of spans to highlight in text.
    Each span: {start, end, text, category}
    """
    spans = []
    text_lower = text.lower()
    all_patterns = [
        (URGENCY_PHRASES, 'urgency'),
        (REWARD_PHRASES, 'reward'),
        (THREAT_PHRASES, 'threat'),
        (CREDENTIAL_PHRASES, 'credential'),
    ]

    for phrases, category in all_patterns:
        for phrase in phrases:
            start = 0
            while True:
                idx = text_lower.find(phrase, start)
                if idx == -1:
                    break
                spans.append({
                    "start": idx,
                    "end": idx + len(phrase),
                    "text": text[idx:idx + len(phrase)],
                    "category": category
                })
                start = idx + 1

    # Sort by start position, remove overlaps
    spans.sort(key=lambda x: x['start'])
    return spans[:20]  # Limit to 20 highlights


def detect_input_type(text: str) -> str:
    """
    Automatically detect if input is URL or text message.
    Returns 'url' or 'text'.
    """
    text_stripped = text.strip()

    # URL patterns
    url_patterns = [
        r'^https?://',
        r'^www\.',
        r'^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(/|$)',
        r'^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\.[a-zA-Z]{2,}',
    ]

    for pattern in url_patterns:
        if re.match(pattern, text_stripped, re.IGNORECASE):
            return 'url'

    # If text has spaces and is longer than 30 chars → text
    if ' ' in text_stripped and len(text_stripped) > 30:
        return 'text'

    # Single word with TLD → URL
    if re.match(r'^[^\s]+\.[a-zA-Z]{2,4}(/[^\s]*)?$', text_stripped):
        return 'url'

    return 'text'
