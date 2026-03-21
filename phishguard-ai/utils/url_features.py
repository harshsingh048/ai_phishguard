"""
PhishGuard AI - URL Feature Extractor
Extracts 20 features from URLs for the ML model.
"""
import re
import math
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Known legitimate TLDs
LEGITIMATE_TLDS = {'.com', '.org', '.net', '.edu', '.gov', '.io', '.co', '.uk', '.ca', '.au'}

# Suspicious TLDs commonly used in phishing
SUSPICIOUS_TLDS = {'.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.click', '.link',
                   '.download', '.zip', '.review', '.country', '.stream', '.gdn', '.racing',
                   '.win', '.bid', '.loan', '.party', '.date', '.faith', '.trade', '.accountant'}

# Legitimate brands commonly impersonated
IMPERSONATED_BRANDS = [
    'paypal', 'amazon', 'google', 'facebook', 'microsoft', 'apple', 'netflix',
    'bank', 'chase', 'wellsfargo', 'citibank', 'instagram', 'twitter', 'linkedin',
    'dropbox', 'outlook', 'office365', 'gmail', 'yahoo', 'ebay', 'walmart', 'irs',
    'fedex', 'ups', 'dhl', 'usps', 'covid', 'cdc', 'who'
]

# Suspicious URL keywords
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'update', 'confirm', 'secure', 'account',
    'banking', 'payment', 'password', 'credential', 'suspend', 'locked',
    'urgent', 'alert', 'warning', 'limited', 'expire', 'click', 'free',
    'winner', 'prize', 'reward', 'offer', 'discount', 'deal', 'bonus'
]

# Homoglyph character mappings
HOMOGLYPHS = {
    'a': ['@', '4', 'а'],  # Latin a vs Cyrillic а
    'e': ['3', 'е'],
    'i': ['1', 'l', 'ı'],
    'o': ['0', 'о'],
    's': ['5', '$'],
    'g': ['9'],
    'l': ['1', 'I'],
    'b': ['6'],
}


def extract_url_features(url: str) -> dict:
    """
    Extract 20 features from a URL.
    Returns dict with feature names and values.
    """
    features = {}

    # Normalize URL
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
        full_url = url.lower()

        # Remove port from domain if present
        domain_clean = re.sub(r':\d+', '', domain)
        # Remove www.
        domain_no_www = re.sub(r'^www\.', '', domain_clean)

        # ── Feature 1: URL length ──────────────────────────────────────
        features['url_length'] = len(url)

        # ── Feature 2: Domain length ───────────────────────────────────
        features['domain_length'] = len(domain_no_www)

        # ── Feature 3: Number of subdomains ───────────────────────────
        parts = domain_no_www.split('.')
        features['num_subdomains'] = max(0, len(parts) - 2)

        # ── Feature 4: Has IP address ──────────────────────────────────
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        features['has_ip'] = 1 if re.search(ip_pattern, domain) else 0

        # ── Feature 5: Uses HTTPS ──────────────────────────────────────
        features['is_https'] = 1 if parsed.scheme == 'https' else 0

        # ── Feature 6: URL entropy (randomness) ───────────────────────
        features['url_entropy'] = _calculate_entropy(full_url)

        # ── Feature 7: Number of special chars ────────────────────────
        special_chars = re.findall(r'[@!#$%^&*()+=\[\]{};\':"\\|,<>\?]', url)
        features['num_special_chars'] = len(special_chars)

        # ── Feature 8: Number of dots ─────────────────────────────────
        features['num_dots'] = url.count('.')

        # ── Feature 9: Number of hyphens ──────────────────────────────
        features['num_hyphens'] = url.count('-')

        # ── Feature 10: Number of digits ──────────────────────────────
        features['num_digits'] = sum(c.isdigit() for c in url)

        # ── Feature 11: Suspicious TLD ────────────────────────────────
        tld = '.' + parts[-1] if parts else ''
        features['suspicious_tld'] = 1 if tld in SUSPICIOUS_TLDS else 0

        # ── Feature 12: Contains brand name (impersonation check) ──────
        features['has_brand_name'] = 1 if any(brand in domain_no_www for brand in IMPERSONATED_BRANDS) else 0

        # ── Feature 13: Suspicious keywords in URL ────────────────────
        keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in full_url)
        features['suspicious_keyword_count'] = keyword_count

        # ── Feature 14: URL path depth ─────────────────────────────────
        path_parts = [p for p in path.split('/') if p]
        features['path_depth'] = len(path_parts)

        # ── Feature 15: Has port number ───────────────────────────────
        features['has_port'] = 1 if ':' in domain and not domain.endswith(':443') and not domain.endswith(':80') else 0

        # ── Feature 16: Query string length ───────────────────────────
        features['query_length'] = len(query)

        # ── Feature 17: Number of query params ────────────────────────
        features['num_query_params'] = len(query.split('&')) if query else 0

        # ── Feature 18: Homoglyph detection ───────────────────────────
        features['has_homoglyph'] = 1 if _detect_homoglyphs(domain_no_www) else 0

        # ── Feature 19: Domain digit ratio ────────────────────────────
        if len(domain_no_www) > 0:
            features['domain_digit_ratio'] = sum(c.isdigit() for c in domain_no_www) / len(domain_no_www)
        else:
            features['domain_digit_ratio'] = 0.0

        # ── Feature 20: Has redirect pattern ──────────────────────────
        redirect_patterns = ['redirect', 'url=', 'link=', 'goto=', 'redir=', 'forward=']
        features['has_redirect'] = 1 if any(p in full_url for p in redirect_patterns) else 0

    except Exception as e:
        logger.error(f"Feature extraction error for URL {url}: {e}")
        # Return default features if parsing fails
        features = {f'feature_{i}': 0 for i in range(20)}

    return features


def get_feature_vector(url: str) -> list:
    """Return features as ordered list for ML model."""
    features = extract_url_features(url)
    feature_order = [
        'url_length', 'domain_length', 'num_subdomains', 'has_ip', 'is_https',
        'url_entropy', 'num_special_chars', 'num_dots', 'num_hyphens', 'num_digits',
        'suspicious_tld', 'has_brand_name', 'suspicious_keyword_count', 'path_depth',
        'has_port', 'query_length', 'num_query_params', 'has_homoglyph',
        'domain_digit_ratio', 'has_redirect'
    ]
    return [features.get(f, 0) for f in feature_order]


def get_rule_based_score(url: str) -> tuple[float, list]:
    """
    Pure rule-based scoring for fast mode.
    Returns (score 0-100, list of triggered rules).
    """
    score = 0.0
    triggered = []
    features = extract_url_features(url)

    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    domain_no_www = re.sub(r'^www\.', '', re.sub(r':\d+', '', domain))

    # Rule checks
    if features.get('has_ip'):
        score += 25
        triggered.append("Uses IP address instead of domain name")

    if not features.get('is_https'):
        score += 10
        triggered.append("Does not use HTTPS (insecure connection)")

    if features.get('suspicious_tld'):
        score += 20
        triggered.append(f"Suspicious top-level domain detected")

    if features.get('has_brand_name') and features.get('suspicious_tld'):
        score += 20
        triggered.append("Brand name with suspicious TLD (impersonation)")

    if features.get('num_subdomains', 0) > 2:
        score += 15
        triggered.append(f"Excessive subdomains ({features['num_subdomains']})")

    if features.get('url_length', 0) > 100:
        score += 10
        triggered.append(f"Unusually long URL ({features['url_length']} chars)")

    if features.get('suspicious_keyword_count', 0) >= 2:
        score += min(20, features['suspicious_keyword_count'] * 8)
        triggered.append(f"Multiple suspicious keywords detected")

    if features.get('has_homoglyph'):
        score += 25
        triggered.append("Homoglyph characters detected (visual deception)")

    if features.get('has_redirect'):
        score += 15
        triggered.append("URL redirect pattern detected")

    if features.get('num_hyphens', 0) >= 3:
        score += 10
        triggered.append(f"Multiple hyphens in URL ({features['num_hyphens']})")

    if features.get('num_dots', 0) > 5:
        score += 10
        triggered.append(f"Excessive dots in URL ({features['num_dots']})")

    if features.get('url_entropy', 0) > 4.5:
        score += 10
        triggered.append("High URL entropy (random-looking domain)")

    if features.get('has_port'):
        score += 10
        triggered.append("Non-standard port in URL")

    return min(100.0, score), triggered


def highlight_url_parts(url: str) -> dict:
    """
    Break down URL into highlighted parts for UI.
    Returns dict with color-coded components.
    """
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        domain_no_www = re.sub(r'^www\.', '', re.sub(r':\d+', '', domain.lower()))
        parts = domain_no_www.split('.')
        tld = '.' + parts[-1] if len(parts) > 1 else ''

        highlighted = {
            "scheme": {"text": parsed.scheme + "://", "risk": "low" if parsed.scheme == 'https' else "high"},
            "domain": {"text": domain, "risk": _rate_domain_risk(domain_no_www, tld)},
            "path": {"text": parsed.path, "risk": _rate_path_risk(parsed.path)},
            "query": {"text": ('?' + parsed.query) if parsed.query else '', "risk": _rate_query_risk(parsed.query)},
        }
        return highlighted
    except Exception:
        return {"full_url": {"text": url, "risk": "unknown"}}


def _calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of text."""
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    n = len(text)
    for count in freq.values():
        p = count / n
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 3)


def _detect_homoglyphs(domain: str) -> bool:
    """Check for homoglyph substitutions in domain."""
    # Check for mixed scripts or obvious substitutions
    digits_in_word = re.search(r'[a-z][0-9]|[0-9][a-z]', domain)
    if digits_in_word:
        return True
    # Check for @ in URL
    if '@' in domain:
        return True
    return False


def _rate_domain_risk(domain: str, tld: str) -> str:
    """Rate domain risk level."""
    if tld in SUSPICIOUS_TLDS:
        return "high"
    if any(brand in domain for brand in IMPERSONATED_BRANDS):
        return "medium"
    return "low"


def _rate_path_risk(path: str) -> str:
    """Rate URL path risk level."""
    if any(kw in path.lower() for kw in ['login', 'signin', 'verify', 'password', 'credential']):
        return "high"
    if len(path) > 100:
        return "medium"
    return "low"


def _rate_query_risk(query: str) -> str:
    """Rate query string risk level."""
    if any(kw in query.lower() for kw in ['redirect', 'url=', 'goto=', 'token=', 'session=']):
        return "medium"
    return "low"
