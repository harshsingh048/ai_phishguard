"""
PhishGuard AI - Domain Intelligence Service
WHOIS lookups, domain age analysis, threat feed checks.
"""
import re
import logging
import socket
import concurrent.futures
from datetime import datetime, timezone
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Try to import whois (optional)
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    logger.warning("python-whois not installed. WHOIS lookups disabled.")

# Legitimate domains whitelist
LEGITIMATE_DOMAINS = {
    'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'microsoft.com',
    'apple.com', 'netflix.com', 'linkedin.com', 'twitter.com', 'instagram.com',
    'github.com', 'stackoverflow.com', 'wikipedia.org', 'reddit.com', 'paypal.com',
    'ebay.com', 'walmart.com', 'adobe.com', 'salesforce.com', 'zoom.us',
    'dropbox.com', 'slack.com', 'spotify.com', 'cloudflare.com', 'aws.amazon.com'
}


def get_domain_from_url(url: str) -> str:
    """Extract base domain from URL."""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        domain = re.sub(r':\d+', '', domain)  # remove port
        domain = re.sub(r'^www\.', '', domain)  # remove www
        return domain
    except Exception:
        return url


def check_whitelist(url: str) -> dict:
    """Check if domain is in known legitimate domains list."""
    domain = get_domain_from_url(url)

    # Direct match
    if domain in LEGITIMATE_DOMAINS:
        return {"whitelisted": True, "domain": domain}

    # Check if it's a subdomain of a legitimate domain
    for legit in LEGITIMATE_DOMAINS:
        if domain.endswith('.' + legit):
            return {"whitelisted": True, "domain": domain, "parent": legit}

    return {"whitelisted": False, "domain": domain}


def check_whois(url: str) -> dict:
    """
    Perform WHOIS lookup for domain age analysis.
    Returns domain age info or fallback data.
    """
    if not WHOIS_AVAILABLE:
        return {
            "available": False,
            "reason": "WHOIS library not installed",
            "domain_age_days": None,
            "is_new_domain": None
        }

    domain = get_domain_from_url(url)

    try:
        w = whois.whois(domain)

        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            age_days = (now - creation_date).days
            is_new = age_days < 90  # < 90 days = new domain

            return {
                "available": True,
                "domain": domain,
                "creation_date": creation_date.isoformat(),
                "domain_age_days": age_days,
                "is_new_domain": is_new,
                "registrar": str(w.registrar) if w.registrar else "Unknown",
                "country": str(w.country) if hasattr(w, 'country') and w.country else "Unknown"
            }
        else:
            return {
                "available": True,
                "domain": domain,
                "creation_date": None,
                "domain_age_days": None,
                "is_new_domain": None,
                "registrar": "Unknown"
            }

    except Exception as e:
        logger.warning(f"WHOIS lookup failed for {domain}: {e}")
        return {
            "available": False,
            "domain": domain,
            "reason": str(e),
            "domain_age_days": None,
            "is_new_domain": None
        }


def check_dns_resolution(url: str) -> dict:
    """Check if domain resolves and get IP."""
    domain = get_domain_from_url(url)
    try:
        ip = socket.gethostbyname(domain)
        return {"resolves": True, "ip": ip, "domain": domain}
    except socket.gaierror:
        return {"resolves": False, "ip": None, "domain": domain}
    except Exception as e:
        return {"resolves": False, "ip": None, "domain": domain, "error": str(e)}


def check_threat_feed_db(url: str) -> dict:
    """Check URL against local threat feed database."""
    try:
        from database.db import ThreatFeed
        domain = get_domain_from_url(url)

        # Check domain
        threat = ThreatFeed.query.filter(
            (ThreatFeed.indicator == domain) |
            (ThreatFeed.indicator == url)
        ).first()

        if threat:
            return {
                "found": True,
                "indicator": threat.indicator,
                "threat_type": threat.threat_type,
                "confidence": threat.confidence,
                "source": threat.source
            }
        return {"found": False}
    except Exception as e:
        logger.error(f"Threat feed DB check failed: {e}")
        return {"found": False, "error": str(e)}


def run_deep_domain_analysis(url: str) -> dict:
    """
    Run full domain analysis in parallel (deep mode).
    Combines WHOIS + DNS + threat feed.
    """
    results = {}
    score_boost = 0
    reasons = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        futures = {
            'whois': executor.submit(check_whois, url),
            'dns': executor.submit(check_dns_resolution, url),
            'threat_feed': executor.submit(check_threat_feed_db, url),
            'whitelist': executor.submit(check_whitelist, url),
        }

        for key, future in futures.items():
            try:
                results[key] = future.result(timeout=8)
            except Exception as e:
                results[key] = {"error": str(e)}

    # Analyze results
    whois_data = results.get('whois', {})
    if whois_data.get('is_new_domain') is True:
        score_boost += 20
        reasons.append(f"Newly registered domain ({whois_data.get('domain_age_days', 0)} days old)")

    dns_data = results.get('dns', {})
    if not dns_data.get('resolves', True):
        score_boost += 5
        reasons.append("Domain does not resolve to any IP")

    threat_data = results.get('threat_feed', {})
    if threat_data.get('found'):
        score_boost += 40
        reasons.append(f"Found in threat intelligence feed: {threat_data.get('threat_type')}")

    whitelist_data = results.get('whitelist', {})
    if whitelist_data.get('whitelisted'):
        score_boost -= 30  # Legitimate domain bonus
        reasons.append("Domain found in legitimate domains whitelist")

    return {
        "domain_data": results,
        "score_boost": score_boost,
        "reasons": reasons
    }
