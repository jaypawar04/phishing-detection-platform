import ipaddress
import re
from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "update",
    "secure",
    "password",
    "credential",
    "banking",
    "confirm",
    "suspend",
    "unlock",
    "wallet",
    "payment",
}


SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "cutt.ly",
    "ow.ly",
}


def analyze_url(url: str) -> dict:
    score = 0
    reasons = []
    features = {}

    normalized_url = url.strip()

    if not re.match(
        r"^[a-zA-Z][a-zA-Z0-9+.-]*://",
        normalized_url
    ):
        normalized_url = "http://" + normalized_url

    parsed = urlparse(normalized_url)
    hostname = parsed.hostname or ""

    features["scheme"] = parsed.scheme
    features["hostname"] = hostname
    features["url_length"] = len(url)
    features["has_ip_address"] = False
    features["has_at_symbol"] = "@" in url
    features["uses_https"] = parsed.scheme.lower() == "https"

    # 1. Invalid hostname
    if not hostname:
        score += 50
        reasons.append({
            "indicator": "Invalid hostname",
            "severity": "high",
            "points": 50,
        })

    # 2. IP address
    if hostname:
        try:
            ipaddress.ip_address(hostname)

            features["has_ip_address"] = True

            score += 30
            reasons.append({
                "indicator": "IP address used instead of domain",
                "severity": "high",
                "points": 30,
            })

        except ValueError:
            pass

    # 3. URL length
    if len(url) > 200:
        score += 20
        reasons.append({
            "indicator": "Extremely long URL",
            "severity": "medium",
            "points": 20,
        })

    elif len(url) > 100:
        score += 10
        reasons.append({
            "indicator": "Unusually long URL",
            "severity": "low",
            "points": 10,
        })

    # 4. @ symbol
    if "@" in url:
        score += 25
        reasons.append({
            "indicator": "URL contains @ symbol",
            "severity": "high",
            "points": 25,
        })

    # 5. HTTPS
    if parsed.scheme.lower() == "http":
        score += 10
        reasons.append({
            "indicator": "Connection does not use HTTPS",
            "severity": "medium",
            "points": 10,
        })

    # 6. Suspicious keywords
    url_lower = url.lower()

    detected_keywords = [
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in url_lower
    ]

    features["suspicious_keywords"] = detected_keywords

    keyword_points = min(len(detected_keywords) * 5, 25)

    if detected_keywords:
        score += keyword_points

        reasons.append({
            "indicator": "Suspicious keywords detected",
            "severity": "medium",
            "points": keyword_points,
            "keywords": sorted(detected_keywords),
        })

    # 7. URL shortener
    is_shortened = hostname.lower() in SHORTENER_DOMAINS

    features["is_shortened_url"] = is_shortened

    if is_shortened:
        score += 20

        reasons.append({
            "indicator": "Known URL shortening service",
            "severity": "medium",
            "points": 20,
        })

    # 8. Subdomains
    if hostname:
        hostname_parts = hostname.split(".")
        subdomain_count = max(len(hostname_parts) - 2, 0)
    else:
        subdomain_count = 0

    features["subdomain_count"] = subdomain_count

    if subdomain_count >= 3:
        score += 15

        reasons.append({
            "indicator": "Excessive number of subdomains",
            "severity": "medium",
            "points": 15,
        })

    # 9. Punycode
    if hostname.lower().startswith("xn--") or ".xn--" in hostname.lower():
        score += 25

        reasons.append({
            "indicator": "Punycode domain detected",
            "severity": "high",
            "points": 25,
        })

    # 10. Suspicious character patterns
    if re.search(r"[%]{2,}|-{3,}|_{2,}", url):
        score += 10

        reasons.append({
            "indicator": "Suspicious character pattern",
            "severity": "medium",
            "points": 10,
        })

    # Risk escalation
    indicator_count = len(reasons)

    if indicator_count >= 4:
        score += 10

        reasons.append({
            "indicator": "Multiple suspicious indicators detected",
            "severity": "high",
            "points": 10,
        })

    # Maximum score
    score = min(score, 100)

    # Verdict
    if score >= 80:
        verdict = "phishing"
    elif score >= 60:
        verdict = "high_risk"
    elif score >= 30:
        verdict = "suspicious"
    else:
        verdict = "legitimate"

    return {
        "url": url,
        "risk_score": score,
        "verdict": verdict,
        "reasons": reasons,
        "features": features,
    }