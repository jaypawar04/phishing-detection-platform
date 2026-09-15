from urllib.parse import urlparse
import ipaddress
import re


SUSPICIOUS_KEYWORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "password",
    "credential",
    "secure",
    "security",
    "update",
    "confirm",
    "confirmation",
    "wallet",
    "payment",
    "invoice",
    "bank",
    "billing",
    "unlock",
    "recover",
}

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "shorturl.at",
}

SUSPICIOUS_TLDS = {
    ".zip",
    ".mov",
    ".click",
    ".top",
    ".xyz",
    ".work",
    ".gq",
    ".tk",
    ".ml",
    ".cf",
    ".ga",
}


def is_ip_address(hostname: str) -> bool:
    """Return True when hostname is an IPv4 or IPv6 address."""

    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def count_subdomains(hostname: str) -> int:
    """Count subdomain labels before the registered domain."""

    if not hostname:
        return 0

    parts = hostname.split(".")

    if len(parts) <= 2:
        return 0

    return len(parts) - 2


def detect_suspicious_keywords(url: str) -> list[str]:
    """Find phishing-related keywords anywhere in the URL."""

    url_lower = url.lower()

    return sorted(
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in url_lower
    )


def analyze_url(url: str) -> dict:
    """
    Analyze a URL using static URL-based phishing indicators.

    Returns:
        risk_score: integer from 0 to 100
        verdict: legitimate / suspicious / high_risk / phishing
        reasons: list of detection indicators
        features: extracted URL characteristics
    """

    parsed = urlparse(url)

    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""

    full_url_lower = url.lower()

    risk_score = 0
    reasons = []

    # ---------------------------------------------------------
    # Feature extraction
    # ---------------------------------------------------------

    ip_address = is_ip_address(hostname)
    subdomain_count = count_subdomains(hostname)

    suspicious_keywords = detect_suspicious_keywords(url)

    is_shortened = (
        hostname in URL_SHORTENERS
        or hostname.startswith("www.")
        and hostname[4:] in URL_SHORTENERS
    )

    has_at_symbol = "@" in url

    is_suspicious_port = False

    try:
        if parsed.port is not None:
            is_suspicious_port = parsed.port not in {
                80,
                443,
                8080,
            }
    except ValueError:
        is_suspicious_port = True

    has_punycode = "xn--" in hostname

    encoded_character_count = len(
        re.findall(r"%[0-9a-fA-F]{2}", url)
    )

    hyphen_count = hostname.count("-")

    url_length = len(url)

    suspicious_tld = any(
        hostname.endswith(tld)
        for tld in SUSPICIOUS_TLDS
    )

    # ---------------------------------------------------------
    # Detection rules
    # ---------------------------------------------------------

    if ip_address:
        points = 30

        risk_score += points

        reasons.append(
            {
                "indicator": "IP address used instead of domain",
                "severity": "high",
                "points": points,
            }
        )

    if scheme != "https":
        points = 10

        risk_score += points

        reasons.append(
            {
                "indicator": "Connection does not use HTTPS",
                "severity": "medium",
                "points": points,
            }
        )

    if suspicious_keywords:
        points = min(
            20,
            5 * len(suspicious_keywords)
        )

        risk_score += points

        reasons.append(
            {
                "indicator": "Suspicious keywords detected",
                "severity": "medium",
                "points": points,
                "keywords": suspicious_keywords,
            }
        )

    if is_shortened:
        points = 10

        risk_score += points

        reasons.append(
            {
                "indicator": "URL shortening service detected",
                "severity": "medium",
                "points": points,
            }
        )

    if has_at_symbol:
        points = 15

        risk_score += points

        reasons.append(
            {
                "indicator": "URL contains @ symbol",
                "severity": "high",
                "points": points,
            }
        )

    if subdomain_count >= 3:
        points = 10

        risk_score += points

        reasons.append(
            {
                "indicator": "Excessive subdomains detected",
                "severity": "medium",
                "points": points,
                "subdomains": subdomain_count,
            }
        )

    if url_length > 100:
        points = 10

        risk_score += points

        reasons.append(
            {
                "indicator": "Unusually long URL",
                "severity": "medium",
                "points": points,
                "length": url_length,
            }
        )

    if hyphen_count >= 3:
        points = 5

        risk_score += points

        reasons.append(
            {
                "indicator": "Multiple hyphens detected in hostname",
                "severity": "low",
                "points": points,
                "hyphens": hyphen_count,
            }
        )

    if is_suspicious_port:
        points = 10

        risk_score += points

        reasons.append(
            {
                "indicator": "Unusual network port detected",
                "severity": "medium",
                "points": points,
            }
        )

    if has_punycode:
        points = 15

        risk_score += points

        reasons.append(
            {
                "indicator": "Punycode/IDN domain detected",
                "severity": "high",
                "points": points,
            }
        )

    if encoded_character_count >= 3:
        points = 10

        risk_score += points

        reasons.append(
            {
                "indicator": "Multiple encoded characters detected",
                "severity": "medium",
                "points": points,
                "encoded_characters": encoded_character_count,
            }
        )

    if suspicious_tld:
        points = 10

        risk_score += points

        reasons.append(
            {
                "indicator": "Suspicious top-level domain detected",
                "severity": "medium",
                "points": points,
            }
        )

    # ---------------------------------------------------------
    # Limit score
    # ---------------------------------------------------------

    risk_score = min(risk_score, 100)

    # ---------------------------------------------------------
    # Verdict
    # ---------------------------------------------------------

    has_indicators = len(reasons) > 0

    has_high_severity = any(
        reason.get("severity") == "high"
        for reason in reasons
    )

    if risk_score >= 80:
        verdict = "phishing"

    elif risk_score >= 50:
        verdict = "high_risk"

    elif risk_score >= 20:
        verdict = "suspicious"

    elif has_high_severity:
        verdict = "suspicious"

    elif has_indicators:
        verdict = "suspicious"

    else:
        verdict = "legitimate"

    # ---------------------------------------------------------
    # Features returned to API
    # ---------------------------------------------------------

    features = {
        "scheme": scheme,
        "hostname": hostname,
        "url_length": url_length,
        "has_ip_address": ip_address,
        "has_at_symbol": has_at_symbol,
        "uses_https": scheme == "https",
        "suspicious_keywords": suspicious_keywords,
        "is_shortened_url": is_shortened,
        "subdomain_count": subdomain_count,
        "hyphen_count": hyphen_count,
        "has_punycode": has_punycode,
        "encoded_character_count": encoded_character_count,
        "suspicious_tld": suspicious_tld,
        "suspicious_port": is_suspicious_port,
        "path": path,
        "query_present": bool(query),
    }

    return {
        "risk_score": risk_score,
        "verdict": verdict,
        "reasons": reasons,
        "features": features,
    }