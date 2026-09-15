from backend.detector import analyze_url


def test_legitimate_google():
    result = analyze_url("https://www.google.com")

    assert result["verdict"] == "legitimate"
    assert result["risk_score"] < 30


def test_legitimate_example():
    result = analyze_url("https://example.com")

    assert result["verdict"] == "legitimate"
    assert result["risk_score"] < 30


def test_ip_address_url():
    result = analyze_url("http://192.168.1.10/login")

    assert result["risk_score"] >= 30
    assert result["verdict"] == "suspicious"


def test_suspicious_login_url():
    result = analyze_url(
        "http://secure-login.example.com/verify-account"
    )

    assert result["risk_score"] >= 30
    assert result["verdict"] == "suspicious"


def test_at_symbol():
    result = analyze_url(
        "http://example.com@malicious.example/login"
    )

    assert result["risk_score"] >= 30


def test_punycode_domain():
    result = analyze_url(
        "https://xn--example-9za.com"
    )

    assert result["risk_score"] >= 25


def test_url_shortener():
    result = analyze_url(
        "https://bit.ly/example"
    )

    assert result["risk_score"] >= 20


def test_long_url():
    long_url = (
        "https://example.com/"
        + "a" * 110
    )

    result = analyze_url(long_url)

    assert result["risk_score"] >= 10