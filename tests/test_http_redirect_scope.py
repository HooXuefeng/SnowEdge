from app.scanners.http_probe import safe_redirect_url

def test_same_scope_redirect_allowed():
    assert safe_redirect_url(
        "https://example.com/start",
        "/login",
        ["example.com"],
    ) == "https://example.com/login"

def test_external_redirect_blocked():
    assert safe_redirect_url(
        "https://example.com/start",
        "https://evil.example.net/",
        ["example.com"],
    ) is None
