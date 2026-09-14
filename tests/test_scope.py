from app.scope import normalize_scope_rule, normalize_scope_rules, target_in_scope

def test_exact_domain():
    assert target_in_scope("https://example.com/login", ["example.com"])
    assert not target_in_scope("https://evil-example.com", ["example.com"])

def test_wildcard_domain():
    assert target_in_scope("api.example.com", ["*.example.com"])
    assert not target_in_scope("example.com", ["*.example.com"])

def test_ip_and_cidr():
    assert target_in_scope("192.0.2.10", ["192.0.2.10"])
    assert target_in_scope("192.0.2.99", ["192.0.2.0/24"])
    assert not target_in_scope("192.0.3.1", ["192.0.2.0/24"])


def test_full_url_scope_is_normalized_and_matches_existing_projects():
    assert normalize_scope_rule("https://Example.COM:8443/app/login?next=/") == "example.com"
    assert target_in_scope("https://example.com:9443/api", ["https://Example.COM:8443/app"])
    assert normalize_scope_rules(["https://example.com/a", "example.com", "  "]) == ["example.com"]


def test_scope_rule_rejects_credentials_and_invalid_ports():
    import pytest
    with pytest.raises(ValueError):
        normalize_scope_rule("https://user:secret@example.com/")
    with pytest.raises(ValueError):
        normalize_scope_rule("example.com:99999")


def test_unrestricted_scope_accepts_any_valid_target():
    assert normalize_scope_rule("*") == "*"
    assert target_in_scope("https://any.example/path", ["*"])
    assert target_in_scope("192.0.2.10", ["*"])
