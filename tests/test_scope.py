from app.scope import target_in_scope

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
