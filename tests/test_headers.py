from app.scanners.headers import analyze_headers

def test_missing_headers():
    findings = analyze_headers({"server": "demo"}, "https")
    titles = {x["title"] for x in findings}
    assert "Missing security header: strict-transport-security" in titles
    assert "Server header disclosed" in titles
