SECURITY_HEADERS = {
    "strict-transport-security": "HSTS is not present.",
    "content-security-policy": "Content-Security-Policy is not present.",
    "x-content-type-options": "X-Content-Type-Options is not present.",
    "referrer-policy": "Referrer-Policy is not present.",
}

def analyze_headers(headers: dict[str, str], scheme: str) -> list[dict]:
    lowered = {k.lower(): v for k, v in headers.items()}
    findings = []

    for header, description in SECURITY_HEADERS.items():
        if header == "strict-transport-security" and scheme != "https":
            continue
        if header not in lowered:
            findings.append({
                "title": f"Missing security header: {header}",
                "severity": "low",
                "description": description,
                "recommendation": f"Review whether the application should send the {header} header.",
            })

    server = lowered.get("server")
    if server:
        findings.append({
            "title": "Server header disclosed",
            "severity": "info",
            "description": f"The HTTP response exposes a Server header: {server}",
            "recommendation": "Avoid unnecessarily exposing detailed server product/version information.",
        })

    return findings
