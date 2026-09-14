from __future__ import annotations
import ipaddress
import re
from urllib.parse import urlparse

def normalize_host(target: str) -> str:
    raw = target.strip()
    parsed = urlparse(raw if "://" in raw else f"//{raw}", scheme="")
    host = parsed.hostname or raw.split("/")[0]
    return host.strip().rstrip(".").lower()


def normalize_scope_rule(raw_rule: str) -> str:
    """Convert a user-facing scope entry to the host-based rule used by SnowEdge.

    Users commonly paste a full HTTP URL while creating a project.  Scope checks
    are intentionally host based, so store/compare the URL's hostname instead of
    leaving an unmatchable ``https://...`` string in the project.
    """
    value = (raw_rule or "").strip()
    if not value:
        raise ValueError("授权范围不能为空。")
    if value == "*":
        return "*"

    if "://" in value:
        parsed = urlparse(value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError("URL 授权范围仅支持有效的 HTTP/HTTPS 地址。")
        if parsed.username or parsed.password:
            raise ValueError("授权范围 URL 不能包含用户名或密码。")
        value = parsed.hostname

    if value.startswith("*."):
        suffix = value[2:].strip().rstrip(".").lower()
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", suffix):
            raise ValueError("通配范围格式无效。")
        return "*." + suffix

    try:
        if "/" in value:
            return str(ipaddress.ip_network(value, strict=False))
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass

    # A host with an explicit port still authorizes that host because the current
    # Scope Engine is host based.  This also handles bracketed IPv6 literals.
    parsed = urlparse(f"//{value}")
    try:
        host = parsed.hostname
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("授权范围中的端口无效。") from exc
    host = (host or "").strip().rstrip(".").lower()
    if not host or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host):
        raise ValueError("范围支持 URL、域名、*.子域名、IP 或 CIDR。")
    return host


def normalize_scope_rules(rules: list[str]) -> list[str]:
    normalized: list[str] = []
    for raw_rule in rules:
        if not (raw_rule or "").strip():
            continue
        rule = normalize_scope_rule(raw_rule)
        if rule not in normalized:
            normalized.append(rule)
    return normalized

def _matches_hostname(host: str, rule: str) -> bool:
    rule = rule.lower().strip().rstrip(".")
    if rule.startswith("*."):
        suffix = rule[2:]
        return host.endswith("." + suffix) and host != suffix
    return host == rule

def target_in_scope(target: str, rules: list[str]) -> bool:
    host = normalize_host(target)
    try:
        host_ip = ipaddress.ip_address(host)
    except ValueError:
        host_ip = None

    for raw_rule in rules:
        try:
            rule = normalize_scope_rule(raw_rule)
        except ValueError:
            continue
        if rule == "*":
            return True

        try:
            if "/" in rule:
                network = ipaddress.ip_network(rule, strict=False)
                if host_ip and host_ip in network:
                    return True
                continue
            rule_ip = ipaddress.ip_address(rule)
            if host_ip and host_ip == rule_ip:
                return True
            continue
        except ValueError:
            pass

        if _matches_hostname(host, rule):
            return True

    return False
