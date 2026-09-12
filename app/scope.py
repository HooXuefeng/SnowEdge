from __future__ import annotations
import ipaddress
from urllib.parse import urlparse

def normalize_host(target: str) -> str:
    raw = target.strip()
    parsed = urlparse(raw if "://" in raw else f"//{raw}", scheme="")
    host = parsed.hostname or raw.split("/")[0]
    return host.strip().rstrip(".").lower()

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
        rule = raw_rule.strip()
        if not rule:
            continue

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
