from __future__ import annotations

import json
from difflib import SequenceMatcher

VOLATILE_HEADERS = {"date", "set-cookie", "x-request-id", "traceparent", "server-timing"}


def _json_paths(value, prefix="$", out=None):
    if out is None:
        out = {}
    if isinstance(value, dict):
        for key, child in value.items():
            _json_paths(child, f"{prefix}.{key}", out)
    elif isinstance(value, list):
        for i, child in enumerate(value[:100]):
            _json_paths(child, f"{prefix}[{i}]", out)
    else:
        out[prefix] = value
    return out


def _header_diff(left: dict, right: dict):
    l = {str(k).lower(): str(v) for k, v in left.items() if str(k).lower() not in VOLATILE_HEADERS}
    r = {str(k).lower(): str(v) for k, v in right.items() if str(k).lower() not in VOLATILE_HEADERS}
    return {
        "added": {k: r[k] for k in r.keys() - l.keys()},
        "removed": {k: l[k] for k in l.keys() - r.keys()},
        "changed": {k: {"left": l[k], "right": r[k]} for k in l.keys() & r.keys() if l[k] != r[k]},
    }


def compare_responses(left_status, left_headers, left_body, right_status, right_headers, right_body):
    left_body = left_body or ""
    right_body = right_body or ""
    similarity = SequenceMatcher(None, left_body[:200000], right_body[:200000]).ratio()
    result = {
        "status": {"left": left_status, "right": right_status, "same": left_status == right_status},
        "length": {"left": len(left_body), "right": len(right_body), "delta": len(right_body) - len(left_body)},
        "text_similarity": round(similarity, 4),
        "headers": _header_diff(left_headers or {}, right_headers or {}),
        "json": {"detected": False, "added": {}, "removed": {}, "changed": {}},
    }
    try:
        lj = _json_paths(json.loads(left_body))
        rj = _json_paths(json.loads(right_body))
        result["json"] = {
            "detected": True,
            "added": {k: rj[k] for k in rj.keys() - lj.keys()},
            "removed": {k: lj[k] for k in lj.keys() - rj.keys()},
            "changed": {k: {"left": lj[k], "right": rj[k]} for k in lj.keys() & rj.keys() if lj[k] != rj[k]},
        }
    except Exception:
        pass
    result["signals"] = {
        "status_changed": left_status != right_status,
        "large_length_delta": abs(len(right_body) - len(left_body)) > max(100, int(max(len(left_body), 1) * 0.2)),
        "low_similarity": similarity < 0.85,
        "json_field_changes": len(result["json"].get("changed", {})) if result["json"].get("detected") else 0,
    }
    return result
