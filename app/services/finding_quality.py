from __future__ import annotations

from collections import Counter

from sqlalchemy.orm import Session, load_only

from ..models import (
    Evidence, EvidenceAttachment, Finding, FindingLifecycle,
    ProofCapsule, RetestRun,
)


REQUEST_KINDS = ("normal_request", "baseline_request", "poc_request", "request_replay")
RESPONSE_KINDS = ("normal_response", "baseline_response", "poc_response", "authorization_candidate")


def _finding_evidence(db: Session, finding_id: int) -> list[Evidence]:
    return (
        db.query(Evidence)
        .filter(Evidence.finding_id == finding_id)
        .order_by(Evidence.id.asc())
        .all()
    )


def finding_quality(db: Session, finding: Finding, prefetched=None) -> dict:
    if prefetched is None:
        evidence = _finding_evidence(db, finding.id)
        kinds = [(e.kind or "").lower() for e in evidence]
        attachments = (
            db.query(EvidenceAttachment)
            .filter(EvidenceAttachment.finding_id == finding.id)
            .count()
        )
        capsule = (
            db.query(ProofCapsule)
            .filter(ProofCapsule.finding_id == finding.id)
            .order_by(ProofCapsule.id.desc())
            .first()
        )
        retests = (
            db.query(RetestRun)
            .filter(RetestRun.finding_id == finding.id)
            .count()
        )
        lifecycle = (
            db.query(FindingLifecycle)
            .filter(FindingLifecycle.finding_id == finding.id)
            .first()
        )
    else:
        evidence = prefetched['evidence'].get(finding.id, [])
        kinds = [(e.kind or '').lower() for e in evidence]
        attachments = len(prefetched['attachments'].get(finding.id, []))
        capsules = prefetched['capsules'].get(finding.id, [])
        capsule = capsules[-1] if capsules else None
        retests = len(prefetched['retests'].get(finding.id, []))
        lifecycles = prefetched['lifecycles'].get(finding.id, [])
        lifecycle = lifecycles[0] if lifecycles else None

    checks = []

    def add(key, label, points, max_points, ok, detail, severity="normal"):
        checks.append({
            "key": key,
            "label": label,
            "points": points if ok else 0,
            "max_points": max_points,
            "ok": bool(ok),
            "detail": detail,
            "severity": severity,
        })

    add("evidence", "存在关联 Evidence", 18, 18, len(evidence) > 0, f"{len(evidence)} 条 Evidence")
    add("description", "漏洞详述完整", 8, 8, len((finding.description or "").strip()) >= 40, "建议至少说明位置、现象和安全影响")
    add("recommendation", "修复建议完整", 7, 7, len((finding.recommendation or "").strip()) >= 20, "建议给出可执行修复方向")
    add("taxonomy", "分类信息", 7, 7, bool(finding.vuln_type or finding.txb02_category or finding.cwe_id), "CWE/类型/txb02 至少一项")
    add("request", "请求证据", 12, 12, any(any(x in k for x in REQUEST_KINDS) for k in kinds), "正常请求或 POC 请求")
    add("response", "响应证据", 12, 12, any(any(x in k for x in RESPONSE_KINDS) for k in kinds), "正常响应或 POC 响应")
    add("screenshot", "验证截图", 12, 12, attachments > 0, f"{attachments} 张截图")
    add("proof", "Proof Capsule", 10, 10, capsule is not None, f"Capsule #{capsule.id}" if capsule else "尚未创建")
    add("retest", "复测记录", 8, 8, retests > 0 or finding.verification_state == "resolved", f"{retests} 次 Retest")
    add("confirmed", "人工确认状态", 6, 6, finding.finding_state == "confirmed", finding.finding_state)

    score = sum(x["points"] for x in checks)
    max_score = sum(x["max_points"] for x in checks)

    ai_like = any(x in (finding.source or "").lower() for x in {"ai", "copilot", "agent"})
    deterministic_signal = bool(evidence) and (
        any("authorization" in k or "http_" in k or "request_replay" in k for k in kinds)
        or capsule is not None
    )
    penalty = 0
    if ai_like and not deterministic_signal:
        penalty = 20
        score = max(0, score - penalty)

    pct = round(score / max_score * 100) if max_score else 0
    grade = "A" if pct >= 90 else "B" if pct >= 75 else "C" if pct >= 60 else "D"
    missing = [x for x in checks if not x["ok"]]
    ready = pct >= 75 and finding.finding_state == "confirmed" and len(evidence) > 0

    return {
        "finding_id": finding.id,
        "score": pct,
        "grade": grade,
        "ready": ready,
        "checks": checks,
        "missing": missing,
        "penalty": penalty,
        "evidence_count": len(evidence),
        "screenshot_count": attachments,
        "retest_count": retests,
        "lifecycle_status": lifecycle.status if lifecycle else "open",
    }


def project_quality_summary(db: Session, project_id: int) -> dict:
    findings = (
        db.query(Finding)
        .filter(Finding.project_id == project_id)
        .order_by(Finding.id.asc())
        .all()
    )
    prefetched = {}
    for key, model in [('evidence', Evidence), ('attachments', EvidenceAttachment), ('capsules', ProofCapsule), ('retests', RetestRun), ('lifecycles', FindingLifecycle)]:
        grouped = {}
        columns = [model.id, model.finding_id]
        if model is Evidence:
            columns.append(Evidence.kind)
        if model is FindingLifecycle:
            columns.append(FindingLifecycle.status)
        for row in db.query(model).options(load_only(*columns)).join(Finding, model.finding_id == Finding.id).filter(Finding.project_id == project_id).order_by(model.id.asc()):
            grouped.setdefault(row.finding_id, []).append(row)
        prefetched[key] = grouped
    rows = [finding_quality(db, f, prefetched) for f in findings]
    if not rows:
        return {"count": 0, "average": 0, "ready": 0, "needs_work": 0, "rows": []}
    return {
        "count": len(rows),
        "average": round(sum(x["score"] for x in rows) / len(rows)),
        "ready": sum(1 for x in rows if x["ready"]),
        "needs_work": sum(1 for x in rows if not x["ready"]),
        "rows": rows,
    }


def report_preflight(db: Session, project_id: int) -> dict:
    findings = (
        db.query(Finding)
        .filter(Finding.project_id == project_id)
        .order_by(Finding.id.asc())
        .all()
    )
    qualities = {f.id: finding_quality(db, f) for f in findings}
    issues = []

    def issue(level, finding, key, title, detail):
        issues.append({
            "level": level,
            "finding_id": finding.id if finding else None,
            "key": key,
            "title": title,
            "detail": detail,
        })

    if not findings:
        issues.append({
            "level": "info", "finding_id": None, "key": "no_findings",
            "title": "暂无漏洞记录", "detail": "当前报告可以生成项目摘要，但没有漏洞详情。",
        })

    for finding in findings:
        q = qualities[finding.id]
        if finding.finding_state == "candidate":
            issue("warn", finding, "candidate", "仍为 Candidate", "提交正式报告前建议人工确认或标记 false_positive。")
        if q["score"] < 75:
            issue("warn", finding, "quality", f"证据质量仅 {q['score']}/100", "建议补齐缺失证据再导出正式报告。")
        if q["screenshot_count"] == 0:
            issue("warn", finding, "screenshot", "缺少验证截图", "txb02 Word 中不会出现验证图片。")
        missing_keys = {x["key"] for x in q["missing"]}
        if "request" in missing_keys:
            issue("warn", finding, "request", "缺少请求证据", "建议补正常请求或 POC 请求。")
        if "response" in missing_keys:
            issue("warn", finding, "response", "缺少响应证据", "建议补正常响应或 POC 响应。")
        if finding.verification_state == "needs_review":
            issue("info", finding, "review", "验证状态 Needs Review", "报告中应明确仍需人工确认的部分。")

    counts = Counter(x["level"] for x in issues)
    blocking = sum(
        1 for f in findings
        if f.finding_state == "candidate" or qualities[f.id]["score"] < 60
    )
    return {
        "issues": issues,
        "warning_count": counts.get("warn", 0),
        "info_count": counts.get("info", 0),
        "blocking_count": blocking,
        "ready": blocking == 0,
        "quality": project_quality_summary(db, project_id),
    }
