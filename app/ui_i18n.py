from .services.evidence_safety import redact_url

STATUS_ZH = {
    "queued": "等待执行",
    "running": "执行中",
    "retry_wait": "等待重试",
    "cancel_requested": "取消中",
    "cancelled": "已取消",
    "done": "已完成",
    "done_with_errors": "完成但有失败",
    "error": "失败",
    "unavailable": "运行环境不可用",
    "planned": "已规划",
    "approved": "已批准",
    "manual_ready": "待人工执行",
    "skipped": "已跳过",
    "disabled": "未启用",
    "open": "待处理",
    "triaged": "已研判",
    "remediation": "整改中",
    "retest_ready": "待复测",
    "resolved": "已修复",
    "accepted_risk": "风险接受",
    "false_positive": "误报",
    "reproduced": "仍可复现",
    "needs_review": "待人工复核",
    "covered": "已覆盖",
    "partial": "部分覆盖",
    "gap": "尚未覆盖",
    "historical_import": "历史导入",
    "offline": "离线",
    "stale": "心跳失联",
    "candidate": "候选",
    "confirmed": "已确认",
    "unverified": "未验证",
    "not_queued": "未排队",
}
SEVERITY_ZH = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "信息",
}
POLICY_ZH = {
    "READ_ONLY": "只读",
    "LOW_RISK_VALIDATE": "低风险验证",
    "STATE_CHANGE": "状态变更",
    "DESTRUCTIVE": "破坏性",
}
CLASSIFICATION_ZH = {
    "authorization_control_enforced": "权限控制已生效",
    "potential_horizontal_authorization_gap": "疑似水平越权",
    "potential_vertical_authorization_gap": "疑似垂直越权",
    "potential_unauthenticated_access": "疑似未授权访问",
    "horizontal_access_needs_review": "水平权限待复核",
    "vertical_access_needs_review": "垂直权限待复核",
    "needs_review": "待人工复核",
    "inconclusive": "结论不足",
    "pending": "等待执行",
    "error": "执行失败",
}

def audit_zh(value):
    import json
    labels = {'title':'标题','severity':'风险等级','target':'目标','vuln_type':'漏洞类型','description':'描述与复现步骤','parameter':'参数','recommendation':'修复建议','cwe_id':'CWE','owasp_category':'OWASP 分类','txb02_category':'txb02 分类','name':'项目名','client_name':'客户','environment':'环境','start_date':'开始日期','end_date':'结束日期','authorization_note':'授权说明','scope_text':'授权范围','evidence_id':'证据编号','parent_evidence_id':'关联证据编号','outcome':'复测结果'}
    try:
        data = json.loads(value)
        before, after = data.get('before', {}), data.get('after', {})
        def display(v):
            return SEVERITY_ZH.get(str(v), STATUS_ZH.get(str(v), str(v))) if v not in ('', None) else '未填写'
        return '\n'.join(f"{labels.get(key,key)}：{display(before.get(key))} → {display(val)}" for key,val in after.items() if before.get(key) != val)
    except (ValueError, TypeError, AttributeError):
        return '记录格式无法显示。'

def configure_templates(templates):
    templates.env.filters['audit_zh'] = audit_zh
    templates.env.filters["status_zh"] = lambda v: STATUS_ZH.get(str(v), str(v))
    templates.env.filters["severity_zh"] = lambda v: SEVERITY_ZH.get(str(v).lower(), str(v))
    templates.env.filters["policy_zh"] = lambda v: POLICY_ZH.get(str(v), str(v))
    templates.env.filters["classification_zh"] = lambda v: CLASSIFICATION_ZH.get(str(v), str(v))
    templates.env.filters["redact_url"] = redact_url
    return templates
