from .base import AIProvider

class MockProvider(AIProvider):
    async def analyze(self, context: dict) -> list[dict]:
        findings = []
        http = context.get("http") or {}
        tls = context.get("tls") or {}

        if http.get("ok") and http.get("status_code", 0) >= 500:
            findings.append({
                "title": "Server returned a 5xx response",
                "severity": "info",
                "description": "The target returned a server-side error during the authorized probe.",
                "recommendation": "Review server logs and confirm whether the error exposes implementation details.",
            })

        if tls and not tls.get("ok"):
            findings.append({
                "title": "TLS handshake could not be validated",
                "severity": "info",
                "description": tls.get("error", "TLS analysis failed."),
                "recommendation": "Review certificate trust, hostname configuration and TLS availability.",
            })

        return findings

    async def review_authorization(self, context: dict) -> dict:
        classification = context.get("classification", "needs_review")
        return {
            "assessment": (
                "Mock provider second opinion: the deterministic authorization classifier "
                f"reported '{classification}'. Manual confirmation remains required for candidate issues."
            ),
            "risk": "candidate" if classification.startswith("potential_") else "review",
            "confidence_adjustment": 0,
            "manual_checks": [
                "Confirm the intended resource owner or role requirement.",
                "Confirm the comparison identity is not legitimately entitled to the resource.",
                "Verify the behavior through the application UI or server-side authorization design.",
            ],
        }

    async def recommend_skills(self, context: dict, catalog: list[dict]) -> dict:
        allowed = {item.get("slug") for item in catalog}
        recommendations = []
        for item in context.get("deterministic_candidates", []):
            slug = item.get("slug")
            if slug in allowed:
                recommendations.append({
                    "slug": slug,
                    "reason": item.get("reason", "Evidence profile suggests this Skill."),
                    "priority": item.get("priority", "medium"),
                })
        return {
            "recommendations": recommendations,
            "summary": "Mock provider mirrored the evidence-based deterministic Skill shortlist.",
        }

    async def specialist_review(self, role: dict, context: dict, allowed_handoffs: list[str]) -> dict:
        slug = role.get("slug", "specialist")
        graph = context.get("graph_summary", {})
        memory = context.get("memory_summary", {})
        observations = []
        handoffs = []

        if slug == "planner":
            observations.append({
                "subject_key": "project",
                "observation": (
                    f"Workspace currently has {graph.get('nodes', 0)} knowledge nodes, "
                    f"{graph.get('edges', 0)} relations and {memory.get('count', 0)} structured memories."
                ),
                "confidence": 95,
            })
            for target in ["web_analyst", "authorization_analyst", "evidence_reviewer"]:
                if target in allowed_handoffs:
                    handoffs.append({
                        "to_role": target,
                        "reason": "Review the shared evidence graph from the specialist domain perspective.",
                        "subject_keys": ["project"],
                    })
        elif slug == "recon_analyst":
            observations.append({
                "subject_key": "knowledge:service",
                "observation": "Review existing asset/service and transport evidence before repeating reconnaissance.",
                "confidence": 90,
            })
        elif slug == "web_analyst":
            observations.append({
                "subject_key": "knowledge:web",
                "observation": "Correlate endpoints, route candidates, browser observations and stored requests before proposing additional read-only coverage.",
                "confidence": 92,
            })
            if "authorization_analyst" in allowed_handoffs:
                handoffs.append({
                    "to_role": "authorization_analyst",
                    "reason": "Stored web requests and identity-aware browser observations may support differential authorization review.",
                    "subject_keys": ["knowledge:web"],
                })
        elif slug == "authorization_analyst":
            observations.append({
                "subject_key": "knowledge:authorization",
                "observation": "Prior authorization cases and assessment memories should be checked for already-enforced controls before repeating the same identity/object comparison.",
                "confidence": 95,
            })
            if "evidence_reviewer" in allowed_handoffs:
                handoffs.append({
                    "to_role": "evidence_reviewer",
                    "reason": "Review candidate authorization conclusions against evidence and Proof Capsule state.",
                    "subject_keys": ["knowledge:authorization"],
                })
        elif slug == "evidence_reviewer":
            observations.append({
                "subject_key": "knowledge:evidence",
                "observation": "Prefer deterministic Proof Capsule and Evidence state over unsupported model conclusions.",
                "confidence": 98,
            })
            if "reporter" in allowed_handoffs:
                handoffs.append({
                    "to_role": "reporter",
                    "reason": "Use only evidence-backed and verification-aware conclusions in reporting.",
                    "subject_keys": ["knowledge:evidence"],
                })
        elif slug == "reporter":
            observations.append({
                "subject_key": "report",
                "observation": "Report should distinguish observed, candidate, reproduced, resolved and needs-review states.",
                "confidence": 98,
            })

        return {
            "summary": f"Mock {role.get('name', slug)} completed an analysis-only review.",
            "observations": observations,
            "handoffs": handoffs[:6],
            "next_checks": [
                "Review repeat-guidance memories before scheduling equivalent assessment work.",
                "Keep any additional network action behind the existing Skill/Scope/Policy workflow.",
            ],
        }

    async def analyst_copilot(self, question: str, context: dict, allowed_refs: list[str]) -> dict:
        nodes = context.get("knowledge", [])
        memories = context.get("memories", [])
        coverage = context.get("coverage", [])
        citations = []
        facts = []
        for item in context.get('focused_sources', [])[:2]:
            if item.get('ref') in allowed_refs:
                citations.append(item['ref'])
                facts.append(f"演示模式：已选中来源 {item['ref']}，需要实际模型与人工验证形成结论。")
        for item in context.get('diagnostics', [])[:2]:
            if item.get('ref') in allowed_refs:
                citations.append(item['ref'])
                facts.append(f"诊断记录 {item['ref']}：{item.get('kind', '')}")
        for item in nodes[:3]:
            ref = item.get("ref")
            if ref in allowed_refs:
                citations.append(ref)
                facts.append(f"{item.get('type')}: {item.get('label')}")
        for item in memories[:2]:
            ref = item.get("ref")
            if ref in allowed_refs:
                citations.append(ref)
                facts.append(f"memory: {item.get('summary')}")
        if not citations and coverage:
            ref = coverage[0].get("ref")
            if ref in allowed_refs:
                citations.append(ref)
                facts.append(f"coverage: {coverage[0].get('label')} = {coverage[0].get('status')}")
        return {
            "answer": (
                "这是演示模式的项目摘要，尚未调用真实 AI 模型。"
                + ("已检索到的记录：" + "；".join(facts[:5]) if facts else "当前没有找到足够相关的结构化记录。")
            ),
            "citations": citations[:8],
            "gaps": ["Use the cited project records to confirm details before taking any assessment action."] if not citations else [],
            "suggested_views": ["knowledge_graph", "memory", "coverage"],
        }
