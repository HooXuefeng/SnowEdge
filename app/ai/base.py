from abc import ABC, abstractmethod

class AIProvider(ABC):
    @abstractmethod
    async def analyze(self, context: dict) -> list[dict]:
        raise NotImplementedError

    async def review_authorization(self, context: dict) -> dict:
        """Optional second-opinion review over redacted authorization evidence."""
        return {}

    async def recommend_skills(self, context: dict, catalog: list[dict]) -> dict:
        """Recommend only from a caller-supplied Skill catalog."""
        return {"recommendations": [], "summary": ""}

    async def specialist_review(self, role: dict, context: dict, allowed_handoffs: list[str]) -> dict:
        """Analysis-only specialist review. It never grants or invokes tool permission."""
        return {
            "summary": "",
            "observations": [],
            "handoffs": [],
            "next_checks": [],
        }

    async def analyst_copilot(self, question: str, context: dict, allowed_refs: list[str]) -> dict:
        """Answer only from supplied redacted project context; never invoke tools."""
        return {"answer": "", "citations": [], "gaps": [], "suggested_views": []}

