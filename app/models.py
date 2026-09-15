from datetime import UTC, datetime
import hashlib
from sqlalchemy import String, Text, ForeignKey, DateTime, Integer, Index, event
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .db import Base

def _utcnow() -> datetime:
    """UTC timestamp stored as naive datetime for existing SQLite compatibility."""
    return datetime.now(UTC).replace(tzinfo=None)

class Project(Base):
    __tablename__ = "projects"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    scope_text: Mapped[str] = mapped_column(Text)
    client_name: Mapped[str] = mapped_column(String(240), default="")
    environment: Mapped[str] = mapped_column(String(80), default="test")
    engagement_type: Mapped[str] = mapped_column(String(80), default="authorized_pentest")
    status: Mapped[str] = mapped_column(String(60), default="preparing")
    start_date: Mapped[str] = mapped_column(String(32), default="")
    end_date: Mapped[str] = mapped_column(String(32), default="")
    authorization_note: Mapped[str] = mapped_column(Text, default="")
    testers_json: Mapped[str] = mapped_column(Text, default="[]")
    template_slug: Mapped[str] = mapped_column(String(80), default="web-api")
    scan_profile_id: Mapped[int | None] = mapped_column(ForeignKey("scan_profiles.id"), nullable=True)
    network_route_profile_id: Mapped[int | None] = mapped_column(ForeignKey("network_route_profiles.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    assets = relationship("Asset", back_populates="project", cascade="all, delete-orphan")
    tasks = relationship("Task", back_populates="project", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="project", cascade="all, delete-orphan")

class Asset(Base):
    __tablename__ = "assets"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    target: Mapped[str] = mapped_column(String(500))
    kind: Mapped[str] = mapped_column(String(50), default="unknown")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    project = relationship("Project", back_populates="assets")
    endpoints = relationship("Endpoint", back_populates="asset", cascade="all, delete-orphan")
    services = relationship("Service", back_populates="asset", cascade="all, delete-orphan")

class Endpoint(Base):
    __tablename__ = "endpoints"
    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"))
    url: Mapped[str] = mapped_column(String(1000))
    method: Mapped[str] = mapped_column(String(16), default="GET")
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    normalized_path: Mapped[str] = mapped_column(String(1000), default="")
    fingerprint: Mapped[str] = mapped_column(String(80), default="")
    content_type: Mapped[str] = mapped_column(String(200), default="")
    auth_observed: Mapped[int] = mapped_column(Integer, default=0)
    source: Mapped[str] = mapped_column(String(100), default="discovery")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    asset = relationship("Asset", back_populates="endpoints")

class Service(Base):
    __tablename__ = "services"
    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"))
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(20), default="tcp")
    name: Mapped[str] = mapped_column(String(100), default="unknown")
    banner: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    asset = relationship("Asset", back_populates="services")

class Task(Base):
    __tablename__ = "tasks"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    action: Mapped[str] = mapped_column(String(100))
    target: Mapped[str] = mapped_column(String(1000))
    policy_class: Mapped[str] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(50), default="queued")
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    project = relationship("Project", back_populates="tasks")
    evidence = relationship("Evidence", back_populates="task", cascade="all, delete-orphan")

class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    title: Mapped[str] = mapped_column(String(300))
    severity: Mapped[str] = mapped_column(String(30), default="info")
    target: Mapped[str] = mapped_column(String(1000))
    description: Mapped[str] = mapped_column(Text)
    recommendation: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(100), default="system")
    fingerprint: Mapped[str] = mapped_column(String(80), default="")
    dedupe_status: Mapped[str] = mapped_column(String(40), default="unique")
    duplicate_of_id: Mapped[int | None] = mapped_column(ForeignKey("findings.id"), nullable=True)
    vuln_type: Mapped[str] = mapped_column(String(160), default="")
    parameter: Mapped[str] = mapped_column(String(300), default="")
    cwe_id: Mapped[str] = mapped_column(String(32), default="")
    owasp_category: Mapped[str] = mapped_column(String(80), default="")
    txb02_category: Mapped[str] = mapped_column(String(180), default="")
    finding_state: Mapped[str] = mapped_column(String(60), default="candidate")
    verification_state: Mapped[str] = mapped_column(String(60), default="unverified")
    reopened_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    project = relationship("Project", back_populates="findings")
    evidence = relationship("Evidence", back_populates="finding", cascade="all, delete-orphan")

class Evidence(Base):
    __tablename__ = "evidence"
    __table_args__ = (
        Index("ix_evidence_project_id", "project_id"),
        Index("ix_evidence_content_sha256", "content_sha256"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("findings.id"), nullable=True)
    task_id: Mapped[int | None] = mapped_column(ForeignKey("tasks.id"), nullable=True)
    project_id: Mapped[int | None] = mapped_column(ForeignKey("projects.id"), nullable=True)
    job_id: Mapped[int | None] = mapped_column(ForeignKey("persistent_jobs.id"), nullable=True)
    parent_evidence_id: Mapped[int | None] = mapped_column(ForeignKey("evidence.id"), nullable=True)
    source_type: Mapped[str] = mapped_column(String(80), default="")
    source_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    redaction_state: Mapped[str] = mapped_column(String(40), default="unknown")
    content_sha256: Mapped[str] = mapped_column(String(64), default="")
    integrity_sha256: Mapped[str] = mapped_column(String(64), default="")
    kind: Mapped[str] = mapped_column(String(100))
    content: Mapped[str] = mapped_column(Text)
    captured_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    finding = relationship("Finding", back_populates="evidence")
    task = relationship("Task", back_populates="evidence")


class WebArtifact(Base):
    __tablename__ = "web_artifacts"
    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"))
    url: Mapped[str] = mapped_column(String(1500))
    artifact_type: Mapped[str] = mapped_column(String(50), default="page")
    source_url: Mapped[str] = mapped_column(String(1500), default="")
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    content_type: Mapped[str] = mapped_column(String(200), default="")
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

class RouteCandidate(Base):
    __tablename__ = "route_candidates"
    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"))
    path: Mapped[str] = mapped_column(String(1500))
    method: Mapped[str] = mapped_column(String(16), default="UNKNOWN")
    source: Mapped[str] = mapped_column(String(1500), default="")
    confidence: Mapped[str] = mapped_column(String(30), default="medium")
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

class AgentRun(Base):
    __tablename__ = "agent_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    target: Mapped[str] = mapped_column(String(1000))
    mission: Mapped[str] = mapped_column(Text, default="Authorized security assessment")
    stage: Mapped[str] = mapped_column(String(80), default="queued")
    status: Mapped[str] = mapped_column(String(50), default="queued")
    summary: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

class AgentEvent(Base):
    __tablename__ = "agent_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    agent_run_id: Mapped[int] = mapped_column(ForeignKey("agent_runs.id"))
    event_type: Mapped[str] = mapped_column(String(80), default="observation")
    stage: Mapped[str] = mapped_column(String(80), default="")
    title: Mapped[str] = mapped_column(String(300), default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    policy_class: Mapped[str] = mapped_column(String(50), default="READ_ONLY")
    status: Mapped[str] = mapped_column(String(50), default="done")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class Identity(Base):
    __tablename__ = "identities"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    name: Mapped[str] = mapped_column(String(120))
    role: Mapped[str] = mapped_column(String(80), default="User")
    headers_encrypted: Mapped[str] = mapped_column(Text, default="")
    cookies_encrypted: Mapped[str] = mapped_column(Text, default="")
    vault_item_id: Mapped[int | None] = mapped_column(ForeignKey("secret_vault_items.id"), nullable=True)
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

class StoredRequest(Base):
    __tablename__ = "stored_requests"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    name: Mapped[str] = mapped_column(String(240), default="Request")
    method: Mapped[str] = mapped_column(String(16), default="GET")
    url: Mapped[str] = mapped_column(String(2000))
    headers_json: Mapped[str] = mapped_column(Text, default="{}")
    secret_headers_encrypted: Mapped[str] = mapped_column(Text, default="")
    body: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(80), default="manual")
    policy_class: Mapped[str] = mapped_column(String(50), default="READ_ONLY")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

class ReplayResult(Base):
    __tablename__ = "replay_results"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    stored_request_id: Mapped[int] = mapped_column(ForeignKey("stored_requests.id"))
    identity_id: Mapped[int | None] = mapped_column(ForeignKey("identities.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="done")
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    final_url: Mapped[str] = mapped_column(String(2000), default="")
    request_headers_json: Mapped[str] = mapped_column(Text, default="{}")
    response_headers_json: Mapped[str] = mapped_column(Text, default="{}")
    response_body: Mapped[str] = mapped_column(Text, default="")
    elapsed_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

class ResponseDiff(Base):
    __tablename__ = "response_diffs"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    left_replay_id: Mapped[int] = mapped_column(ForeignKey("replay_results.id"))
    right_replay_id: Mapped[int] = mapped_column(ForeignKey("replay_results.id"))
    summary_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class AuthorizationCase(Base):
    __tablename__ = "authorization_cases"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    stored_request_id: Mapped[int] = mapped_column(ForeignKey("stored_requests.id"))
    test_type: Mapped[str] = mapped_column(String(50), default="horizontal")
    baseline_identity_id: Mapped[int | None] = mapped_column(ForeignKey("identities.id"), nullable=True)
    comparison_identity_id: Mapped[int | None] = mapped_column(ForeignKey("identities.id"), nullable=True)
    expected_owner_identity_id: Mapped[int | None] = mapped_column(ForeignKey("identities.id"), nullable=True)
    baseline_replay_id: Mapped[int | None] = mapped_column(ForeignKey("replay_results.id"), nullable=True)
    comparison_replay_id: Mapped[int | None] = mapped_column(ForeignKey("replay_results.id"), nullable=True)
    response_diff_id: Mapped[int | None] = mapped_column(ForeignKey("response_diffs.id"), nullable=True)
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("findings.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="queued")
    classification: Mapped[str] = mapped_column(String(100), default="pending")
    confidence: Mapped[int] = mapped_column(Integer, default=0)
    object_label: Mapped[str] = mapped_column(String(300), default="")
    summary_json: Mapped[str] = mapped_column(Text, default="{}")
    ai_review_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class SkillDefinition(Base):
    __tablename__ = "skill_definitions"
    id: Mapped[int] = mapped_column(primary_key=True)
    slug: Mapped[str] = mapped_column(String(120), unique=True)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    category: Mapped[str] = mapped_column(String(100), default="general")
    tags_json: Mapped[str] = mapped_column(Text, default="[]")
    risk_tier: Mapped[str] = mapped_column(String(40), default="safe")
    execution_mode: Mapped[str] = mapped_column(String(50), default="KNOWLEDGE_ONLY")
    capabilities_json: Mapped[str] = mapped_column(Text, default="[]")
    body_markdown: Mapped[str] = mapped_column(Text, default="")
    source_kind: Mapped[str] = mapped_column(String(50), default="builtin")
    source_url: Mapped[str] = mapped_column(String(1200), default="")
    source_name: Mapped[str] = mapped_column(String(240), default="")
    version: Mapped[str] = mapped_column(String(40), default="1.0.0")
    builtin: Mapped[int] = mapped_column(Integer, default=0)
    enabled_by_default: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

class ProjectSkill(Base):
    __tablename__ = "project_skills"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    skill_id: Mapped[int] = mapped_column(ForeignKey("skill_definitions.id"))
    enabled: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

class SkillRun(Base):
    __tablename__ = "skill_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    skill_id: Mapped[int] = mapped_column(ForeignKey("skill_definitions.id"))
    agent_run_id: Mapped[int | None] = mapped_column(ForeignKey("agent_runs.id"), nullable=True)
    target: Mapped[str] = mapped_column(String(1200), default="")
    status: Mapped[str] = mapped_column(String(50), default="queued")
    stage: Mapped[str] = mapped_column(String(100), default="")
    output_summary_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class SkillPlan(Base):
    __tablename__ = "skill_plans"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    target: Mapped[str] = mapped_column(String(1200), default="")
    status: Mapped[str] = mapped_column(String(50), default="draft")
    profile_json: Mapped[str] = mapped_column(Text, default="{}")
    recommendations_json: Mapped[str] = mapped_column(Text, default="[]")
    approved_skills_json: Mapped[str] = mapped_column(Text, default="[]")
    ai_summary: Mapped[str] = mapped_column(Text, default="")
    executed_agent_run_id: Mapped[int | None] = mapped_column(ForeignKey("agent_runs.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class ExecutionGraphNode(Base):
    __tablename__ = "execution_graph_nodes"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    skill_plan_id: Mapped[int] = mapped_column(ForeignKey("skill_plans.id"))
    skill_slug: Mapped[str] = mapped_column(String(120))
    label: Mapped[str] = mapped_column(String(220), default="")
    stage: Mapped[str] = mapped_column(String(80), default="analysis")
    execution_mode: Mapped[str] = mapped_column(String(50), default="DETERMINISTIC")
    status: Mapped[str] = mapped_column(String(50), default="planned")
    order_index: Mapped[int] = mapped_column(Integer, default=0)
    depends_on_json: Mapped[str] = mapped_column(Text, default="[]")
    capabilities_json: Mapped[str] = mapped_column(Text, default="[]")
    rationale: Mapped[str] = mapped_column(Text, default="")
    skill_run_id: Mapped[int | None] = mapped_column(ForeignKey("skill_runs.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class ProofCapsule(Base):
    __tablename__ = "proof_capsules"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"))
    verifier_type: Mapped[str] = mapped_column(String(100), default="evidence_snapshot")
    status: Mapped[str] = mapped_column(String(50), default="ready")
    expected_json: Mapped[str] = mapped_column(Text, default="{}")
    observed_json: Mapped[str] = mapped_column(Text, default="{}")
    source_evidence_ids_json: Mapped[str] = mapped_column(Text, default="[]")
    retest_count: Mapped[int] = mapped_column(Integer, default=0)
    last_retest_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class RetestRun(Base):
    __tablename__ = "retest_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"))
    proof_capsule_id: Mapped[int] = mapped_column(ForeignKey("proof_capsules.id"))
    verifier_type: Mapped[str] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(50), default="queued")
    expected_json: Mapped[str] = mapped_column(Text, default="{}")
    observed_json: Mapped[str] = mapped_column(Text, default="{}")
    evidence_id: Mapped[int | None] = mapped_column(ForeignKey("evidence.id"), nullable=True)
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class BrowserSession(Base):
    __tablename__ = "browser_sessions"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    target_url: Mapped[str] = mapped_column(String(2000))
    identity_id: Mapped[int | None] = mapped_column(ForeignKey("identities.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="queued")
    final_url: Mapped[str] = mapped_column(String(2000), default="")
    title: Mapped[str] = mapped_column(String(500), default="")
    browser_name: Mapped[str] = mapped_column(String(120), default="")
    summary_json: Mapped[str] = mapped_column(Text, default="{}")
    error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class BrowserEvent(Base):
    __tablename__ = "browser_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    browser_session_id: Mapped[int] = mapped_column(ForeignKey("browser_sessions.id"))
    event_type: Mapped[str] = mapped_column(String(80))
    method: Mapped[str] = mapped_column(String(20), default="")
    url: Mapped[str] = mapped_column(String(2200), default="")
    resource_type: Mapped[str] = mapped_column(String(80), default="")
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    detail_json: Mapped[str] = mapped_column(Text, default="{}")
    in_scope: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class BrowserArtifact(Base):
    __tablename__ = "browser_artifacts"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    browser_session_id: Mapped[int] = mapped_column(ForeignKey("browser_sessions.id"))
    artifact_type: Mapped[str] = mapped_column(String(80))
    label: Mapped[str] = mapped_column(String(300), default="")
    file_path: Mapped[str] = mapped_column(String(2000), default="")
    content_text: Mapped[str] = mapped_column(Text, default="")
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class KnowledgeNode(Base):
    __tablename__ = "knowledge_nodes"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    node_key: Mapped[str] = mapped_column(String(240))
    node_type: Mapped[str] = mapped_column(String(80))
    entity_type: Mapped[str] = mapped_column(String(80), default="")
    entity_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    label: Mapped[str] = mapped_column(String(500), default="")
    summary_json: Mapped[str] = mapped_column(Text, default="{}")
    risk_level: Mapped[str] = mapped_column(String(30), default="info")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class KnowledgeEdge(Base):
    __tablename__ = "knowledge_edges"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    source_node_id: Mapped[int] = mapped_column(ForeignKey("knowledge_nodes.id"))
    target_node_id: Mapped[int] = mapped_column(ForeignKey("knowledge_nodes.id"))
    relation: Mapped[str] = mapped_column(String(120))
    strength: Mapped[str] = mapped_column(String(30), default="observed")
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class AssessmentMemory(Base):
    __tablename__ = "assessment_memories"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    fingerprint: Mapped[str] = mapped_column(String(180))
    memory_type: Mapped[str] = mapped_column(String(80))
    subject: Mapped[str] = mapped_column(String(1200), default="")
    outcome: Mapped[str] = mapped_column(String(120), default="")
    confidence: Mapped[int] = mapped_column(Integer, default=0)
    repeat_guidance: Mapped[str] = mapped_column(String(80), default="review")
    source_type: Mapped[str] = mapped_column(String(80), default="")
    source_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class SpecialistAgentRun(Base):
    __tablename__ = "specialist_agent_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    parent_agent_run_id: Mapped[int | None] = mapped_column(ForeignKey("agent_runs.id"), nullable=True)
    role_slug: Mapped[str] = mapped_column(String(100))
    role_name: Mapped[str] = mapped_column(String(180))
    status: Mapped[str] = mapped_column(String(50), default="queued")
    intent_contract_json: Mapped[str] = mapped_column(Text, default="{}")
    input_snapshot_json: Mapped[str] = mapped_column(Text, default="{}")
    output_json: Mapped[str] = mapped_column(Text, default="{}")
    drift_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class AgentHandoff(Base):
    __tablename__ = "agent_handoffs"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    from_specialist_run_id: Mapped[int] = mapped_column(ForeignKey("specialist_agent_runs.id"))
    to_role_slug: Mapped[str] = mapped_column(String(100))
    handoff_type: Mapped[str] = mapped_column(String(80), default="analysis")
    reason: Mapped[str] = mapped_column(Text, default="")
    subject_keys_json: Mapped[str] = mapped_column(Text, default="[]")
    status: Mapped[str] = mapped_column(String(50), default="recorded")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class CoverageSnapshot(Base):
    __tablename__ = "coverage_snapshots"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    score: Mapped[int] = mapped_column(Integer, default=0)
    covered_count: Mapped[int] = mapped_column(Integer, default=0)
    partial_count: Mapped[int] = mapped_column(Integer, default=0)
    gap_count: Mapped[int] = mapped_column(Integer, default=0)
    needs_review_count: Mapped[int] = mapped_column(Integer, default=0)
    matrix_json: Mapped[str] = mapped_column(Text, default="[]")
    gaps_json: Mapped[str] = mapped_column(Text, default="[]")
    summary: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class CopilotQuery(Base):
    __tablename__ = "copilot_queries"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    question: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(50), default="queued")
    provider: Mapped[str] = mapped_column(String(120), default="")
    answer_json: Mapped[str] = mapped_column(Text, default="{}")
    citation_count: Mapped[int] = mapped_column(Integer, default=0)
    drift_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class FindingLifecycle(Base):
    __tablename__ = "finding_lifecycles"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"))
    status: Mapped[str] = mapped_column(String(80), default="open")
    owner: Mapped[str] = mapped_column(String(180), default="")
    priority: Mapped[str] = mapped_column(String(40), default="normal")
    remediation_note: Mapped[str] = mapped_column(Text, default="")
    retest_status: Mapped[str] = mapped_column(String(80), default="not_queued")
    proof_capsule_id: Mapped[int | None] = mapped_column(ForeignKey("proof_capsules.id"), nullable=True)
    last_retest_run_id: Mapped[int | None] = mapped_column(ForeignKey("retest_runs.id"), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class RemediationEvent(Base):
    __tablename__ = "remediation_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"))
    lifecycle_id: Mapped[int] = mapped_column(ForeignKey("finding_lifecycles.id"))
    event_type: Mapped[str] = mapped_column(String(100))
    from_status: Mapped[str] = mapped_column(String(80), default="")
    to_status: Mapped[str] = mapped_column(String(80), default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(80), default="analyst")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class EndpointParameter(Base):
    __tablename__ = "endpoint_parameters"
    id: Mapped[int] = mapped_column(primary_key=True)
    endpoint_id: Mapped[int] = mapped_column(ForeignKey("endpoints.id"))
    location: Mapped[str] = mapped_column(String(40))
    name: Mapped[str] = mapped_column(String(300))
    value_type: Mapped[str] = mapped_column(String(80), default="unknown")
    required: Mapped[int] = mapped_column(Integer, default=0)
    sensitive: Mapped[int] = mapped_column(Integer, default=0)
    source: Mapped[str] = mapped_column(String(100), default="observed")
    example_redacted: Mapped[str] = mapped_column(String(500), default="")
    fingerprint: Mapped[str] = mapped_column(String(80), default="")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class PersistentJob(Base):
    __tablename__ = "persistent_jobs"
    __table_args__ = (
        Index("ix_persistent_jobs_status_priority", "status", "priority", "id"),
        Index("ix_persistent_jobs_lease_expires", "lease_expires_at"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int | None] = mapped_column(ForeignKey("projects.id"), nullable=True)
    kind: Mapped[str] = mapped_column(String(100))
    target: Mapped[str] = mapped_column(String(1200), default="")
    payload_json: Mapped[str] = mapped_column(Text, default="{}")
    scope_snapshot_json: Mapped[str] = mapped_column(Text, default="[]")
    scope_hash: Mapped[str] = mapped_column(String(80), default="")
    status: Mapped[str] = mapped_column(String(60), default="queued")
    priority: Mapped[int] = mapped_column(Integer, default=100)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=2)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=300)
    error: Mapped[str] = mapped_column(Text, default="")
    result_json: Mapped[str] = mapped_column(Text, default="{}")
    worker_id: Mapped[str] = mapped_column(String(120), default="")
    lease_token: Mapped[str] = mapped_column(String(120), default="")
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class PersistentJobEvent(Base):
    __tablename__ = "persistent_job_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("persistent_jobs.id"))
    event_type: Mapped[str] = mapped_column(String(80))
    status: Mapped[str] = mapped_column(String(60), default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class ToolchainRun(Base):
    __tablename__ = "toolchain_runs"
    __table_args__ = (Index("ix_toolchain_runs_project_created", "project_id", "created_at"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    plan_id: Mapped[str] = mapped_column(String(80))
    name: Mapped[str] = mapped_column(String(200))
    source_target: Mapped[str] = mapped_column(String(1200))
    ports_json: Mapped[str] = mapped_column(Text, default="[]")
    status: Mapped[str] = mapped_column(String(60), default="queued")
    current_step: Mapped[int] = mapped_column(Integer, default=0)
    total_steps: Mapped[int] = mapped_column(Integer, default=0)
    summary_json: Mapped[str] = mapped_column(Text, default="{}")
    error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class ToolchainStep(Base):
    __tablename__ = "toolchain_steps"
    __table_args__ = (Index("ix_toolchain_steps_run_position", "run_id", "position", unique=True),)
    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("toolchain_runs.id"))
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    position: Mapped[int] = mapped_column(Integer)
    tool_id: Mapped[str] = mapped_column(String(80))
    status: Mapped[str] = mapped_column(String(60), default="pending")
    input_json: Mapped[str] = mapped_column(Text, default="[]")
    job_ids_json: Mapped[str] = mapped_column(Text, default="[]")
    result_json: Mapped[str] = mapped_column(Text, default="{}")
    error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class AuthorizationMatrixRun(Base):
    __tablename__ = "authorization_matrix_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    stored_request_id: Mapped[int] = mapped_column(ForeignKey("stored_requests.id"))
    baseline_identity_id: Mapped[int | None] = mapped_column(ForeignKey("identities.id"), nullable=True)
    selected_identity_ids_json: Mapped[str] = mapped_column(Text, default="[]")
    include_anonymous: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(60), default="queued")
    case_ids_json: Mapped[str] = mapped_column(Text, default="[]")
    summary_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class FindingOccurrence(Base):
    __tablename__ = "finding_occurrences"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"))
    source: Mapped[str] = mapped_column(String(100), default="")
    target: Mapped[str] = mapped_column(String(1000), default="")
    fingerprint: Mapped[str] = mapped_column(String(80), default="")
    evidence_id: Mapped[int | None] = mapped_column(ForeignKey("evidence.id"), nullable=True)
    detail_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class JobWorker(Base):
    __tablename__ = "job_workers"
    id: Mapped[int] = mapped_column(primary_key=True)
    worker_id: Mapped[str] = mapped_column(String(120), unique=True)
    hostname: Mapped[str] = mapped_column(String(240), default="")
    pid: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(40), default="online")
    capabilities_json: Mapped[str] = mapped_column(Text, default="[]")
    active_job_id: Mapped[int | None] = mapped_column(ForeignKey("persistent_jobs.id"), nullable=True)
    last_heartbeat_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    stopped_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class EvidenceProvenance(Base):
    __tablename__ = "evidence_provenance"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    evidence_id: Mapped[int] = mapped_column(ForeignKey("evidence.id"))
    relation: Mapped[str] = mapped_column(String(80), default="DERIVED_FROM")
    entity_type: Mapped[str] = mapped_column(String(80))
    entity_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    entity_ref: Mapped[str] = mapped_column(String(500), default="")
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class ImportBatch(Base):
    __tablename__ = "import_batches"
    __table_args__ = (
        Index("ix_import_batches_project_id", "project_id", "id"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    import_type: Mapped[str] = mapped_column(String(80))
    filename: Mapped[str] = mapped_column(String(300), default="")
    file_sha256: Mapped[str] = mapped_column(String(64), default="")
    status: Mapped[str] = mapped_column(String(60), default="queued")
    records_seen: Mapped[int] = mapped_column(Integer, default=0)
    records_imported: Mapped[int] = mapped_column(Integer, default=0)
    records_skipped: Mapped[int] = mapped_column(Integer, default=0)
    summary_json: Mapped[str] = mapped_column(Text, default="{}")
    error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class ImportRecord(Base):
    __tablename__ = "import_records"
    id: Mapped[int] = mapped_column(primary_key=True)
    batch_id: Mapped[int] = mapped_column(ForeignKey("import_batches.id"))
    record_type: Mapped[str] = mapped_column(String(80))
    source_ref: Mapped[str] = mapped_column(String(500), default="")
    status: Mapped[str] = mapped_column(String(60), default="imported")
    entity_type: Mapped[str] = mapped_column(String(80), default="")
    entity_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    detail_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


def _evidence_hash_material(target: Evidence) -> tuple[str, str]:
    content = target.content or ""
    content_sha = hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()
    material = "\x1f".join([
        target.kind or "",
        content_sha,
        str(target.project_id or ""),
        str(target.finding_id or ""),
        str(target.task_id or ""),
        str(target.job_id or ""),
        str(target.parent_evidence_id or ""),
        target.source_type or "",
        str(target.source_id or ""),
        target.redaction_state or "",
    ])
    integrity_sha = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return content_sha, integrity_sha


@event.listens_for(Evidence, "before_insert")
def _hash_evidence_before_insert(mapper, connection, target):
    target.content_sha256, target.integrity_sha256 = _evidence_hash_material(target)
    if target.captured_at is None:
        target.captured_at = _utcnow()


@event.listens_for(Evidence, "before_update")
def _hash_evidence_before_update(mapper, connection, target):
    target.content_sha256, target.integrity_sha256 = _evidence_hash_material(target)


class AppPreference(Base):
    __tablename__ = "app_preferences"
    id: Mapped[int] = mapped_column(primary_key=True)
    key: Mapped[str] = mapped_column(String(120), unique=True)
    value_json: Mapped[str] = mapped_column(Text, default="{}")
    secret_encrypted: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class EvidenceAttachment(Base):
    __tablename__ = "evidence_attachments"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"))
    evidence_id: Mapped[int | None] = mapped_column(ForeignKey("evidence.id"), nullable=True)
    attachment_type: Mapped[str] = mapped_column(String(60), default="screenshot")
    label: Mapped[str] = mapped_column(String(300), default="")
    file_path: Mapped[str] = mapped_column(String(2000))
    mime_type: Mapped[str] = mapped_column(String(100), default="image/png")
    file_sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    sort_order: Mapped[int] = mapped_column(Integer, default=0)
    annotation_json: Mapped[str] = mapped_column(Text, default="[]")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class BackupRecord(Base):
    __tablename__ = "backup_records"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    backup_type: Mapped[str] = mapped_column(String(60), default="sanitized_auto")
    file_path: Mapped[str] = mapped_column(String(2000))
    file_sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(60), default="done")
    detail_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class StoredRequestRevision(Base):
    __tablename__ = "stored_request_revisions"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    stored_request_id: Mapped[int] = mapped_column(ForeignKey("stored_requests.id"))
    revision_no: Mapped[int] = mapped_column(Integer, default=1)
    name: Mapped[str] = mapped_column(String(240), default="Request")
    method: Mapped[str] = mapped_column(String(16), default="GET")
    url: Mapped[str] = mapped_column(String(2000))
    headers_json: Mapped[str] = mapped_column(Text, default="{}")
    secret_headers_encrypted: Mapped[str] = mapped_column(Text, default="")
    body: Mapped[str] = mapped_column(Text, default="")
    policy_class: Mapped[str] = mapped_column(String(50), default="READ_ONLY")
    change_note: Mapped[str] = mapped_column(String(500), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class SecretVaultItem(Base):
    __tablename__ = "secret_vault_items"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int | None] = mapped_column(ForeignKey("projects.id"), nullable=True)
    label: Mapped[str] = mapped_column(String(240))
    secret_type: Mapped[str] = mapped_column(String(80), default="custom")
    username: Mapped[str] = mapped_column(String(240), default="")
    value_encrypted: Mapped[str] = mapped_column(Text, default="")
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    disabled: Mapped[int] = mapped_column(Integer, default=0)
    deleted: Mapped[int] = mapped_column(Integer, default=0)
    notes: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class WorkspaceDraft(Base):
    __tablename__ = "workspace_drafts"
    __table_args__ = (Index("ix_workspace_draft_entity", "project_id", "entity_type", "entity_id", unique=True),)
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    entity_type: Mapped[str] = mapped_column(String(80), default="stored_request")
    entity_id: Mapped[int] = mapped_column(Integer)
    content_json: Mapped[str] = mapped_column(Text, default="{}")
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class RecoveryEvent(Base):
    __tablename__ = "recovery_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int | None] = mapped_column(ForeignKey("projects.id"), nullable=True)
    event_type: Mapped[str] = mapped_column(String(100))
    entity_type: Mapped[str] = mapped_column(String(80), default="")
    entity_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String(60), default="observed")
    detail_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class TechnologyFingerprint(Base):
    __tablename__ = "technology_fingerprints"
    __table_args__ = (
        Index("ix_technology_fingerprints_project_asset", "project_id", "asset_id"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"))
    endpoint_id: Mapped[int | None] = mapped_column(ForeignKey("endpoints.id"), nullable=True)
    category: Mapped[str] = mapped_column(String(80), default="technology")
    product: Mapped[str] = mapped_column(String(200))
    version: Mapped[str] = mapped_column(String(100), default="")
    confidence: Mapped[int] = mapped_column(Integer, default=70)
    detection_mode: Mapped[str] = mapped_column(String(40), default="passive")
    rule_id: Mapped[str] = mapped_column(String(120), default="")
    evidence_source: Mapped[str] = mapped_column(String(100), default="")
    evidence_summary_json: Mapped[str] = mapped_column(Text, default="{}")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class FingerprintRule(Base):
    __tablename__ = "fingerprint_rules"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int | None] = mapped_column(ForeignKey("projects.id"), nullable=True)
    name: Mapped[str] = mapped_column(String(200))
    category: Mapped[str] = mapped_column(String(80), default="technology")
    product: Mapped[str] = mapped_column(String(200))
    source: Mapped[str] = mapped_column(String(40), default="body")
    header_name: Mapped[str] = mapped_column(String(120), default="")
    pattern: Mapped[str] = mapped_column(String(300))
    confidence: Mapped[int] = mapped_column(Integer, default=80)
    enabled: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class ScanProfile(Base):
    __tablename__ = "scan_profiles"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    enabled_skill_slugs_json: Mapped[str] = mapped_column(Text, default="[]")
    batch_target_limit: Mapped[int] = mapped_column(Integer, default=20)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class NetworkRouteProfile(Base):
    __tablename__ = "network_route_profiles"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    route_type: Mapped[str] = mapped_column(String(40), default="direct")
    host: Mapped[str] = mapped_column(String(240), default="")
    port: Mapped[int] = mapped_column(Integer, default=0)
    username: Mapped[str] = mapped_column(String(240), default="")
    secret_encrypted: Mapped[str] = mapped_column(Text, default="")
    enabled: Mapped[int] = mapped_column(Integer, default=1)
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class BatchAssessment(Base):
    __tablename__ = "batch_assessments"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    name: Mapped[str] = mapped_column(String(240), default="Batch Assessment")
    scan_profile_id: Mapped[int | None] = mapped_column(ForeignKey("scan_profiles.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(60), default="queued")
    total_targets: Mapped[int] = mapped_column(Integer, default=0)
    completed_targets: Mapped[int] = mapped_column(Integer, default=0)
    failed_targets: Mapped[int] = mapped_column(Integer, default=0)
    skipped_targets: Mapped[int] = mapped_column(Integer, default=0)
    resource_gate: Mapped[str] = mapped_column(String(80), default="scan")
    max_parallel: Mapped[int] = mapped_column(Integer, default=1)
    summary_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class BatchAssessmentItem(Base):
    __tablename__ = "batch_assessment_items"
    __table_args__ = (Index("ix_batch_assessment_items_batch", "batch_id", "id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    batch_id: Mapped[int] = mapped_column(ForeignKey("batch_assessments.id"))
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    target: Mapped[str] = mapped_column(String(1000))
    status: Mapped[str] = mapped_column(String(60), default="queued")
    detail: Mapped[str] = mapped_column(Text, default="")
    result_json: Mapped[str] = mapped_column(Text, default="{}")
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
