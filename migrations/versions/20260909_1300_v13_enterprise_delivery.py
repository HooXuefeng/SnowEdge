"""V1.3 worker leases, evidence integrity, finding state and passive import records.

Revision ID: v1_3_enterprise
Revises: v1_2_core
"""
from alembic import op
import sqlalchemy as sa

revision = "v1_3_enterprise"
down_revision = "v1_2_core"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("persistent_jobs") as batch:
        batch.add_column(sa.Column("worker_id", sa.String(length=120), nullable=False, server_default=""))
        batch.add_column(sa.Column("lease_token", sa.String(length=120), nullable=False, server_default=""))
        batch.add_column(sa.Column("lease_expires_at", sa.DateTime(), nullable=True))
        batch.add_column(sa.Column("heartbeat_at", sa.DateTime(), nullable=True))

    with op.batch_alter_table("evidence") as batch:
        batch.add_column(sa.Column("project_id", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("job_id", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("parent_evidence_id", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("source_type", sa.String(length=80), nullable=False, server_default=""))
        batch.add_column(sa.Column("source_id", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("redaction_state", sa.String(length=40), nullable=False, server_default="unknown"))
        batch.add_column(sa.Column("content_sha256", sa.String(length=64), nullable=False, server_default=""))
        batch.add_column(sa.Column("integrity_sha256", sa.String(length=64), nullable=False, server_default=""))
        batch.add_column(sa.Column("captured_at", sa.DateTime(), nullable=True))

    with op.batch_alter_table("findings") as batch:
        batch.add_column(sa.Column("finding_state", sa.String(length=60), nullable=False, server_default="candidate"))
        batch.add_column(sa.Column("reopened_count", sa.Integer(), nullable=False, server_default="0"))

    op.create_table(
        "job_workers",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("worker_id", sa.String(length=120), nullable=False, unique=True),
        sa.Column("hostname", sa.String(length=240), nullable=False, server_default=""),
        sa.Column("pid", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("status", sa.String(length=40), nullable=False, server_default="online"),
        sa.Column("capabilities_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("active_job_id", sa.Integer(), sa.ForeignKey("persistent_jobs.id"), nullable=True),
        sa.Column("last_heartbeat_at", sa.DateTime(), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("stopped_at", sa.DateTime(), nullable=True),
    )

    op.create_table(
        "evidence_provenance",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("evidence_id", sa.Integer(), sa.ForeignKey("evidence.id"), nullable=False),
        sa.Column("relation", sa.String(length=80), nullable=False, server_default="DERIVED_FROM"),
        sa.Column("entity_type", sa.String(length=80), nullable=False),
        sa.Column("entity_id", sa.Integer(), nullable=True),
        sa.Column("entity_ref", sa.String(length=500), nullable=False, server_default=""),
        sa.Column("metadata_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(), nullable=True),
    )

    op.create_table(
        "import_batches",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("import_type", sa.String(length=80), nullable=False),
        sa.Column("filename", sa.String(length=300), nullable=False, server_default=""),
        sa.Column("file_sha256", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("status", sa.String(length=60), nullable=False, server_default="queued"),
        sa.Column("records_seen", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("records_imported", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("records_skipped", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("summary_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("error", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(), nullable=True),
    )

    op.create_table(
        "import_records",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("batch_id", sa.Integer(), sa.ForeignKey("import_batches.id"), nullable=False),
        sa.Column("record_type", sa.String(length=80), nullable=False),
        sa.Column("source_ref", sa.String(length=500), nullable=False, server_default=""),
        sa.Column("status", sa.String(length=60), nullable=False, server_default="imported"),
        sa.Column("entity_type", sa.String(length=80), nullable=False, server_default=""),
        sa.Column("entity_id", sa.Integer(), nullable=True),
        sa.Column("detail_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(), nullable=True),
    )


    op.create_index(
        "ix_persistent_jobs_status_priority",
        "persistent_jobs",
        ["status", "priority", "id"],
        unique=False,
    )
    op.create_index(
        "ix_persistent_jobs_lease_expires",
        "persistent_jobs",
        ["lease_expires_at"],
        unique=False,
    )
    op.create_index(
        "ix_evidence_project_id",
        "evidence",
        ["project_id"],
        unique=False,
    )
    op.create_index(
        "ix_evidence_content_sha256",
        "evidence",
        ["content_sha256"],
        unique=False,
    )
    op.create_index(
        "ix_import_batches_project_id",
        "import_batches",
        ["project_id", "id"],
        unique=False,
    )

def downgrade():
    op.drop_index("ix_import_batches_project_id", table_name="import_batches")
    op.drop_index("ix_evidence_content_sha256", table_name="evidence")
    op.drop_index("ix_evidence_project_id", table_name="evidence")
    op.drop_index("ix_persistent_jobs_lease_expires", table_name="persistent_jobs")
    op.drop_index("ix_persistent_jobs_status_priority", table_name="persistent_jobs")
    op.drop_table("import_records")
    op.drop_table("import_batches")
    op.drop_table("evidence_provenance")
    op.drop_table("job_workers")

    with op.batch_alter_table("findings") as batch:
        batch.drop_column("reopened_count")
        batch.drop_column("finding_state")

    with op.batch_alter_table("evidence") as batch:
        for name in [
            "captured_at", "integrity_sha256", "content_sha256", "redaction_state",
            "source_id", "source_type", "parent_evidence_id", "job_id", "project_id",
        ]:
            batch.drop_column(name)

    with op.batch_alter_table("persistent_jobs") as batch:
        for name in ["heartbeat_at", "lease_expires_at", "lease_token", "worker_id"]:
            batch.drop_column(name)
