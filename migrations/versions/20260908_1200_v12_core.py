"""V1.2 persistent jobs, endpoint parameters, finding taxonomy and engagement metadata.

Revision ID: v1_2_core
Revises: v1_1_legacy
"""
from alembic import op
import sqlalchemy as sa

revision = "v1_2_core"
down_revision = "v1_1_legacy"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("projects") as batch:
        batch.add_column(sa.Column("client_name", sa.String(length=240), nullable=False, server_default=""))
        batch.add_column(sa.Column("environment", sa.String(length=80), nullable=False, server_default="test"))
        batch.add_column(sa.Column("engagement_type", sa.String(length=80), nullable=False, server_default="authorized_pentest"))
        batch.add_column(sa.Column("status", sa.String(length=60), nullable=False, server_default="preparing"))
        batch.add_column(sa.Column("start_date", sa.String(length=32), nullable=False, server_default=""))
        batch.add_column(sa.Column("end_date", sa.String(length=32), nullable=False, server_default=""))
        batch.add_column(sa.Column("authorization_note", sa.Text(), nullable=False, server_default=""))
        batch.add_column(sa.Column("testers_json", sa.Text(), nullable=False, server_default="[]"))

    with op.batch_alter_table("endpoints") as batch:
        batch.add_column(sa.Column("normalized_path", sa.String(length=1000), nullable=False, server_default=""))
        batch.add_column(sa.Column("fingerprint", sa.String(length=80), nullable=False, server_default=""))
        batch.add_column(sa.Column("content_type", sa.String(length=200), nullable=False, server_default=""))
        batch.add_column(sa.Column("auth_observed", sa.Integer(), nullable=False, server_default="0"))
        batch.add_column(sa.Column("source", sa.String(length=100), nullable=False, server_default="discovery"))
        batch.add_column(sa.Column("first_seen_at", sa.DateTime(), nullable=True))
        batch.add_column(sa.Column("last_seen_at", sa.DateTime(), nullable=True))

    with op.batch_alter_table("findings") as batch:
        batch.add_column(sa.Column("fingerprint", sa.String(length=80), nullable=False, server_default=""))
        batch.add_column(sa.Column("dedupe_status", sa.String(length=40), nullable=False, server_default="unique"))
        batch.add_column(sa.Column("duplicate_of_id", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("vuln_type", sa.String(length=160), nullable=False, server_default=""))
        batch.add_column(sa.Column("parameter", sa.String(length=300), nullable=False, server_default=""))
        batch.add_column(sa.Column("cwe_id", sa.String(length=32), nullable=False, server_default=""))
        batch.add_column(sa.Column("owasp_category", sa.String(length=80), nullable=False, server_default=""))
        batch.add_column(sa.Column("txb02_category", sa.String(length=180), nullable=False, server_default=""))
        batch.add_column(sa.Column("verification_state", sa.String(length=60), nullable=False, server_default="unverified"))

    op.create_table(
        "endpoint_parameters",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("endpoint_id", sa.Integer(), sa.ForeignKey("endpoints.id"), nullable=False),
        sa.Column("location", sa.String(length=40), nullable=False),
        sa.Column("name", sa.String(length=300), nullable=False),
        sa.Column("value_type", sa.String(length=80), nullable=False, server_default="unknown"),
        sa.Column("required", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("sensitive", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("source", sa.String(length=100), nullable=False, server_default="observed"),
        sa.Column("example_redacted", sa.String(length=500), nullable=False, server_default=""),
        sa.Column("fingerprint", sa.String(length=80), nullable=False, server_default=""),
        sa.Column("first_seen_at", sa.DateTime(), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(), nullable=True),
    )

    op.create_table(
        "persistent_jobs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=True),
        sa.Column("kind", sa.String(length=100), nullable=False),
        sa.Column("target", sa.String(length=1200), nullable=False, server_default=""),
        sa.Column("payload_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("scope_snapshot_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("scope_hash", sa.String(length=80), nullable=False, server_default=""),
        sa.Column("status", sa.String(length=60), nullable=False, server_default="queued"),
        sa.Column("priority", sa.Integer(), nullable=False, server_default="100"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="2"),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False, server_default="300"),
        sa.Column("error", sa.Text(), nullable=False, server_default=""),
        sa.Column("result_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("next_run_at", sa.DateTime(), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
    )

    op.create_table(
        "persistent_job_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("job_id", sa.Integer(), sa.ForeignKey("persistent_jobs.id"), nullable=False),
        sa.Column("event_type", sa.String(length=80), nullable=False),
        sa.Column("status", sa.String(length=60), nullable=False, server_default=""),
        sa.Column("detail", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(), nullable=True),
    )

    op.create_table(
        "authorization_matrix_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("stored_request_id", sa.Integer(), sa.ForeignKey("stored_requests.id"), nullable=False),
        sa.Column("baseline_identity_id", sa.Integer(), sa.ForeignKey("identities.id"), nullable=True),
        sa.Column("selected_identity_ids_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("include_anonymous", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("status", sa.String(length=60), nullable=False, server_default="queued"),
        sa.Column("case_ids_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("summary_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(), nullable=True),
    )

    op.create_table(
        "finding_occurrences",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("finding_id", sa.Integer(), sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("source", sa.String(length=100), nullable=False, server_default=""),
        sa.Column("target", sa.String(length=1000), nullable=False, server_default=""),
        sa.Column("fingerprint", sa.String(length=80), nullable=False, server_default=""),
        sa.Column("evidence_id", sa.Integer(), sa.ForeignKey("evidence.id"), nullable=True),
        sa.Column("detail_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(), nullable=True),
    )


def downgrade():
    op.drop_table("finding_occurrences")
    op.drop_table("authorization_matrix_runs")
    op.drop_table("persistent_job_events")
    op.drop_table("persistent_jobs")
    op.drop_table("endpoint_parameters")

    with op.batch_alter_table("findings") as batch:
        for name in [
            "verification_state", "txb02_category", "owasp_category", "cwe_id",
            "parameter", "vuln_type", "duplicate_of_id", "dedupe_status", "fingerprint",
        ]:
            batch.drop_column(name)

    with op.batch_alter_table("endpoints") as batch:
        for name in [
            "last_seen_at", "first_seen_at", "source", "auth_observed",
            "content_type", "fingerprint", "normalized_path",
        ]:
            batch.drop_column(name)

    with op.batch_alter_table("projects") as batch:
        for name in [
            "testers_json", "authorization_note", "end_date", "start_date",
            "status", "engagement_type", "environment", "client_name",
        ]:
            batch.drop_column(name)
