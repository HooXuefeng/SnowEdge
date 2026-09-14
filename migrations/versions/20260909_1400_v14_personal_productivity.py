"""V1.4 personal productivity settings, attachments and backup records.

Revision ID: v1_4_personal
Revises: v1_3_enterprise
"""
from alembic import op
import sqlalchemy as sa

revision = "v1_4_personal"
down_revision = "v1_3_enterprise"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    if "projects" in tables:
        project_columns = {c["name"] for c in inspector.get_columns("projects")}
        if "template_slug" not in project_columns:
            with op.batch_alter_table("projects") as batch:
                batch.add_column(sa.Column("template_slug", sa.String(length=80), nullable=False, server_default="web-api"))

    op.create_table(
        "app_preferences",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("key", sa.String(length=120), nullable=False, unique=True),
        sa.Column("value_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("secret_encrypted", sa.Text(), nullable=False, server_default=""),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
    )
    op.create_table(
        "evidence_attachments",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("finding_id", sa.Integer(), nullable=False),
        sa.Column("evidence_id", sa.Integer(), nullable=True),
        sa.Column("attachment_type", sa.String(length=60), nullable=False, server_default="screenshot"),
        sa.Column("label", sa.String(length=300), nullable=False, server_default=""),
        sa.Column("file_path", sa.String(length=2000), nullable=False),
        sa.Column("mime_type", sa.String(length=100), nullable=False, server_default="image/png"),
        sa.Column("file_sha256", sa.String(length=64), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(), nullable=True),
    )
    op.create_table(
        "backup_records",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("backup_type", sa.String(length=60), nullable=False, server_default="sanitized_auto"),
        sa.Column("file_path", sa.String(length=2000), nullable=False),
        sa.Column("file_sha256", sa.String(length=64), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("status", sa.String(length=60), nullable=False, server_default="done"),
        sa.Column("created_at", sa.DateTime(), nullable=True),
    )


def downgrade():
    op.drop_table("backup_records")
    op.drop_table("evidence_attachments")
    op.drop_table("app_preferences")
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "projects" in inspector.get_table_names():
        columns = {c["name"] for c in inspector.get_columns("projects")}
        if "template_slug" in columns:
            with op.batch_alter_table("projects") as batch:
                batch.drop_column("template_slug")
