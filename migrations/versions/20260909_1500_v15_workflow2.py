"""V1.5 request revisions and screenshot annotation metadata.

Revision ID: v1_5_workflow2
Revises: v1_4_personal
"""
from alembic import op
import sqlalchemy as sa

revision = "v1_5_workflow2"
down_revision = "v1_4_personal"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    if "evidence_attachments" in tables:
        cols = {c["name"] for c in inspector.get_columns("evidence_attachments")}
        with op.batch_alter_table("evidence_attachments") as batch:
            if "sort_order" not in cols:
                batch.add_column(sa.Column("sort_order", sa.Integer(), nullable=False, server_default="0"))
            if "annotation_json" not in cols:
                batch.add_column(sa.Column("annotation_json", sa.Text(), nullable=False, server_default="[]"))

    if "stored_request_revisions" not in tables:
        op.create_table(
            "stored_request_revisions",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("project_id", sa.Integer(), nullable=False),
            sa.Column("stored_request_id", sa.Integer(), nullable=False),
            sa.Column("revision_no", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("name", sa.String(length=240), nullable=False, server_default="Request"),
            sa.Column("method", sa.String(length=16), nullable=False, server_default="GET"),
            sa.Column("url", sa.String(length=2000), nullable=False),
            sa.Column("headers_json", sa.Text(), nullable=False, server_default="{}"),
            sa.Column("secret_headers_encrypted", sa.Text(), nullable=False, server_default=""),
            sa.Column("body", sa.Text(), nullable=False, server_default=""),
            sa.Column("policy_class", sa.String(length=50), nullable=False, server_default="READ_ONLY"),
            sa.Column("change_note", sa.String(length=500), nullable=False, server_default=""),
            sa.Column("created_at", sa.DateTime(), nullable=True),
        )
        op.create_index(
            "ix_stored_request_revisions_request_revision",
            "stored_request_revisions",
            ["stored_request_id", "revision_no"],
            unique=True,
        )


def downgrade():
    op.drop_index("ix_stored_request_revisions_request_revision", table_name="stored_request_revisions")
    op.drop_table("stored_request_revisions")
    with op.batch_alter_table("evidence_attachments") as batch:
        batch.drop_column("annotation_json")
        batch.drop_column("sort_order")
