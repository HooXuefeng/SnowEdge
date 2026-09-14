"""V1.6 personal reliability, vault, drafts and recovery metadata.

Revision ID: v1_6_reliability
Revises: v1_5_workflow2
"""
from alembic import op
import sqlalchemy as sa

revision = "v1_6_reliability"
down_revision = "v1_5_workflow2"
branch_labels = None
depends_on = None


def upgrade():
    bind=op.get_bind(); inspector=sa.inspect(bind); tables=set(inspector.get_table_names())
    if "identities" in tables:
        cols={c["name"] for c in inspector.get_columns("identities")}
        if "vault_item_id" not in cols:
            with op.batch_alter_table("identities") as batch:
                batch.add_column(sa.Column("vault_item_id",sa.Integer(),nullable=True))
    if "backup_records" in tables:
        cols={c["name"] for c in inspector.get_columns("backup_records")}
        if "detail_json" not in cols:
            with op.batch_alter_table("backup_records") as batch:
                batch.add_column(sa.Column("detail_json",sa.Text(),nullable=False,server_default="{}"))
    if "secret_vault_items" not in tables:
        op.create_table("secret_vault_items",
            sa.Column("id",sa.Integer(),primary_key=True),sa.Column("project_id",sa.Integer(),nullable=True),
            sa.Column("label",sa.String(240),nullable=False),sa.Column("secret_type",sa.String(80),nullable=False,server_default="custom"),
            sa.Column("username",sa.String(240),nullable=False,server_default=""),sa.Column("value_encrypted",sa.Text(),nullable=False,server_default=""),
            sa.Column("expires_at",sa.DateTime(),nullable=True),sa.Column("last_used_at",sa.DateTime(),nullable=True),
            sa.Column("disabled",sa.Integer(),nullable=False,server_default="0"),sa.Column("deleted",sa.Integer(),nullable=False,server_default="0"),
            sa.Column("notes",sa.Text(),nullable=False,server_default=""),sa.Column("updated_at",sa.DateTime(),nullable=True),sa.Column("created_at",sa.DateTime(),nullable=True))
    if "workspace_drafts" not in tables:
        op.create_table("workspace_drafts",sa.Column("id",sa.Integer(),primary_key=True),sa.Column("project_id",sa.Integer(),nullable=False),
            sa.Column("entity_type",sa.String(80),nullable=False,server_default="stored_request"),sa.Column("entity_id",sa.Integer(),nullable=False),
            sa.Column("content_json",sa.Text(),nullable=False,server_default="{}"),sa.Column("updated_at",sa.DateTime(),nullable=True),sa.Column("created_at",sa.DateTime(),nullable=True))
        op.create_index("ix_workspace_draft_entity","workspace_drafts",["project_id","entity_type","entity_id"],unique=True)
    if "recovery_events" not in tables:
        op.create_table("recovery_events",sa.Column("id",sa.Integer(),primary_key=True),sa.Column("project_id",sa.Integer(),nullable=True),
            sa.Column("event_type",sa.String(100),nullable=False),sa.Column("entity_type",sa.String(80),nullable=False,server_default=""),
            sa.Column("entity_id",sa.Integer(),nullable=True),sa.Column("status",sa.String(60),nullable=False,server_default="observed"),
            sa.Column("detail_json",sa.Text(),nullable=False,server_default="{}"),sa.Column("created_at",sa.DateTime(),nullable=True))


def downgrade():
    op.drop_table("recovery_events")
    op.drop_index("ix_workspace_draft_entity",table_name="workspace_drafts"); op.drop_table("workspace_drafts")
    op.drop_table("secret_vault_items")
    with op.batch_alter_table("backup_records") as batch: batch.drop_column("detail_json")
    with op.batch_alter_table("identities") as batch: batch.drop_column("vault_item_id")
