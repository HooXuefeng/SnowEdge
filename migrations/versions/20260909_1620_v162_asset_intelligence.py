"""V1.6.2 asset intelligence, profiles, routes and batch assessments.

Revision ID: v1_6_2_assetux
Revises: v1_6_reliability
"""
from alembic import op
import sqlalchemy as sa

revision = "v1_6_2_assetux"
down_revision = "v1_6_reliability"
branch_labels = None
depends_on = None


def upgrade():
    bind=op.get_bind(); inspector=sa.inspect(bind); tables=set(inspector.get_table_names())
    if "projects" in tables:
        cols={c["name"] for c in inspector.get_columns("projects")}
        with op.batch_alter_table("projects") as batch:
            if "scan_profile_id" not in cols: batch.add_column(sa.Column("scan_profile_id",sa.Integer(),nullable=True))
            if "network_route_profile_id" not in cols: batch.add_column(sa.Column("network_route_profile_id",sa.Integer(),nullable=True))
    if "technology_fingerprints" not in tables:
        op.create_table("technology_fingerprints",
            sa.Column("id",sa.Integer(),primary_key=True),sa.Column("project_id",sa.Integer(),nullable=False),sa.Column("asset_id",sa.Integer(),nullable=False),
            sa.Column("endpoint_id",sa.Integer(),nullable=True),sa.Column("category",sa.String(80),nullable=False,server_default="technology"),
            sa.Column("product",sa.String(200),nullable=False),sa.Column("version",sa.String(100),nullable=False,server_default=""),
            sa.Column("confidence",sa.Integer(),nullable=False,server_default="70"),sa.Column("detection_mode",sa.String(40),nullable=False,server_default="passive"),
            sa.Column("rule_id",sa.String(120),nullable=False,server_default=""),sa.Column("evidence_source",sa.String(100),nullable=False,server_default=""),
            sa.Column("evidence_summary_json",sa.Text(),nullable=False,server_default="{}"),sa.Column("first_seen_at",sa.DateTime(),nullable=True),sa.Column("last_seen_at",sa.DateTime(),nullable=True))
        op.create_index("ix_technology_fingerprints_project_asset","technology_fingerprints",["project_id","asset_id"])
    if "fingerprint_rules" not in tables:
        op.create_table("fingerprint_rules",
            sa.Column("id",sa.Integer(),primary_key=True),sa.Column("project_id",sa.Integer(),nullable=True),sa.Column("name",sa.String(200),nullable=False),
            sa.Column("category",sa.String(80),nullable=False,server_default="technology"),sa.Column("product",sa.String(200),nullable=False),
            sa.Column("source",sa.String(40),nullable=False,server_default="body"),sa.Column("header_name",sa.String(120),nullable=False,server_default=""),
            sa.Column("pattern",sa.String(300),nullable=False),sa.Column("confidence",sa.Integer(),nullable=False,server_default="80"),
            sa.Column("enabled",sa.Integer(),nullable=False,server_default="1"),sa.Column("created_at",sa.DateTime(),nullable=True))
    if "scan_profiles" not in tables:
        op.create_table("scan_profiles",sa.Column("id",sa.Integer(),primary_key=True),sa.Column("name",sa.String(200),nullable=False,unique=True),
            sa.Column("description",sa.Text(),nullable=False,server_default=""),sa.Column("enabled_skill_slugs_json",sa.Text(),nullable=False,server_default="[]"),
            sa.Column("batch_target_limit",sa.Integer(),nullable=False,server_default="20"),sa.Column("created_at",sa.DateTime(),nullable=True),sa.Column("updated_at",sa.DateTime(),nullable=True))
    if "network_route_profiles" not in tables:
        op.create_table("network_route_profiles",sa.Column("id",sa.Integer(),primary_key=True),sa.Column("name",sa.String(200),nullable=False,unique=True),
            sa.Column("route_type",sa.String(40),nullable=False,server_default="direct"),sa.Column("host",sa.String(240),nullable=False,server_default=""),
            sa.Column("port",sa.Integer(),nullable=False,server_default="0"),sa.Column("username",sa.String(240),nullable=False,server_default=""),
            sa.Column("secret_encrypted",sa.Text(),nullable=False,server_default=""),sa.Column("enabled",sa.Integer(),nullable=False,server_default="1"),
            sa.Column("notes",sa.Text(),nullable=False,server_default=""),sa.Column("created_at",sa.DateTime(),nullable=True),sa.Column("updated_at",sa.DateTime(),nullable=True))
    if "batch_assessments" not in tables:
        op.create_table("batch_assessments",sa.Column("id",sa.Integer(),primary_key=True),sa.Column("project_id",sa.Integer(),nullable=False),
            sa.Column("name",sa.String(240),nullable=False,server_default="Batch Assessment"),sa.Column("scan_profile_id",sa.Integer(),nullable=True),
            sa.Column("status",sa.String(60),nullable=False,server_default="queued"),sa.Column("total_targets",sa.Integer(),nullable=False,server_default="0"),
            sa.Column("completed_targets",sa.Integer(),nullable=False,server_default="0"),sa.Column("failed_targets",sa.Integer(),nullable=False,server_default="0"),
            sa.Column("skipped_targets",sa.Integer(),nullable=False,server_default="0"),sa.Column("resource_gate",sa.String(80),nullable=False,server_default="scan"),
            sa.Column("max_parallel",sa.Integer(),nullable=False,server_default="1"),sa.Column("summary_json",sa.Text(),nullable=False,server_default="{}"),
            sa.Column("created_at",sa.DateTime(),nullable=True),sa.Column("finished_at",sa.DateTime(),nullable=True))
    if "batch_assessment_items" not in tables:
        op.create_table("batch_assessment_items",sa.Column("id",sa.Integer(),primary_key=True),sa.Column("batch_id",sa.Integer(),nullable=False),
            sa.Column("project_id",sa.Integer(),nullable=False),sa.Column("target",sa.String(1000),nullable=False),sa.Column("status",sa.String(60),nullable=False,server_default="queued"),
            sa.Column("detail",sa.Text(),nullable=False,server_default=""),sa.Column("result_json",sa.Text(),nullable=False,server_default="{}"),
            sa.Column("started_at",sa.DateTime(),nullable=True),sa.Column("finished_at",sa.DateTime(),nullable=True))
        op.create_index("ix_batch_assessment_items_batch","batch_assessment_items",["batch_id","id"])


def downgrade():
    op.drop_index("ix_batch_assessment_items_batch",table_name="batch_assessment_items"); op.drop_table("batch_assessment_items")
    op.drop_table("batch_assessments"); op.drop_table("network_route_profiles"); op.drop_table("scan_profiles"); op.drop_table("fingerprint_rules")
    op.drop_index("ix_technology_fingerprints_project_asset",table_name="technology_fingerprints"); op.drop_table("technology_fingerprints")
    with op.batch_alter_table("projects") as batch:
        batch.drop_column("network_route_profile_id"); batch.drop_column("scan_profile_id")
