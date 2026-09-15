"""V1.8 persistent toolchain runs and dependent steps.

Revision ID: v1_8_toolchain_runs
Revises: v1_6_2_assetux
"""
from alembic import op
import sqlalchemy as sa

revision = "v1_8_toolchain_runs"
down_revision = "v1_6_2_assetux"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind(); tables = set(sa.inspect(bind).get_table_names())
    if "toolchain_runs" not in tables:
        op.create_table("toolchain_runs",
            sa.Column("id", sa.Integer(), primary_key=True), sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=False),
            sa.Column("plan_id", sa.String(80), nullable=False), sa.Column("name", sa.String(200), nullable=False),
            sa.Column("source_target", sa.String(1200), nullable=False), sa.Column("ports_json", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("status", sa.String(60), nullable=False, server_default="queued"), sa.Column("current_step", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("total_steps", sa.Integer(), nullable=False, server_default="0"), sa.Column("summary_json", sa.Text(), nullable=False, server_default="{}"),
            sa.Column("error", sa.Text(), nullable=False, server_default=""), sa.Column("created_at", sa.DateTime(), nullable=True),
            sa.Column("started_at", sa.DateTime(), nullable=True), sa.Column("finished_at", sa.DateTime(), nullable=True), sa.Column("updated_at", sa.DateTime(), nullable=True))
        op.create_index("ix_toolchain_runs_project_created", "toolchain_runs", ["project_id", "created_at"])
    if "toolchain_steps" not in tables:
        op.create_table("toolchain_steps",
            sa.Column("id", sa.Integer(), primary_key=True), sa.Column("run_id", sa.Integer(), sa.ForeignKey("toolchain_runs.id"), nullable=False), sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id"), nullable=False),
            sa.Column("position", sa.Integer(), nullable=False), sa.Column("tool_id", sa.String(80), nullable=False),
            sa.Column("status", sa.String(60), nullable=False, server_default="pending"), sa.Column("input_json", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("job_ids_json", sa.Text(), nullable=False, server_default="[]"), sa.Column("result_json", sa.Text(), nullable=False, server_default="{}"),
            sa.Column("error", sa.Text(), nullable=False, server_default=""), sa.Column("created_at", sa.DateTime(), nullable=True),
            sa.Column("started_at", sa.DateTime(), nullable=True), sa.Column("finished_at", sa.DateTime(), nullable=True), sa.Column("updated_at", sa.DateTime(), nullable=True))
        op.create_index("ix_toolchain_steps_run_position", "toolchain_steps", ["run_id", "position"], unique=True)


def downgrade():
    op.drop_index("ix_toolchain_steps_run_position", table_name="toolchain_steps"); op.drop_table("toolchain_steps")
    op.drop_index("ix_toolchain_runs_project_created", table_name="toolchain_runs"); op.drop_table("toolchain_runs")
