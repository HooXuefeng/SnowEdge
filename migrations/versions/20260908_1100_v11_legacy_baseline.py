"""V1.1 legacy schema baseline.

Revision ID: v1_1_legacy
Revises:
"""
revision = "v1_1_legacy"
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    # V1.1 installations are stamped to this revision before V1.2 migration.
    pass

def downgrade():
    pass
