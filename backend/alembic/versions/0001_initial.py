"""initial migration

Revision ID: 0001_initial
Revises:
Create Date: 2026-08-25
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0001_initial'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'mappings',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('raw_command', sa.Text(), nullable=False),
        sa.Column('vendor', sa.String(), nullable=False),
        sa.Column('field_name', sa.String(), nullable=False),
        sa.Column('observed_value', sa.Text(), nullable=False),
        sa.Column('meaning', sa.Text(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('created_at', sa.String(), nullable=False),
    )
    op.create_table(
        'analyses',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('filename', sa.String(), nullable=False),
        sa.Column('vendor', sa.String(), nullable=False),
        sa.Column('framework', sa.String(), nullable=False),
        sa.Column('created_at', sa.String(), nullable=False),
        sa.Column('result_json', sa.Text(), nullable=False),
        sa.Column('upload_url', sa.Text(), nullable=True),
    )


def downgrade():
    op.drop_table('analyses')
    op.drop_table('mappings')
