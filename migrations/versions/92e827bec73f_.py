"""empty message

Revision ID: 92e827bec73f
Revises: 
Create Date: 2025-04-18 20:37:32.393710

"""
from alembic import op
import sqlalchemy as sa

revision = '92e827bec73f'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('role',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=80), nullable=False),
    sa.Column('description', sa.String(length=200), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_table('user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=80), nullable=False),
    sa.Column('email', sa.String(length=120), nullable=False),
    sa.Column('password_hash', sa.String(length=512), nullable=False),
    sa.Column('is_active', sa.Boolean(), nullable=False),
    sa.Column('is_verified', sa.Boolean(), nullable=False),
    sa.Column('email_verification_token', sa.String(length=120), nullable=True),
    sa.Column('reset_token', sa.String(length=120), nullable=True),
    sa.Column('token_expiration', sa.DateTime(), nullable=True),
    sa.Column('token_revoked_at', sa.DateTime(), nullable=True),
    sa.Column('failed_attempts', sa.Integer(), nullable=False),
    sa.Column('is_locked', sa.Boolean(), nullable=False),
    sa.Column('lock_until', sa.DateTime(), nullable=True),
    sa.Column('totp_secret', sa.String(length=32), nullable=True),
    sa.Column('is_totp_enabled', sa.Boolean(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email'),
    sa.UniqueConstraint('username')
    )
    op.create_table('activity_log',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('actor_id', sa.Integer(), nullable=False),
    sa.Column('action', sa.String(length=255), nullable=False),
    sa.Column('target', sa.String(length=255), nullable=True),
    sa.Column('timestamp', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['actor_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('user_roles',
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('role_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['role_id'], ['role.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], )
    )

def downgrade():
    op.drop_table('user_roles')
    op.drop_table('activity_log')
    op.drop_table('user')
    op.drop_table('role')