"""Add roles and user_roles tables

Revision ID: 002
Revises: 001
Create Date: 2024-01-02 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '002'
down_revision = '001'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create roles table
    op.create_table('roles',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False, server_default=sa.text('gen_random_uuid()')),
        sa.Column('name', sa.String(length=50), nullable=False),
        sa.Column('display_name', sa.String(length=100), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('is_system_role', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('is_admin_role', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('permissions', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_roles_name'), 'roles', ['name'], unique=True)
    
    # Create user_roles association table
    op.create_table('user_roles',
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('role_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('assigned_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('assigned_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['role_id'], ['roles.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['assigned_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('user_id', 'role_id')
    )
    op.create_index(op.f('ix_user_roles_user_id'), 'user_roles', ['user_id'])
    op.create_index(op.f('ix_user_roles_role_id'), 'user_roles', ['role_id'])
    
    # Insert default system roles
    op.execute("""
        INSERT INTO roles (name, display_name, description, is_system_role, is_admin_role, permissions) VALUES
        ('super_admin', 'Super Administrator', 'Full system access with all permissions', true, true, '["*"]'),
        ('admin', 'Administrator', 'Standard admin with user management capabilities', true, true, '["user.read", "user.create", "user.update", "user.delete", "signup.approve", "signup.reject", "audit.read"]'),
        ('moderator', 'Moderator', 'Can review and approve user signups', true, false, '["signup.read", "signup.approve", "signup.reject", "user.read"]'),
        ('user', 'Standard User', 'Regular user with basic access', true, false, '["profile.read", "profile.update"]')
    """)


def downgrade() -> None:
    op.drop_table('user_roles')
    op.drop_table('roles')
