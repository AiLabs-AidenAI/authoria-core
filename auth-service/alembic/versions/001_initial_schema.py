"""Initial schema

Revision ID: 001
Revises: 
Create Date: 2024-01-01 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create users table
    op.create_table('users',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('display_name', sa.String(length=255), nullable=False),
        sa.Column('password_hash', sa.Text(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('is_approved', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('is_admin', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('email_verified', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('last_login', sa.DateTime(timezone=True), nullable=True),
        sa.Column('metadata', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)
    op.create_index(op.f('ix_users_tenant_id'), 'users', ['tenant_id'])

    # Create auth_provider_links table
    op.create_table('auth_provider_links',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('provider_name', sa.String(length=100), nullable=False),
        sa.Column('external_id', sa.String(length=500), nullable=False),
        sa.Column('metadata', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('linked_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('last_used', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_auth_provider_links_user_id'), 'auth_provider_links', ['user_id'])
    op.create_index(op.f('ix_auth_provider_links_provider_external'), 'auth_provider_links', ['provider_name', 'external_id'], unique=True)

    # Create pending_signups table
    op.create_table('pending_signups',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('display_name', sa.String(length=255), nullable=False),
        sa.Column('provider_requested', sa.String(length=100), nullable=False),
        sa.Column('payload', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('requested_by_ip', sa.String(length=45), nullable=True),
        sa.Column('approved_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('approved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('rejection_reason', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['approved_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_pending_signups_email'), 'pending_signups', ['email'])
    op.create_index(op.f('ix_pending_signups_status'), 'pending_signups', ['status'])
    op.create_index(op.f('ix_pending_signups_tenant_id'), 'pending_signups', ['tenant_id'])

    # Create refresh_tokens table
    op.create_table('refresh_tokens',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('token_hash', sa.String(length=255), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('replaced_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('client_info', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.ForeignKeyConstraint(['replaced_by'], ['refresh_tokens.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_refresh_tokens_token_hash'), 'refresh_tokens', ['token_hash'], unique=True)
    op.create_index(op.f('ix_refresh_tokens_user_id'), 'refresh_tokens', ['user_id'])

    # Create login_attempts table
    op.create_table('login_attempts',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('provider', sa.String(length=100), nullable=False),
        sa.Column('success', sa.Boolean(), nullable=False),
        sa.Column('failure_reason', sa.String(length=255), nullable=True),
        sa.Column('metadata', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_login_attempts_email'), 'login_attempts', ['email'])
    op.create_index(op.f('ix_login_attempts_ip_address'), 'login_attempts', ['ip_address'])
    op.create_index(op.f('ix_login_attempts_timestamp'), 'login_attempts', ['timestamp'])

    # Create audit_log table
    op.create_table('audit_log',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('actor_user_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('action_type', sa.String(length=100), nullable=False),
        sa.Column('target_type', sa.String(length=100), nullable=False),
        sa.Column('target_id', sa.String(length=100), nullable=True),
        sa.Column('payload', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['actor_user_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_audit_log_action_type'), 'audit_log', ['action_type'])
    op.create_index(op.f('ix_audit_log_target_type'), 'audit_log', ['target_type'])
    op.create_index(op.f('ix_audit_log_timestamp'), 'audit_log', ['timestamp'])

    # Create auth_providers table
    op.create_table('auth_providers',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('display_name', sa.String(length=200), nullable=False),
        sa.Column('provider_type', sa.String(length=50), nullable=False),
        sa.Column('client_id', sa.String(length=500), nullable=True),
        sa.Column('client_secret', sa.Text(), nullable=True),
        sa.Column('authorization_url', sa.Text(), nullable=True),
        sa.Column('token_url', sa.Text(), nullable=True),
        sa.Column('userinfo_url', sa.Text(), nullable=True),
        sa.Column('scope', sa.String(length=500), server_default='openid profile email'),
        sa.Column('entity_id', sa.String(length=500), nullable=True),
        sa.Column('sso_url', sa.Text(), nullable=True),
        sa.Column('x509_cert', sa.Text(), nullable=True),
        sa.Column('auto_approve_domains', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('require_email_verification', sa.Boolean(), server_default='true'),
        sa.Column('enabled', sa.Boolean(), server_default='false'),
        sa.Column('icon_url', sa.String(length=500), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('config_metadata', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_auth_providers_name'), 'auth_providers', ['name'], unique=True)
    op.create_index(op.f('ix_auth_providers_enabled'), 'auth_providers', ['enabled'])

    # Create smtp_config table
    op.create_table('smtp_config',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('host', sa.String(length=255), nullable=False),
        sa.Column('port', sa.Integer(), server_default='587', nullable=False),
        sa.Column('username', sa.String(length=255), nullable=True),
        sa.Column('password', sa.Text(), nullable=True),
        sa.Column('use_tls', sa.Boolean(), server_default='true'),
        sa.Column('use_ssl', sa.Boolean(), server_default='false'),
        sa.Column('from_email', sa.String(length=255), nullable=False),
        sa.Column('from_name', sa.String(length=255), nullable=True),
        sa.Column('reply_to', sa.String(length=255), nullable=True),
        sa.Column('max_emails_per_hour', sa.Integer(), server_default='100'),
        sa.Column('enabled', sa.Boolean(), server_default='false'),
        sa.Column('is_default', sa.Boolean(), server_default='false'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_smtp_config_name'), 'smtp_config', ['name'], unique=True)
    op.create_index(op.f('ix_smtp_config_is_default'), 'smtp_config', ['is_default'])

    # Create auth_settings table
    op.create_table('auth_settings',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('access_token_expire_minutes', sa.Integer(), server_default='15'),
        sa.Column('refresh_token_expire_days', sa.Integer(), server_default='30'),
        sa.Column('jwt_algorithm', sa.String(length=20), server_default='HS256'),
        sa.Column('password_min_length', sa.Integer(), server_default='8'),
        sa.Column('password_require_uppercase', sa.Boolean(), server_default='true'),
        sa.Column('password_require_lowercase', sa.Boolean(), server_default='true'),
        sa.Column('password_require_numbers', sa.Boolean(), server_default='true'),
        sa.Column('password_require_special', sa.Boolean(), server_default='true'),
        sa.Column('login_rate_limit', sa.Integer(), server_default='5'),
        sa.Column('signup_rate_limit', sa.Integer(), server_default='3'),
        sa.Column('otp_rate_limit', sa.Integer(), server_default='3'),
        sa.Column('otp_length', sa.Integer(), server_default='6'),
        sa.Column('otp_expire_minutes', sa.Integer(), server_default='10'),
        sa.Column('require_admin_approval', sa.Boolean(), server_default='true'),
        sa.Column('auto_approve_verified_emails', sa.Boolean(), server_default='false'),
        sa.Column('enable_mfa', sa.Boolean(), server_default='false'),
        sa.Column('session_timeout_minutes', sa.Integer(), server_default='480'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

    # Create client_applications table
    op.create_table('client_applications',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(length=200), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('client_id', sa.String(length=100), nullable=False),
        sa.Column('client_secret', sa.Text(), nullable=False),
        sa.Column('redirect_uris', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('allowed_origins', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('allowed_scopes', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('allowed_grant_types', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('access_token_lifetime', sa.Integer(), nullable=True),
        sa.Column('refresh_token_lifetime', sa.Integer(), nullable=True),
        sa.Column('require_pkce', sa.Boolean(), server_default='true'),
        sa.Column('enabled', sa.Boolean(), server_default='true'),
        sa.Column('logo_url', sa.String(length=500), nullable=True),
        sa.Column('website_url', sa.String(length=500), nullable=True),
        sa.Column('contact_email', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_client_applications_client_id'), 'client_applications', ['client_id'], unique=True)
    op.create_index(op.f('ix_client_applications_enabled'), 'client_applications', ['enabled'])

    # Create email_templates table
    op.create_table('email_templates',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('template_type', sa.String(length=50), nullable=False),
        sa.Column('subject', sa.String(length=500), nullable=False),
        sa.Column('html_content', sa.Text(), nullable=False),
        sa.Column('text_content', sa.Text(), nullable=True),
        sa.Column('available_variables', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('enabled', sa.Boolean(), server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_email_templates_name'), 'email_templates', ['name'], unique=True)
    op.create_index(op.f('ix_email_templates_template_type'), 'email_templates', ['template_type'])


def downgrade() -> None:
    op.drop_table('email_templates')
    op.drop_table('client_applications')
    op.drop_table('auth_settings')
    op.drop_table('smtp_config')
    op.drop_table('auth_providers')
    op.drop_table('audit_log')
    op.drop_table('login_attempts')
    op.drop_table('refresh_tokens')
    op.drop_table('pending_signups')
    op.drop_table('auth_provider_links')
    op.drop_table('users')