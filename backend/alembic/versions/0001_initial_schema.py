"""Initial schema

Revision ID: 0001_initial_schema
Revises: 
Create Date: 2026-09-30 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '0001_initial_schema'
down_revision = None
branch_labels = None
depends_on = None

def upgrade() -> None:
    # Users
    op.create_table(
        'users',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('email', sa.String(length=255), nullable=False, unique=True),
        sa.Column('hashed_password', sa.String(length=255), nullable=False),
        sa.Column('full_name', sa.String(length=255), nullable=True),
        sa.Column('is_active', sa.Boolean(), default=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now())
    )
    # Repositories
    op.create_table(
        'repositories',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('url', sa.String(length=512), nullable=False, unique=True),
        sa.Column('owner', sa.String(length=128), nullable=False),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('primary_language', sa.String(length=64), nullable=True),
        sa.Column('default_branch', sa.String(length=64), default='main'),
        sa.Column('stars', sa.Integer(), default=0),
        sa.Column('forks', sa.Integer(), default=0),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), server_default=sa.func.now())
    )
    # Batches
    op.create_table(
        'batches',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('user_id', sa.String(length=36), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('label', sa.String(length=255), nullable=False),
        sa.Column('repo_urls_json', sa.JSON(), nullable=False),
        sa.Column('total_repos', sa.Integer(), default=0),
        sa.Column('completed_repos', sa.Integer(), default=0),
        sa.Column('status', sa.String(length=32), default='QUEUED'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True)
    )
    # Scans
    op.create_table(
        'scans',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('repository_id', sa.String(length=36), sa.ForeignKey('repositories.id'), nullable=False),
        sa.Column('batch_id', sa.String(length=36), sa.ForeignKey('batches.id'), nullable=True),
        sa.Column('user_id', sa.String(length=36), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('status', sa.String(length=32), default='QUEUED'),
        sa.Column('risk_score', sa.Float(), default=0.0),
        sa.Column('trust_score', sa.Float(), default=100.0),
        sa.Column('risk_category', sa.String(length=32), default='LOW'),
        sa.Column('verdict', sa.String(length=255), nullable=True),
        sa.Column('verdict_summary', sa.Text(), nullable=True),
        sa.Column('explanation', sa.Text(), nullable=True),
        sa.Column('remediation', sa.Text(), nullable=True),
        sa.Column('claims_json', sa.JSON(), nullable=True),
        sa.Column('behaviors_json', sa.JSON(), nullable=True),
        sa.Column('hidden_behaviors_json', sa.JSON(), nullable=True),
        sa.Column('dimension_scores_json', sa.JSON(), nullable=True),
        sa.Column('access_token', sa.String(length=64), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True)
    )
    # Findings
    op.create_table(
        'findings',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('scan_id', sa.String(length=36), sa.ForeignKey('scans.id'), nullable=False),
        sa.Column('category', sa.String(length=32), nullable=False),
        sa.Column('capability_label', sa.String(length=64), nullable=True),
        sa.Column('severity', sa.String(length=32), nullable=False),
        sa.Column('confidence', sa.String(length=32), default='high'),
        sa.Column('file_path', sa.String(length=512), nullable=True),
        sa.Column('line_number', sa.Integer(), nullable=True),
        sa.Column('snippet', sa.Text(), nullable=True),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('source', sa.String(length=32), default='behavior'),
        sa.Column('metadata_json', sa.JSON(), nullable=True)
    )
    # Comparison entries
    op.create_table(
        'comparison_entries',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('scan_id', sa.String(length=36), sa.ForeignKey('scans.id'), nullable=False),
        sa.Column('claimed_capability', sa.String(length=128), nullable=False),
        sa.Column('detected_capability', sa.String(length=128), nullable=False),
        sa.Column('match_state', sa.String(length=32), nullable=False),
        sa.Column('severity', sa.String(length=32), nullable=False),
        sa.Column('notes', sa.Text(), nullable=True)
    )
    # Vulnerabilities
    op.create_table(
        'vulnerabilities',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('scan_id', sa.String(length=36), sa.ForeignKey('scans.id'), nullable=False),
        sa.Column('package_name', sa.String(length=128), nullable=False),
        sa.Column('version', sa.String(length=64), nullable=False),
        sa.Column('cve_id', sa.String(length=64), nullable=False),
        sa.Column('severity', sa.String(length=32), nullable=False),
        sa.Column('summary', sa.Text(), nullable=True),
        sa.Column('fixed_version', sa.String(length=64), nullable=True),
        sa.Column('source', sa.String(length=64), default='osv.dev')
    )
    # Secret Findings
    op.create_table(
        'secret_findings',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('scan_id', sa.String(length=36), sa.ForeignKey('scans.id'), nullable=False),
        sa.Column('secret_type', sa.String(length=64), nullable=False),
        sa.Column('file_path', sa.String(length=512), nullable=False),
        sa.Column('line_number', sa.Integer(), nullable=True),
        sa.Column('redacted_value', sa.String(length=128), nullable=False),
        sa.Column('confidence', sa.String(length=32), default='high')
    )
    # Policies
    op.create_table(
        'policies',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('user_id', sa.String(length=36), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('rules_json', sa.JSON(), nullable=False),
        sa.Column('is_default', sa.Boolean(), default=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), onupdate=sa.func.now())
    )
    # Policy evaluations
    op.create_table(
        'policy_evaluations',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('scan_id', sa.String(length=36), sa.ForeignKey('scans.id'), nullable=False),
        sa.Column('policy_id', sa.String(length=36), sa.ForeignKey('policies.id'), nullable=False),
        sa.Column('decision', sa.String(length=32), nullable=False),
        sa.Column('triggered_rules_json', sa.JSON(), nullable=False),
        sa.Column('evaluated_at', sa.DateTime(timezone=True), server_default=sa.func.now())
    )
    # Security Attestations
    op.create_table(
        'security_attestations',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('scan_id', sa.String(length=36), sa.ForeignKey('scans.id'), nullable=False, unique=True),
        sa.Column('trust_score', sa.Float(), nullable=False),
        sa.Column('risk_category', sa.String(length=32), nullable=False),
        sa.Column('recommendation', sa.String(length=64), nullable=False),
        sa.Column('capabilities_json', sa.JSON(), nullable=False),
        sa.Column('hidden_capabilities_json', sa.JSON(), nullable=False),
        sa.Column('content_hash', sa.String(length=64), nullable=False),
        sa.Column('signature', sa.Text(), nullable=False),
        sa.Column('public_key', sa.Text(), nullable=False),
        sa.Column('issued_at', sa.DateTime(timezone=True), server_default=sa.func.now())
    )

def downgrade() -> None:
    op.drop_table('security_attestations')
    op.drop_table('policy_evaluations')
    op.drop_table('policies')
    op.drop_table('secret_findings')
    op.drop_table('vulnerabilities')
    op.drop_table('comparison_entries')
    op.drop_table('findings')
    op.drop_table('scans')
    op.drop_table('batches')
    op.drop_table('repositories')
    op.drop_table('users')
