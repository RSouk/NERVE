"""
NERVE Database Module
=====================

Central database module for the NERVE security platform. Provides:

- SQLAlchemy ORM models for all 40+ tables
- Authentication and session management
- API key management
- Security event logging and audit trails
- Scan data storage (XASM, Lightbox)
- Compliance tracking
- Health monitoring and backup/restore

Usage:
    from database import (
        init_db, SessionLocal, User, Company,
        hash_password, verify_password,
        create_session, validate_session,
        run_health_check, create_backup
    )

Documentation:
    See README_DATABASE.md for overview
    See DATABASE_SCHEMA.md for table details
    See DATABASE_API.md for function reference
    See DATABASE_MAINTENANCE.md for operations

Schema Version: 1.0.0
Last Updated: January 2026

TODO (Phase 7 - PostgreSQL Migration):
    - Replace sqlite3 direct connections with SQLAlchemy
    - Update JSON columns to use JSONB
    - Add connection pooling support
    - Update backup/restore for pg_dump/pg_restore
    - Add GIN indexes for JSONB columns
"""

from sqlalchemy import create_engine, Column, Integer, BigInteger, String, Text, DateTime, Float, ForeignKey, JSON, Boolean, Enum, text, inspect
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.exc import SQLAlchemyError, IntegrityError, OperationalError
from datetime import datetime, timedelta, timezone
from functools import wraps
from contextlib import contextmanager
import os
import json
import enum
import secrets
import hashlib
import logging
import re
import shutil
import time
import sqlite3
import traceback

# Type hints for better IDE support
from typing import Dict, List, Optional, Any, Union

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('nerve.database')

# Try to import bcrypt, fall back to hashlib if not available
try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False
    logger.warning("bcrypt not installed. Using fallback password hashing.")

# =============================================================================
# CONFIGURATION
# =============================================================================

# Performance tracking (stores recent query metrics for monitoring)
_query_performance_log: List[Dict] = []
_schema_version = "1.0.0"

# Database path configuration
# TODO (Phase 7): Support PostgreSQL connection string via environment variable
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'ghost.db')
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

# SQLAlchemy engine and session factory
# TODO (Phase 7): Add connection pooling configuration for PostgreSQL
engine = create_engine(f'sqlite:///{DB_PATH}', echo=False)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()


# ============================================================================
# USER & COMPANY ENUMS
# ============================================================================

class UserRole(enum.Enum):
    SUPER_ADMIN = 'super_admin'
    ADMIN = 'admin'
    ANALYST = 'analyst'
    USER = 'user'
    COMPANY_USER = 'company_user'
    DEMO = 'demo'

class UserStatus(enum.Enum):
    ACTIVE = 'active'
    LOCKED = 'locked'
    SUSPENDED = 'suspended'
    PENDING_VERIFICATION = 'pending_verification'


# ============================================================================
# USER & COMPANY MODELS
# ============================================================================

class Company(Base):
    __tablename__ = 'companies'

    # Primary Key
    id = Column(Integer, primary_key=True)

    # Company Info
    name = Column(String(255), nullable=False)
    primary_domain = Column(String(255), unique=True, nullable=False, index=True)
    additional_domains = Column(Text)  # JSON array

    # Subscription
    max_seats = Column(Integer, nullable=False, default=1)
    max_domains = Column(Integer, nullable=False, default=1)
    subscription_tier = Column(String(20), nullable=False, default='basic')

    # Billing
    stripe_customer_id = Column(String(255))
    billing_email = Column(String(255))
    subscription_status = Column(String(20))

    # Standard Columns
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    deleted_at = Column(DateTime, index=True)
    is_active = Column(Boolean, nullable=False, default=True)

    def __repr__(self):
        return f'<Company {self.name}>'


class User(Base):
    __tablename__ = 'users'

    # Primary Key
    id = Column(Integer, primary_key=True)

    # Identity
    email = Column(String(255), unique=True, nullable=False, index=True)
    username = Column(String(100), unique=True)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(255))

    # Role & Company
    role = Column(Enum(UserRole), nullable=False, index=True)
    company_id = Column(Integer, ForeignKey('companies.id', ondelete='SET NULL'), index=True)

    # Account Status
    status = Column(Enum(UserStatus), nullable=False, default=UserStatus.ACTIVE, index=True)
    email_verified = Column(Boolean, nullable=False, default=False)
    email_verification_token = Column(String(255))
    email_verified_at = Column(DateTime)

    # Security
    twofa_enabled = Column('2fa_enabled', Boolean, nullable=False, default=False)
    twofa_secret = Column('2fa_secret', String(255))
    twofa_backup_codes = Column('2fa_backup_codes', Text)
    failed_login_attempts = Column(Integer, nullable=False, default=0)
    locked_until = Column(DateTime)

    # Password Management
    password_reset_token = Column(String(255))
    password_reset_expires = Column(DateTime)
    last_password_change = Column(DateTime)
    must_change_password = Column(Boolean, nullable=False, default=False)

    # Contact
    phone_number = Column(String(20))
    timezone = Column(String(50), default='UTC')
    language = Column(String(10), default='en')

    # Subscription
    subscription_tier = Column(String(20))
    subscription_status = Column(String(20))
    stripe_customer_id = Column(String(255))
    stripe_subscription_id = Column(String(255))

    # Demo Accounts
    expires_at = Column(DateTime)

    # Preferences
    email_notifications = Column(Boolean, nullable=False, default=True)
    security_alerts = Column(Boolean, nullable=False, default=True)
    marketing_emails = Column(Boolean, nullable=False, default=False)
    theme = Column(String(10), default='dark')

    # Tracking
    last_login_at = Column(DateTime)
    last_login_ip = Column(String(45))

    # Standard Columns (soft delete pattern)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    deleted_at = Column(DateTime, index=True)
    is_active = Column(Boolean, nullable=False, default=True)

    def __repr__(self):
        return f'<User {self.email}>'


class Session(Base):
    __tablename__ = 'sessions'

    # Primary Key
    id = Column(Integer, primary_key=True)

    # User
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)

    # Tokens
    token = Column(String(255), unique=True, nullable=False, index=True)
    refresh_token = Column(String(255), unique=True)

    # Device Info
    ip_address = Column(String(45), nullable=False)
    user_agent = Column(Text)
    device_type = Column(String(20))  # web, mobile, api
    device_name = Column(String(255))
    location = Column(String(255))

    # Session Management
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    last_activity = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime, nullable=False)
    is_active = Column(Boolean, nullable=False, default=True)
    revoked_at = Column(DateTime)

    def __repr__(self):
        return f'<Session {self.id} for user {self.user_id}>'


class AuditLog(Base):
    __tablename__ = 'audit_logs'

    # Primary Key
    id = Column(Integer, primary_key=True)

    # User & Action
    user_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), index=True)
    action = Column(String(100), nullable=False, index=True)
    resource_type = Column(String(50))
    resource_id = Column(Integer)

    # Details
    description = Column(Text)
    metadata_json = Column(Text)  # JSON

    # Request Info
    ip_address = Column(String(45))
    user_agent = Column(Text)

    # Result
    success = Column(Boolean, nullable=False, default=True)
    error_message = Column(Text)

    # Timestamp
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f'<AuditLog {self.action} by user {self.user_id}>'


class PasswordHistory(Base):
    __tablename__ = 'password_history'

    # Primary Key
    id = Column(Integer, primary_key=True)

    # User
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)

    # Password Hash
    password_hash = Column(String(255), nullable=False)

    # Timestamp
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f'<PasswordHistory for user {self.user_id}>'


class LoginAttempt(Base):
    __tablename__ = 'login_attempts'

    # Primary Key
    id = Column(Integer, primary_key=True)

    # Attempt Info
    email = Column(String(255), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), index=True)

    # Request Info
    ip_address = Column(String(45), nullable=False)
    user_agent = Column(Text)

    # Result
    success = Column(Boolean, nullable=False)
    failure_reason = Column(String(100))

    # Timestamp
    attempted_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), index=True)

    def __repr__(self):
        return f'<LoginAttempt {self.email} at {self.attempted_at}>'



class APIKey(Base):
    """API Keys for programmatic access"""
    __tablename__ = 'api_keys'

    # Primary Key
    id = Column(Integer, primary_key=True)

    # User Link
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)

    # Key Info
    key_hash = Column(String(255), nullable=False, unique=True, index=True)  # SHA256 hash of the key
    key_prefix = Column(String(8), nullable=False)  # First 8 chars for identification (e.g., "nrv_xxxx")
    name = Column(String(100), nullable=False)  # User-friendly name

    # Permissions
    permissions = Column(Text)  # JSON array of allowed endpoints/actions

    # Usage Tracking
    last_used_at = Column(DateTime)
    last_used_ip = Column(String(45))
    usage_count = Column(Integer, nullable=False, default=0)

    # Lifecycle
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime)  # Optional expiry
    revoked_at = Column(DateTime)
    is_active = Column(Boolean, nullable=False, default=True)

    def __repr__(self):
        return f'<APIKey {self.key_prefix}... for user {self.user_id}>'


class SecurityEvent(Base):
    """Security events for audit and threat detection"""
    __tablename__ = 'security_events'

    # Primary Key
    id = Column(Integer, primary_key=True)

    # Event Info
    event_type = Column(String(50), nullable=False, index=True)
    # Types: login_failed, login_success, brute_force_detected, session_revoked,
    #        password_changed, 2fa_enabled, 2fa_disabled, api_key_created,
    #        api_key_revoked, suspicious_activity, account_locked

    severity = Column(String(20), nullable=False, index=True)  # info, low, medium, high, critical

    # Context
    user_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), index=True)
    email = Column(String(255), index=True)  # For failed logins where user may not exist
    ip_address = Column(String(45), index=True)
    user_agent = Column(Text)
    location = Column(String(255))  # GeoIP location if available

    # Details
    description = Column(Text, nullable=False)
    metadata_json = Column(Text)  # Additional context as JSON

    # Flags
    acknowledged = Column(Boolean, nullable=False, default=False)
    acknowledged_by = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'))
    acknowledged_at = Column(DateTime)

    # Timestamp
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), index=True)

    def __repr__(self):
        return f'<SecurityEvent {self.event_type} - {self.severity}>'


class PlatformSettings(Base):
    """Platform-wide configuration settings"""
    __tablename__ = 'platform_settings'

    # Primary Key (setting key is the identifier)
    key = Column(String(100), primary_key=True)

    # Value (stored as JSON for complex values)
    value = Column(Text, nullable=False)

    # Category for organization
    category = Column(String(50), nullable=False, index=True)
    # Categories: general, security, api, scans, critical, email

    # Metadata
    description = Column(Text)  # Human-readable description of the setting
    value_type = Column(String(20), default='string')  # string, number, boolean, json

    # Audit trail
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    updated_by = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), index=True)

    def __repr__(self):
        return f'<PlatformSettings {self.key}={self.value}>'


class ErrorLog(Base):
    """Application error logs for monitoring and debugging"""
    __tablename__ = 'error_logs'

    # Primary Key
    id = Column(Integer, primary_key=True)

    # Error Info
    error_type = Column(String(100), nullable=False, index=True)  # Exception class name
    error_message = Column(Text, nullable=False)
    stack_trace = Column(Text)

    # Context
    endpoint = Column(String(255), index=True)  # API endpoint that caused the error
    method = Column(String(10))  # HTTP method
    user_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), index=True)
    ip_address = Column(String(45))
    user_agent = Column(Text)
    request_data = Column(Text)  # JSON of request body (sanitized)

    # Severity
    severity = Column(String(20), nullable=False, default='error', index=True)  # warning, error, critical

    # Timestamp
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), index=True)

    def __repr__(self):
        return f'<ErrorLog {self.error_type} at {self.endpoint}>'


# ============================================================================
# CONTENT MANAGEMENT MODELS
# ============================================================================

class NewsSource(Base):
    """RSS news sources for the Ghost Dashboard news feed"""
    __tablename__ = 'news_sources'

    id = Column(Integer, primary_key=True)
    url = Column(String(500), nullable=False, unique=True)
    name = Column(String(200))  # Optional friendly name
    active = Column(Boolean, default=True, nullable=False)
    last_fetched = Column(DateTime)
    fetch_error = Column(Text)  # Last error if fetch failed
    article_count = Column(Integer, default=0)

    # Audit
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    created_by = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'))

    def __repr__(self):
        return f'<NewsSource {self.url}>'

    def to_dict(self):
        return {
            'id': self.id,
            'url': self.url,
            'name': self.name,
            'active': self.active,
            'last_fetched': self.last_fetched.isoformat() if self.last_fetched else None,
            'fetch_error': self.fetch_error,
            'article_count': self.article_count,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class EducationResource(Base):
    """Education resources for the NERVE Dashboard"""
    __tablename__ = 'education_resources'

    id = Column(Integer, primary_key=True)
    title = Column(String(255), nullable=False)
    url = Column(String(500), nullable=False)
    type = Column(String(50), nullable=False)  # Guide, Tutorial, Video
    description = Column(Text)
    featured = Column(Boolean, default=False, nullable=False)
    order_index = Column(Integer, default=0)  # For sorting

    # Audit
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    created_by = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'))

    def __repr__(self):
        return f'<EducationResource {self.title}>'

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'url': self.url,
            'type': self.type,
            'description': self.description,
            'featured': self.featured,
            'order_index': self.order_index,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class BackupRecord(Base):
    """Records of database backups"""
    __tablename__ = 'backup_records'

    id = Column(Integer, primary_key=True)
    filename = Column(String(255), nullable=False, unique=True)
    filepath = Column(String(500), nullable=False)
    size_bytes = Column(BigInteger, nullable=False)
    status = Column(String(20), nullable=False, default='complete')  # in_progress, complete, failed
    backup_type = Column(String(20), nullable=False, default='manual')  # manual, scheduled
    error_message = Column(Text)

    # Audit
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    created_by = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'))

    def __repr__(self):
        return f'<BackupRecord {self.filename}>'

    def to_dict(self):
        return {
            'id': self.id,
            'filename': self.filename,
            'size_mb': round(self.size_bytes / (1024 * 1024), 2) if self.size_bytes else 0,
            'status': self.status,
            'backup_type': self.backup_type,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'error_message': self.error_message
        }


# ============================================================================
# GHOST SEARCH MODELS
# ============================================================================

class GhostSearchQuery(Base):
    __tablename__ = 'ghost_search_queries'

    # Primary Key
    id = Column(Integer, primary_key=True)

    # User
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)

    # Query Info
    query_type = Column(String(20), nullable=False)  # email, domain, phone, ip
    query_value = Column(String(255), nullable=False)
    results_count = Column(Integer, nullable=False, default=0)

    # Search Metadata
    search_sources = Column(Text)  # JSON array
    response_time_ms = Column(Integer)

    # Timestamp
    searched_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), index=True)

    # Standard Columns
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    deleted_at = Column(DateTime, index=True)
    is_active = Column(Boolean, nullable=False, default=True)

    def __repr__(self):
        return f'<GhostSearchQuery {self.query_type}: {self.query_value}>'


class MonitoredEmail(Base):
    __tablename__ = 'monitored_emails'

    # Primary Key
    id = Column(Integer, primary_key=True)

    # Ownership
    company_id = Column(Integer, ForeignKey('companies.id', ondelete='CASCADE'), index=True)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), index=True)
    created_by_user_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), nullable=False)

    # Email
    email_address = Column(String(255), nullable=False, index=True)
    monitor_scope = Column(String(20), nullable=False)  # company, analyst, admin

    # Status
    last_checked = Column(DateTime)
    findings_count = Column(Integer, nullable=False, default=0)

    # Standard Columns
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    deleted_at = Column(DateTime, index=True)
    is_active = Column(Boolean, nullable=False, default=True)

    def __repr__(self):
        return f'<MonitoredEmail {self.email_address}>'


class MonitoredEmailFinding(Base):
    __tablename__ = 'monitored_email_findings'

    # Primary Key
    id = Column(Integer, primary_key=True)

    # Monitored Email
    monitored_email_id = Column(Integer, ForeignKey('monitored_emails.id', ondelete='CASCADE'), nullable=False, index=True)

    # Finding Info
    finding_type = Column(String(50), nullable=False)  # breach, paste, darkweb, credential_leak
    source = Column(String(100), nullable=False)
    breach_name = Column(String(255))
    breach_date = Column(DateTime)

    # Details
    details = Column(Text, nullable=False)  # JSON
    severity = Column(String(20), nullable=False)  # critical, high, medium, low

    # Notification
    notified = Column(Boolean, nullable=False, default=False)
    notified_at = Column(DateTime)

    # Timestamp
    found_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    # Standard Columns
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    deleted_at = Column(DateTime, index=True)
    is_active = Column(Boolean, nullable=False, default=True)

    def __repr__(self):
        return f'<MonitoredEmailFinding {self.finding_type} from {self.source}>'


class UploadedBreachFile(Base):
    __tablename__ = 'uploaded_breach_files'

    # Primary Key
    id = Column(Integer, primary_key=True)

    # User
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)

    # File Info
    filename = Column(String(255), nullable=False)
    file_size = Column(Integer, nullable=False)
    file_path = Column(String(500), nullable=False)
    storage_location = Column(String(20), nullable=False)  # local, s3

    # Processing
    indexed = Column(Boolean, nullable=False, default=False)
    records_count = Column(Integer)
    processing_status = Column(String(20), nullable=False, default='pending')  # pending, processing, completed, failed
    processing_error = Column(Text)

    # Security
    content_hash = Column(String(64), nullable=False)  # SHA256
    mime_type = Column(String(100), nullable=False)
    virus_scanned = Column(Boolean, nullable=False, default=False)
    virus_scan_result = Column(String(100))
    security_flags = Column(Text)  # JSON

    # Expiry (24 hours)
    uploaded_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime, nullable=False)

    # Standard Columns
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    deleted_at = Column(DateTime, index=True)
    is_active = Column(Boolean, nullable=False, default=True)

    def __repr__(self):
        return f'<UploadedBreachFile {self.filename}>'


class BreachFileResult(Base):
    __tablename__ = 'breach_file_results'

    # Primary Key
    id = Column(Integer, primary_key=True)

    # Source File
    uploaded_file_id = Column(Integer, ForeignKey('uploaded_breach_files.id', ondelete='CASCADE'), nullable=False, index=True)

    # Breach Data
    email = Column(String(255), nullable=False, index=True)
    password_hash = Column(String(255))
    password_plain = Column(String(255))
    additional_data = Column(Text)  # JSON

    # Standard Columns
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    deleted_at = Column(DateTime, index=True)
    is_active = Column(Boolean, nullable=False, default=True)

    def __repr__(self):
        return f'<BreachFileResult {self.email}>'


# ============================================================================
# COMPLIANCE & VULNERABILITY REPORT MODELS
# ============================================================================

class ComplianceAssessment(Base):
    __tablename__ = 'compliance_assessments'

    # Primary Key
    id = Column(Integer, primary_key=True)

    # Company
    company_id = Column(Integer, ForeignKey('companies.id', ondelete='CASCADE'), nullable=False, index=True)
    created_by_user_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), nullable=False)

    # Framework
    framework = Column(String(50), nullable=False, index=True)  # SOC2, ISO27001, GDPR, NIS2, PIPEDA
    framework_version = Column(String(20))

    # Status
    status = Column(String(20), nullable=False, default='in_progress')  # in_progress, completed, expired
    overall_compliance_score = Column(Integer)  # 0-100

    # Dates
    assessment_date = Column(DateTime, nullable=False)
    completion_date = Column(DateTime)
    expiry_date = Column(DateTime)

    # Standard Columns
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    deleted_at = Column(DateTime, index=True)
    is_active = Column(Boolean, nullable=False, default=True)

    def __repr__(self):
        return f'<ComplianceAssessment {self.framework} for company {self.company_id}>'


class ComplianceControl(Base):
    __tablename__ = 'compliance_controls'

    # Primary Key
    id = Column(Integer, primary_key=True)

    # Assessment
    assessment_id = Column(Integer, ForeignKey('compliance_assessments.id', ondelete='CASCADE'), nullable=False, index=True)

    # Control Info
    control_id = Column(String(50), nullable=False)  # e.g., "SOC2-CC6.1"
    control_name = Column(String(255), nullable=False)
    control_category = Column(String(100))

    # Status
    status = Column(String(20), nullable=False, default='not_tested')  # compliant, non_compliant, partial, not_tested
    compliance_score = Column(Integer)  # 0-100

    # Scan Integration - Auto-flagging from XASM/Lightbox scans
    scan_source = Column(String(20))  # 'xasm', 'lightbox', 'manual', None
    scan_finding_type = Column(String(100))  # The vulnerability type that flagged this
    scan_finding_id = Column(String(100))  # Reference to original scan finding
    scan_flagged_at = Column(DateTime)  # When auto-flagged by scan
    scan_verified_at = Column(DateTime)  # When verified by re-scan
    scan_domain = Column(String(255))  # Domain that was scanned

    # Evidence & Notes
    evidence_summary = Column(Text)
    remediation_notes = Column(Text)
    assigned_to_user_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'))

    # Dates
    last_reviewed = Column(DateTime)
    next_review_date = Column(DateTime)

    # Standard Columns
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    deleted_at = Column(DateTime, index=True)
    is_active = Column(Boolean, nullable=False, default=True)

    def __repr__(self):
        return f'<ComplianceControl {self.control_id}: {self.status}>'


class ComplianceEvidence(Base):
    __tablename__ = 'compliance_evidence'

    # Primary Key
    id = Column(Integer, primary_key=True)

    # Control
    control_id = Column(Integer, ForeignKey('compliance_controls.id', ondelete='CASCADE'), nullable=False, index=True)

    # Evidence Info
    evidence_type = Column(String(50), nullable=False)  # document, scan, screenshot, policy, log
    title = Column(String(255), nullable=False)
    description = Column(Text)

    # File
    file_path = Column(String(500))
    file_size = Column(Integer)
    file_type = Column(String(100))

    # Metadata
    uploaded_by_user_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), nullable=False)
    evidence_date = Column(DateTime)  # When evidence was created (not uploaded)

    # Standard Columns
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    deleted_at = Column(DateTime, index=True)
    is_active = Column(Boolean, nullable=False, default=True)

    def __repr__(self):
        return f'<ComplianceEvidence {self.title}>'


class VulnerabilityReport(Base):
    __tablename__ = 'vulnerability_reports'

    # Primary Key
    id = Column(Integer, primary_key=True)

    # Company & User
    company_id = Column(Integer, ForeignKey('companies.id', ondelete='CASCADE'), index=True)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)

    # Source Scans
    xasm_scan_id = Column(Integer, ForeignKey('scan_results_xasm.id', ondelete='SET NULL'))
    lightbox_scan_id = Column(Integer, ForeignKey('scan_results_lightbox.id', ondelete='SET NULL'))

    # Report Data
    risk_score = Column(Integer, nullable=False)  # 0-100
    risk_level = Column(String(20), nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW
    executive_summary = Column(Text, nullable=False)
    report_json = Column(Text, nullable=False)  # Full AI-generated report

    # AI Metadata
    ai_model = Column(String(50), nullable=False)  # gemini-flash-latest
    generation_time_ms = Column(Integer)

    # Standard Columns
    generated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    deleted_at = Column(DateTime, index=True)
    is_active = Column(Boolean, nullable=False, default=True)

    def __repr__(self):
        return f'<VulnerabilityReport risk_level={self.risk_level} for user {self.user_id}>'


# ============================================================================
# ROADMAP MODELS
# ============================================================================

class RoadmapProfile(Base):
    """
    Stores company/user assessment profile data for the security roadmap.
    Maps company characteristics, current security posture, and targets.
    """
    __tablename__ = 'roadmap_profiles'

    # Primary Key
    id = Column(Integer, primary_key=True)

    # User/Company Link (nullable - can be standalone)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), index=True)
    company_id = Column(Integer, ForeignKey('companies.id', ondelete='SET NULL'), index=True)

    # Company Profile
    company_name = Column(String(255), nullable=False)
    company_size = Column(String(50))  # small, medium, large, enterprise
    industry = Column(String(100), index=True)  # healthcare, finance, retail, tech, etc.
    employee_count = Column(Integer)

    # Security Posture
    current_security_score = Column(Integer, default=0)  # 0-100
    target_security_score = Column(Integer, default=75)  # Target to reach

    # Data Sensitivity Flags
    handles_pii = Column(Boolean, default=False)
    handles_payment_data = Column(Boolean, default=False)
    handles_health_data = Column(Boolean, default=False)
    handles_financial_data = Column(Boolean, default=False)

    # JSON Fields for complex data
    current_measures = Column(Text)  # JSON: existing security measures
    compliance_requirements = Column(Text)  # JSON: ["soc2", "hipaa", "pci"]
    assessment_responses = Column(Text)  # JSON: responses to assessment questions

    # Timestamps
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    last_recalculated = Column(DateTime)  # When score was last recalculated
    deleted_at = Column(DateTime, index=True)

    # Flags
    is_active = Column(Boolean, nullable=False, default=True)

    # Relationships
    user_tasks = relationship('RoadmapUserTask', back_populates='profile', cascade='all, delete-orphan')
    achievements = relationship('RoadmapAchievement', back_populates='profile', cascade='all, delete-orphan')
    progress_history = relationship('RoadmapProgressHistory', back_populates='profile', cascade='all, delete-orphan')

    def __repr__(self):
        return f'<RoadmapProfile {self.company_name} (Score: {self.current_security_score}/{self.target_security_score})>'


class RoadmapTask(Base):
    """
    Master library of all possible security tasks.
    These are templates that get assigned to user profiles.
    """
    __tablename__ = 'roadmap_tasks'

    # Primary Key
    id = Column(Integer, primary_key=True)

    # Unique Task Identifier
    task_id = Column(String(100), unique=True, nullable=False, index=True)  # e.g., "TASK_MFA_ENABLE"

    # Task Information
    task_name = Column(String(255), nullable=False)
    task_category = Column(String(50), index=True)  # authentication, network, data, etc.
    description = Column(Text)
    why_it_matters = Column(Text)  # Explains the security importance
    how_to_fix = Column(Text)  # Step-by-step remediation guidance

    # Effort Estimates
    estimated_time_minutes = Column(Integer)  # Time to complete
    estimated_cost_min = Column(Float)  # Minimum cost estimate
    estimated_cost_max = Column(Float)  # Maximum cost estimate

    # Difficulty & Impact
    difficulty_level = Column(String(20))  # easy, medium, hard
    security_score_impact = Column(Integer)  # Points gained when completed
    risk_level = Column(String(20), index=True)  # critical, high, medium, low

    # Applicability Rules (JSON)
    applies_to_industries = Column(Text)  # JSON: ["healthcare", "finance", "all"]
    applies_to_sizes = Column(Text)  # JSON: ["small", "medium", "large", "all"]
    requires_compliance = Column(Text)  # JSON: ["soc2", "hipaa", null]

    # Resources
    documentation_url = Column(Text)
    video_tutorial_url = Column(Text)

    # Timestamps
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Flags
    is_active = Column(Boolean, nullable=False, default=True)

    def __repr__(self):
        return f'<RoadmapTask {self.task_id}: {self.task_name}>'


class RoadmapUserTask(Base):
    """
    Tasks assigned to a specific user/profile.
    Tracks progress, status, and source of the task.
    """
    __tablename__ = 'roadmap_user_tasks'

    # Primary Key
    id = Column(Integer, primary_key=True)

    # Profile Link
    profile_id = Column(Integer, ForeignKey('roadmap_profiles.id', ondelete='CASCADE'), nullable=False, index=True)

    # Task Reference (string ID, not FK for flexibility)
    task_id = Column(String(100), nullable=False, index=True)  # References RoadmapTask.task_id

    # Status & Progress
    status = Column(String(20), nullable=False, default='not_started', index=True)
    # Status options: not_started, in_progress, completed, skipped, not_applicable

    # Phase & Priority
    phase = Column(Integer, default=1, index=True)  # 1, 2, 3, or 4
    priority_order = Column(Integer)  # Order within phase

    # Source Information - Where did this task come from?
    source = Column(String(50), index=True)  # profile, xasm_scan, lightbox_scan, compliance, ghost_search, adversary
    source_reference_id = Column(Integer)  # ID of scan/finding that created it
    source_details = Column(Text)  # JSON: additional source context

    # Scan-based task details
    finding_type = Column(String(100))  # exposed_admin, outdated_ssl, etc.
    finding_severity = Column(String(20))  # critical, high, medium, low
    scan_domain = Column(String(255))  # Domain that was scanned
    scan_date = Column(DateTime)  # When the scan was run

    # Threat Actor Integration
    matched_threat_actor = Column(String(255))  # If from adversary matching
    threat_actor_ttp = Column(Text)  # JSON: TTPs from threat actor

    # Assignment
    assigned_to_user_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), index=True)

    # Timeline Tracking
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    verified_at = Column(DateTime)  # When completion was verified
    last_reminded = Column(DateTime)

    # Notes
    user_notes = Column(Text)
    admin_notes = Column(Text)

    # Timestamps
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    deleted_at = Column(DateTime, index=True)

    # Flags
    is_active = Column(Boolean, nullable=False, default=True)

    # Relationships
    profile = relationship('RoadmapProfile', back_populates='user_tasks')

    def __repr__(self):
        return f'<RoadmapUserTask {self.task_id} - {self.status}>'


class RoadmapAchievement(Base):
    """
    Achievements/badges unlocked by users as they progress.
    Gamification element to encourage completion.
    """
    __tablename__ = 'roadmap_achievements'

    # Primary Key
    id = Column(Integer, primary_key=True)

    # Profile & User Links
    profile_id = Column(Integer, ForeignKey('roadmap_profiles.id', ondelete='CASCADE'), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), index=True)

    # Achievement Details
    achievement_id = Column(String(100), nullable=False, index=True)  # FIRST_STEPS, MFA_MASTER, etc.
    achievement_name = Column(String(255), nullable=False)
    achievement_description = Column(Text)
    achievement_icon = Column(String(50))  # Icon identifier

    # Unlock Criteria
    requirement_type = Column(String(50))  # tasks_completed, score_reached, streak, category_complete
    requirement_value = Column(Integer)  # Number required to unlock

    # Status
    unlocked_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    is_claimed = Column(Boolean, default=False)
    claimed_at = Column(DateTime)

    # Rewards (JSON)
    rewards = Column(Text)  # JSON: {"type": "certificate", "value": "Security Champion"}

    # Timestamps
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    # Relationships
    profile = relationship('RoadmapProfile', back_populates='achievements')

    def __repr__(self):
        return f'<RoadmapAchievement {self.achievement_id} for profile {self.profile_id}>'


class RoadmapProgressHistory(Base):
    """
    Historical snapshots of security progress.
    Used for trending and progress visualization.
    """
    __tablename__ = 'roadmap_progress_history'

    # Primary Key
    id = Column(Integer, primary_key=True)

    # Profile Link
    profile_id = Column(Integer, ForeignKey('roadmap_profiles.id', ondelete='CASCADE'), nullable=False, index=True)

    # Snapshot Data
    security_score = Column(Integer)
    tasks_completed = Column(Integer)
    tasks_total = Column(Integer)

    # Phase Breakdown
    phase1_completed = Column(Integer, default=0)
    phase2_completed = Column(Integer, default=0)
    phase3_completed = Column(Integer, default=0)
    phase4_completed = Column(Integer, default=0)

    # Snapshot Metadata
    snapshot_date = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    snapshot_reason = Column(String(50))  # daily, task_completed, scan_run, manual

    # Relationships
    profile = relationship('RoadmapProfile', back_populates='progress_history')

    def __repr__(self):
        return f'<RoadmapProgressHistory profile={self.profile_id} score={self.security_score} at {self.snapshot_date}>'


class RoadmapTaskLibraryMeta(Base):
    """
    Metadata about the task library itself.
    Tracks versioning and updates to the master task list.
    """
    __tablename__ = 'roadmap_task_library_meta'

    # Primary Key
    id = Column(Integer, primary_key=True)

    # Library Info
    library_version = Column(String(20), nullable=False)  # e.g., "1.0.0"
    total_tasks = Column(Integer)  # Count of tasks in library
    changelog = Column(Text)  # Description of changes

    # Timestamps
    last_updated = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f'<RoadmapTaskLibraryMeta v{self.library_version} ({self.total_tasks} tasks)>'


# ============================================================================
# EXISTING MODELS
# ============================================================================

class Profile(Base):
    __tablename__ = 'profiles'

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    email = Column(String)
    username = Column(String)
    phone = Column(String)
    notes = Column(Text)
    risk_score = Column(Float, default=0.0)

    # OSINT data fields
    breach_count = Column(Integer, default=0)
    social_media_json = Column(Text)  # Store as JSON string
    exposed_passwords = Column(Text)
    data_leaks = Column(Text)

    # User & Standard Columns
    user_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    deleted_at = Column(DateTime, index=True)
    is_active = Column(Boolean, nullable=False, default=True)


class SocialMedia(Base):
    __tablename__ = 'social_media'

    id = Column(Integer, primary_key=True, autoincrement=True)
    profile_id = Column(String, nullable=False)
    platform = Column(String)
    username = Column(String)
    url = Column(String)
    followers = Column(Integer)
    posts_count = Column(Integer)
    discovered_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # User & Standard Columns
    user_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), index=True)
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    deleted_at = Column(DateTime, index=True)
    is_active = Column(Boolean, nullable=False, default=True)


class Breach(Base):
    __tablename__ = 'breaches'

    id = Column(Integer, primary_key=True, autoincrement=True)
    profile_id = Column(String, nullable=False)
    breach_name = Column(String)
    breach_date = Column(String)
    data_classes = Column(Text)  # What data was leaked
    discovered_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # User & Standard Columns
    user_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), index=True)
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    deleted_at = Column(DateTime, index=True)
    is_active = Column(Boolean, nullable=False, default=True)


class Device(Base):
    __tablename__ = 'devices'

    id = Column(Integer, primary_key=True, autoincrement=True)
    profile_id = Column(String)
    ip_address = Column(String)
    hostname = Column(String)
    device_type = Column(String)
    ports_open = Column(Text)
    vulnerabilities = Column(Text)
    location = Column(String)
    discovered_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # User & Standard Columns
    user_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), index=True)
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    deleted_at = Column(DateTime, index=True)
    is_active = Column(Boolean, nullable=False, default=True)


class BaitToken(Base):
    __tablename__ = 'bait_tokens'

    id = Column(Integer, primary_key=True, autoincrement=True)
    identifier = Column(String, unique=True, nullable=False)  # format: "bait_abc123"
    bait_type = Column(String)  # aws_key, stripe_token, database, ssh_key, github_token, slack_token
    token_value = Column(Text)  # JSON serialized fake credential
    seeded_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    seeded_location = Column(String)  # URL where posted (e.g., Pastebin URL)
    first_access = Column(DateTime, nullable=True)
    access_count = Column(Integer, default=0)
    last_access = Column(DateTime, nullable=True)
    status = Column(String, default='active')  # active, triggered, expired, revoked

    # Relationship to access logs
    accesses = relationship('BaitAccess', back_populates='bait_token', cascade='all, delete-orphan')

    # User & Standard Columns
    user_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), index=True)
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    deleted_at = Column(DateTime, index=True)
    is_active = Column(Boolean, nullable=False, default=True)


class BaitAccess(Base):
    __tablename__ = 'bait_accesses'

    id = Column(Integer, primary_key=True, autoincrement=True)
    bait_id = Column(Integer, ForeignKey('bait_tokens.id'), nullable=False)
    accessed_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    source_ip = Column(String)
    user_agent = Column(String)
    request_type = Column(String)  # http, api, ssh, database
    request_headers = Column(Text)  # JSON serialized headers
    request_body = Column(Text)  # JSON serialized request data
    fingerprint = Column(Text)  # scanner fingerprint analysis
    geolocation = Column(String)  # format: "City, Country"
    threat_level = Column(String, default='medium')  # low, medium, high, critical
    notes = Column(Text)  # additional analysis notes

    # Advanced fingerprinting fields
    accept_language = Column(String)  # Accept-Language header for locale detection
    referer = Column(String)  # Referer header for tracking origin
    sec_fetch_headers = Column(Text)  # JSON: Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest
    attribution_type = Column(String)  # human, bot, tool, spoofed
    evidence_strength = Column(String)  # court_ready, moderate, weak

    # Relationship to bait token
    bait_token = relationship('BaitToken', back_populates='accesses')

    # User & Standard Columns
    user_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), index=True)
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    deleted_at = Column(DateTime, index=True)
    is_active = Column(Boolean, nullable=False, default=True)


class UploadedFile(Base):
    __tablename__ = 'uploaded_files'

    id = Column(Integer, primary_key=True, autoincrement=True)
    upload_id = Column(String, unique=True, nullable=False, index=True)  # format: "upload_timestamp_randomstring"
    filename = Column(String, nullable=False)
    file_path = Column(String, nullable=False)  # path to stored file
    upload_time = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    line_count = Column(Integer, default=0)
    parsed_credential_count = Column(Integer, default=0)
    file_size_bytes = Column(Integer, default=0)

    # Relationship to credentials
    credentials = relationship('UploadedCredential', back_populates='uploaded_file', cascade='all, delete-orphan')

    # User & Standard Columns
    user_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), index=True)
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    deleted_at = Column(DateTime, index=True)
    is_active = Column(Boolean, nullable=False, default=True)


class UploadedCredential(Base):
    __tablename__ = 'uploaded_credentials'

    id = Column(Integer, primary_key=True, autoincrement=True)
    upload_id = Column(String, ForeignKey('uploaded_files.upload_id'), nullable=False, index=True)
    email = Column(String, nullable=False, index=True)  # indexed for fast searching
    password = Column(String)
    additional_data = Column(Text)  # any extra fields from the line
    line_number = Column(Integer)

    # Relationship to uploaded file
    uploaded_file = relationship('UploadedFile', back_populates='credentials')

    # User & Standard Columns
    user_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), index=True)
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    deleted_at = Column(DateTime, index=True)
    is_active = Column(Boolean, nullable=False, default=True)


class GitHubFinding(Base):
    __tablename__ = 'github_findings'

    id = Column(Integer, primary_key=True, autoincrement=True)
    gist_id = Column(String, unique=True, nullable=False, index=True)  # GitHub gist ID
    gist_url = Column(String, nullable=False)
    filename = Column(String)
    created_at = Column(DateTime)  # when the gist was created
    query_term = Column(String, index=True)  # the email/api_key/credential found
    query_type = Column(String, index=True)  # email, api_key, database, password
    credential_type = Column(String)  # aws_key, stripe_token, password, github_token, etc
    credential_value = Column(Text)  # the actual credential/password
    context = Column(Text)  # surrounding 500 chars
    discovered_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))  # when we found it

    # User & Standard Columns
    user_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), index=True)
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    deleted_at = Column(DateTime, index=True)
    is_active = Column(Boolean, nullable=False, default=True)


class PasteBinFinding(Base):
    __tablename__ = 'pastebin_findings'

    id = Column(Integer, primary_key=True, autoincrement=True)
    paste_id = Column(String, unique=True, nullable=False, index=True)  # 8 char PasteBin ID
    paste_title = Column(String)
    paste_url = Column(String, nullable=False)
    posted_date = Column(String)  # date from archive page
    query_term = Column(String, index=True)  # email/domain/username found
    query_type = Column(String, index=True)  # email, domain, username, password
    credential_password = Column(String)  # password if found
    context = Column(Text)  # surrounding 500 chars
    discovered_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))  # when we found it

    # User & Standard Columns
    user_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), index=True)
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    deleted_at = Column(DateTime, index=True)
    is_active = Column(Boolean, nullable=False, default=True)


class LightboxFinding(Base):
    __tablename__ = 'lightbox_findings'

    id = Column(Integer, primary_key=True, autoincrement=True)
    asset = Column(String, nullable=False, index=True)  # subdomain tested
    finding_type = Column(String, nullable=False, index=True)  # Sensitive File Exposed, Directory Listing, etc.
    url = Column(String, nullable=False)  # the URL that was tested
    description = Column(Text)  # description of the finding
    severity = Column(String, index=True)  # CRITICAL, HIGH, MEDIUM, LOW
    status_code = Column(Integer)  # HTTP status code
    discovered_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))  # when we found it
    scan_id = Column(String, index=True)  # to group findings from the same scan

    # User & Standard Columns
    user_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), index=True)
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    deleted_at = Column(DateTime, index=True)
    is_active = Column(Boolean, nullable=False, default=True)


class OpsychSearchResult(Base):
    __tablename__ = 'opsych_search_results'

    id = Column(Integer, primary_key=True, autoincrement=True)
    search_id = Column(String, nullable=False, index=True)  # format: "search_timestamp_randomstring"
    query_input = Column(String, nullable=False, index=True)  # original search query
    query_type = Column(String)  # email, username, phone, name
    platform = Column(String, index=True)  # Social media platform name
    username = Column(String, index=True)  # Username found on platform
    url = Column(String)  # Profile URL
    bio = Column(Text)  # Profile bio/description
    source = Column(String)  # Sherlock, Holehe, Mastodon API, GitHub API
    discovered_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))  # when we found it

    # User & Standard Columns
    user_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), index=True)
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    deleted_at = Column(DateTime, index=True)
    is_active = Column(Boolean, nullable=False, default=True)


class ASMScan(Base):
    __tablename__ = 'asm_scans'

    id = Column(Integer, primary_key=True, autoincrement=True)
    domain = Column(String, nullable=False, index=True, unique=True)  # scanned domain
    scan_results = Column(Text, nullable=False)  # JSON-serialized scan results
    scanned_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)  # when scan was performed
    risk_score = Column(Integer)  # cached risk score
    risk_level = Column(String)  # cached risk level
    vulnerabilities_found = Column(Integer)  # cached vuln count

    # User & Standard Columns
    user_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), index=True)
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    deleted_at = Column(DateTime, index=True)
    is_active = Column(Boolean, nullable=False, default=True)


class CachedASMScan(Base):
    __tablename__ = 'cached_asm_scans'

    id = Column(Integer, primary_key=True)
    domain = Column(String(255), nullable=False, index=True)
    scanned_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    risk_score = Column(Integer, default=0)
    risk_level = Column(String(20))  # 'low', 'medium', 'high', 'critical'
    total_cves = Column(Integer, default=0)
    critical_cves = Column(Integer, default=0)
    vulnerabilities_found = Column(Integer, default=0)  # Total vulnerability count
    open_ports_count = Column(Integer, default=0)  # Number of open ports
    scan_results = Column(JSON)

    # User & Standard Columns
    user_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), index=True)
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    deleted_at = Column(DateTime, index=True)
    is_active = Column(Boolean, nullable=False, default=True)


class LightboxScan(Base):
    """Store Lightbox scan results"""
    __tablename__ = 'lightbox_scans'

    id = Column(Integer, primary_key=True, autoincrement=True)
    domain = Column(String, nullable=False, index=True)
    scanned_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    # Summary stats
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)

    # Full results (JSON)
    findings = Column(Text)  # JSON-serialized findings
    scan_metadata = Column(Text)  # JSON-serialized metadata: assets tested, checks run, etc.

    # User & Standard Columns
    user_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), index=True)
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    deleted_at = Column(DateTime, index=True)
    is_active = Column(Boolean, nullable=False, default=True)

    def to_dict(self):
        return {
            'id': self.id,
            'domain': self.domain,
            'scanned_at': self.scanned_at.isoformat(),
            'total_findings': self.total_findings,
            'critical_count': self.critical_count,
            'high_count': self.high_count,
            'medium_count': self.medium_count,
            'low_count': self.low_count,
            'findings': json.loads(self.findings) if self.findings else [],
            'scan_metadata': json.loads(self.scan_metadata) if self.scan_metadata else {}
        }


class XASMScanHistory(Base):
    """XASM Scan History - stores all XASM scans with full results"""
    __tablename__ = 'xasm_scan_history'

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String, unique=True, nullable=False, index=True)
    target = Column(String, nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    status = Column(String, nullable=False, default='completed')
    results_json = Column(Text)  # Full scan results as JSON
    summary_stats = Column(Text)  # Summary statistics as JSON

    # User & Standard Columns
    user_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    deleted_at = Column(DateTime, index=True)
    is_active = Column(Boolean, nullable=False, default=True)

    def to_dict(self):
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'target': self.target,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'status': self.status,
            'summary': json.loads(self.summary_stats) if self.summary_stats else {},
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class LightboxScanHistory(Base):
    """Lightbox Scan History - stores all Lightbox scans with full results"""
    __tablename__ = 'lightbox_scan_history'

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String, unique=True, nullable=False, index=True)
    target = Column(String, nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    status = Column(String, nullable=False, default='completed')
    results_json = Column(Text)  # Full scan results as JSON
    summary_stats = Column(Text)  # Summary statistics as JSON
    total_tests = Column(Integer, default=0)
    passed_tests = Column(Integer, default=0)
    failed_tests = Column(Integer, default=0)

    # User & Standard Columns
    user_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    deleted_at = Column(DateTime, index=True)
    is_active = Column(Boolean, nullable=False, default=True)

    def to_dict(self):
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'target': self.target,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'status': self.status,
            'summary': json.loads(self.summary_stats) if self.summary_stats else {},
            'total_tests': self.total_tests,
            'passed_tests': self.passed_tests,
            'failed_tests': self.failed_tests,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


# ============================================================================
# AI REPORT SCAN STORAGE MODELS (48-hour expiry)
# ============================================================================

class ScanResultsXASM(Base):
    """Store XASM scan results for AI report generation (48h expiry)"""
    __tablename__ = 'scan_results_xasm'

    id = Column(Integer, primary_key=True, autoincrement=True)
    company = Column(String, nullable=False, unique=True, index=True)
    results_json = Column(Text, nullable=False)
    scan_date = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime, nullable=False)

    # User & Standard Columns
    user_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    deleted_at = Column(DateTime, index=True)
    is_active = Column(Boolean, nullable=False, default=True)


class ScanResultsLightbox(Base):
    """Store Lightbox scan results for AI report generation (48h expiry)"""
    __tablename__ = 'scan_results_lightbox'

    id = Column(Integer, primary_key=True, autoincrement=True)
    company = Column(String, nullable=False, unique=True, index=True)
    results_json = Column(Text, nullable=False)
    scan_date = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime, nullable=False)

    # User & Standard Columns
    user_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    deleted_at = Column(DateTime, index=True)
    is_active = Column(Boolean, nullable=False, default=True)


def init_db() -> None:
    """
    Initialize the database and create all tables.

    This function is called automatically on module import. It's safe to call
    multiple times as SQLAlchemy's create_all() is idempotent.

    Example:
        >>> from database import init_db
        >>> init_db()
        Database initialized at: /path/to/ghost.db
    """
    Base.metadata.create_all(engine)
    print(f"Database initialized at: {DB_PATH}")


def get_db():
    """
    Get a database session.

    Returns:
        Session: SQLAlchemy session object

    Warning:
        Remember to close the session when done to avoid connection leaks.
        Prefer using safe_db_session() context manager for automatic cleanup.

    Example:
        >>> session = get_db()
        >>> try:
        ...     user = session.query(User).first()
        ... finally:
        ...     session.close()
    """
    db = SessionLocal()
    try:
        return db
    finally:
        pass


# ============================================================================
# XASM SCAN HISTORY FUNCTIONS
# ============================================================================

def save_xasm_scan(scan_id, target, results, user_id=None):
    """Save XASM scan to history"""

    session = SessionLocal()

    # Calculate summary stats
    summary = {
        'total_subdomains': len(results.get('subdomains', [])),
        'total_services': len(results.get('port_scan_results', [])),
        'total_vulnerabilities': results.get('cve_statistics', {}).get('total_cves', 0),
        'critical_vulns': results.get('cve_statistics', {}).get('critical_cves', 0),
        'high_vulns': len([v for v in results.get('port_scan_results', []) if v.get('risk_level') == 'HIGH']),
        'risk_score': results.get('risk_score', 0),
        'risk_level': results.get('risk_level', 'low')
    }

    try:
        # Check if scan already exists
        existing = session.query(XASMScanHistory).filter_by(scan_id=scan_id).first()

        if existing:
            # Update existing scan
            existing.results_json = json.dumps(results)
            existing.summary_stats = json.dumps(summary)
            existing.status = results.get('status', 'completed')
            existing.timestamp = datetime.now(timezone.utc)
            session.commit()
            print(f"[DB] Updated XASM scan: {scan_id}")
        else:
            # Create new scan record
            new_scan = XASMScanHistory(
                scan_id=scan_id,
                target=target,
                timestamp=datetime.now(timezone.utc),
                status=results.get('status', 'completed'),
                results_json=json.dumps(results),
                summary_stats=json.dumps(summary),
                user_id=user_id
            )
            session.add(new_scan)
            session.commit()
            print(f"[DB] Saved XASM scan: {scan_id}")

    except Exception as e:
        session.rollback()
        print(f"[DB] Error saving XASM scan: {e}")
    finally:
        session.close()


def save_lightbox_scan(scan_id, target, results, user_id=None):
    """Save Lightbox scan to history"""

    session = SessionLocal()

    # Calculate summary stats
    test_results = results.get('test_results', {})

    # Handle both dict and list formats for results
    if isinstance(results, dict):
        total_tests = results.get('total_tests', 0)
        total_findings = results.get('total_findings', 0)
        critical = len(results.get('critical', []))
        high = len(results.get('high', []))
        medium = len(results.get('medium', []))
        low = len(results.get('low', []))
        passed = total_tests - total_findings if total_tests > total_findings else 0
        failed = total_findings
    else:
        total_tests = 0
        passed = 0
        failed = 0

    summary = {
        'total_tests': total_tests,
        'passed': passed,
        'failed': failed,
        'pass_rate': round((passed / total_tests * 100) if total_tests > 0 else 0, 1),
        'critical': critical if 'critical' in dir() else 0,
        'high': high if 'high' in dir() else 0,
        'medium': medium if 'medium' in dir() else 0,
        'low': low if 'low' in dir() else 0
    }

    try:
        # Check if scan already exists
        existing = session.query(LightboxScanHistory).filter_by(scan_id=scan_id).first()

        if existing:
            # Update existing scan
            existing.results_json = json.dumps(results)
            existing.summary_stats = json.dumps(summary)
            existing.status = results.get('status', 'completed') if isinstance(results, dict) else 'completed'
            existing.total_tests = total_tests
            existing.passed_tests = passed
            existing.failed_tests = failed
            existing.timestamp = datetime.now(timezone.utc)
            session.commit()
            print(f"[DB] Updated Lightbox scan: {scan_id}")
        else:
            # Create new scan record
            new_scan = LightboxScanHistory(
                scan_id=scan_id,
                target=target,
                timestamp=datetime.now(timezone.utc),
                status=results.get('status', 'completed') if isinstance(results, dict) else 'completed',
                results_json=json.dumps(results),
                summary_stats=json.dumps(summary),
                total_tests=total_tests,
                passed_tests=passed,
                failed_tests=failed,
                user_id=user_id
            )
            session.add(new_scan)
            session.commit()
            print(f"[DB] Saved Lightbox scan: {scan_id}")

    except Exception as e:
        session.rollback()
        print(f"[DB] Error saving Lightbox scan: {e}")
    finally:
        session.close()


def get_xasm_scan_history(user_id=None, limit=30):
    """Get XASM scan history (last 30 days)"""

    session = SessionLocal()
    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)

    try:
        query = session.query(XASMScanHistory).filter(
            XASMScanHistory.timestamp > thirty_days_ago
        )

        if user_id:
            query = query.filter(XASMScanHistory.user_id == user_id)

        scans = query.order_by(XASMScanHistory.timestamp.desc()).limit(limit).all()

        history = [scan.to_dict() for scan in scans]
        return history

    finally:
        session.close()


def get_lightbox_scan_history(user_id=None, limit=30):
    """Get Lightbox scan history (last 30 days)"""

    session = SessionLocal()
    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)

    try:
        query = session.query(LightboxScanHistory).filter(
            LightboxScanHistory.timestamp > thirty_days_ago
        )

        if user_id:
            query = query.filter(LightboxScanHistory.user_id == user_id)

        scans = query.order_by(LightboxScanHistory.timestamp.desc()).limit(limit).all()

        history = [scan.to_dict() for scan in scans]
        return history

    finally:
        session.close()


def delete_xasm_scan(scan_id):
    """Delete XASM scan from history"""
    session = SessionLocal()

    try:
        scan = session.query(XASMScanHistory).filter_by(scan_id=scan_id).first()
        if scan:
            session.delete(scan)
            session.commit()
            print(f"[DB] Deleted XASM scan: {scan_id}")
            return True
        return False
    except Exception as e:
        session.rollback()
        print(f"[DB] Error deleting XASM scan: {e}")
        return False
    finally:
        session.close()


def delete_lightbox_scan_history(scan_id):
    """Delete Lightbox scan from history"""
    session = SessionLocal()

    try:
        scan = session.query(LightboxScanHistory).filter_by(scan_id=scan_id).first()
        if scan:
            session.delete(scan)
            session.commit()
            print(f"[DB] Deleted Lightbox scan: {scan_id}")
            return True
        return False
    except Exception as e:
        session.rollback()
        print(f"[DB] Error deleting Lightbox scan: {e}")
        return False
    finally:
        session.close()


def get_xasm_scan_by_id(scan_id):
    """Get full XASM scan results by ID with target info"""
    session = SessionLocal()

    try:
        scan = session.query(XASMScanHistory).filter_by(scan_id=scan_id).first()
        if scan and scan.results_json:
            return {
                'target': scan.target,
                'results': json.loads(scan.results_json),
                'timestamp': scan.timestamp.isoformat() if scan.timestamp else None,
                'scan_id': scan.scan_id
            }
        return None
    finally:
        session.close()


def get_lightbox_scan_by_id(scan_id):
    """Get full Lightbox scan results by ID with target info"""
    session = SessionLocal()

    try:
        scan = session.query(LightboxScanHistory).filter_by(scan_id=scan_id).first()
        if scan and scan.results_json:
            return {
                'target': scan.target,
                'results': json.loads(scan.results_json),
                'timestamp': scan.timestamp.isoformat() if scan.timestamp else None,
                'scan_id': scan.scan_id,
                'total_tests': scan.total_tests,
                'passed_tests': scan.passed_tests,
                'failed_tests': scan.failed_tests
            }
        return None
    finally:
        session.close()


def cleanup_old_scan_history(days=30):
    """Delete scan history older than specified days"""

    session = SessionLocal()
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    try:
        # Delete old XASM scans
        xasm_deleted = session.query(XASMScanHistory).filter(
            XASMScanHistory.timestamp < cutoff
        ).delete()

        # Delete old Lightbox scans
        lightbox_deleted = session.query(LightboxScanHistory).filter(
            LightboxScanHistory.timestamp < cutoff
        ).delete()

        session.commit()
        print(f"[DB] Cleaned up {xasm_deleted} XASM and {lightbox_deleted} Lightbox scans older than {days} days")

    except Exception as e:
        session.rollback()
        print(f"[DB] Error cleaning up scan history: {e}")
    finally:
        session.close()


# ============================================================================
# AI REPORT SCAN STORAGE FUNCTIONS (48-hour expiry)
# ============================================================================

def save_xasm_for_ai(company: str, results: dict) -> bool:
    """Save XASM results for AI report generation (48h expiry)"""
    import json
    from datetime import datetime, timedelta, timezone

    session = SessionLocal()

    try:
        # Use timezone-aware datetime
        now = datetime.now(timezone.utc)
        expires_at = (now + timedelta(hours=48)).isoformat()

        # Check if scan already exists
        existing = session.query(ScanResultsXASM).filter_by(company=company).first()

        if existing:
            # Update existing
            existing.results_json = json.dumps(results)
            existing.scan_date = now.isoformat()
            existing.expires_at = expires_at
        else:
            # Create new
            scan = ScanResultsXASM(
                company=company,
                results_json=json.dumps(results),
                scan_date=now.isoformat(),
                expires_at=expires_at
            )
            session.add(scan)

        session.commit()
        print(f"[DB] Saved XASM scan for AI report: {company} (expires in 48h)")
        return True

    except Exception as e:
        print(f"[DB] Error saving XASM for AI: {e}")
        session.rollback()
        return False
    finally:
        session.close()


def save_lightbox_for_ai(company: str, results: dict) -> bool:
    """Save Lightbox results for AI report generation (48h expiry)"""
    import json
    from datetime import datetime, timedelta, timezone

    session = SessionLocal()

    try:
        # Use timezone-aware datetime
        now = datetime.now(timezone.utc)
        expires_at = (now + timedelta(hours=48)).isoformat()

        # Check if scan already exists
        existing = session.query(ScanResultsLightbox).filter_by(company=company).first()

        if existing:
            # Update existing
            existing.results_json = json.dumps(results)
            existing.scan_date = now.isoformat()
            existing.expires_at = expires_at
        else:
            # Create new
            scan = ScanResultsLightbox(
                company=company,
                results_json=json.dumps(results),
                scan_date=now.isoformat(),
                expires_at=expires_at
            )
            session.add(scan)

        session.commit()
        print(f"[DB] Saved Lightbox scan for AI report: {company} (expires in 48h)")
        return True

    except Exception as e:
        print(f"[DB] Error saving Lightbox for AI: {e}")
        session.rollback()
        return False
    finally:
        session.close()


def load_xasm_for_ai(company: str) -> dict:
    """Load XASM results for AI report from CachedASMScan"""
    session = SessionLocal()

    try:
        # Query CachedASMScan by domain (company parameter is actually domain)
        scan = session.query(CachedASMScan).filter_by(domain=company).first()

        if not scan:
            print(f"[DB] No XASM scan found for {company}")
            return None

        print(f"[DB] Loaded XASM scan for {company}")
        # scan_results is already a dict (JSON column)
        return scan.scan_results if scan.scan_results else None

    except Exception as e:
        print(f"[DB] Error loading XASM for AI: {e}")
        import traceback
        traceback.print_exc()
        return None
    finally:
        session.close()


def load_lightbox_for_ai(company: str) -> dict:
    """Load Lightbox results for AI report from LightboxScan"""
    session = SessionLocal()

    try:
        # Query LightboxScan by domain (company parameter is actually domain)
        scan = session.query(LightboxScan).filter_by(domain=company).first()

        if not scan:
            print(f"[DB] No Lightbox scan found for {company}")
            return None

        print(f"[DB] Loaded Lightbox scan for {company}")
        # Return the scan as a dict using the to_dict method
        return scan.to_dict()

    except Exception as e:
        print(f"[DB] Error loading Lightbox for AI: {e}")
        import traceback
        traceback.print_exc()
        return None
    finally:
        session.close()


def get_companies_with_scans() -> list:
    """Get list of domains with available scans for AI reports"""
    session = SessionLocal()

    try:
        # Get all available XASM scans
        xasm_records = session.query(CachedASMScan).all()

        # Get all available Lightbox scans
        lightbox_records = session.query(LightboxScan).all()

        # Build domain map
        domain_map = {}

        for record in xasm_records:
            if record.domain not in domain_map:
                domain_map[record.domain] = {
                    'company': record.domain,
                    'has_xasm': False,
                    'has_lightbox': False,
                    'xasm_date': None,
                    'lightbox_date': None
                }
            domain_map[record.domain]['has_xasm'] = True
            domain_map[record.domain]['xasm_date'] = record.scanned_at.isoformat() if record.scanned_at else None

        for record in lightbox_records:
            if record.domain not in domain_map:
                domain_map[record.domain] = {
                    'company': record.domain,
                    'has_xasm': False,
                    'has_lightbox': False,
                    'xasm_date': None,
                    'lightbox_date': None
                }
            domain_map[record.domain]['has_lightbox'] = True
            domain_map[record.domain]['lightbox_date'] = record.scanned_at.isoformat() if record.scanned_at else None

        return list(domain_map.values())

    except Exception as e:
        print(f"[DB] Error getting companies: {e}")
        return []
    finally:
        session.close()


def cleanup_expired_ai_scans():
    """Delete all expired scan results (run periodically)"""
    session = SessionLocal()
    now = datetime.now(timezone.utc)

    try:
        # Delete expired XASM scans
        xasm_deleted = session.query(ScanResultsXASM).filter(
            ScanResultsXASM.expires_at < now
        ).delete()

        # Delete expired Lightbox scans
        lightbox_deleted = session.query(ScanResultsLightbox).filter(
            ScanResultsLightbox.expires_at < now
        ).delete()

        session.commit()

        total = xasm_deleted + lightbox_deleted
        if total > 0:
            print(f"[DB] Cleanup: Deleted {total} expired scans ({xasm_deleted} XASM, {lightbox_deleted} Lightbox)")

    except Exception as e:
        session.rollback()
        print(f"[DB] Error during cleanup: {e}")
    finally:
        session.close()




# ============================================================================
# PASSWORD HASHING UTILITIES
# ============================================================================

def hash_password(plain_password: str) -> str:
    """
    Hash a password using bcrypt (or fallback to PBKDF2).

    Args:
        plain_password: The plaintext password to hash

    Returns:
        The hashed password string
    """
    if BCRYPT_AVAILABLE:
        # Use bcrypt with salt
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(plain_password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    else:
        # Fallback: PBKDF2 with SHA256
        salt = secrets.token_hex(16)
        key = hashlib.pbkdf2_hmac(
            'sha256',
            plain_password.encode('utf-8'),
            salt.encode('utf-8'),
            100000  # iterations
        )
        return f"pbkdf2${salt}${key.hex()}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against its hash.

    Args:
        plain_password: The plaintext password to verify
        hashed_password: The stored hash to compare against

    Returns:
        True if password matches, False otherwise
    """
    if not plain_password or not hashed_password:
        return False

    try:
        if hashed_password.startswith('pbkdf2$'):
            # Fallback format: pbkdf2$salt$hash
            parts = hashed_password.split('$')
            if len(parts) != 3:
                return False
            _, salt, stored_hash = parts
            key = hashlib.pbkdf2_hmac(
                'sha256',
                plain_password.encode('utf-8'),
                salt.encode('utf-8'),
                100000
            )
            return secrets.compare_digest(key.hex(), stored_hash)
        else:
            # bcrypt format
            if BCRYPT_AVAILABLE:
                return bcrypt.checkpw(
                    plain_password.encode('utf-8'),
                    hashed_password.encode('utf-8')
                )
            return False
    except Exception as e:
        print(f"[AUTH] Password verification error: {e}")
        return False


def generate_secure_token(length: int = 32) -> str:
    """Generate a cryptographically secure random token."""
    return secrets.token_urlsafe(length)


# ============================================================================
# SESSION MANAGEMENT FUNCTIONS
# ============================================================================

def create_session(user_id: int, ip_address: str, user_agent: str = None,
                   device_type: str = 'web', expires_hours: int = 24) -> dict:
    """
    Create a new session for a user.

    Args:
        user_id: The user's ID
        ip_address: Client IP address
        user_agent: Client user agent string
        device_type: Type of device (web, mobile, api)
        expires_hours: Session expiry in hours

    Returns:
        Dict with session token and refresh token
    """
    session = SessionLocal()

    try:
        # Generate tokens
        token = generate_secure_token(32)
        refresh_token = generate_secure_token(48)

        # Create session record
        new_session = Session(
            user_id=user_id,
            token=token,
            refresh_token=refresh_token,
            ip_address=ip_address,
            user_agent=user_agent,
            device_type=device_type,
            created_at=datetime.now(timezone.utc),
            last_activity=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=expires_hours),
            is_active=True
        )

        session.add(new_session)

        # Update user's last login
        user = session.query(User).filter_by(id=user_id).first()
        if user:
            user.last_login_at = datetime.now(timezone.utc)
            user.last_login_ip = ip_address

        session.commit()

        print(f"[AUTH] Session created for user {user_id}")
        return {
            'session_id': new_session.id,
            'token': token,
            'refresh_token': refresh_token,
            'expires_at': new_session.expires_at.isoformat()
        }

    except Exception as e:
        session.rollback()
        print(f"[AUTH] Error creating session: {e}")
        return None
    finally:
        session.close()


def validate_session(token: str, update_activity: bool = True) -> dict:
    """
    Validate a session token and return session info.

    Args:
        token: The session token to validate
        update_activity: Whether to update last_activity timestamp

    Returns:
        Dict with session info if valid, None if invalid
    """
    session = SessionLocal()

    try:
        db_session = session.query(Session).filter_by(
            token=token,
            is_active=True
        ).first()

        if not db_session:
            return None

        # Check expiry (use naive datetime for comparison since DB stores naive)
        now_naive = datetime.utcnow()
        expires_naive = db_session.expires_at.replace(tzinfo=None) if db_session.expires_at.tzinfo else db_session.expires_at
        if expires_naive < now_naive:
            db_session.is_active = False
            session.commit()
            return None

        # Check if revoked
        if db_session.revoked_at:
            return None

        # Update activity
        if update_activity:
            db_session.last_activity = datetime.now(timezone.utc)
            session.commit()

        return {
            'session_id': db_session.id,
            'user_id': db_session.user_id,
            'device_type': db_session.device_type,
            'created_at': db_session.created_at.isoformat(),
            'expires_at': db_session.expires_at.isoformat(),
            'last_activity': db_session.last_activity.isoformat()
        }

    except Exception as e:
        print(f"[AUTH] Session validation error: {e}")
        return None
    finally:
        session.close()


def revoke_session(token: str) -> bool:
    """Revoke a session by token."""
    session = SessionLocal()

    try:
        db_session = session.query(Session).filter_by(token=token).first()
        if db_session:
            db_session.is_active = False
            db_session.revoked_at = datetime.now(timezone.utc)
            session.commit()
            print(f"[AUTH] Session revoked: {db_session.id}")
            return True
        return False
    except Exception as e:
        session.rollback()
        print(f"[AUTH] Error revoking session: {e}")
        return False
    finally:
        session.close()


def revoke_all_user_sessions(user_id: int, except_token: str = None) -> int:
    """Revoke all sessions for a user (optionally except current)."""
    session = SessionLocal()

    try:
        query = session.query(Session).filter(
            Session.user_id == user_id,
            Session.is_active == True
        )

        if except_token:
            query = query.filter(Session.token != except_token)

        now = datetime.now(timezone.utc)
        count = 0
        for s in query.all():
            s.is_active = False
            s.revoked_at = now
            count += 1

        session.commit()
        print(f"[AUTH] Revoked {count} sessions for user {user_id}")
        return count
    except Exception as e:
        session.rollback()
        print(f"[AUTH] Error revoking user sessions: {e}")
        return 0
    finally:
        session.close()


def cleanup_expired_sessions() -> int:
    """Clean up all expired sessions."""
    session = SessionLocal()

    try:
        now = datetime.now(timezone.utc)
        count = session.query(Session).filter(
            Session.expires_at < now,
            Session.is_active == True
        ).update({
            Session.is_active: False
        })
        session.commit()

        if count > 0:
            print(f"[AUTH] Cleaned up {count} expired sessions")
        return count
    except Exception as e:
        session.rollback()
        print(f"[AUTH] Error cleaning up sessions: {e}")
        return 0
    finally:
        session.close()


# ============================================================================
# API KEY MANAGEMENT FUNCTIONS
# ============================================================================

def create_api_key(user_id: int, name: str, permissions: list = None,
                   expires_days: int = None) -> dict:
    """
    Create a new API key for a user.

    Args:
        user_id: The user's ID
        name: User-friendly name for the key
        permissions: List of allowed actions/endpoints
        expires_days: Optional expiry in days

    Returns:
        Dict with key (only returned once!) and metadata
    """
    session = SessionLocal()

    try:
        # Generate key: nrv_<random>
        raw_key = f"nrv_{secrets.token_urlsafe(32)}"
        key_prefix = raw_key[:12]  # nrv_xxxxxxxx

        # Hash the key for storage
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

        # Calculate expiry
        expires_at = None
        if expires_days:
            expires_at = datetime.now(timezone.utc) + timedelta(days=expires_days)

        new_key = APIKey(
            user_id=user_id,
            key_hash=key_hash,
            key_prefix=key_prefix,
            name=name,
            permissions=json.dumps(permissions) if permissions else None,
            created_at=datetime.now(timezone.utc),
            expires_at=expires_at,
            is_active=True
        )

        session.add(new_key)
        session.commit()

        # Log security event
        log_security_event(
            event_type='api_key_created',
            severity='info',
            user_id=user_id,
            description=f'API key created: {name} ({key_prefix}...)'
        )

        print(f"[AUTH] API key created for user {user_id}: {key_prefix}...")
        return {
            'key': raw_key,  # Only returned this once!
            'key_id': new_key.id,
            'key_prefix': key_prefix,
            'name': name,
            'expires_at': expires_at.isoformat() if expires_at else None
        }

    except Exception as e:
        session.rollback()
        print(f"[AUTH] Error creating API key: {e}")
        return None
    finally:
        session.close()


def validate_api_key(raw_key: str) -> dict:
    """
    Validate an API key and return user info.

    Args:
        raw_key: The full API key string

    Returns:
        Dict with key info and user_id if valid, None if invalid
    """
    session = SessionLocal()

    try:
        # Hash the provided key
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

        api_key = session.query(APIKey).filter_by(
            key_hash=key_hash,
            is_active=True
        ).first()

        if not api_key:
            return None

        # Check expiry (use naive datetime for comparison)
        if api_key.expires_at:
            now_naive = datetime.utcnow()
            expires_naive = api_key.expires_at.replace(tzinfo=None) if api_key.expires_at.tzinfo else api_key.expires_at
            if expires_naive < now_naive:
                return None

        # Check if revoked
        if api_key.revoked_at:
            return None

        # Update usage stats
        api_key.last_used_at = datetime.now(timezone.utc)
        api_key.usage_count += 1
        session.commit()

        return {
            'key_id': api_key.id,
            'user_id': api_key.user_id,
            'name': api_key.name,
            'permissions': json.loads(api_key.permissions) if api_key.permissions else None
        }

    except Exception as e:
        print(f"[AUTH] API key validation error: {e}")
        return None
    finally:
        session.close()


def revoke_api_key(key_id: int, user_id: int = None) -> bool:
    """
    Revoke an API key.

    Args:
        key_id: The API key ID
        user_id: Optional user ID for authorization check

    Returns:
        True if revoked, False otherwise
    """
    session = SessionLocal()

    try:
        query = session.query(APIKey).filter_by(id=key_id)
        if user_id:
            query = query.filter_by(user_id=user_id)

        api_key = query.first()
        if api_key:
            api_key.is_active = False
            api_key.revoked_at = datetime.now(timezone.utc)
            session.commit()

            # Log security event
            log_security_event(
                event_type='api_key_revoked',
                severity='info',
                user_id=api_key.user_id,
                description=f'API key revoked: {api_key.name} ({api_key.key_prefix}...)'
            )

            print(f"[AUTH] API key revoked: {api_key.key_prefix}...")
            return True
        return False
    except Exception as e:
        session.rollback()
        print(f"[AUTH] Error revoking API key: {e}")
        return False
    finally:
        session.close()


def list_user_api_keys(user_id: int) -> list:
    """List all API keys for a user (without exposing the actual keys)."""
    session = SessionLocal()

    try:
        keys = session.query(APIKey).filter_by(
            user_id=user_id,
            is_active=True
        ).all()

        return [{
            'key_id': k.id,
            'key_prefix': k.key_prefix,
            'name': k.name,
            'last_used_at': k.last_used_at.isoformat() if k.last_used_at else None,
            'usage_count': k.usage_count,
            'created_at': k.created_at.isoformat(),
            'expires_at': k.expires_at.isoformat() if k.expires_at else None
        } for k in keys]

    finally:
        session.close()


# ============================================================================
# SECURITY AUDIT FUNCTIONS
# ============================================================================

def log_login_attempt(email: str, success: bool, ip_address: str,
                      user_agent: str = None, failure_reason: str = None,
                      user_id: int = None) -> bool:
    """
    Log a login attempt.

    Args:
        email: Email attempted
        success: Whether login succeeded
        ip_address: Client IP
        user_agent: Client user agent
        failure_reason: Reason for failure if applicable
        user_id: User ID if known

    Returns:
        True if logged successfully
    """
    session = SessionLocal()

    try:
        attempt = LoginAttempt(
            email=email,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
            failure_reason=failure_reason,
            attempted_at=datetime.now(timezone.utc)
        )

        session.add(attempt)
        session.commit()

        # Log as security event
        if success:
            log_security_event(
                event_type='login',
                severity='info',
                email=email,
                user_id=user_id,
                ip_address=ip_address,
                user_agent=user_agent,
                description=f'Successful login for {email}'
            )
        else:
            log_security_event(
                event_type='login_failed',
                severity='warning',
                email=email,
                user_id=user_id,
                ip_address=ip_address,
                user_agent=user_agent,
                description=f'Failed login attempt for {email}: {failure_reason or "Invalid credentials"}'
            )

        return True

    except Exception as e:
        session.rollback()
        print(f"[AUDIT] Error logging login attempt: {e}")
        return False
    finally:
        session.close()


def detect_brute_force(email: str = None, ip_address: str = None,
                       window_minutes: int = 15, threshold: int = 5) -> dict:
    """
    Detect brute force login attempts.

    Args:
        email: Email to check (optional)
        ip_address: IP to check (optional)
        window_minutes: Time window to check
        threshold: Number of failures to trigger detection

    Returns:
        Dict with detection results
    """
    session = SessionLocal()

    try:
        window_start = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        results = {
            'detected': False,
            'email_attempts': 0,
            'ip_attempts': 0,
            'should_lock': False
        }

        # Check by email
        if email:
            email_count = session.query(LoginAttempt).filter(
                LoginAttempt.email == email,
                LoginAttempt.success == False,
                LoginAttempt.attempted_at > window_start
            ).count()
            results['email_attempts'] = email_count

        # Check by IP
        if ip_address:
            ip_count = session.query(LoginAttempt).filter(
                LoginAttempt.ip_address == ip_address,
                LoginAttempt.success == False,
                LoginAttempt.attempted_at > window_start
            ).count()
            results['ip_attempts'] = ip_count

        # Determine if brute force detected
        if results['email_attempts'] >= threshold or results['ip_attempts'] >= threshold:
            results['detected'] = True
            results['should_lock'] = results['email_attempts'] >= threshold

            # Log security event
            log_security_event(
                event_type='brute_force_detected',
                severity='high',
                email=email,
                ip_address=ip_address,
                description=f'Brute force detected: {results["email_attempts"]} email attempts, {results["ip_attempts"]} IP attempts in {window_minutes} minutes'
            )

        return results

    finally:
        session.close()


def lock_user_account(user_id: int, lock_minutes: int = 30,
                      reason: str = 'Too many failed login attempts') -> bool:
    """Lock a user account temporarily."""
    session = SessionLocal()

    try:
        user = session.query(User).filter_by(id=user_id).first()
        if user:
            user.status = UserStatus.LOCKED
            user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=lock_minutes)
            session.commit()

            # Log security event
            log_security_event(
                event_type='account_locked',
                severity='medium',
                user_id=user_id,
                description=f'Account locked for {lock_minutes} minutes: {reason}'
            )

            print(f"[AUTH] User {user_id} locked for {lock_minutes} minutes")
            return True
        return False
    except Exception as e:
        session.rollback()
        print(f"[AUTH] Error locking account: {e}")
        return False
    finally:
        session.close()


def check_account_lock(user_id: int) -> dict:
    """Check if a user account is locked."""
    session = SessionLocal()

    try:
        user = session.query(User).filter_by(id=user_id).first()
        if not user:
            return {'locked': False, 'exists': False}

        if user.status == UserStatus.LOCKED:
            now_naive = datetime.utcnow()
            if user.locked_until:
                locked_naive = user.locked_until.replace(tzinfo=None) if user.locked_until.tzinfo else user.locked_until
                if locked_naive > now_naive:
                    remaining = int((locked_naive - now_naive).total_seconds() / 60)
                    return {
                        'locked': True,
                        'exists': True,
                        'locked_until': user.locked_until.isoformat(),
                        'remaining_minutes': remaining
                    }
            # Lock expired or no locked_until, unlock
            user.status = UserStatus.ACTIVE
            user.locked_until = None
            session.commit()

        return {'locked': False, 'exists': True}

    finally:
        session.close()


def log_security_event(event_type: str, severity: str, description: str,
                       user_id: int = None, email: str = None,
                       ip_address: str = None, user_agent: str = None,
                       metadata: dict = None) -> bool:
    """
    Log a security event.

    Args:
        event_type: Type of security event
        severity: Severity level (info, low, medium, high, critical)
        description: Human-readable description
        user_id: Related user ID
        email: Related email
        ip_address: Client IP
        user_agent: Client user agent
        metadata: Additional metadata as dict

    Returns:
        True if logged successfully
    """
    session = SessionLocal()

    try:
        event = SecurityEvent(
            event_type=event_type,
            severity=severity,
            user_id=user_id,
            email=email,
            ip_address=ip_address,
            user_agent=user_agent,
            description=description,
            metadata_json=json.dumps(metadata) if metadata else None,
            created_at=datetime.now(timezone.utc)
        )

        session.add(event)
        session.commit()
        return True

    except Exception as e:
        session.rollback()
        print(f"[AUDIT] Error logging security event: {e}")
        return False
    finally:
        session.close()


def get_security_events(user_id: int = None, event_type: str = None,
                        severity: str = None, hours: int = 24,
                        limit: int = 100) -> list:
    """Get security events with filters."""
    session = SessionLocal()

    try:
        window_start = datetime.now(timezone.utc) - timedelta(hours=hours)

        query = session.query(SecurityEvent).filter(
            SecurityEvent.created_at > window_start
        )

        if user_id:
            query = query.filter(SecurityEvent.user_id == user_id)
        if event_type:
            query = query.filter(SecurityEvent.event_type == event_type)
        if severity:
            query = query.filter(SecurityEvent.severity == severity)

        events = query.order_by(SecurityEvent.created_at.desc()).limit(limit).all()

        return [{
            'id': e.id,
            'event_type': e.event_type,
            'severity': e.severity,
            'description': e.description,
            'user_id': e.user_id,
            'email': e.email,
            'ip_address': e.ip_address,
            'created_at': e.created_at.isoformat(),
            'acknowledged': e.acknowledged
        } for e in events]

    finally:
        session.close()


def get_failed_logins_by_ip(ip_address: str, hours: int = 24) -> list:
    """Get failed login attempts from a specific IP."""
    session = SessionLocal()

    try:
        window_start = datetime.now(timezone.utc) - timedelta(hours=hours)

        attempts = session.query(LoginAttempt).filter(
            LoginAttempt.ip_address == ip_address,
            LoginAttempt.success == False,
            LoginAttempt.attempted_at > window_start
        ).order_by(LoginAttempt.attempted_at.desc()).all()

        return [{
            'id': a.id,
            'email': a.email,
            'failure_reason': a.failure_reason,
            'attempted_at': a.attempted_at.isoformat()
        } for a in attempts]

    finally:
        session.close()


def increment_failed_login_count(user_id: int) -> int:
    """Increment failed login count for a user and return new count."""
    session = SessionLocal()

    try:
        user = session.query(User).filter_by(id=user_id).first()
        if user:
            user.failed_login_attempts += 1
            session.commit()
            return user.failed_login_attempts
        return 0
    except Exception as e:
        session.rollback()
        print(f"[AUTH] Error incrementing failed login count: {e}")
        return 0
    finally:
        session.close()


def reset_failed_login_count(user_id: int) -> bool:
    """Reset failed login count after successful login."""
    session = SessionLocal()

    try:
        user = session.query(User).filter_by(id=user_id).first()
        if user:
            user.failed_login_attempts = 0
            session.commit()
            return True
        return False
    except Exception as e:
        session.rollback()
        print(f"[AUTH] Error resetting failed login count: {e}")
        return False
    finally:
        session.close()



# ============================================================================
# ERROR HANDLING & LOGGING
# ============================================================================

class DatabaseError(Exception):
    """Base exception for database errors"""
    pass

class ValidationError(DatabaseError):
    """Raised when data validation fails"""
    pass

class DatabaseConnectionError(DatabaseError):
    """Raised when database connection fails"""
    pass

class TransactionError(DatabaseError):
    """Raised when a transaction fails"""
    pass


def handle_db_error(func):
    """Decorator to handle database errors consistently"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except IntegrityError as e:
            logger.error(f"[DB] Integrity error in {func.__name__}: {e}")
            raise DatabaseError(f"Data integrity violation: {str(e)}")
        except OperationalError as e:
            logger.error(f"[DB] Operational error in {func.__name__}: {e}")
            raise DatabaseConnectionError(f"Database operation failed: {str(e)}")
        except SQLAlchemyError as e:
            logger.error(f"[DB] SQLAlchemy error in {func.__name__}: {e}")
            raise DatabaseError(f"Database error: {str(e)}")
        except Exception as e:
            logger.error(f"[DB] Unexpected error in {func.__name__}: {e}")
            raise
    return wrapper


@contextmanager
def safe_db_session():
    """Context manager for safe database sessions with auto-rollback."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception as e:
        session.rollback()
        logger.error(f"[DB] Session error, rolled back: {e}")
        raise
    finally:
        session.close()


def log_db_operation(operation: str, table: str, record_id: int = None, details: dict = None):
    """Log database operation for auditing."""
    log_entry = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'operation': operation,
        'table': table,
        'record_id': record_id,
        'details': details
    }
    logger.info(f"[DB] {operation} on {table}" + (f" (id={record_id})" if record_id else ""))
    return log_entry


# ============================================================================
# DATABASE HEALTH CHECKS
# ============================================================================
# These functions provide comprehensive health monitoring for the database.
# Use run_health_check() for a complete health report.
# TODO (Phase 7): Update health checks for PostgreSQL-specific metrics

def check_database_connection() -> Dict[str, Any]:
    """
    Check if database connection is healthy.

    Performs a simple SELECT 1 query to verify the database is accessible
    and measures the query latency.

    Returns:
        dict: Health check result with keys:
            - healthy (bool): True if connection succeeded
            - latency_ms (float): Query latency in milliseconds
            - error (str): Error message if unhealthy

    Example:
        >>> result = check_database_connection()
        >>> if result['healthy']:
        ...     print(f"Connection OK, latency: {result['latency_ms']}ms")
    """
    result = {
        'healthy': False,
        'latency_ms': None,
        'error': None
    }

    start = time.time()
    try:
        session = SessionLocal()
        session.execute(text("SELECT 1"))
        session.close()
        result['healthy'] = True
        result['latency_ms'] = round((time.time() - start) * 1000, 2)
    except Exception as e:
        result['error'] = str(e)
        logger.error(f"[DB] Connection check failed: {e}")

    return result


def check_table_integrity() -> dict:
    """Check integrity of all tables."""
    result = {
        'tables_checked': 0,
        'errors': [],
        'healthy': True
    }

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Get all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]

        for table in tables:
            try:
                cursor.execute(f"PRAGMA table_info({table})")
                cursor.execute(f"SELECT COUNT(*) FROM {table}")
                result['tables_checked'] += 1
            except Exception as e:
                result['errors'].append({'table': table, 'error': str(e)})
                result['healthy'] = False

        # Run integrity check
        cursor.execute("PRAGMA integrity_check")
        integrity = cursor.fetchone()[0]
        if integrity != 'ok':
            result['errors'].append({'check': 'integrity', 'error': integrity})
            result['healthy'] = False

        conn.close()
    except Exception as e:
        result['errors'].append({'check': 'connection', 'error': str(e)})
        result['healthy'] = False

    return result


def check_foreign_key_constraints() -> dict:
    """Check foreign key constraint violations."""
    result = {
        'violations': [],
        'healthy': True
    }

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("PRAGMA foreign_key_check")
        violations = cursor.fetchall()

        if violations:
            result['healthy'] = False
            result['violations'] = [
                {'table': v[0], 'row_id': v[1], 'parent': v[2], 'fk_index': v[3]}
                for v in violations
            ]

        conn.close()
    except Exception as e:
        result['healthy'] = False
        result['violations'].append({'error': str(e)})

    return result


def get_database_stats() -> dict:
    """Get database statistics."""
    stats = {
        'size_bytes': 0,
        'size_mb': 0,
        'table_counts': {},
        'total_records': 0
    }

    try:
        # File size
        if os.path.exists(DB_PATH):
            stats['size_bytes'] = os.path.getsize(DB_PATH)
            stats['size_mb'] = round(stats['size_bytes'] / (1024 * 1024), 2)

        # Table counts
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]

        for table in tables:
            try:
                cursor.execute(f"SELECT COUNT(*) FROM {table}")
                count = cursor.fetchone()[0]
                stats['table_counts'][table] = count
                stats['total_records'] += count
            except:
                pass

        conn.close()
    except Exception as e:
        logger.error(f"[DB] Failed to get stats: {e}")

    return stats


# ============================================================================
# DATA VALIDATION
# ============================================================================

def validate_email(email: str) -> bool:
    """Validate email format."""
    if not email:
        return False
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def validate_domain(domain: str) -> bool:
    """Validate domain format."""
    if not domain:
        return False
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))


def validate_ip_address(ip: str) -> bool:
    """Validate IPv4 address format."""
    if not ip:
        return False
    pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    return bool(re.match(pattern, ip))


def sanitize_input(value: str, max_length: int = 255, allow_html: bool = False) -> str:
    """Sanitize string input."""
    if not value:
        return ""

    # Convert to string and strip
    result = str(value).strip()

    # Remove HTML if not allowed
    if not allow_html:
        result = re.sub(r'<[^>]+>', '', result)

    # Truncate
    if len(result) > max_length:
        result = result[:max_length]

    return result


def validate_record(data: dict, rules: dict) -> dict:
    """
    Validate a record against rules.

    Args:
        data: Dictionary of field values
        rules: Dictionary of field rules, e.g.:
            {
                'email': {'type': 'email', 'required': True},
                'domain': {'type': 'domain', 'required': False},
                'name': {'type': 'string', 'max_length': 100}
            }

    Returns:
        Dictionary with 'valid' boolean and 'errors' list
    """
    result = {'valid': True, 'errors': []}

    validators = {
        'email': validate_email,
        'domain': validate_domain,
        'ip': validate_ip_address
    }

    for field, rule in rules.items():
        value = data.get(field)

        # Check required
        if rule.get('required') and not value:
            result['errors'].append(f"{field} is required")
            result['valid'] = False
            continue

        if value:
            # Type validation
            field_type = rule.get('type', 'string')
            if field_type in validators:
                if not validators[field_type](value):
                    result['errors'].append(f"{field} is not a valid {field_type}")
                    result['valid'] = False

            # Length validation
            max_len = rule.get('max_length')
            if max_len and len(str(value)) > max_len:
                result['errors'].append(f"{field} exceeds maximum length of {max_len}")
                result['valid'] = False

    return result


# ============================================================================
# TRANSACTION HELPERS
# ============================================================================

def atomic_operation(func):
    """Decorator for atomic database operations."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        session = SessionLocal()
        try:
            # Pass session to function
            result = func(session, *args, **kwargs)
            session.commit()
            return result
        except Exception as e:
            session.rollback()
            logger.error(f"[DB] Atomic operation {func.__name__} failed, rolled back: {e}")
            raise TransactionError(f"Transaction failed: {str(e)}")
        finally:
            session.close()
    return wrapper


def batch_insert(model_class, records: list, batch_size: int = 100) -> dict:
    """
    Insert records in batches for better performance.

    Args:
        model_class: SQLAlchemy model class
        records: List of dictionaries with record data
        batch_size: Number of records per batch

    Returns:
        Dictionary with insert statistics
    """
    result = {
        'total': len(records),
        'inserted': 0,
        'failed': 0,
        'errors': []
    }

    session = SessionLocal()

    try:
        for i in range(0, len(records), batch_size):
            batch = records[i:i + batch_size]

            try:
                for record_data in batch:
                    record = model_class(**record_data)
                    session.add(record)

                session.commit()
                result['inserted'] += len(batch)
            except Exception as e:
                session.rollback()
                result['failed'] += len(batch)
                result['errors'].append({
                    'batch_start': i,
                    'error': str(e)
                })

        logger.info(f"[DB] Batch insert complete: {result['inserted']}/{result['total']} records")
    finally:
        session.close()

    return result


def safe_update(model_class, record_id: int, updates: dict, user_id: int = None) -> dict:
    """
    Safely update a record with validation and logging.

    Args:
        model_class: SQLAlchemy model class
        record_id: ID of record to update
        updates: Dictionary of field updates
        user_id: Optional user ID for audit trail

    Returns:
        Dictionary with update result
    """
    result = {
        'success': False,
        'record_id': record_id,
        'changes': {},
        'error': None
    }

    session = SessionLocal()

    try:
        record = session.query(model_class).filter_by(id=record_id).first()

        if not record:
            result['error'] = "Record not found"
            return result

        # Track changes
        for field, new_value in updates.items():
            if hasattr(record, field):
                old_value = getattr(record, field)
                if old_value != new_value:
                    result['changes'][field] = {'old': old_value, 'new': new_value}
                    setattr(record, field, new_value)

        # Update timestamp if exists
        if hasattr(record, 'updated_at'):
            record.updated_at = datetime.now(timezone.utc)

        # Update modified_by if exists and user provided
        if user_id and hasattr(record, 'modified_by'):
            record.modified_by = user_id

        session.commit()
        result['success'] = True

        logger.info(f"[DB] Updated {model_class.__tablename__} id={record_id}: {list(result['changes'].keys())}")

    except Exception as e:
        session.rollback()
        result['error'] = str(e)
        logger.error(f"[DB] Update failed: {e}")
    finally:
        session.close()

    return result


# ============================================================================
# BACKUP & RESTORE
# ============================================================================
# These functions provide database backup and restore capabilities.
# Backups are created using SQLite's backup API for consistency.
# TODO (Phase 7): Replace with pg_dump/pg_restore for PostgreSQL

def create_backup(backup_dir: str = None) -> Dict[str, Any]:
    """
    Create a database backup.

    Uses SQLite's backup API to create an atomic, consistent backup of the
    database while it's in use. The backup is named with a timestamp for
    easy identification.

    Args:
        backup_dir: Directory for backup file. Defaults to data/backups/

    Returns:
        dict: Backup result with keys:
            - success (bool): True if backup succeeded
            - backup_path (str): Full path to backup file
            - size_bytes (int): Backup file size
            - timestamp (str): ISO format timestamp
            - error (str): Error message if failed

    Example:
        >>> result = create_backup()
        >>> if result['success']:
        ...     print(f"Backup: {result['backup_path']}")
        >>> # Custom backup location
        >>> result = create_backup("/mnt/backups")
    """
    result = {
        'success': False,
        'backup_path': None,
        'size_bytes': 0,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'error': None
    }

    if backup_dir is None:
        backup_dir = os.path.join(os.path.dirname(DB_PATH), 'backups')

    try:
        # Create backup directory
        os.makedirs(backup_dir, exist_ok=True)

        # Generate backup filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_filename = f"nerve_backup_{timestamp}.db"
        backup_path = os.path.join(backup_dir, backup_filename)

        # Use SQLite backup API
        source = sqlite3.connect(DB_PATH)
        dest = sqlite3.connect(backup_path)

        source.backup(dest)

        source.close()
        dest.close()

        result['success'] = True
        result['backup_path'] = backup_path
        result['size_bytes'] = os.path.getsize(backup_path)

        logger.info(f"[DB] Backup created: {backup_path}")

    except Exception as e:
        result['error'] = str(e)
        logger.error(f"[DB] Backup failed: {e}")

    return result


def restore_backup(backup_path: str, confirm: bool = False) -> Dict[str, Any]:
    """
    Restore database from backup.

    Creates a backup of the current database before restoring, then replaces
    the database with the backup file contents.

    Args:
        backup_path: Path to backup file to restore from
        confirm: Must be True to proceed. This is a safety check to prevent
                 accidental data loss.

    Returns:
        dict: Restore result with keys:
            - success (bool): True if restore succeeded
            - backup_path (str): Path that was restored from
            - pre_restore_backup (str): Path to backup of current DB
            - error (str): Error message if failed

    Warning:
        This operation will REPLACE ALL DATA in the current database.
        Always verify the backup before restoring.

    Example:
        >>> # First verify the backup
        >>> info = get_backup_info("/path/to/backup.db")
        >>> # Then restore with confirm=True
        >>> result = restore_backup("/path/to/backup.db", confirm=True)
    """
    result = {
        'success': False,
        'backup_path': backup_path,
        'error': None
    }

    if not confirm:
        result['error'] = "Must set confirm=True to restore backup"
        return result

    if not os.path.exists(backup_path):
        result['error'] = f"Backup file not found: {backup_path}"
        return result

    try:
        # Create a backup of current database first
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        pre_restore_backup = f"{DB_PATH}.pre_restore_{timestamp}"
        shutil.copy2(DB_PATH, pre_restore_backup)

        # Restore from backup
        source = sqlite3.connect(backup_path)
        dest = sqlite3.connect(DB_PATH)

        source.backup(dest)

        source.close()
        dest.close()

        result['success'] = True
        result['pre_restore_backup'] = pre_restore_backup

        logger.info(f"[DB] Restored from backup: {backup_path}")

    except Exception as e:
        result['error'] = str(e)
        logger.error(f"[DB] Restore failed: {e}")

    return result


def get_backup_info(backup_path: str) -> dict:
    """Get information about a backup file."""
    if not os.path.exists(backup_path):
        return {'error': 'Backup file not found'}

    info = {
        'path': backup_path,
        'size_bytes': os.path.getsize(backup_path),
        'size_mb': round(os.path.getsize(backup_path) / (1024 * 1024), 2),
        'created': datetime.fromtimestamp(os.path.getctime(backup_path)).isoformat(),
        'tables': {}
    }

    try:
        conn = sqlite3.connect(backup_path)
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]

        for table in tables:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            info['tables'][table] = cursor.fetchone()[0]

        conn.close()
    except Exception as e:
        info['error'] = str(e)

    return info


def list_backups(backup_dir: str = None) -> list:
    """List available backups."""
    if backup_dir is None:
        backup_dir = os.path.join(os.path.dirname(DB_PATH), 'backups')

    if not os.path.exists(backup_dir):
        return []

    backups = []
    for filename in os.listdir(backup_dir):
        if filename.endswith('.db') and filename.startswith('nerve_backup_'):
            filepath = os.path.join(backup_dir, filename)
            backups.append({
                'filename': filename,
                'path': filepath,
                'size_bytes': os.path.getsize(filepath),
                'created': datetime.fromtimestamp(os.path.getctime(filepath)).isoformat()
            })

    return sorted(backups, key=lambda x: x['created'], reverse=True)


# ============================================================================
# PERFORMANCE MONITORING
# ============================================================================

def log_query_performance(query: str, duration_ms: float, rows_affected: int = 0):
    """Log query performance for analysis."""
    global _query_performance_log

    entry = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'query': query[:500],  # Truncate long queries
        'duration_ms': duration_ms,
        'rows_affected': rows_affected
    }

    _query_performance_log.append(entry)

    # Keep only last 1000 entries
    if len(_query_performance_log) > 1000:
        _query_performance_log = _query_performance_log[-1000:]

    # Log slow queries
    if duration_ms > 1000:
        logger.warning(f"[DB] Slow query ({duration_ms}ms): {query[:100]}...")


def get_performance_stats() -> dict:
    """Get query performance statistics."""
    if not _query_performance_log:
        return {
            'total_queries': 0,
            'avg_duration_ms': 0,
            'max_duration_ms': 0,
            'slow_queries': 0
        }

    durations = [q['duration_ms'] for q in _query_performance_log]

    return {
        'total_queries': len(_query_performance_log),
        'avg_duration_ms': round(sum(durations) / len(durations), 2),
        'max_duration_ms': max(durations),
        'slow_queries': sum(1 for d in durations if d > 1000),
        'recent_queries': _query_performance_log[-10:]
    }


def get_slow_queries(threshold_ms: float = 1000) -> list:
    """Get queries that exceeded the threshold."""
    return [q for q in _query_performance_log if q['duration_ms'] > threshold_ms]


def clear_performance_log():
    """Clear the performance log."""
    global _query_performance_log
    _query_performance_log = []


def optimize_database() -> dict:
    """Run database optimization tasks."""
    result = {
        'success': False,
        'tasks_completed': [],
        'error': None
    }

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Analyze tables
        cursor.execute("ANALYZE")
        result['tasks_completed'].append('analyze')

        # Vacuum database
        cursor.execute("VACUUM")
        result['tasks_completed'].append('vacuum')

        # Reindex
        cursor.execute("REINDEX")
        result['tasks_completed'].append('reindex')

        conn.close()
        result['success'] = True

        logger.info("[DB] Database optimization complete")

    except Exception as e:
        result['error'] = str(e)
        logger.error(f"[DB] Optimization failed: {e}")

    return result


# ============================================================================
# MIGRATION HELPERS
# ============================================================================

def get_schema_version() -> str:
    """Get current schema version."""
    return _schema_version


def set_schema_version(version: str):
    """Set schema version (internal use)."""
    global _schema_version
    _schema_version = version


def get_applied_migrations() -> list:
    """Get list of applied migrations."""
    session = SessionLocal()

    try:
        # Check if migrations table exists
        inspector = inspect(engine)
        if 'schema_migrations' not in inspector.get_table_names():
            return []

        result = session.execute(text("SELECT version, applied_at FROM schema_migrations ORDER BY applied_at"))
        return [{'version': row[0], 'applied_at': row[1]} for row in result]
    except Exception as e:
        logger.error(f"[DB] Failed to get migrations: {e}")
        return []
    finally:
        session.close()


def apply_migration(migration_sql: str, version: str, description: str = None) -> dict:
    """
    Apply a SQL migration.

    Args:
        migration_sql: SQL statements to execute
        version: Version identifier for this migration
        description: Optional description

    Returns:
        Dict with migration result
    """
    result = {
        'success': False,
        'version': version,
        'error': None
    }

    session = SessionLocal()

    try:
        # Ensure migrations table exists
        session.execute(text(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "version VARCHAR(50) UNIQUE NOT NULL, "
            "description TEXT, "
            "applied_at DATETIME DEFAULT CURRENT_TIMESTAMP)"
        ))

        # Check if already applied
        existing = session.execute(
            text("SELECT 1 FROM schema_migrations WHERE version = :v"),
            {'v': version}
        ).fetchone()

        if existing:
            result['error'] = f"Migration {version} already applied"
            return result

        # Execute migration
        for statement in migration_sql.split(';'):
            statement = statement.strip()
            if statement:
                session.execute(text(statement))

        # Record migration
        session.execute(
            text("INSERT INTO schema_migrations (version, description) VALUES (:v, :d)"),
            {'v': version, 'd': description}
        )

        session.commit()
        result['success'] = True

        logger.info(f"[DB] Migration {version} applied successfully")

    except Exception as e:
        session.rollback()
        result['error'] = str(e)
        logger.error(f"[DB] Migration {version} failed: {e}")
    finally:
        session.close()

    return result


def rollback_migration(version: str) -> dict:
    """Mark a migration as rolled back (does not undo changes)."""
    result = {
        'success': False,
        'version': version,
        'error': None
    }

    session = SessionLocal()

    try:
        session.execute(
            text("DELETE FROM schema_migrations WHERE version = :v"),
            {'v': version}
        )
        session.commit()
        result['success'] = True

        logger.info(f"[DB] Migration {version} marked as rolled back")

    except Exception as e:
        session.rollback()
        result['error'] = str(e)
    finally:
        session.close()

    return result


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def run_health_check() -> Dict[str, Any]:
    """
    Run comprehensive health check on database.

    Combines multiple health check functions into a single comprehensive
    report. Use this for monitoring and diagnostics.

    Returns:
        dict: Comprehensive health report with keys:
            - timestamp (str): ISO format timestamp
            - connection (dict): Connection health from check_database_connection()
            - tables (dict): Table integrity from check_table_integrity()
            - foreign_keys (dict): FK constraints from check_foreign_key_constraints()
            - stats (dict): Database statistics from get_database_stats()
            - performance (dict): Performance metrics from get_performance_stats()

    Example:
        >>> health = run_health_check()
        >>> if health['connection']['healthy'] and health['tables']['healthy']:
        ...     print("Database is healthy")
        >>> print(f"Size: {health['stats']['size_mb']} MB")

    See Also:
        DATABASE_MAINTENANCE.md for monitoring integration examples
    """
    return {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'connection': check_database_connection(),
        'tables': check_table_integrity(),
        'foreign_keys': check_foreign_key_constraints(),
        'stats': get_database_stats(),
        'performance': get_performance_stats()
    }


def export_schema() -> str:
    """
    Export current database schema as SQL.

    Extracts all CREATE TABLE statements from the database. Useful for
    documentation, migrations, or recreating the schema in another database.

    Returns:
        str: SQL statements for all tables, separated by newlines

    Example:
        >>> schema = export_schema()
        >>> with open('schema_dump.sql', 'w') as f:
        ...     f.write(schema)

    TODO (Phase 7): Update for PostgreSQL-compatible syntax
    """
    # TODO (Phase 7): Replace sqlite3 direct connection with SQLAlchemy
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    schema = []
    cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' ORDER BY name")

    for (sql,) in cursor.fetchall():
        if sql:
            schema.append(sql + ';')

    conn.close()
    return '\n\n'.join(schema)



# Initialize database on import
init_db()