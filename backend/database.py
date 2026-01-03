from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Float, ForeignKey, JSON, Boolean, Enum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime, timedelta, timezone
import os
import json
import enum

# Create database in the data folder
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'ghost.db')
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

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


def init_db():
    """Initialize the database and create all tables"""
    Base.metadata.create_all(engine)
    print(f"Database initialized at: {DB_PATH}")

def get_db():
    """Get database session"""
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
    """Load XASM results for AI report (returns None if expired/missing)"""
    import json
    from datetime import datetime, timezone

    session = SessionLocal()

    try:
        scan = session.query(ScanResultsXASM).filter_by(company=company).first()

        if not scan:
            print(f"[DB] No XASM scan found for {company}")
            return None

        # expires_at is already a datetime object from SQLAlchemy, not a string
        expires_at = scan.expires_at

        # Make both timezone-aware for comparison
        now = datetime.now(timezone.utc)

        # If expires_at has no timezone info, assume UTC
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        else:
            # Convert to UTC if it has a different timezone
            expires_at = expires_at.astimezone(timezone.utc)

        # Check expiry
        if now > expires_at:
            print(f"[DB] XASM scan expired for {company}")
            session.delete(scan)
            session.commit()
            return None

        print(f"[DB] Loaded XASM scan for {company}")
        return json.loads(scan.results_json)

    except Exception as e:
        print(f"[DB] Error loading XASM for AI: {e}")
        import traceback
        traceback.print_exc()
        return None
    finally:
        session.close()


def load_lightbox_for_ai(company: str) -> dict:
    """Load Lightbox results for AI report (returns None if expired/missing)"""
    import json
    from datetime import datetime, timezone

    session = SessionLocal()

    try:
        scan = session.query(ScanResultsLightbox).filter_by(company=company).first()

        if not scan:
            print(f"[DB] No Lightbox scan found for {company}")
            return None

        # expires_at is already a datetime object from SQLAlchemy, not a string
        expires_at = scan.expires_at

        # Make both timezone-aware for comparison
        now = datetime.now(timezone.utc)

        # If expires_at has no timezone info, assume UTC
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        else:
            # Convert to UTC if it has a different timezone
            expires_at = expires_at.astimezone(timezone.utc)

        # Check expiry
        if now > expires_at:
            print(f"[DB] Lightbox scan expired for {company}")
            session.delete(scan)
            session.commit()
            return None

        print(f"[DB] Loaded Lightbox scan for {company}")
        return json.loads(scan.results_json)

    except Exception as e:
        print(f"[DB] Error loading Lightbox for AI: {e}")
        import traceback
        traceback.print_exc()
        return None
    finally:
        session.close()


def get_companies_with_scans() -> list:
    """Get list of companies with available scans for AI reports"""
    session = SessionLocal()
    now = datetime.now(timezone.utc)

    try:
        # Get all non-expired XASM scans
        xasm_records = session.query(ScanResultsXASM).filter(
            ScanResultsXASM.expires_at > now
        ).all()

        # Get all non-expired Lightbox scans
        lightbox_records = session.query(ScanResultsLightbox).filter(
            ScanResultsLightbox.expires_at > now
        ).all()

        # Build company map
        company_map = {}

        for record in xasm_records:
            if record.company not in company_map:
                company_map[record.company] = {
                    'company': record.company,
                    'has_xasm': False,
                    'has_lightbox': False,
                    'xasm_date': None,
                    'lightbox_date': None
                }
            company_map[record.company]['has_xasm'] = True
            company_map[record.company]['xasm_date'] = record.scan_date.isoformat() if record.scan_date else None

        for record in lightbox_records:
            if record.company not in company_map:
                company_map[record.company] = {
                    'company': record.company,
                    'has_xasm': False,
                    'has_lightbox': False,
                    'xasm_date': None,
                    'lightbox_date': None
                }
            company_map[record.company]['has_lightbox'] = True
            company_map[record.company]['lightbox_date'] = record.scan_date.isoformat() if record.scan_date else None

        return list(company_map.values())

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


# Initialize database on import
init_db()