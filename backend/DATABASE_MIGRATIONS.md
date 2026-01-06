# NERVE Database Migration History

> Documentation of all database schema migrations and changes.

**Current Schema Version:** 1.0.0
**Last Migration:** January 2026 (Phase 8)
**Database Engine:** SQLite (PostgreSQL migration planned)

---

## Table of Contents

1. [Migration Overview](#migration-overview)
2. [Phase 1: Initial Schema](#phase-1-initial-schema)
3. [Phase 2: Ghost Search Tables](#phase-2-ghost-search-tables)
4. [Phase 3: Compliance Tables](#phase-3-compliance-tables)
5. [Phase 4: Roadmap Tables](#phase-4-roadmap-tables)
6. [Phase 5: Security Features](#phase-5-security-features)
7. [Phase 6: Reliability Improvements](#phase-6-reliability-improvements)
8. [Phase 7: PostgreSQL Prep (TODO)](#phase-7-postgresql-prep-todo)
9. [Phase 8: Documentation](#phase-8-documentation)
10. [Migration Best Practices](#migration-best-practices)
11. [Rollback Procedures](#rollback-procedures)

---

## Migration Overview

The NERVE database has evolved through 8 development phases:

| Phase | Name | Status | Date | Tables Added |
|-------|------|--------|------|--------------|
| 1 | Initial Schema | Complete | Dec 2025 | 15 |
| 2 | Ghost Search | Complete | Dec 2025 | 6 |
| 3 | Compliance | Complete | Jan 2026 | 4 |
| 4 | Roadmap | Complete | Jan 2026 | 6 |
| 5 | Security Features | Complete | Jan 2026 | 3 |
| 6 | Reliability | Complete | Jan 2026 | 0 (improvements) |
| 7 | PostgreSQL Prep | **TODO** | TBD | 0 (refactoring) |
| 8 | Documentation | Complete | Jan 2026 | 0 (docs only) |

---

## Phase 1: Initial Schema

**Date Completed:** December 2025
**Commit:** Initial database setup

### What Was Added

#### Core Authentication Tables
- `users` - User accounts with full auth support
- `companies` - Multi-tenant company records
- `sessions` - User session management
- `password_history` - Password reuse prevention
- `login_attempts` - Login attempt tracking
- `audit_logs` - General audit trail

#### OSINT Tables
- `profiles` - OSINT profile data
- `social_media` - Social media accounts
- `breaches` - Breach records
- `devices` - Discovered devices

#### Attack Surface Tables
- `asm_scans` - ASM scan results
- `lightbox_findings` - Lightbox findings

#### BAIT Module Tables
- `bait_tokens` - Honeypot tokens
- `bait_accesses` - Token access logs

#### File Upload Tables
- `uploaded_files` - Upload tracking
- `uploaded_credentials` - Parsed credentials

### Why It Was Needed
- Initial application setup
- Core functionality for user authentication
- OSINT and attack surface scanning support

### Test Results
- All tables created successfully
- Foreign key relationships validated
- CRUD operations verified

---

## Phase 2: Ghost Search Tables

**Date Completed:** December 2025
**Commit:** Add Ghost Search module

### What Was Added

| Table | Purpose |
|-------|---------|
| `ghost_search_queries` | Search query history |
| `monitored_emails` | Email monitoring configuration |
| `monitored_email_findings` | Findings from email monitoring |
| `uploaded_breach_files` | Breach file uploads |
| `breach_file_results` | Parsed breach file data |
| `github_findings` | GitHub/Gist search results |
| `pastebin_findings` | Pastebin search results |
| `opsych_search_results` | OPSYCH social media results |

### Schema Changes

```sql
-- Ghost Search Queries
CREATE TABLE ghost_search_queries (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    query_type VARCHAR(20) NOT NULL,
    query_value VARCHAR(255) NOT NULL,
    results_count INTEGER NOT NULL DEFAULT 0,
    search_sources TEXT,
    response_time_ms INTEGER,
    searched_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    deleted_at DATETIME,
    is_active BOOLEAN NOT NULL DEFAULT 1
);

-- Monitored Emails
CREATE TABLE monitored_emails (
    id INTEGER PRIMARY KEY,
    company_id INTEGER REFERENCES companies(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    created_by_user_id INTEGER NOT NULL REFERENCES users(id),
    email_address VARCHAR(255) NOT NULL,
    monitor_scope VARCHAR(20) NOT NULL,
    last_checked DATETIME,
    findings_count INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    deleted_at DATETIME,
    is_active BOOLEAN NOT NULL DEFAULT 1
);
```

### Why It Was Needed
- Ghost Search module for credential monitoring
- Email breach monitoring capability
- Integration with external OSINT sources

### Backup Location
- `backend_backup_20251220_ghost_search/`

### Test Results
- Ghost Search queries functional
- Email monitoring working
- Breach file parsing tested with sample data

---

## Phase 3: Compliance Tables

**Date Completed:** January 2026
**Commit:** Add Compliance framework

### What Was Added

| Table | Purpose |
|-------|---------|
| `compliance_assessments` | Framework assessments |
| `compliance_controls` | Individual controls |
| `compliance_evidence` | Evidence attachments |
| `vulnerability_reports` | AI-generated reports |

### Schema Changes

```sql
-- Compliance Assessments
CREATE TABLE compliance_assessments (
    id INTEGER PRIMARY KEY,
    company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    created_by_user_id INTEGER NOT NULL REFERENCES users(id),
    framework VARCHAR(50) NOT NULL,
    framework_version VARCHAR(20),
    status VARCHAR(20) NOT NULL DEFAULT 'in_progress',
    overall_compliance_score INTEGER,
    assessment_date DATETIME NOT NULL,
    completion_date DATETIME,
    expiry_date DATETIME,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    deleted_at DATETIME,
    is_active BOOLEAN NOT NULL DEFAULT 1
);

-- Compliance Controls (with scan integration)
CREATE TABLE compliance_controls (
    id INTEGER PRIMARY KEY,
    assessment_id INTEGER NOT NULL REFERENCES compliance_assessments(id) ON DELETE CASCADE,
    control_id VARCHAR(50) NOT NULL,
    control_name VARCHAR(255) NOT NULL,
    control_category VARCHAR(100),
    status VARCHAR(20) NOT NULL DEFAULT 'not_tested',
    compliance_score INTEGER,
    scan_source VARCHAR(20),
    scan_finding_type VARCHAR(100),
    scan_finding_id VARCHAR(100),
    scan_flagged_at DATETIME,
    scan_verified_at DATETIME,
    scan_domain VARCHAR(255),
    evidence_summary TEXT,
    remediation_notes TEXT,
    assigned_to_user_id INTEGER REFERENCES users(id),
    last_reviewed DATETIME,
    next_review_date DATETIME,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    deleted_at DATETIME,
    is_active BOOLEAN NOT NULL DEFAULT 1
);
```

### Why It Was Needed
- SOC2, ISO27001, GDPR, NIS2, PIPEDA compliance tracking
- Auto-flagging from XASM/Lightbox scan findings
- AI-powered vulnerability reporting

### Backup Location
- `backend_backup_20260103_compliance/`

### Test Results
- Assessment creation and management working
- Control auto-flagging from scans validated
- Evidence attachment upload functional
- AI report generation tested

---

## Phase 4: Roadmap Tables

**Date Completed:** January 2026
**Commit:** Add Roadmap module

### What Was Added

| Table | Purpose |
|-------|---------|
| `roadmap_profiles` | Company security profiles |
| `roadmap_tasks` | Master task library |
| `roadmap_user_tasks` | Assigned user tasks |
| `roadmap_achievements` | Gamification badges |
| `roadmap_progress_history` | Progress snapshots |
| `roadmap_task_library_meta` | Task library versioning |

### Schema Changes

```sql
-- Roadmap Profiles
CREATE TABLE roadmap_profiles (
    id INTEGER PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    company_id INTEGER REFERENCES companies(id),
    company_name VARCHAR(255) NOT NULL,
    company_size VARCHAR(50),
    industry VARCHAR(100),
    employee_count INTEGER,
    current_security_score INTEGER DEFAULT 0,
    target_security_score INTEGER DEFAULT 75,
    handles_pii BOOLEAN DEFAULT 0,
    handles_payment_data BOOLEAN DEFAULT 0,
    handles_health_data BOOLEAN DEFAULT 0,
    handles_financial_data BOOLEAN DEFAULT 0,
    current_measures TEXT,
    compliance_requirements TEXT,
    assessment_responses TEXT,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    last_recalculated DATETIME,
    deleted_at DATETIME,
    is_active BOOLEAN NOT NULL DEFAULT 1
);

-- Roadmap User Tasks (with scan/threat actor integration)
CREATE TABLE roadmap_user_tasks (
    id INTEGER PRIMARY KEY,
    profile_id INTEGER NOT NULL REFERENCES roadmap_profiles(id) ON DELETE CASCADE,
    task_id VARCHAR(100) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'not_started',
    phase INTEGER DEFAULT 1,
    priority_order INTEGER,
    source VARCHAR(50),
    source_reference_id INTEGER,
    source_details TEXT,
    finding_type VARCHAR(100),
    finding_severity VARCHAR(20),
    scan_domain VARCHAR(255),
    scan_date DATETIME,
    matched_threat_actor VARCHAR(255),
    threat_actor_ttp TEXT,
    assigned_to_user_id INTEGER REFERENCES users(id),
    started_at DATETIME,
    completed_at DATETIME,
    verified_at DATETIME,
    last_reminded DATETIME,
    user_notes TEXT,
    admin_notes TEXT,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    deleted_at DATETIME,
    is_active BOOLEAN NOT NULL DEFAULT 1
);
```

### Why It Was Needed
- Security improvement roadmap tracking
- Integration with scan findings
- Gamification to encourage security improvements
- Progress tracking and reporting

### Backup Location
- `backend_backup_20260103_roadmap/`

### Test Results
- Profile creation and assessment working
- Task assignment and progress tracking functional
- Achievement system validated
- Progress history snapshots capturing correctly

---

## Phase 5: Security Features

**Date Completed:** January 2026
**Commit:** Add Security features

### What Was Added

| Table | Purpose |
|-------|---------|
| `api_keys` | API key management |
| `security_events` | Security event logging |
| Additional scan history tables | Scan result storage |

### Schema Changes

```sql
-- API Keys
CREATE TABLE api_keys (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_hash VARCHAR(255) NOT NULL UNIQUE,
    key_prefix VARCHAR(8) NOT NULL,
    name VARCHAR(100) NOT NULL,
    permissions TEXT,
    last_used_at DATETIME,
    last_used_ip VARCHAR(45),
    usage_count INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL,
    expires_at DATETIME,
    revoked_at DATETIME,
    is_active BOOLEAN NOT NULL DEFAULT 1
);

-- Security Events
CREATE TABLE security_events (
    id INTEGER PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    user_id INTEGER REFERENCES users(id),
    email VARCHAR(255),
    ip_address VARCHAR(45),
    user_agent TEXT,
    location VARCHAR(255),
    description TEXT NOT NULL,
    metadata_json TEXT,
    acknowledged BOOLEAN NOT NULL DEFAULT 0,
    acknowledged_by INTEGER REFERENCES users(id),
    acknowledged_at DATETIME,
    created_at DATETIME NOT NULL
);

-- Scan Result Tables
CREATE TABLE cached_asm_scans (
    id INTEGER PRIMARY KEY,
    domain VARCHAR(255) NOT NULL,
    scanned_at DATETIME,
    risk_score INTEGER DEFAULT 0,
    risk_level VARCHAR(20),
    total_cves INTEGER DEFAULT 0,
    critical_cves INTEGER DEFAULT 0,
    vulnerabilities_found INTEGER DEFAULT 0,
    open_ports_count INTEGER DEFAULT 0,
    scan_results JSON,
    user_id INTEGER REFERENCES users(id),
    updated_at DATETIME NOT NULL,
    deleted_at DATETIME,
    is_active BOOLEAN NOT NULL DEFAULT 1
);

CREATE TABLE xasm_scan_history (...);
CREATE TABLE lightbox_scan_history (...);
CREATE TABLE scan_results_xasm (...);
CREATE TABLE scan_results_lightbox (...);
```

### Why It Was Needed
- Secure API access for integrations
- Comprehensive security event logging
- Brute force detection
- Account lockout mechanisms
- Improved scan result storage and caching

### Backup Location
- `backend_backup_20260105_security/`

### Test Results
- API key creation and validation working
- Security event logging functional
- Brute force detection tested
- Account lock/unlock working

---

## Phase 6: Reliability Improvements

**Date Completed:** January 2026
**Commit:** Reliability improvements

### What Was Changed

No new tables added. Focused on:

1. **Standard Column Patterns**
   - Added `user_id`, `deleted_at`, `is_active`, `updated_at` to all tables
   - Consistent soft delete support

2. **Error Handling**
   - Added `DatabaseError`, `ValidationError`, `DatabaseConnectionError`, `TransactionError` exceptions
   - Added `@handle_db_error` decorator
   - Added `safe_db_session` context manager

3. **Health Check Functions**
   - `check_database_connection()`
   - `check_table_integrity()`
   - `check_foreign_key_constraints()`
   - `run_health_check()`

4. **Backup Functions**
   - `create_backup()`
   - `restore_backup()`
   - `list_backups()`
   - `get_backup_info()`

5. **Performance Monitoring**
   - `log_query_performance()`
   - `get_performance_stats()`
   - `get_slow_queries()`
   - `optimize_database()`

6. **Data Validation**
   - `validate_email()`
   - `validate_domain()`
   - `validate_ip_address()`
   - `sanitize_input()`
   - `validate_record()`

7. **Transaction Helpers**
   - `@atomic_operation` decorator
   - `batch_insert()`
   - `safe_update()`

8. **Migration Helpers**
   - `get_schema_version()`
   - `get_applied_migrations()`
   - `apply_migration()`
   - `rollback_migration()`

### Migration Script

```python
# Add standard columns to existing tables
migration_sql = """
-- Add user_id to tables missing it
ALTER TABLE lightbox_findings ADD COLUMN user_id INTEGER REFERENCES users(id);
ALTER TABLE asm_scans ADD COLUMN user_id INTEGER REFERENCES users(id);

-- Add soft delete columns
ALTER TABLE lightbox_findings ADD COLUMN deleted_at DATETIME;
ALTER TABLE lightbox_findings ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT 1;

-- Add updated_at columns
ALTER TABLE lightbox_findings ADD COLUMN updated_at DATETIME;

-- Create indexes for soft delete columns
CREATE INDEX idx_users_deleted_at ON users(deleted_at);
CREATE INDEX idx_companies_deleted_at ON companies(deleted_at);
-- ... etc for all tables
"""
```

### Why It Was Needed
- Production-ready reliability requirements
- Consistent soft delete pattern across all tables
- Comprehensive health monitoring
- Safe backup/restore procedures
- Better error handling

### Backup Location
- `backend_backup_20260106_140328/`

### Test Results
- Health checks passing
- Backup/restore cycle tested
- Performance monitoring functional
- Validation functions working correctly

---

## Phase 7: PostgreSQL Prep (TODO)

**Status:** Not Started
**Target Date:** TBD

### Planned Changes

1. **SQLAlchemy Compatibility**
   - Replace SQLite-specific code with portable alternatives
   - Update JSON column handling for PostgreSQL JSONB

2. **Connection Handling**
   - Add connection pooling support (pgbouncer)
   - Implement connection retry logic

3. **Health Checks**
   - Replace `sqlite3` direct connections with SQLAlchemy
   - Add PostgreSQL-specific health metrics

4. **Backup/Restore**
   - Replace SQLite backup API with `pg_dump`/`pg_restore`
   - Add streaming backup support

5. **Performance**
   - Add GIN indexes for JSONB columns
   - Implement partial indexes for `deleted_at IS NULL`
   - Configure autovacuum settings

6. **Data Types**
   - `DateTime` → `TIMESTAMP WITH TIME ZONE`
   - `JSON` → `JSONB`
   - Add proper `ENUM` types

### Pre-Migration Checklist

- [ ] Audit all raw SQL queries
- [ ] Test with PostgreSQL in development
- [ ] Create data migration scripts
- [ ] Set up PostgreSQL backup infrastructure
- [ ] Configure read replicas (if needed)
- [ ] Update deployment documentation

---

## Phase 8: Documentation

**Date Completed:** January 2026
**Commit:** Comprehensive documentation

### What Was Done

1. **Created Documentation Files**
   - `DATABASE_SCHEMA.md` - All 40 tables documented
   - `DATABASE_API.md` - All functions documented
   - `DATABASE_MIGRATIONS.md` - This file
   - `DATABASE_MAINTENANCE.md` - Maintenance procedures
   - `README_DATABASE.md` - Overview and quick start

2. **Added Inline Documentation**
   - Google-style docstrings for all functions
   - Type hints where missing
   - Comments for complex logic
   - TODO markers for Phase 7

### Why It Was Needed
- Developer onboarding
- API reference
- Maintenance procedures
- Change tracking

---

## Migration Best Practices

### Before Any Migration

1. **Create Backup**
   ```python
   from database import create_backup
   backup = create_backup()
   print(f"Backup at: {backup['backup_path']}")
   ```

2. **Run Health Check**
   ```python
   from database import run_health_check
   health = run_health_check()
   assert health['connection']['healthy']
   assert health['tables']['healthy']
   ```

3. **Document Current State**
   ```python
   from database import get_database_stats
   stats = get_database_stats()
   print(f"Tables: {len(stats['table_counts'])}")
   print(f"Records: {stats['total_records']}")
   ```

### During Migration

1. **Use the Migration Helper**
   ```python
   from database import apply_migration

   result = apply_migration(
       migration_sql="ALTER TABLE users ADD COLUMN new_field VARCHAR(100);",
       version="1.2.0",
       description="Add new_field to users"
   )

   if not result['success']:
       print(f"Migration failed: {result['error']}")
   ```

2. **Test Incrementally**
   - Apply one change at a time
   - Verify each change before proceeding
   - Keep migration SQL in version control

### After Migration

1. **Verify Health**
   ```python
   health = run_health_check()
   assert health['tables']['healthy']
   assert health['foreign_keys']['healthy']
   ```

2. **Run Application Tests**
   - All unit tests should pass
   - Integration tests should pass
   - Manual smoke testing

3. **Update Documentation**
   - Update `DATABASE_SCHEMA.md`
   - Update `DATABASE_MIGRATIONS.md`
   - Update version in `database.py`

---

## Rollback Procedures

### Automatic Rollback (During Migration)

If a migration fails, changes are automatically rolled back within the transaction.

### Manual Rollback (After Migration)

1. **Restore from Backup**
   ```python
   from database import restore_backup

   result = restore_backup(
       backup_path="/path/to/backup.db",
       confirm=True  # Required safety flag
   )
   ```

2. **Mark Migration as Rolled Back**
   ```python
   from database import rollback_migration

   rollback_migration("1.2.0")
   ```

### Emergency Rollback

If the application is in a broken state:

1. Stop the application
2. Locate the pre-migration backup in `data/backups/`
3. Replace the database file:
   ```bash
   cp data/backups/nerve_backup_YYYYMMDD_HHMMSS.db data/ghost.db
   ```
4. Restart the application
5. Verify functionality

---

## Schema Migrations Table

The `schema_migrations` table tracks applied migrations:

```sql
CREATE TABLE schema_migrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

Query current state:
```python
from database import get_applied_migrations

migrations = get_applied_migrations()
for m in migrations:
    print(f"{m['version']} - {m['applied_at']}")
```

---

*Last updated: January 2026*
