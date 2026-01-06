# NERVE Database Documentation

> Central reference for all NERVE database documentation.

---

## Quick Links

| Document | Description |
|----------|-------------|
| [DATABASE_SCHEMA.md](DATABASE_SCHEMA.md) | Complete schema reference for all 40 tables |
| [DATABASE_API.md](DATABASE_API.md) | Function reference and usage examples |
| [DATABASE_MIGRATIONS.md](DATABASE_MIGRATIONS.md) | Migration history and procedures |
| [DATABASE_MAINTENANCE.md](DATABASE_MAINTENANCE.md) | Maintenance and troubleshooting guide |

---

## Architecture Overview

```
                    ┌─────────────────────────────────────┐
                    │           NERVE Backend             │
                    │         (FastAPI/Python)            │
                    └──────────────┬──────────────────────┘
                                   │
                    ┌──────────────▼──────────────────────┐
                    │          database.py                │
                    │   - SQLAlchemy ORM Models           │
                    │   - Authentication Functions        │
                    │   - Session Management              │
                    │   - Health Checks                   │
                    │   - Backup/Restore                  │
                    └──────────────┬──────────────────────┘
                                   │
                    ┌──────────────▼──────────────────────┐
                    │       SQLite Database               │
                    │       (data/ghost.db)               │
                    │                                     │
                    │   Future: PostgreSQL                │
                    └─────────────────────────────────────┘
```

### Module Organization

```
backend/
├── database.py              # Main database module
├── data/
│   ├── ghost.db            # SQLite database file
│   └── backups/            # Database backups
├── DATABASE_SCHEMA.md      # Schema documentation
├── DATABASE_API.md         # API documentation
├── DATABASE_MIGRATIONS.md  # Migration history
├── DATABASE_MAINTENANCE.md # Maintenance guide
└── README_DATABASE.md      # This file
```

---

## Quick Start

### Import the Database Module

```python
from database import (
    # Core
    init_db, get_db, SessionLocal, Base,

    # Models
    User, Company, Session, APIKey,

    # Authentication
    hash_password, verify_password,
    create_session, validate_session,
    create_api_key, validate_api_key,

    # Security
    log_security_event, detect_brute_force,

    # Health
    run_health_check, get_database_stats,

    # Backup
    create_backup, restore_backup
)
```

### Basic Usage

```python
from database import SessionLocal, User, hash_password

# Create a user
session = SessionLocal()
user = User(
    email="user@example.com",
    password_hash=hash_password("secure_password"),
    role=UserRole.ANALYST,
    status=UserStatus.ACTIVE
)
session.add(user)
session.commit()
session.close()
```

### Using the Safe Session Context Manager

```python
from database import safe_db_session, User

with safe_db_session() as session:
    user = session.query(User).filter_by(email="user@example.com").first()
    user.full_name = "Updated Name"
    # Auto-commits on success, auto-rollbacks on exception
```

---

## Table Summary

| Module | Tables | Purpose |
|--------|--------|---------|
| **Core** | `users`, `companies`, `sessions`, `audit_logs`, `password_history`, `login_attempts` | Authentication and audit |
| **Security** | `api_keys`, `security_events` | API access and security monitoring |
| **Ghost Search** | `ghost_search_queries`, `monitored_emails`, `monitored_email_findings`, `uploaded_breach_files`, `breach_file_results` | Credential monitoring |
| **OSINT** | `profiles`, `social_media`, `breaches`, `devices`, `github_findings`, `pastebin_findings`, `opsych_search_results` | OSINT data storage |
| **Attack Surface** | `asm_scans`, `cached_asm_scans`, `lightbox_findings`, `lightbox_scans`, `xasm_scan_history`, `lightbox_scan_history`, `scan_results_xasm`, `scan_results_lightbox` | Vulnerability scanning |
| **Compliance** | `compliance_assessments`, `compliance_controls`, `compliance_evidence`, `vulnerability_reports` | Compliance tracking |
| **Roadmap** | `roadmap_profiles`, `roadmap_tasks`, `roadmap_user_tasks`, `roadmap_achievements`, `roadmap_progress_history`, `roadmap_task_library_meta` | Security improvement tracking |
| **BAIT** | `bait_tokens`, `bait_accesses` | Honeypot tokens |
| **Files** | `uploaded_files`, `uploaded_credentials` | File uploads |

**Total: ~40 tables**

---

## Common Operations

### Authentication

```python
from database import (
    hash_password, verify_password,
    create_session, validate_session, revoke_session
)

# Hash a password
hashed = hash_password("my_password")

# Verify a password
is_valid = verify_password("my_password", hashed)

# Create a session
session_data = create_session(
    user_id=1,
    ip_address="192.168.1.1",
    user_agent="Mozilla/5.0..."
)
token = session_data['token']

# Validate a session
info = validate_session(token)
if info:
    user_id = info['user_id']

# Revoke a session (logout)
revoke_session(token)
```

### API Keys

```python
from database import create_api_key, validate_api_key, revoke_api_key

# Create an API key
result = create_api_key(
    user_id=1,
    name="CI/CD Pipeline",
    permissions=["scan:read", "scan:write"]
)
api_key = result['key']  # Only shown once!

# Validate an API key
info = validate_api_key(api_key)
if info:
    print(f"User: {info['user_id']}")

# Revoke an API key
revoke_api_key(key_id=5)
```

### Health Checks

```python
from database import run_health_check

health = run_health_check()
print(f"Connection: {'OK' if health['connection']['healthy'] else 'FAILED'}")
print(f"Tables: {'OK' if health['tables']['healthy'] else 'FAILED'}")
print(f"Size: {health['stats']['size_mb']} MB")
```

### Backups

```python
from database import create_backup, restore_backup, list_backups

# Create backup
result = create_backup()
print(f"Backup: {result['backup_path']}")

# List backups
for backup in list_backups():
    print(f"{backup['filename']} - {backup['created']}")

# Restore (requires confirm=True)
restore_backup("/path/to/backup.db", confirm=True)
```

---

## Standard Patterns

All tables follow these consistent patterns:

### Soft Delete

```python
# Records are never physically deleted
deleted_at = Column(DateTime, index=True)  # NULL = not deleted
is_active = Column(Boolean, default=True)

# Query only active records
session.query(User).filter(User.deleted_at.is_(None)).all()
```

### User Tracking

```python
# All records track their owner
user_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'))

# Query records for a user
session.query(Profile).filter_by(user_id=current_user.id).all()
```

### Timestamps

```python
created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
updated_at = Column(DateTime, onupdate=lambda: datetime.now(timezone.utc))
```

---

## Error Handling

```python
from database import DatabaseError, ValidationError, safe_db_session

try:
    with safe_db_session() as session:
        # Your operations
        pass
except DatabaseError as e:
    print(f"Database error: {e}")
except ValidationError as e:
    print(f"Validation error: {e}")
```

---

## Development Phases

| Phase | Status | Description |
|-------|--------|-------------|
| 1 | Complete | Initial schema |
| 2 | Complete | Ghost Search tables |
| 3 | Complete | Compliance tables |
| 4 | Complete | Roadmap tables |
| 5 | Complete | Security features |
| 6 | Complete | Reliability improvements |
| **7** | **TODO** | **PostgreSQL migration** |
| 8 | Complete | Documentation |

See [DATABASE_MIGRATIONS.md](DATABASE_MIGRATIONS.md) for details.

---

## Phase 7 TODO: PostgreSQL Migration

The following items need to be addressed before migrating to PostgreSQL:

- [ ] Replace SQLite-specific code with portable SQLAlchemy
- [ ] Update JSON columns to use JSONB
- [ ] Replace direct sqlite3 connections with SQLAlchemy
- [ ] Update backup/restore to use pg_dump/pg_restore
- [ ] Add connection pooling (pgbouncer)
- [ ] Update health checks for PostgreSQL
- [ ] Add GIN indexes for JSONB columns
- [ ] Test all functions with PostgreSQL
- [ ] Update deployment documentation

---

## Support

- **Documentation Issues:** Update the relevant `.md` file
- **Code Issues:** Check `database.py` docstrings
- **Bugs:** Create an issue in the project repository

---

*Last Updated: January 2026*
