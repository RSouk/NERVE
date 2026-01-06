# NERVE Database API Reference

> Complete documentation of all database functions in the NERVE security platform.

**Version:** 1.0.0
**Last Updated:** January 2026
**Location:** `backend/database.py`

---

## Table of Contents

1. [Overview](#overview)
2. [Core Database Functions](#core-database-functions)
3. [Password Hashing](#password-hashing)
4. [Session Management](#session-management)
5. [API Key Management](#api-key-management)
6. [Security Audit Functions](#security-audit-functions)
7. [Scan Storage Functions](#scan-storage-functions)
8. [Error Handling](#error-handling)
9. [Database Health Checks](#database-health-checks)
10. [Data Validation](#data-validation)
11. [Transaction Helpers](#transaction-helpers)
12. [Backup & Restore](#backup--restore)
13. [Performance Monitoring](#performance-monitoring)
14. [Migration Helpers](#migration-helpers)
15. [Utility Functions](#utility-functions)

---

## Overview

The database API provides functions for:
- Authentication and session management
- Security auditing and event logging
- Scan data storage and retrieval
- Database health monitoring
- Backup and restore operations
- Data validation and sanitization

### Quick Start

```python
from database import (
    init_db, get_db, SessionLocal,
    hash_password, verify_password,
    create_session, validate_session,
    create_api_key, validate_api_key,
    run_health_check, create_backup
)

# Initialize database
init_db()

# Get a database session
session = SessionLocal()

# Use context manager for safe operations
from database import safe_db_session
with safe_db_session() as session:
    # Your database operations here
    pass
```

---

## Core Database Functions

### init_db()

Initialize the database and create all tables.

```python
def init_db() -> None
```

**Usage:**
```python
from database import init_db
init_db()
# Output: Database initialized at: /path/to/ghost.db
```

**Notes:**
- Called automatically on module import
- Safe to call multiple times (idempotent)
- Creates all SQLAlchemy model tables

---

### get_db()

Get a database session.

```python
def get_db() -> Session
```

**Returns:**
- SQLAlchemy session object

**Usage:**
```python
from database import get_db
session = get_db()
# Use session for queries
```

**Warning:** Remember to close sessions when done.

---

### SessionLocal

Session factory for creating database sessions.

```python
SessionLocal = sessionmaker(bind=engine)
```

**Usage:**
```python
from database import SessionLocal
session = SessionLocal()
try:
    # operations
    session.commit()
finally:
    session.close()
```

---

## Password Hashing

### hash_password()

Hash a password using bcrypt (or fallback to PBKDF2).

```python
def hash_password(plain_password: str) -> str
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `plain_password` | str | The plaintext password to hash |

**Returns:**
- Hashed password string (bcrypt or PBKDF2 format)

**Example:**
```python
from database import hash_password

hashed = hash_password("my_secure_password")
# Returns: "$2b$12$..." (bcrypt) or "pbkdf2$..." (fallback)
```

**Notes:**
- Uses bcrypt with 12 rounds if available
- Falls back to PBKDF2-SHA256 with 100,000 iterations
- Salt is automatically generated and embedded in hash

---

### verify_password()

Verify a password against its hash.

```python
def verify_password(plain_password: str, hashed_password: str) -> bool
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `plain_password` | str | The plaintext password to verify |
| `hashed_password` | str | The stored hash to compare against |

**Returns:**
- `True` if password matches, `False` otherwise

**Example:**
```python
from database import verify_password, hash_password

hashed = hash_password("my_password")
is_valid = verify_password("my_password", hashed)  # True
is_valid = verify_password("wrong_password", hashed)  # False
```

**Security:**
- Uses constant-time comparison to prevent timing attacks
- Handles both bcrypt and PBKDF2 formats automatically

---

### generate_secure_token()

Generate a cryptographically secure random token.

```python
def generate_secure_token(length: int = 32) -> str
```

**Parameters:**
| Name | Type | Default | Description |
|------|------|---------|-------------|
| `length` | int | 32 | Token length in bytes |

**Returns:**
- URL-safe base64-encoded token string

**Example:**
```python
from database import generate_secure_token

token = generate_secure_token()  # 43 character string
short_token = generate_secure_token(16)  # shorter token
```

---

## Session Management

### create_session()

Create a new session for a user.

```python
def create_session(
    user_id: int,
    ip_address: str,
    user_agent: str = None,
    device_type: str = 'web',
    expires_hours: int = 24
) -> dict
```

**Parameters:**
| Name | Type | Default | Description |
|------|------|---------|-------------|
| `user_id` | int | required | The user's ID |
| `ip_address` | str | required | Client IP address |
| `user_agent` | str | None | Client user agent string |
| `device_type` | str | 'web' | Device type (web, mobile, api) |
| `expires_hours` | int | 24 | Session expiry in hours |

**Returns:**
```python
{
    'session_id': int,
    'token': str,
    'refresh_token': str,
    'expires_at': str  # ISO format
}
```

**Example:**
```python
from database import create_session

result = create_session(
    user_id=1,
    ip_address="192.168.1.1",
    user_agent="Mozilla/5.0...",
    device_type="web",
    expires_hours=24
)

print(f"Token: {result['token']}")
```

**Notes:**
- Updates user's `last_login_at` and `last_login_ip`
- Returns `None` if creation fails

---

### validate_session()

Validate a session token and return session info.

```python
def validate_session(token: str, update_activity: bool = True) -> dict
```

**Parameters:**
| Name | Type | Default | Description |
|------|------|---------|-------------|
| `token` | str | required | The session token to validate |
| `update_activity` | bool | True | Whether to update last_activity |

**Returns:**
```python
{
    'session_id': int,
    'user_id': int,
    'device_type': str,
    'created_at': str,
    'expires_at': str,
    'last_activity': str
}
```

Returns `None` if session is invalid, expired, or revoked.

**Example:**
```python
from database import validate_session

session_info = validate_session("token_string")
if session_info:
    print(f"User ID: {session_info['user_id']}")
else:
    print("Invalid session")
```

---

### revoke_session()

Revoke a session by token.

```python
def revoke_session(token: str) -> bool
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `token` | str | The session token to revoke |

**Returns:**
- `True` if revoked successfully, `False` otherwise

**Example:**
```python
from database import revoke_session

success = revoke_session("token_to_revoke")
```

---

### revoke_all_user_sessions()

Revoke all sessions for a user (optionally except current).

```python
def revoke_all_user_sessions(user_id: int, except_token: str = None) -> int
```

**Parameters:**
| Name | Type | Default | Description |
|------|------|---------|-------------|
| `user_id` | int | required | User's ID |
| `except_token` | str | None | Token to exclude from revocation |

**Returns:**
- Number of sessions revoked

**Example:**
```python
from database import revoke_all_user_sessions

# Revoke all sessions
count = revoke_all_user_sessions(user_id=1)

# Revoke all except current session
count = revoke_all_user_sessions(user_id=1, except_token="current_token")
```

---

### cleanup_expired_sessions()

Clean up all expired sessions.

```python
def cleanup_expired_sessions() -> int
```

**Returns:**
- Number of sessions cleaned up

**Example:**
```python
from database import cleanup_expired_sessions

cleaned = cleanup_expired_sessions()
print(f"Cleaned up {cleaned} expired sessions")
```

---

## API Key Management

### create_api_key()

Create a new API key for a user.

```python
def create_api_key(
    user_id: int,
    name: str,
    permissions: list = None,
    expires_days: int = None
) -> dict
```

**Parameters:**
| Name | Type | Default | Description |
|------|------|---------|-------------|
| `user_id` | int | required | The user's ID |
| `name` | str | required | User-friendly name for the key |
| `permissions` | list | None | List of allowed actions/endpoints |
| `expires_days` | int | None | Optional expiry in days |

**Returns:**
```python
{
    'key': str,        # Full key - ONLY RETURNED ONCE!
    'key_id': int,
    'key_prefix': str,  # e.g., "nrv_xxxxxxxx"
    'name': str,
    'expires_at': str   # ISO format or None
}
```

**Example:**
```python
from database import create_api_key

result = create_api_key(
    user_id=1,
    name="CI/CD Pipeline",
    permissions=["scan:read", "scan:write"],
    expires_days=90
)

# IMPORTANT: Store the key securely - it's only shown once!
print(f"API Key: {result['key']}")
```

**Security:**
- The full key is only returned once at creation
- Keys are stored as SHA256 hashes
- Logs a security event on creation

---

### validate_api_key()

Validate an API key and return user info.

```python
def validate_api_key(raw_key: str) -> dict
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `raw_key` | str | The full API key string |

**Returns:**
```python
{
    'key_id': int,
    'user_id': int,
    'name': str,
    'permissions': list
}
```

Returns `None` if key is invalid, expired, or revoked.

**Example:**
```python
from database import validate_api_key

info = validate_api_key("nrv_abc123xyz789...")
if info:
    print(f"Valid key for user {info['user_id']}")
    print(f"Permissions: {info['permissions']}")
```

**Notes:**
- Updates `last_used_at` and `usage_count` on successful validation

---

### revoke_api_key()

Revoke an API key.

```python
def revoke_api_key(key_id: int, user_id: int = None) -> bool
```

**Parameters:**
| Name | Type | Default | Description |
|------|------|---------|-------------|
| `key_id` | int | required | The API key ID |
| `user_id` | int | None | Optional user ID for authorization check |

**Returns:**
- `True` if revoked, `False` otherwise

**Example:**
```python
from database import revoke_api_key

success = revoke_api_key(key_id=5, user_id=1)
```

---

### list_user_api_keys()

List all API keys for a user (without exposing actual keys).

```python
def list_user_api_keys(user_id: int) -> list
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `user_id` | int | The user's ID |

**Returns:**
```python
[
    {
        'key_id': int,
        'key_prefix': str,  # e.g., "nrv_xxxxxxxx"
        'name': str,
        'last_used_at': str,
        'usage_count': int,
        'created_at': str,
        'expires_at': str
    },
    ...
]
```

**Example:**
```python
from database import list_user_api_keys

keys = list_user_api_keys(user_id=1)
for key in keys:
    print(f"{key['name']}: {key['key_prefix']}... (used {key['usage_count']} times)")
```

---

## Security Audit Functions

### log_login_attempt()

Log a login attempt.

```python
def log_login_attempt(
    email: str,
    success: bool,
    ip_address: str,
    user_agent: str = None,
    failure_reason: str = None,
    user_id: int = None
) -> bool
```

**Parameters:**
| Name | Type | Default | Description |
|------|------|---------|-------------|
| `email` | str | required | Email attempted |
| `success` | bool | required | Whether login succeeded |
| `ip_address` | str | required | Client IP |
| `user_agent` | str | None | Client user agent |
| `failure_reason` | str | None | Reason for failure |
| `user_id` | int | None | User ID if known |

**Returns:**
- `True` if logged successfully

**Example:**
```python
from database import log_login_attempt

# Failed login
log_login_attempt(
    email="user@example.com",
    success=False,
    ip_address="192.168.1.1",
    failure_reason="invalid_password"
)

# Successful login
log_login_attempt(
    email="user@example.com",
    success=True,
    ip_address="192.168.1.1",
    user_id=1
)
```

---

### detect_brute_force()

Detect brute force login attempts.

```python
def detect_brute_force(
    email: str = None,
    ip_address: str = None,
    window_minutes: int = 15,
    threshold: int = 5
) -> dict
```

**Parameters:**
| Name | Type | Default | Description |
|------|------|---------|-------------|
| `email` | str | None | Email to check |
| `ip_address` | str | None | IP to check |
| `window_minutes` | int | 15 | Time window to check |
| `threshold` | int | 5 | Failures to trigger detection |

**Returns:**
```python
{
    'detected': bool,
    'email_attempts': int,
    'ip_attempts': int,
    'should_lock': bool
}
```

**Example:**
```python
from database import detect_brute_force

result = detect_brute_force(
    email="user@example.com",
    ip_address="192.168.1.1"
)

if result['detected']:
    print(f"Brute force detected!")
    if result['should_lock']:
        # Lock the account
        pass
```

---

### lock_user_account()

Lock a user account temporarily.

```python
def lock_user_account(
    user_id: int,
    lock_minutes: int = 30,
    reason: str = 'Too many failed login attempts'
) -> bool
```

**Parameters:**
| Name | Type | Default | Description |
|------|------|---------|-------------|
| `user_id` | int | required | User's ID |
| `lock_minutes` | int | 30 | Lock duration in minutes |
| `reason` | str | 'Too many failed login attempts' | Lock reason |

**Returns:**
- `True` if locked successfully

---

### check_account_lock()

Check if a user account is locked.

```python
def check_account_lock(user_id: int) -> dict
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `user_id` | int | User's ID |

**Returns:**
```python
{
    'locked': bool,
    'exists': bool,
    'locked_until': str,  # ISO format, if locked
    'remaining_minutes': int  # if locked
}
```

---

### log_security_event()

Log a security event.

```python
def log_security_event(
    event_type: str,
    severity: str,
    description: str,
    user_id: int = None,
    email: str = None,
    ip_address: str = None,
    user_agent: str = None,
    metadata: dict = None
) -> bool
```

**Parameters:**
| Name | Type | Default | Description |
|------|------|---------|-------------|
| `event_type` | str | required | Type of security event |
| `severity` | str | required | Severity (info, low, medium, high, critical) |
| `description` | str | required | Human-readable description |
| `user_id` | int | None | Related user ID |
| `email` | str | None | Related email |
| `ip_address` | str | None | Client IP |
| `user_agent` | str | None | Client user agent |
| `metadata` | dict | None | Additional context |

**Event Types:**
- `login_failed`, `login_success`
- `brute_force_detected`
- `session_revoked`
- `password_changed`
- `2fa_enabled`, `2fa_disabled`
- `api_key_created`, `api_key_revoked`
- `suspicious_activity`
- `account_locked`

**Example:**
```python
from database import log_security_event

log_security_event(
    event_type='suspicious_activity',
    severity='high',
    description='Multiple failed 2FA attempts',
    user_id=1,
    ip_address="192.168.1.1",
    metadata={'attempts': 5, 'time_window': '5 minutes'}
)
```

---

### get_security_events()

Get security events with filters.

```python
def get_security_events(
    user_id: int = None,
    event_type: str = None,
    severity: str = None,
    hours: int = 24,
    limit: int = 100
) -> list
```

**Returns:** List of security event dictionaries.

---

### get_failed_logins_by_ip()

Get failed login attempts from a specific IP.

```python
def get_failed_logins_by_ip(ip_address: str, hours: int = 24) -> list
```

---

### increment_failed_login_count()

Increment failed login count for a user.

```python
def increment_failed_login_count(user_id: int) -> int
```

**Returns:** New failed login count.

---

### reset_failed_login_count()

Reset failed login count after successful login.

```python
def reset_failed_login_count(user_id: int) -> bool
```

---

## Scan Storage Functions

### save_xasm_scan()

Save XASM scan to history.

```python
def save_xasm_scan(scan_id: str, target: str, results: dict, user_id: int = None) -> None
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `scan_id` | str | Unique scan identifier |
| `target` | str | Scan target domain |
| `results` | dict | Full scan results |
| `user_id` | int | Optional owner user ID |

---

### save_lightbox_scan()

Save Lightbox scan to history.

```python
def save_lightbox_scan(scan_id: str, target: str, results: dict, user_id: int = None) -> None
```

---

### get_xasm_scan_history()

Get XASM scan history (last 30 days).

```python
def get_xasm_scan_history(user_id: int = None, limit: int = 30) -> list
```

**Returns:** List of scan history dictionaries.

---

### get_lightbox_scan_history()

Get Lightbox scan history (last 30 days).

```python
def get_lightbox_scan_history(user_id: int = None, limit: int = 30) -> list
```

---

### get_xasm_scan_by_id()

Get full XASM scan results by ID.

```python
def get_xasm_scan_by_id(scan_id: str) -> dict
```

**Returns:**
```python
{
    'target': str,
    'results': dict,
    'timestamp': str,
    'scan_id': str
}
```

---

### get_lightbox_scan_by_id()

Get full Lightbox scan results by ID.

```python
def get_lightbox_scan_by_id(scan_id: str) -> dict
```

---

### delete_xasm_scan()

Delete XASM scan from history.

```python
def delete_xasm_scan(scan_id: str) -> bool
```

---

### delete_lightbox_scan_history()

Delete Lightbox scan from history.

```python
def delete_lightbox_scan_history(scan_id: str) -> bool
```

---

### cleanup_old_scan_history()

Delete scan history older than specified days.

```python
def cleanup_old_scan_history(days: int = 30) -> None
```

---

### save_xasm_for_ai()

Save XASM results for AI report generation (48h expiry).

```python
def save_xasm_for_ai(company: str, results: dict) -> bool
```

---

### save_lightbox_for_ai()

Save Lightbox results for AI report generation (48h expiry).

```python
def save_lightbox_for_ai(company: str, results: dict) -> bool
```

---

### load_xasm_for_ai()

Load XASM results for AI report.

```python
def load_xasm_for_ai(company: str) -> dict
```

---

### load_lightbox_for_ai()

Load Lightbox results for AI report.

```python
def load_lightbox_for_ai(company: str) -> dict
```

---

### get_companies_with_scans()

Get list of domains with available scans for AI reports.

```python
def get_companies_with_scans() -> list
```

**Returns:**
```python
[
    {
        'company': str,
        'has_xasm': bool,
        'has_lightbox': bool,
        'xasm_date': str,
        'lightbox_date': str
    },
    ...
]
```

---

### cleanup_expired_ai_scans()

Delete all expired scan results.

```python
def cleanup_expired_ai_scans() -> None
```

---

## Error Handling

### Exception Classes

```python
class DatabaseError(Exception):
    """Base exception for database errors"""

class ValidationError(DatabaseError):
    """Raised when data validation fails"""

class DatabaseConnectionError(DatabaseError):
    """Raised when database connection fails"""

class TransactionError(DatabaseError):
    """Raised when a transaction fails"""
```

### handle_db_error

Decorator to handle database errors consistently.

```python
@handle_db_error
def my_db_function():
    # Database operations
    pass
```

**Example:**
```python
from database import handle_db_error

@handle_db_error
def get_user_by_email(email):
    session = SessionLocal()
    return session.query(User).filter_by(email=email).first()
```

---

### safe_db_session

Context manager for safe database sessions with auto-rollback.

```python
from database import safe_db_session

with safe_db_session() as session:
    user = session.query(User).filter_by(id=1).first()
    user.name = "New Name"
    # Auto-commits on success, auto-rollbacks on exception
```

---

### log_db_operation()

Log database operation for auditing.

```python
def log_db_operation(
    operation: str,
    table: str,
    record_id: int = None,
    details: dict = None
) -> dict
```

---

## Database Health Checks

### check_database_connection()

Check if database connection is healthy.

```python
def check_database_connection() -> dict
```

**Returns:**
```python
{
    'healthy': bool,
    'latency_ms': float,
    'error': str  # if unhealthy
}
```

---

### check_table_integrity()

Check integrity of all tables.

```python
def check_table_integrity() -> dict
```

**Returns:**
```python
{
    'tables_checked': int,
    'errors': list,
    'healthy': bool
}
```

---

### check_foreign_key_constraints()

Check foreign key constraint violations.

```python
def check_foreign_key_constraints() -> dict
```

**Returns:**
```python
{
    'violations': list,
    'healthy': bool
}
```

---

### get_database_stats()

Get database statistics.

```python
def get_database_stats() -> dict
```

**Returns:**
```python
{
    'size_bytes': int,
    'size_mb': float,
    'table_counts': dict,
    'total_records': int
}
```

---

### run_health_check()

Run comprehensive health check on database.

```python
def run_health_check() -> dict
```

**Returns:**
```python
{
    'timestamp': str,
    'connection': dict,
    'tables': dict,
    'foreign_keys': dict,
    'stats': dict,
    'performance': dict
}
```

**Example:**
```python
from database import run_health_check
import json

health = run_health_check()
print(json.dumps(health, indent=2))
```

---

## Data Validation

### validate_email()

Validate email format.

```python
def validate_email(email: str) -> bool
```

**Example:**
```python
from database import validate_email

validate_email("user@example.com")  # True
validate_email("invalid-email")     # False
```

---

### validate_domain()

Validate domain format.

```python
def validate_domain(domain: str) -> bool
```

---

### validate_ip_address()

Validate IPv4 address format.

```python
def validate_ip_address(ip: str) -> bool
```

---

### sanitize_input()

Sanitize string input.

```python
def sanitize_input(
    value: str,
    max_length: int = 255,
    allow_html: bool = False
) -> str
```

**Parameters:**
| Name | Type | Default | Description |
|------|------|---------|-------------|
| `value` | str | required | Input to sanitize |
| `max_length` | int | 255 | Maximum length |
| `allow_html` | bool | False | Allow HTML tags |

---

### validate_record()

Validate a record against rules.

```python
def validate_record(data: dict, rules: dict) -> dict
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `data` | dict | Field values to validate |
| `rules` | dict | Validation rules |

**Rules Format:**
```python
rules = {
    'email': {'type': 'email', 'required': True},
    'domain': {'type': 'domain', 'required': False},
    'name': {'type': 'string', 'max_length': 100}
}
```

**Returns:**
```python
{
    'valid': bool,
    'errors': list
}
```

**Example:**
```python
from database import validate_record

result = validate_record(
    data={'email': 'invalid', 'name': 'John'},
    rules={
        'email': {'type': 'email', 'required': True},
        'name': {'type': 'string', 'max_length': 50}
    }
)

if not result['valid']:
    print(f"Errors: {result['errors']}")
```

---

## Transaction Helpers

### atomic_operation

Decorator for atomic database operations.

```python
@atomic_operation
def my_operation(session, arg1, arg2):
    # Operations are committed on success
    # Rolled back on exception
    pass
```

---

### batch_insert()

Insert records in batches for better performance.

```python
def batch_insert(
    model_class,
    records: list,
    batch_size: int = 100
) -> dict
```

**Parameters:**
| Name | Type | Default | Description |
|------|------|---------|-------------|
| `model_class` | class | required | SQLAlchemy model class |
| `records` | list | required | List of dictionaries |
| `batch_size` | int | 100 | Records per batch |

**Returns:**
```python
{
    'total': int,
    'inserted': int,
    'failed': int,
    'errors': list
}
```

**Example:**
```python
from database import batch_insert, User

records = [
    {'email': 'user1@example.com', 'password_hash': '...'},
    {'email': 'user2@example.com', 'password_hash': '...'},
    # ... thousands more
]

result = batch_insert(User, records, batch_size=100)
print(f"Inserted {result['inserted']} of {result['total']}")
```

---

### safe_update()

Safely update a record with validation and logging.

```python
def safe_update(
    model_class,
    record_id: int,
    updates: dict,
    user_id: int = None
) -> dict
```

**Returns:**
```python
{
    'success': bool,
    'record_id': int,
    'changes': dict,  # {field: {'old': v1, 'new': v2}}
    'error': str
}
```

---

## Backup & Restore

### create_backup()

Create a database backup.

```python
def create_backup(backup_dir: str = None) -> dict
```

**Parameters:**
| Name | Type | Default | Description |
|------|------|---------|-------------|
| `backup_dir` | str | data/backups | Directory for backup file |

**Returns:**
```python
{
    'success': bool,
    'backup_path': str,
    'size_bytes': int,
    'timestamp': str,
    'error': str
}
```

**Example:**
```python
from database import create_backup

result = create_backup()
if result['success']:
    print(f"Backup created: {result['backup_path']}")
```

---

### restore_backup()

Restore database from backup.

```python
def restore_backup(backup_path: str, confirm: bool = False) -> dict
```

**Parameters:**
| Name | Type | Default | Description |
|------|------|---------|-------------|
| `backup_path` | str | required | Path to backup file |
| `confirm` | bool | False | Must be True to proceed |

**Returns:**
```python
{
    'success': bool,
    'backup_path': str,
    'pre_restore_backup': str,  # Backup of current DB
    'error': str
}
```

**Example:**
```python
from database import restore_backup

# IMPORTANT: confirm=True is required as a safety measure
result = restore_backup(
    backup_path="/path/to/nerve_backup_20260106.db",
    confirm=True
)
```

---

### get_backup_info()

Get information about a backup file.

```python
def get_backup_info(backup_path: str) -> dict
```

**Returns:**
```python
{
    'path': str,
    'size_bytes': int,
    'size_mb': float,
    'created': str,
    'tables': dict  # table_name: record_count
}
```

---

### list_backups()

List available backups.

```python
def list_backups(backup_dir: str = None) -> list
```

**Returns:**
```python
[
    {
        'filename': str,
        'path': str,
        'size_bytes': int,
        'created': str
    },
    ...
]
```

---

## Performance Monitoring

### log_query_performance()

Log query performance for analysis.

```python
def log_query_performance(
    query: str,
    duration_ms: float,
    rows_affected: int = 0
) -> None
```

---

### get_performance_stats()

Get query performance statistics.

```python
def get_performance_stats() -> dict
```

**Returns:**
```python
{
    'total_queries': int,
    'avg_duration_ms': float,
    'max_duration_ms': float,
    'slow_queries': int,
    'recent_queries': list
}
```

---

### get_slow_queries()

Get queries that exceeded the threshold.

```python
def get_slow_queries(threshold_ms: float = 1000) -> list
```

---

### clear_performance_log()

Clear the performance log.

```python
def clear_performance_log() -> None
```

---

### optimize_database()

Run database optimization tasks.

```python
def optimize_database() -> dict
```

**Returns:**
```python
{
    'success': bool,
    'tasks_completed': list,  # ['analyze', 'vacuum', 'reindex']
    'error': str
}
```

**Example:**
```python
from database import optimize_database

result = optimize_database()
if result['success']:
    print(f"Completed: {result['tasks_completed']}")
```

---

## Migration Helpers

### get_schema_version()

Get current schema version.

```python
def get_schema_version() -> str
```

---

### set_schema_version()

Set schema version (internal use).

```python
def set_schema_version(version: str) -> None
```

---

### get_applied_migrations()

Get list of applied migrations.

```python
def get_applied_migrations() -> list
```

**Returns:**
```python
[
    {'version': str, 'applied_at': str},
    ...
]
```

---

### apply_migration()

Apply a SQL migration.

```python
def apply_migration(
    migration_sql: str,
    version: str,
    description: str = None
) -> dict
```

**Parameters:**
| Name | Type | Default | Description |
|------|------|---------|-------------|
| `migration_sql` | str | required | SQL statements |
| `version` | str | required | Version identifier |
| `description` | str | None | Optional description |

**Returns:**
```python
{
    'success': bool,
    'version': str,
    'error': str
}
```

**Example:**
```python
from database import apply_migration

result = apply_migration(
    migration_sql="""
        ALTER TABLE users ADD COLUMN phone VARCHAR(20);
        CREATE INDEX idx_users_phone ON users(phone);
    """,
    version="1.1.0",
    description="Add phone column to users"
)
```

---

### rollback_migration()

Mark a migration as rolled back (does not undo changes).

```python
def rollback_migration(version: str) -> dict
```

---

## Utility Functions

### export_schema()

Export current database schema as SQL.

```python
def export_schema() -> str
```

**Returns:** SQL string of all CREATE TABLE statements.

**Example:**
```python
from database import export_schema

schema = export_schema()
with open('schema_dump.sql', 'w') as f:
    f.write(schema)
```

---

## Global Variables

| Variable | Type | Description |
|----------|------|-------------|
| `DB_PATH` | str | Path to SQLite database file |
| `engine` | Engine | SQLAlchemy engine instance |
| `Base` | DeclarativeMeta | SQLAlchemy declarative base |
| `BCRYPT_AVAILABLE` | bool | Whether bcrypt is installed |

---

## TODO: Phase 7 - PostgreSQL Migration

Functions that need adaptation for PostgreSQL:

1. **Health Checks:** Replace `sqlite3` direct connections with SQLAlchemy
2. **Backup/Restore:** Use `pg_dump`/`pg_restore` instead of SQLite backup API
3. **Schema Export:** Use PostgreSQL-compatible syntax
4. **Performance Monitoring:** Add pg-specific metrics

---

*Last updated: January 2026*
