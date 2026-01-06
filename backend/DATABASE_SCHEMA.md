# NERVE Database Schema Reference

> Comprehensive documentation of all database tables in the NERVE security platform.

**Schema Version:** 1.0.0
**Last Updated:** January 2026
**Database Engine:** SQLite (PostgreSQL-ready)

---

## Table of Contents

1. [Overview](#overview)
2. [Core Tables](#core-tables)
   - [companies](#companies)
   - [users](#users)
   - [sessions](#sessions)
   - [audit_logs](#audit_logs)
   - [password_history](#password_history)
   - [login_attempts](#login_attempts)
3. [Security Tables](#security-tables)
   - [api_keys](#api_keys)
   - [security_events](#security_events)
4. [Ghost Search Tables](#ghost-search-tables)
   - [ghost_search_queries](#ghost_search_queries)
   - [monitored_emails](#monitored_emails)
   - [monitored_email_findings](#monitored_email_findings)
   - [uploaded_breach_files](#uploaded_breach_files)
   - [breach_file_results](#breach_file_results)
5. [OSINT Tables](#osint-tables)
   - [profiles](#profiles)
   - [social_media](#social_media)
   - [breaches](#breaches)
   - [devices](#devices)
   - [github_findings](#github_findings)
   - [pastebin_findings](#pastebin_findings)
   - [opsych_search_results](#opsych_search_results)
6. [Attack Surface (XASM/Lightbox) Tables](#attack-surface-tables)
   - [asm_scans](#asm_scans)
   - [cached_asm_scans](#cached_asm_scans)
   - [lightbox_findings](#lightbox_findings)
   - [lightbox_scans](#lightbox_scans)
   - [xasm_scan_history](#xasm_scan_history)
   - [lightbox_scan_history](#lightbox_scan_history)
   - [scan_results_xasm](#scan_results_xasm)
   - [scan_results_lightbox](#scan_results_lightbox)
7. [Compliance Tables](#compliance-tables)
   - [compliance_assessments](#compliance_assessments)
   - [compliance_controls](#compliance_controls)
   - [compliance_evidence](#compliance_evidence)
   - [vulnerability_reports](#vulnerability_reports)
8. [Roadmap Tables](#roadmap-tables)
   - [roadmap_profiles](#roadmap_profiles)
   - [roadmap_tasks](#roadmap_tasks)
   - [roadmap_user_tasks](#roadmap_user_tasks)
   - [roadmap_achievements](#roadmap_achievements)
   - [roadmap_progress_history](#roadmap_progress_history)
   - [roadmap_task_library_meta](#roadmap_task_library_meta)
9. [BAIT Tables](#bait-tables)
   - [bait_tokens](#bait_tokens)
   - [bait_accesses](#bait_accesses)
10. [File Upload Tables](#file-upload-tables)
    - [uploaded_files](#uploaded_files)
    - [uploaded_credentials](#uploaded_credentials)
11. [Standard Column Patterns](#standard-column-patterns)
12. [Indexes](#indexes)
13. [Foreign Key Relationships](#foreign-key-relationships)

---

## Overview

The NERVE database consists of approximately 40 tables organized into functional modules. All tables follow consistent patterns for:

- **Soft Deletes:** `deleted_at` timestamp instead of physical deletion
- **User Tracking:** `user_id` foreign key to track record ownership
- **Timestamps:** `created_at` and `updated_at` for audit trails
- **Active Flags:** `is_active` boolean for logical status

---

## Core Tables

### companies

Stores organization/company information for multi-tenant support.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PRIMARY KEY | Unique identifier |
| `name` | String(255) | NOT NULL | Company name |
| `primary_domain` | String(255) | UNIQUE, NOT NULL, INDEX | Primary company domain |
| `additional_domains` | Text | | JSON array of additional domains |
| `max_seats` | Integer | NOT NULL, DEFAULT 1 | Maximum user licenses |
| `max_domains` | Integer | NOT NULL, DEFAULT 1 | Maximum monitored domains |
| `subscription_tier` | String(20) | NOT NULL, DEFAULT 'basic' | Subscription level |
| `stripe_customer_id` | String(255) | | Stripe customer ID for billing |
| `billing_email` | String(255) | | Billing contact email |
| `subscription_status` | String(20) | | Current subscription status |
| `created_at` | DateTime | NOT NULL | Record creation timestamp |
| `updated_at` | DateTime | NOT NULL | Last update timestamp |
| `deleted_at` | DateTime | INDEX | Soft delete timestamp |
| `is_active` | Boolean | NOT NULL, DEFAULT TRUE | Active status |

**Example Usage:**
```python
from database import Company, SessionLocal

session = SessionLocal()
company = Company(
    name="Acme Corp",
    primary_domain="acme.com",
    max_seats=10,
    subscription_tier="professional"
)
session.add(company)
session.commit()
```

---

### users

Stores user accounts with full authentication and profile data.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PRIMARY KEY | Unique identifier |
| `email` | String(255) | UNIQUE, NOT NULL, INDEX | User email address |
| `username` | String(100) | UNIQUE | Optional username |
| `password_hash` | String(255) | NOT NULL | Hashed password |
| `full_name` | String(255) | | User's full name |
| `role` | Enum(UserRole) | NOT NULL, INDEX | User role (super_admin, admin, analyst, user, company_user, demo) |
| `company_id` | Integer | FK(companies.id), INDEX | Associated company |
| `status` | Enum(UserStatus) | NOT NULL, DEFAULT 'active', INDEX | Account status (active, locked, suspended, pending_verification) |
| `email_verified` | Boolean | NOT NULL, DEFAULT FALSE | Email verification status |
| `email_verification_token` | String(255) | | Email verification token |
| `email_verified_at` | DateTime | | When email was verified |
| `2fa_enabled` | Boolean | NOT NULL, DEFAULT FALSE | Two-factor authentication enabled |
| `2fa_secret` | String(255) | | 2FA secret key |
| `2fa_backup_codes` | Text | | JSON array of backup codes |
| `failed_login_attempts` | Integer | NOT NULL, DEFAULT 0 | Failed login counter |
| `locked_until` | DateTime | | Account lock expiry |
| `password_reset_token` | String(255) | | Password reset token |
| `password_reset_expires` | DateTime | | Token expiry |
| `last_password_change` | DateTime | | Last password change |
| `must_change_password` | Boolean | NOT NULL, DEFAULT FALSE | Force password change |
| `phone_number` | String(20) | | Contact phone |
| `timezone` | String(50) | DEFAULT 'UTC' | User timezone |
| `language` | String(10) | DEFAULT 'en' | Preferred language |
| `subscription_tier` | String(20) | | Individual subscription |
| `subscription_status` | String(20) | | Subscription status |
| `stripe_customer_id` | String(255) | | Stripe customer ID |
| `stripe_subscription_id` | String(255) | | Stripe subscription ID |
| `expires_at` | DateTime | | Demo account expiry |
| `email_notifications` | Boolean | NOT NULL, DEFAULT TRUE | Email notification preference |
| `security_alerts` | Boolean | NOT NULL, DEFAULT TRUE | Security alert preference |
| `marketing_emails` | Boolean | NOT NULL, DEFAULT FALSE | Marketing opt-in |
| `theme` | String(10) | DEFAULT 'dark' | UI theme preference |
| `last_login_at` | DateTime | | Last login timestamp |
| `last_login_ip` | String(45) | | Last login IP address |
| `created_at` | DateTime | NOT NULL | Record creation |
| `updated_at` | DateTime | NOT NULL | Last update |
| `deleted_at` | DateTime | INDEX | Soft delete |
| `is_active` | Boolean | NOT NULL, DEFAULT TRUE | Active status |

**UserRole Enum Values:**
- `super_admin` - Full system access
- `admin` - Administrative access
- `analyst` - Security analyst access
- `user` - Standard user access
- `company_user` - Company-scoped access
- `demo` - Demo account (time-limited)

**UserStatus Enum Values:**
- `active` - Normal account
- `locked` - Temporarily locked
- `suspended` - Suspended by admin
- `pending_verification` - Awaiting email verification

---

### sessions

Stores active user sessions for authentication.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PRIMARY KEY | Session ID |
| `user_id` | Integer | FK(users.id) CASCADE, NOT NULL, INDEX | User reference |
| `token` | String(255) | UNIQUE, NOT NULL, INDEX | Session token |
| `refresh_token` | String(255) | UNIQUE | Refresh token |
| `ip_address` | String(45) | NOT NULL | Client IP |
| `user_agent` | Text | | Client user agent |
| `device_type` | String(20) | | Device type (web, mobile, api) |
| `device_name` | String(255) | | Device identifier |
| `location` | String(255) | | GeoIP location |
| `created_at` | DateTime | NOT NULL | Session creation |
| `last_activity` | DateTime | NOT NULL | Last activity |
| `expires_at` | DateTime | NOT NULL | Session expiry |
| `is_active` | Boolean | NOT NULL, DEFAULT TRUE | Active status |
| `revoked_at` | DateTime | | Revocation timestamp |

---

### audit_logs

General audit trail for all user actions.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PRIMARY KEY | Log entry ID |
| `user_id` | Integer | FK(users.id) SET NULL, INDEX | Acting user |
| `action` | String(100) | NOT NULL, INDEX | Action performed |
| `resource_type` | String(50) | | Type of resource affected |
| `resource_id` | Integer | | ID of affected resource |
| `description` | Text | | Human-readable description |
| `metadata_json` | Text | | Additional context (JSON) |
| `ip_address` | String(45) | | Client IP |
| `user_agent` | Text | | Client user agent |
| `success` | Boolean | NOT NULL, DEFAULT TRUE | Action success status |
| `error_message` | Text | | Error details if failed |
| `created_at` | DateTime | NOT NULL | Log timestamp |

---

### password_history

Stores previous password hashes to prevent reuse.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PRIMARY KEY | Entry ID |
| `user_id` | Integer | FK(users.id) CASCADE, NOT NULL, INDEX | User reference |
| `password_hash` | String(255) | NOT NULL | Previous password hash |
| `created_at` | DateTime | NOT NULL | When password was set |

---

### login_attempts

Records all login attempts for security analysis.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PRIMARY KEY | Attempt ID |
| `email` | String(255) | NOT NULL, INDEX | Email attempted |
| `user_id` | Integer | FK(users.id) SET NULL, INDEX | User if known |
| `ip_address` | String(45) | NOT NULL | Client IP |
| `user_agent` | Text | | Client user agent |
| `success` | Boolean | NOT NULL | Login success |
| `failure_reason` | String(100) | | Failure reason |
| `attempted_at` | DateTime | NOT NULL, INDEX | Attempt timestamp |

---

## Security Tables

### api_keys

API keys for programmatic access.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PRIMARY KEY | Key ID |
| `user_id` | Integer | FK(users.id) CASCADE, NOT NULL, INDEX | Key owner |
| `key_hash` | String(255) | NOT NULL, UNIQUE, INDEX | SHA256 hash of key |
| `key_prefix` | String(8) | NOT NULL | First 8 chars (e.g., "nrv_xxxx") |
| `name` | String(100) | NOT NULL | User-friendly name |
| `permissions` | Text | | JSON array of permissions |
| `last_used_at` | DateTime | | Last usage time |
| `last_used_ip` | String(45) | | Last usage IP |
| `usage_count` | Integer | NOT NULL, DEFAULT 0 | Total usage count |
| `created_at` | DateTime | NOT NULL | Creation time |
| `expires_at` | DateTime | | Optional expiry |
| `revoked_at` | DateTime | | Revocation time |
| `is_active` | Boolean | NOT NULL, DEFAULT TRUE | Active status |

**Example Usage:**
```python
from database import create_api_key, validate_api_key

# Create a new API key
result = create_api_key(
    user_id=1,
    name="CI/CD Pipeline",
    permissions=["scan:read", "scan:write"],
    expires_days=90
)
# result['key'] is only returned once!

# Validate an API key
info = validate_api_key("nrv_abc123...")
if info:
    print(f"Valid key for user {info['user_id']}")
```

---

### security_events

Security events for audit and threat detection.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PRIMARY KEY | Event ID |
| `event_type` | String(50) | NOT NULL, INDEX | Event type |
| `severity` | String(20) | NOT NULL, INDEX | Severity (info, low, medium, high, critical) |
| `user_id` | Integer | FK(users.id) SET NULL, INDEX | Related user |
| `email` | String(255) | INDEX | Related email |
| `ip_address` | String(45) | INDEX | Client IP |
| `user_agent` | Text | | Client user agent |
| `location` | String(255) | | GeoIP location |
| `description` | Text | NOT NULL | Event description |
| `metadata_json` | Text | | Additional context (JSON) |
| `acknowledged` | Boolean | NOT NULL, DEFAULT FALSE | Acknowledged status |
| `acknowledged_by` | Integer | FK(users.id) SET NULL | Acknowledging user |
| `acknowledged_at` | DateTime | | Acknowledgement time |
| `created_at` | DateTime | NOT NULL, INDEX | Event timestamp |

**Event Types:**
- `login_failed` - Failed login attempt
- `login_success` - Successful login
- `brute_force_detected` - Brute force attack detected
- `session_revoked` - Session terminated
- `password_changed` - Password updated
- `2fa_enabled` / `2fa_disabled` - 2FA status change
- `api_key_created` / `api_key_revoked` - API key lifecycle
- `suspicious_activity` - Unusual behavior detected
- `account_locked` - Account locked

---

## Ghost Search Tables

### ghost_search_queries

Records Ghost Search module queries.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PRIMARY KEY | Query ID |
| `user_id` | Integer | FK(users.id) CASCADE, NOT NULL, INDEX | Querying user |
| `query_type` | String(20) | NOT NULL | Type (email, domain, phone, ip) |
| `query_value` | String(255) | NOT NULL | Search value |
| `results_count` | Integer | NOT NULL, DEFAULT 0 | Number of results |
| `search_sources` | Text | | JSON array of sources queried |
| `response_time_ms` | Integer | | Query response time |
| `searched_at` | DateTime | NOT NULL, INDEX | Search timestamp |
| `created_at` | DateTime | NOT NULL | Record creation |
| `updated_at` | DateTime | NOT NULL | Last update |
| `deleted_at` | DateTime | INDEX | Soft delete |
| `is_active` | Boolean | NOT NULL, DEFAULT TRUE | Active status |

---

### monitored_emails

Emails being monitored for breach exposure.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PRIMARY KEY | Monitor ID |
| `company_id` | Integer | FK(companies.id) CASCADE, INDEX | Owning company |
| `user_id` | Integer | FK(users.id) CASCADE, INDEX | Owning user |
| `created_by_user_id` | Integer | FK(users.id) SET NULL, NOT NULL | Creator |
| `email_address` | String(255) | NOT NULL, INDEX | Email to monitor |
| `monitor_scope` | String(20) | NOT NULL | Scope (company, analyst, admin) |
| `last_checked` | DateTime | | Last check time |
| `findings_count` | Integer | NOT NULL, DEFAULT 0 | Total findings |
| `created_at` | DateTime | NOT NULL | Creation time |
| `updated_at` | DateTime | NOT NULL | Last update |
| `deleted_at` | DateTime | INDEX | Soft delete |
| `is_active` | Boolean | NOT NULL, DEFAULT TRUE | Active status |

---

### monitored_email_findings

Findings from monitored email checks.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PRIMARY KEY | Finding ID |
| `monitored_email_id` | Integer | FK(monitored_emails.id) CASCADE, NOT NULL, INDEX | Parent email |
| `finding_type` | String(50) | NOT NULL | Type (breach, paste, darkweb, credential_leak) |
| `source` | String(100) | NOT NULL | Finding source |
| `breach_name` | String(255) | | Breach name if applicable |
| `breach_date` | DateTime | | Breach date |
| `details` | Text | NOT NULL | JSON details |
| `severity` | String(20) | NOT NULL | Severity level |
| `notified` | Boolean | NOT NULL, DEFAULT FALSE | Notification sent |
| `notified_at` | DateTime | | Notification time |
| `found_at` | DateTime | NOT NULL | Discovery time |
| `created_at` | DateTime | NOT NULL | Record creation |
| `updated_at` | DateTime | NOT NULL | Last update |
| `deleted_at` | DateTime | INDEX | Soft delete |
| `is_active` | Boolean | NOT NULL, DEFAULT TRUE | Active status |

---

### uploaded_breach_files

Breach files uploaded for analysis.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PRIMARY KEY | File ID |
| `user_id` | Integer | FK(users.id) CASCADE, NOT NULL, INDEX | Uploading user |
| `filename` | String(255) | NOT NULL | Original filename |
| `file_size` | Integer | NOT NULL | File size in bytes |
| `file_path` | String(500) | NOT NULL | Storage path |
| `storage_location` | String(20) | NOT NULL | Storage type (local, s3) |
| `indexed` | Boolean | NOT NULL, DEFAULT FALSE | Indexing complete |
| `records_count` | Integer | | Number of records |
| `processing_status` | String(20) | NOT NULL, DEFAULT 'pending' | Status (pending, processing, completed, failed) |
| `processing_error` | Text | | Error message if failed |
| `content_hash` | String(64) | NOT NULL | SHA256 hash |
| `mime_type` | String(100) | NOT NULL | File MIME type |
| `virus_scanned` | Boolean | NOT NULL, DEFAULT FALSE | Virus scan complete |
| `virus_scan_result` | String(100) | | Scan result |
| `security_flags` | Text | | JSON security flags |
| `uploaded_at` | DateTime | NOT NULL | Upload time |
| `expires_at` | DateTime | NOT NULL | Expiry (24 hours) |
| `created_at` | DateTime | NOT NULL | Record creation |
| `updated_at` | DateTime | NOT NULL | Last update |
| `deleted_at` | DateTime | INDEX | Soft delete |
| `is_active` | Boolean | NOT NULL, DEFAULT TRUE | Active status |

---

### breach_file_results

Individual records extracted from breach files.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PRIMARY KEY | Result ID |
| `uploaded_file_id` | Integer | FK(uploaded_breach_files.id) CASCADE, NOT NULL, INDEX | Source file |
| `email` | String(255) | NOT NULL, INDEX | Email address |
| `password_hash` | String(255) | | Password hash |
| `password_plain` | String(255) | | Plaintext password |
| `additional_data` | Text | | JSON additional data |
| `created_at` | DateTime | NOT NULL | Record creation |
| `updated_at` | DateTime | NOT NULL | Last update |
| `deleted_at` | DateTime | INDEX | Soft delete |
| `is_active` | Boolean | NOT NULL, DEFAULT TRUE | Active status |

---

## OSINT Tables

### profiles

OSINT profiles for individuals.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | String | PRIMARY KEY | Profile ID |
| `name` | String | NOT NULL | Person's name |
| `email` | String | | Email address |
| `username` | String | | Username |
| `phone` | String | | Phone number |
| `notes` | Text | | Notes |
| `risk_score` | Float | DEFAULT 0.0 | Calculated risk score |
| `breach_count` | Integer | DEFAULT 0 | Number of breaches |
| `social_media_json` | Text | | JSON social media data |
| `exposed_passwords` | Text | | Exposed passwords |
| `data_leaks` | Text | | Data leak information |
| `user_id` | Integer | FK(users.id) SET NULL, INDEX | Owner |
| `created_at` | DateTime | | Creation time |
| `updated_at` | DateTime | NOT NULL | Last update |
| `deleted_at` | DateTime | INDEX | Soft delete |
| `is_active` | Boolean | NOT NULL, DEFAULT TRUE | Active status |

---

### social_media

Social media accounts discovered.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PRIMARY KEY | Record ID |
| `profile_id` | String | NOT NULL | Parent profile |
| `platform` | String | | Platform name |
| `username` | String | | Username on platform |
| `url` | String | | Profile URL |
| `followers` | Integer | | Follower count |
| `posts_count` | Integer | | Number of posts |
| `discovered_at` | DateTime | | Discovery time |
| `user_id` | Integer | FK(users.id) SET NULL, INDEX | Owner |
| `updated_at` | DateTime | NOT NULL | Last update |
| `deleted_at` | DateTime | INDEX | Soft delete |
| `is_active` | Boolean | NOT NULL, DEFAULT TRUE | Active status |

---

### breaches

Breach records associated with profiles.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PRIMARY KEY | Record ID |
| `profile_id` | String | NOT NULL | Parent profile |
| `breach_name` | String | | Name of breach |
| `breach_date` | String | | Date of breach |
| `data_classes` | Text | | What data was leaked |
| `discovered_at` | DateTime | | When discovered |
| `user_id` | Integer | FK(users.id) SET NULL, INDEX | Owner |
| `updated_at` | DateTime | NOT NULL | Last update |
| `deleted_at` | DateTime | INDEX | Soft delete |
| `is_active` | Boolean | NOT NULL, DEFAULT TRUE | Active status |

---

### devices

Discovered devices/infrastructure.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PRIMARY KEY | Device ID |
| `profile_id` | String | | Associated profile |
| `ip_address` | String | | IP address |
| `hostname` | String | | Hostname |
| `device_type` | String | | Device type |
| `ports_open` | Text | | Open ports |
| `vulnerabilities` | Text | | Vulnerabilities found |
| `location` | String | | Geographic location |
| `discovered_at` | DateTime | | Discovery time |
| `user_id` | Integer | FK(users.id) SET NULL, INDEX | Owner |
| `updated_at` | DateTime | NOT NULL | Last update |
| `deleted_at` | DateTime | INDEX | Soft delete |
| `is_active` | Boolean | NOT NULL, DEFAULT TRUE | Active status |

---

### github_findings

Findings from GitHub/Gist searches.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PRIMARY KEY | Finding ID |
| `gist_id` | String | UNIQUE, NOT NULL, INDEX | GitHub gist ID |
| `gist_url` | String | NOT NULL | Gist URL |
| `filename` | String | | File name |
| `created_at` | DateTime | | Gist creation time |
| `query_term` | String | INDEX | Search term |
| `query_type` | String | INDEX | Type (email, api_key, database, password) |
| `credential_type` | String | | Credential type found |
| `credential_value` | Text | | The credential |
| `context` | Text | | Surrounding context |
| `discovered_at` | DateTime | | Discovery time |
| `user_id` | Integer | FK(users.id) SET NULL, INDEX | Owner |
| `updated_at` | DateTime | NOT NULL | Last update |
| `deleted_at` | DateTime | INDEX | Soft delete |
| `is_active` | Boolean | NOT NULL, DEFAULT TRUE | Active status |

---

### pastebin_findings

Findings from Pastebin searches.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PRIMARY KEY | Finding ID |
| `paste_id` | String | UNIQUE, NOT NULL, INDEX | Pastebin ID |
| `paste_title` | String | | Paste title |
| `paste_url` | String | NOT NULL | Paste URL |
| `posted_date` | String | | Post date |
| `query_term` | String | INDEX | Search term |
| `query_type` | String | INDEX | Type (email, domain, username, password) |
| `credential_password` | String | | Password if found |
| `context` | Text | | Surrounding context |
| `discovered_at` | DateTime | | Discovery time |
| `user_id` | Integer | FK(users.id) SET NULL, INDEX | Owner |
| `updated_at` | DateTime | NOT NULL | Last update |
| `deleted_at` | DateTime | INDEX | Soft delete |
| `is_active` | Boolean | NOT NULL, DEFAULT TRUE | Active status |

---

### opsych_search_results

OPSYCH social media search results.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PRIMARY KEY | Result ID |
| `search_id` | String | NOT NULL, INDEX | Search batch ID |
| `query_input` | String | NOT NULL, INDEX | Original query |
| `query_type` | String | | Query type |
| `platform` | String | INDEX | Platform found |
| `username` | String | INDEX | Username found |
| `url` | String | | Profile URL |
| `bio` | Text | | Profile bio |
| `source` | String | | Source tool (Sherlock, Holehe, etc.) |
| `discovered_at` | DateTime | | Discovery time |
| `user_id` | Integer | FK(users.id) SET NULL, INDEX | Owner |
| `updated_at` | DateTime | NOT NULL | Last update |
| `deleted_at` | DateTime | INDEX | Soft delete |
| `is_active` | Boolean | NOT NULL, DEFAULT TRUE | Active status |

---

## Attack Surface Tables

### asm_scans

Legacy ASM scan results.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PRIMARY KEY | Scan ID |
| `domain` | String | NOT NULL, UNIQUE, INDEX | Scanned domain |
| `scan_results` | Text | NOT NULL | JSON results |
| `scanned_at` | DateTime | NOT NULL | Scan time |
| `risk_score` | Integer | | Risk score |
| `risk_level` | String | | Risk level |
| `vulnerabilities_found` | Integer | | Vuln count |
| `user_id` | Integer | FK(users.id) SET NULL, INDEX | Owner |
| `updated_at` | DateTime | NOT NULL | Last update |
| `deleted_at` | DateTime | INDEX | Soft delete |
| `is_active` | Boolean | NOT NULL, DEFAULT TRUE | Active status |

---

### cached_asm_scans

Cached XASM scan results for quick access.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PRIMARY KEY | Cache ID |
| `domain` | String(255) | NOT NULL, INDEX | Domain |
| `scanned_at` | DateTime | | Scan time |
| `risk_score` | Integer | DEFAULT 0 | Risk score |
| `risk_level` | String(20) | | Risk level |
| `total_cves` | Integer | DEFAULT 0 | Total CVEs |
| `critical_cves` | Integer | DEFAULT 0 | Critical CVEs |
| `vulnerabilities_found` | Integer | DEFAULT 0 | Vuln count |
| `open_ports_count` | Integer | DEFAULT 0 | Open ports |
| `scan_results` | JSON | | Full results |
| `user_id` | Integer | FK(users.id) SET NULL, INDEX | Owner |
| `updated_at` | DateTime | NOT NULL | Last update |
| `deleted_at` | DateTime | INDEX | Soft delete |
| `is_active` | Boolean | NOT NULL, DEFAULT TRUE | Active status |

---

### lightbox_findings

Individual Lightbox scan findings.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PRIMARY KEY | Finding ID |
| `asset` | String | NOT NULL, INDEX | Asset tested |
| `finding_type` | String | NOT NULL, INDEX | Finding type |
| `url` | String | NOT NULL | Tested URL |
| `description` | Text | | Finding description |
| `severity` | String | INDEX | Severity level |
| `status_code` | Integer | | HTTP status |
| `discovered_at` | DateTime | | Discovery time |
| `scan_id` | String | INDEX | Scan batch ID |
| `user_id` | Integer | FK(users.id) SET NULL, INDEX | Owner |
| `updated_at` | DateTime | NOT NULL | Last update |
| `deleted_at` | DateTime | INDEX | Soft delete |
| `is_active` | Boolean | NOT NULL, DEFAULT TRUE | Active status |

---

### lightbox_scans

Lightbox scan summaries.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PRIMARY KEY | Scan ID |
| `domain` | String | NOT NULL, INDEX | Scanned domain |
| `scanned_at` | DateTime | NOT NULL | Scan time |
| `total_findings` | Integer | DEFAULT 0 | Total findings |
| `critical_count` | Integer | DEFAULT 0 | Critical count |
| `high_count` | Integer | DEFAULT 0 | High count |
| `medium_count` | Integer | DEFAULT 0 | Medium count |
| `low_count` | Integer | DEFAULT 0 | Low count |
| `findings` | Text | | JSON findings |
| `scan_metadata` | Text | | JSON metadata |
| `user_id` | Integer | FK(users.id) SET NULL, INDEX | Owner |
| `updated_at` | DateTime | NOT NULL | Last update |
| `deleted_at` | DateTime | INDEX | Soft delete |
| `is_active` | Boolean | NOT NULL, DEFAULT TRUE | Active status |

---

### xasm_scan_history

Historical XASM scan records.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PRIMARY KEY | History ID |
| `scan_id` | String | UNIQUE, NOT NULL, INDEX | Scan identifier |
| `target` | String | NOT NULL, INDEX | Scan target |
| `timestamp` | DateTime | NOT NULL | Scan time |
| `status` | String | NOT NULL, DEFAULT 'completed' | Scan status |
| `results_json` | Text | | Full results JSON |
| `summary_stats` | Text | | Summary statistics |
| `user_id` | Integer | FK(users.id) SET NULL, INDEX | Owner |
| `created_at` | DateTime | | Creation time |
| `updated_at` | DateTime | NOT NULL | Last update |
| `deleted_at` | DateTime | INDEX | Soft delete |
| `is_active` | Boolean | NOT NULL, DEFAULT TRUE | Active status |

---

### lightbox_scan_history

Historical Lightbox scan records.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PRIMARY KEY | History ID |
| `scan_id` | String | UNIQUE, NOT NULL, INDEX | Scan identifier |
| `target` | String | NOT NULL, INDEX | Scan target |
| `timestamp` | DateTime | NOT NULL | Scan time |
| `status` | String | NOT NULL, DEFAULT 'completed' | Scan status |
| `results_json` | Text | | Full results JSON |
| `summary_stats` | Text | | Summary statistics |
| `total_tests` | Integer | DEFAULT 0 | Tests run |
| `passed_tests` | Integer | DEFAULT 0 | Passed tests |
| `failed_tests` | Integer | DEFAULT 0 | Failed tests |
| `user_id` | Integer | FK(users.id) SET NULL, INDEX | Owner |
| `created_at` | DateTime | | Creation time |
| `updated_at` | DateTime | NOT NULL | Last update |
| `deleted_at` | DateTime | INDEX | Soft delete |
| `is_active` | Boolean | NOT NULL, DEFAULT TRUE | Active status |

---

### scan_results_xasm

XASM scan results for AI report generation (48h expiry).

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PRIMARY KEY | Result ID |
| `company` | String | NOT NULL, UNIQUE, INDEX | Company/domain |
| `results_json` | Text | NOT NULL | Full results |
| `scan_date` | DateTime | | Scan date |
| `expires_at` | DateTime | NOT NULL | Expiry time |
| `user_id` | Integer | FK(users.id) SET NULL, INDEX | Owner |
| `created_at` | DateTime | | Creation time |
| `updated_at` | DateTime | NOT NULL | Last update |
| `deleted_at` | DateTime | INDEX | Soft delete |
| `is_active` | Boolean | NOT NULL, DEFAULT TRUE | Active status |

---

### scan_results_lightbox

Lightbox scan results for AI report generation (48h expiry).

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PRIMARY KEY | Result ID |
| `company` | String | NOT NULL, UNIQUE, INDEX | Company/domain |
| `results_json` | Text | NOT NULL | Full results |
| `scan_date` | DateTime | | Scan date |
| `expires_at` | DateTime | NOT NULL | Expiry time |
| `user_id` | Integer | FK(users.id) SET NULL, INDEX | Owner |
| `created_at` | DateTime | | Creation time |
| `updated_at` | DateTime | NOT NULL | Last update |
| `deleted_at` | DateTime | INDEX | Soft delete |
| `is_active` | Boolean | NOT NULL, DEFAULT TRUE | Active status |

---

## Compliance Tables

### compliance_assessments

Compliance framework assessments.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PRIMARY KEY | Assessment ID |
| `company_id` | Integer | FK(companies.id) CASCADE, NOT NULL, INDEX | Company |
| `created_by_user_id` | Integer | FK(users.id) SET NULL, NOT NULL | Creator |
| `framework` | String(50) | NOT NULL, INDEX | Framework (SOC2, ISO27001, GDPR, NIS2, PIPEDA) |
| `framework_version` | String(20) | | Framework version |
| `status` | String(20) | NOT NULL, DEFAULT 'in_progress' | Status |
| `overall_compliance_score` | Integer | | Score 0-100 |
| `assessment_date` | DateTime | NOT NULL | Assessment date |
| `completion_date` | DateTime | | Completion date |
| `expiry_date` | DateTime | | Expiry date |
| `created_at` | DateTime | NOT NULL | Creation time |
| `updated_at` | DateTime | NOT NULL | Last update |
| `deleted_at` | DateTime | INDEX | Soft delete |
| `is_active` | Boolean | NOT NULL, DEFAULT TRUE | Active status |

---

### compliance_controls

Individual compliance controls within assessments.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PRIMARY KEY | Control ID |
| `assessment_id` | Integer | FK(compliance_assessments.id) CASCADE, NOT NULL, INDEX | Parent assessment |
| `control_id` | String(50) | NOT NULL | Control identifier (e.g., "SOC2-CC6.1") |
| `control_name` | String(255) | NOT NULL | Control name |
| `control_category` | String(100) | | Category |
| `status` | String(20) | NOT NULL, DEFAULT 'not_tested' | Status (compliant, non_compliant, partial, not_tested) |
| `compliance_score` | Integer | | Score 0-100 |
| `scan_source` | String(20) | | Auto-flag source (xasm, lightbox, manual) |
| `scan_finding_type` | String(100) | | Vulnerability type |
| `scan_finding_id` | String(100) | | Finding reference |
| `scan_flagged_at` | DateTime | | Auto-flag time |
| `scan_verified_at` | DateTime | | Verification time |
| `scan_domain` | String(255) | | Scanned domain |
| `evidence_summary` | Text | | Evidence summary |
| `remediation_notes` | Text | | Remediation notes |
| `assigned_to_user_id` | Integer | FK(users.id) SET NULL | Assigned user |
| `last_reviewed` | DateTime | | Last review date |
| `next_review_date` | DateTime | | Next review date |
| `created_at` | DateTime | NOT NULL | Creation time |
| `updated_at` | DateTime | NOT NULL | Last update |
| `deleted_at` | DateTime | INDEX | Soft delete |
| `is_active` | Boolean | NOT NULL, DEFAULT TRUE | Active status |

---

### compliance_evidence

Evidence attached to compliance controls.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PRIMARY KEY | Evidence ID |
| `control_id` | Integer | FK(compliance_controls.id) CASCADE, NOT NULL, INDEX | Parent control |
| `evidence_type` | String(50) | NOT NULL | Type (document, scan, screenshot, policy, log) |
| `title` | String(255) | NOT NULL | Evidence title |
| `description` | Text | | Description |
| `file_path` | String(500) | | File path |
| `file_size` | Integer | | File size |
| `file_type` | String(100) | | File MIME type |
| `uploaded_by_user_id` | Integer | FK(users.id) SET NULL, NOT NULL | Uploader |
| `evidence_date` | DateTime | | Evidence creation date |
| `created_at` | DateTime | NOT NULL | Record creation |
| `updated_at` | DateTime | NOT NULL | Last update |
| `deleted_at` | DateTime | INDEX | Soft delete |
| `is_active` | Boolean | NOT NULL, DEFAULT TRUE | Active status |

---

### vulnerability_reports

AI-generated vulnerability reports.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PRIMARY KEY | Report ID |
| `company_id` | Integer | FK(companies.id) CASCADE, INDEX | Company |
| `user_id` | Integer | FK(users.id) CASCADE, NOT NULL, INDEX | Owner |
| `xasm_scan_id` | Integer | FK(scan_results_xasm.id) SET NULL | XASM scan source |
| `lightbox_scan_id` | Integer | FK(scan_results_lightbox.id) SET NULL | Lightbox scan source |
| `risk_score` | Integer | NOT NULL | Risk score 0-100 |
| `risk_level` | String(20) | NOT NULL | Level (CRITICAL, HIGH, MEDIUM, LOW) |
| `executive_summary` | Text | NOT NULL | Summary |
| `report_json` | Text | NOT NULL | Full report JSON |
| `ai_model` | String(50) | NOT NULL | AI model used |
| `generation_time_ms` | Integer | | Generation time |
| `generated_at` | DateTime | NOT NULL | Generation time |
| `created_at` | DateTime | NOT NULL | Record creation |
| `updated_at` | DateTime | NOT NULL | Last update |
| `deleted_at` | DateTime | INDEX | Soft delete |
| `is_active` | Boolean | NOT NULL, DEFAULT TRUE | Active status |

---

## Roadmap Tables

### roadmap_profiles

Company/user security roadmap profiles.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PRIMARY KEY | Profile ID |
| `user_id` | Integer | FK(users.id) SET NULL, INDEX | User |
| `company_id` | Integer | FK(companies.id) SET NULL, INDEX | Company |
| `company_name` | String(255) | NOT NULL | Company name |
| `company_size` | String(50) | | Size (small, medium, large, enterprise) |
| `industry` | String(100) | INDEX | Industry |
| `employee_count` | Integer | | Employee count |
| `current_security_score` | Integer | DEFAULT 0 | Current score 0-100 |
| `target_security_score` | Integer | DEFAULT 75 | Target score |
| `handles_pii` | Boolean | DEFAULT FALSE | Handles PII |
| `handles_payment_data` | Boolean | DEFAULT FALSE | Handles payment data |
| `handles_health_data` | Boolean | DEFAULT FALSE | Handles health data |
| `handles_financial_data` | Boolean | DEFAULT FALSE | Handles financial data |
| `current_measures` | Text | | JSON current measures |
| `compliance_requirements` | Text | | JSON compliance requirements |
| `assessment_responses` | Text | | JSON assessment responses |
| `created_at` | DateTime | NOT NULL | Creation time |
| `updated_at` | DateTime | NOT NULL | Last update |
| `last_recalculated` | DateTime | | Last score recalculation |
| `deleted_at` | DateTime | INDEX | Soft delete |
| `is_active` | Boolean | NOT NULL, DEFAULT TRUE | Active status |

**Relationships:**
- `user_tasks` - RoadmapUserTask (one-to-many)
- `achievements` - RoadmapAchievement (one-to-many)
- `progress_history` - RoadmapProgressHistory (one-to-many)

---

### roadmap_tasks

Master library of security tasks.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PRIMARY KEY | Task ID |
| `task_id` | String(100) | UNIQUE, NOT NULL, INDEX | Task identifier |
| `task_name` | String(255) | NOT NULL | Task name |
| `task_category` | String(50) | INDEX | Category |
| `description` | Text | | Description |
| `why_it_matters` | Text | | Security importance |
| `how_to_fix` | Text | | Remediation steps |
| `estimated_time_minutes` | Integer | | Time estimate |
| `estimated_cost_min` | Float | | Min cost estimate |
| `estimated_cost_max` | Float | | Max cost estimate |
| `difficulty_level` | String(20) | | Difficulty (easy, medium, hard) |
| `security_score_impact` | Integer | | Score points |
| `risk_level` | String(20) | INDEX | Risk level |
| `applies_to_industries` | Text | | JSON industries |
| `applies_to_sizes` | Text | | JSON company sizes |
| `requires_compliance` | Text | | JSON compliance requirements |
| `documentation_url` | Text | | Documentation link |
| `video_tutorial_url` | Text | | Video tutorial link |
| `created_at` | DateTime | NOT NULL | Creation time |
| `updated_at` | DateTime | NOT NULL | Last update |
| `is_active` | Boolean | NOT NULL, DEFAULT TRUE | Active status |

---

### roadmap_user_tasks

Tasks assigned to specific profiles.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PRIMARY KEY | User task ID |
| `profile_id` | Integer | FK(roadmap_profiles.id) CASCADE, NOT NULL, INDEX | Profile |
| `task_id` | String(100) | NOT NULL, INDEX | Task reference |
| `status` | String(20) | NOT NULL, DEFAULT 'not_started', INDEX | Status |
| `phase` | Integer | DEFAULT 1, INDEX | Phase (1-4) |
| `priority_order` | Integer | | Priority within phase |
| `source` | String(50) | INDEX | Source (profile, xasm_scan, lightbox_scan, compliance, ghost_search, adversary) |
| `source_reference_id` | Integer | | Source record ID |
| `source_details` | Text | | JSON source context |
| `finding_type` | String(100) | | Finding type |
| `finding_severity` | String(20) | | Finding severity |
| `scan_domain` | String(255) | | Scanned domain |
| `scan_date` | DateTime | | Scan date |
| `matched_threat_actor` | String(255) | | Matched threat actor |
| `threat_actor_ttp` | Text | | JSON TTPs |
| `assigned_to_user_id` | Integer | FK(users.id) SET NULL, INDEX | Assigned user |
| `started_at` | DateTime | | Start time |
| `completed_at` | DateTime | | Completion time |
| `verified_at` | DateTime | | Verification time |
| `last_reminded` | DateTime | | Last reminder |
| `user_notes` | Text | | User notes |
| `admin_notes` | Text | | Admin notes |
| `created_at` | DateTime | NOT NULL | Creation time |
| `updated_at` | DateTime | NOT NULL | Last update |
| `deleted_at` | DateTime | INDEX | Soft delete |
| `is_active` | Boolean | NOT NULL, DEFAULT TRUE | Active status |

**Status Values:**
- `not_started` - Not yet begun
- `in_progress` - Currently working
- `completed` - Finished
- `skipped` - Intentionally skipped
- `not_applicable` - Does not apply

---

### roadmap_achievements

Gamification achievements/badges.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PRIMARY KEY | Achievement ID |
| `profile_id` | Integer | FK(roadmap_profiles.id) CASCADE, NOT NULL, INDEX | Profile |
| `user_id` | Integer | FK(users.id) SET NULL, INDEX | User |
| `achievement_id` | String(100) | NOT NULL, INDEX | Achievement identifier |
| `achievement_name` | String(255) | NOT NULL | Achievement name |
| `achievement_description` | Text | | Description |
| `achievement_icon` | String(50) | | Icon identifier |
| `requirement_type` | String(50) | | Requirement type |
| `requirement_value` | Integer | | Requirement value |
| `unlocked_at` | DateTime | NOT NULL | Unlock time |
| `is_claimed` | Boolean | DEFAULT FALSE | Claimed status |
| `claimed_at` | DateTime | | Claim time |
| `rewards` | Text | | JSON rewards |
| `created_at` | DateTime | NOT NULL | Creation time |

---

### roadmap_progress_history

Historical progress snapshots.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PRIMARY KEY | History ID |
| `profile_id` | Integer | FK(roadmap_profiles.id) CASCADE, NOT NULL, INDEX | Profile |
| `security_score` | Integer | | Score snapshot |
| `tasks_completed` | Integer | | Completed tasks |
| `tasks_total` | Integer | | Total tasks |
| `phase1_completed` | Integer | DEFAULT 0 | Phase 1 complete |
| `phase2_completed` | Integer | DEFAULT 0 | Phase 2 complete |
| `phase3_completed` | Integer | DEFAULT 0 | Phase 3 complete |
| `phase4_completed` | Integer | DEFAULT 0 | Phase 4 complete |
| `snapshot_date` | DateTime | NOT NULL, INDEX | Snapshot time |
| `snapshot_reason` | String(50) | | Reason (daily, task_completed, scan_run, manual) |

---

### roadmap_task_library_meta

Task library metadata and versioning.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PRIMARY KEY | Meta ID |
| `library_version` | String(20) | NOT NULL | Version (e.g., "1.0.0") |
| `total_tasks` | Integer | | Task count |
| `changelog` | Text | | Change description |
| `last_updated` | DateTime | NOT NULL | Update time |
| `created_at` | DateTime | NOT NULL | Creation time |

---

## BAIT Tables

### bait_tokens

Honeypot/canary tokens for breach detection.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PRIMARY KEY | Token ID |
| `identifier` | String | UNIQUE, NOT NULL | Token identifier (e.g., "bait_abc123") |
| `bait_type` | String | | Type (aws_key, stripe_token, database, ssh_key, github_token, slack_token) |
| `token_value` | Text | | JSON fake credential |
| `seeded_at` | DateTime | | Seeding time |
| `seeded_location` | String | | Where posted |
| `first_access` | DateTime | | First access time |
| `access_count` | Integer | DEFAULT 0 | Access count |
| `last_access` | DateTime | | Last access time |
| `status` | String | DEFAULT 'active' | Status (active, triggered, expired, revoked) |
| `user_id` | Integer | FK(users.id) SET NULL, INDEX | Owner |
| `updated_at` | DateTime | NOT NULL | Last update |
| `deleted_at` | DateTime | INDEX | Soft delete |
| `is_active` | Boolean | NOT NULL, DEFAULT TRUE | Active status |

**Relationships:**
- `accesses` - BaitAccess (one-to-many, cascade delete)

---

### bait_accesses

Access logs for bait tokens.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PRIMARY KEY | Access ID |
| `bait_id` | Integer | FK(bait_tokens.id), NOT NULL | Parent token |
| `accessed_at` | DateTime | | Access time |
| `source_ip` | String | | Source IP |
| `user_agent` | String | | User agent |
| `request_type` | String | | Request type (http, api, ssh, database) |
| `request_headers` | Text | | JSON headers |
| `request_body` | Text | | JSON body |
| `fingerprint` | Text | | Scanner fingerprint |
| `geolocation` | String | | Location |
| `threat_level` | String | DEFAULT 'medium' | Threat level |
| `notes` | Text | | Analysis notes |
| `accept_language` | String | | Accept-Language header |
| `referer` | String | | Referer header |
| `sec_fetch_headers` | Text | | JSON Sec-Fetch headers |
| `attribution_type` | String | | Attribution (human, bot, tool, spoofed) |
| `evidence_strength` | String | | Evidence strength (court_ready, moderate, weak) |
| `user_id` | Integer | FK(users.id) SET NULL, INDEX | Owner |
| `updated_at` | DateTime | NOT NULL | Last update |
| `deleted_at` | DateTime | INDEX | Soft delete |
| `is_active` | Boolean | NOT NULL, DEFAULT TRUE | Active status |

---

## File Upload Tables

### uploaded_files

Uploaded credential files.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PRIMARY KEY | File ID |
| `upload_id` | String | UNIQUE, NOT NULL, INDEX | Upload identifier |
| `filename` | String | NOT NULL | Original filename |
| `file_path` | String | NOT NULL | Storage path |
| `upload_time` | DateTime | | Upload time |
| `line_count` | Integer | DEFAULT 0 | Line count |
| `parsed_credential_count` | Integer | DEFAULT 0 | Credentials found |
| `file_size_bytes` | Integer | DEFAULT 0 | File size |
| `user_id` | Integer | FK(users.id) SET NULL, INDEX | Owner |
| `updated_at` | DateTime | NOT NULL | Last update |
| `deleted_at` | DateTime | INDEX | Soft delete |
| `is_active` | Boolean | NOT NULL, DEFAULT TRUE | Active status |

**Relationships:**
- `credentials` - UploadedCredential (one-to-many, cascade delete)

---

### uploaded_credentials

Parsed credentials from uploaded files.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | Integer | PRIMARY KEY | Credential ID |
| `upload_id` | String | FK(uploaded_files.upload_id), NOT NULL, INDEX | Parent file |
| `email` | String | NOT NULL, INDEX | Email address |
| `password` | String | | Password |
| `additional_data` | Text | | Extra data |
| `line_number` | Integer | | Source line |
| `user_id` | Integer | FK(users.id) SET NULL, INDEX | Owner |
| `updated_at` | DateTime | NOT NULL | Last update |
| `deleted_at` | DateTime | INDEX | Soft delete |
| `is_active` | Boolean | NOT NULL, DEFAULT TRUE | Active status |

---

## Standard Column Patterns

All tables follow these patterns for consistency:

### Soft Delete Pattern
```python
deleted_at = Column(DateTime, index=True)  # NULL = not deleted
is_active = Column(Boolean, nullable=False, default=True)
```

### User Tracking Pattern
```python
user_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), index=True)
```

### Timestamp Pattern
```python
created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc),
                    onupdate=lambda: datetime.now(timezone.utc))
```

---

## Indexes

Key indexes for query performance:

| Table | Index | Columns |
|-------|-------|---------|
| users | PRIMARY | id |
| users | UNIQUE | email |
| users | UNIQUE | username |
| users | INDEX | role |
| users | INDEX | status |
| users | INDEX | company_id |
| users | INDEX | deleted_at |
| companies | PRIMARY | id |
| companies | UNIQUE | primary_domain |
| companies | INDEX | deleted_at |
| sessions | PRIMARY | id |
| sessions | UNIQUE | token |
| sessions | UNIQUE | refresh_token |
| sessions | INDEX | user_id |
| api_keys | PRIMARY | id |
| api_keys | UNIQUE | key_hash |
| api_keys | INDEX | user_id |
| security_events | INDEX | event_type |
| security_events | INDEX | severity |
| security_events | INDEX | user_id |
| security_events | INDEX | created_at |
| cached_asm_scans | INDEX | domain |
| lightbox_scans | INDEX | domain |
| xasm_scan_history | UNIQUE | scan_id |
| xasm_scan_history | INDEX | target |
| compliance_assessments | INDEX | company_id |
| compliance_assessments | INDEX | framework |
| roadmap_user_tasks | INDEX | profile_id |
| roadmap_user_tasks | INDEX | status |
| roadmap_user_tasks | INDEX | phase |

---

## Foreign Key Relationships

```
companies
    └── users (company_id → companies.id)
    └── compliance_assessments (company_id → companies.id)
    └── monitored_emails (company_id → companies.id)
    └── roadmap_profiles (company_id → companies.id)
    └── vulnerability_reports (company_id → companies.id)

users
    └── sessions (user_id → users.id)
    └── audit_logs (user_id → users.id)
    └── password_history (user_id → users.id)
    └── login_attempts (user_id → users.id)
    └── api_keys (user_id → users.id)
    └── security_events (user_id → users.id)
    └── ghost_search_queries (user_id → users.id)
    └── monitored_emails (user_id, created_by_user_id → users.id)
    └── uploaded_breach_files (user_id → users.id)
    └── compliance_controls (assigned_to_user_id → users.id)
    └── compliance_evidence (uploaded_by_user_id → users.id)
    └── roadmap_profiles (user_id → users.id)
    └── roadmap_user_tasks (assigned_to_user_id → users.id)
    └── roadmap_achievements (user_id → users.id)
    └── vulnerability_reports (user_id → users.id)
    └── [all other tables with user_id field]

compliance_assessments
    └── compliance_controls (assessment_id → compliance_assessments.id)

compliance_controls
    └── compliance_evidence (control_id → compliance_controls.id)

roadmap_profiles
    └── roadmap_user_tasks (profile_id → roadmap_profiles.id)
    └── roadmap_achievements (profile_id → roadmap_profiles.id)
    └── roadmap_progress_history (profile_id → roadmap_profiles.id)

monitored_emails
    └── monitored_email_findings (monitored_email_id → monitored_emails.id)

uploaded_breach_files
    └── breach_file_results (uploaded_file_id → uploaded_breach_files.id)

uploaded_files
    └── uploaded_credentials (upload_id → uploaded_files.upload_id)

bait_tokens
    └── bait_accesses (bait_id → bait_tokens.id)

scan_results_xasm
    └── vulnerability_reports (xasm_scan_id → scan_results_xasm.id)

scan_results_lightbox
    └── vulnerability_reports (lightbox_scan_id → scan_results_lightbox.id)
```

---

## TODO: Phase 7 - PostgreSQL Migration

When migrating to PostgreSQL, consider:

1. **Data Types:**
   - `Text` → `TEXT` (same)
   - `String` → `VARCHAR`
   - `Integer` → `INTEGER` or `BIGINT`
   - `Boolean` → `BOOLEAN`
   - `DateTime` → `TIMESTAMP WITH TIME ZONE`
   - `JSON` → `JSONB` (native PostgreSQL JSON)

2. **Index Optimizations:**
   - Use `GIN` indexes for JSON columns
   - Consider partial indexes for `deleted_at IS NULL`
   - Add `CONCURRENTLY` for online index creation

3. **Constraints:**
   - Add `CHECK` constraints for enum values
   - Consider `EXCLUSION` constraints where needed

4. **Performance:**
   - Enable connection pooling (pgbouncer)
   - Configure autovacuum settings
   - Set up read replicas for scaling

---

*Last updated: January 2026*
