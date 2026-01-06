# NERVE Database Maintenance Guide

> Procedures for maintaining the NERVE database in production.

**Version:** 1.0.0
**Last Updated:** January 2026

---

## Table of Contents

1. [Overview](#overview)
2. [Daily Maintenance](#daily-maintenance)
3. [Backup Procedures](#backup-procedures)
4. [Restore Procedures](#restore-procedures)
5. [Health Monitoring](#health-monitoring)
6. [Performance Optimization](#performance-optimization)
7. [Data Cleanup](#data-cleanup)
8. [Troubleshooting](#troubleshooting)
9. [Emergency Procedures](#emergency-procedures)

---

## Overview

The NERVE database requires regular maintenance to ensure:
- Data integrity
- Optimal performance
- Reliable backups
- Security compliance

### Quick Reference

| Task | Frequency | Command |
|------|-----------|---------|
| Health check | Hourly | `run_health_check()` |
| Session cleanup | Hourly | `cleanup_expired_sessions()` |
| AI scan cleanup | Daily | `cleanup_expired_ai_scans()` |
| Scan history cleanup | Weekly | `cleanup_old_scan_history(30)` |
| Backup | Daily | `create_backup()` |
| Optimization | Weekly | `optimize_database()` |

---

## Daily Maintenance

### Automated Tasks

Add these to your task scheduler (cron, Windows Task Scheduler, or Celery):

```python
# daily_maintenance.py
from database import (
    cleanup_expired_sessions,
    cleanup_expired_ai_scans,
    cleanup_old_scan_history,
    create_backup,
    run_health_check,
    get_database_stats
)
import logging

logger = logging.getLogger('maintenance')

def run_daily_maintenance():
    """Run all daily maintenance tasks."""

    # 1. Health check first
    logger.info("Running health check...")
    health = run_health_check()

    if not health['connection']['healthy']:
        logger.error("Database connection unhealthy!")
        return False

    if not health['tables']['healthy']:
        logger.error(f"Table integrity issues: {health['tables']['errors']}")

    # 2. Create daily backup
    logger.info("Creating daily backup...")
    backup = create_backup()

    if backup['success']:
        logger.info(f"Backup created: {backup['backup_path']}")
    else:
        logger.error(f"Backup failed: {backup['error']}")

    # 3. Cleanup expired sessions
    logger.info("Cleaning up expired sessions...")
    session_count = cleanup_expired_sessions()
    logger.info(f"Cleaned up {session_count} expired sessions")

    # 4. Cleanup expired AI scans (48h expiry)
    logger.info("Cleaning up expired AI scans...")
    cleanup_expired_ai_scans()

    # 5. Log database stats
    stats = get_database_stats()
    logger.info(f"Database size: {stats['size_mb']} MB")
    logger.info(f"Total records: {stats['total_records']}")

    return True

if __name__ == "__main__":
    run_daily_maintenance()
```

### Cron Schedule Example

```bash
# /etc/cron.d/nerve-maintenance

# Health check every hour
0 * * * * nerve python /app/backend/maintenance/hourly_check.py

# Daily maintenance at 2 AM
0 2 * * * nerve python /app/backend/maintenance/daily_maintenance.py

# Weekly optimization on Sunday at 3 AM
0 3 * * 0 nerve python /app/backend/maintenance/weekly_optimization.py

# Monthly old data cleanup on 1st at 4 AM
0 4 1 * * nerve python /app/backend/maintenance/monthly_cleanup.py
```

---

## Backup Procedures

### Creating Backups

#### Manual Backup

```python
from database import create_backup, get_backup_info

# Create backup with default location
result = create_backup()
print(f"Backup created: {result['backup_path']}")
print(f"Size: {result['size_bytes']} bytes")

# Create backup to custom location
result = create_backup(backup_dir="/mnt/backups/nerve")
```

#### Scheduled Backup Script

```python
# backup_script.py
import os
from datetime import datetime
from database import create_backup, list_backups

def run_backup():
    # Create backup
    result = create_backup()

    if not result['success']:
        raise Exception(f"Backup failed: {result['error']}")

    # Keep only last 30 backups
    backups = list_backups()
    if len(backups) > 30:
        for old_backup in backups[30:]:
            os.remove(old_backup['path'])
            print(f"Removed old backup: {old_backup['filename']}")

    return result

if __name__ == "__main__":
    run_backup()
```

### Backup Verification

```python
from database import get_backup_info

def verify_backup(backup_path):
    """Verify backup integrity."""
    info = get_backup_info(backup_path)

    if 'error' in info:
        print(f"Backup verification failed: {info['error']}")
        return False

    print(f"Backup: {info['path']}")
    print(f"Size: {info['size_mb']} MB")
    print(f"Created: {info['created']}")
    print(f"Tables: {len(info['tables'])}")

    # Verify expected tables exist
    expected_tables = ['users', 'companies', 'sessions', 'api_keys']
    for table in expected_tables:
        if table not in info['tables']:
            print(f"WARNING: Missing table: {table}")
            return False

    print("Backup verification: PASSED")
    return True
```

### Offsite Backup

```bash
#!/bin/bash
# offsite_backup.sh

# Variables
BACKUP_DIR="/path/to/data/backups"
REMOTE_HOST="backup-server.example.com"
REMOTE_PATH="/backups/nerve"

# Find latest backup
LATEST_BACKUP=$(ls -t $BACKUP_DIR/nerve_backup_*.db | head -1)

# Copy to remote
scp $LATEST_BACKUP $REMOTE_HOST:$REMOTE_PATH/

# Also upload to S3 (optional)
aws s3 cp $LATEST_BACKUP s3://nerve-backups/daily/
```

---

## Restore Procedures

### Standard Restore

```python
from database import restore_backup, get_backup_info, run_health_check

def restore_from_backup(backup_path):
    """Restore database from backup with verification."""

    # 1. Verify backup first
    print("Verifying backup...")
    info = get_backup_info(backup_path)
    if 'error' in info:
        raise Exception(f"Backup verification failed: {info['error']}")

    print(f"Backup info: {info['size_mb']} MB, {len(info['tables'])} tables")

    # 2. Perform restore (confirm=True required!)
    print("Restoring database...")
    result = restore_backup(backup_path, confirm=True)

    if not result['success']:
        raise Exception(f"Restore failed: {result['error']}")

    print(f"Restore complete. Pre-restore backup at: {result['pre_restore_backup']}")

    # 3. Verify restored database
    print("Verifying restored database...")
    health = run_health_check()

    if not health['connection']['healthy']:
        raise Exception("Restored database connection failed!")

    if not health['tables']['healthy']:
        print(f"WARNING: Table integrity issues: {health['tables']['errors']}")

    print("Restore verification: PASSED")
    return result

# Usage
restore_from_backup("/path/to/nerve_backup_20260106.db")
```

### Point-in-Time Recovery

For SQLite, point-in-time recovery requires keeping more backups:

```python
from database import list_backups

def find_backup_before(target_datetime):
    """Find the most recent backup before a target datetime."""
    from datetime import datetime

    backups = list_backups()

    for backup in backups:
        backup_time = datetime.fromisoformat(backup['created'])
        if backup_time < target_datetime:
            return backup['path']

    return None

# Find backup before an incident
from datetime import datetime
target = datetime(2026, 1, 5, 14, 30)  # Before incident at 2:30 PM
backup_path = find_backup_before(target)
```

### Disaster Recovery

If the database file is corrupted:

```bash
#!/bin/bash
# disaster_recovery.sh

echo "NERVE Database Disaster Recovery"
echo "================================"

# 1. Stop the application
echo "Stopping application..."
systemctl stop nerve-app

# 2. Backup corrupted database (for analysis)
echo "Backing up corrupted database..."
mv /path/to/data/ghost.db /path/to/data/ghost.db.corrupted.$(date +%Y%m%d_%H%M%S)

# 3. Find latest good backup
LATEST_BACKUP=$(ls -t /path/to/data/backups/nerve_backup_*.db | head -1)
echo "Latest backup: $LATEST_BACKUP"

# 4. Restore from backup
echo "Restoring from backup..."
cp $LATEST_BACKUP /path/to/data/ghost.db

# 5. Restart application
echo "Starting application..."
systemctl start nerve-app

# 6. Verify
echo "Verifying..."
curl -s http://localhost:8000/api/health | jq

echo "Recovery complete"
```

---

## Health Monitoring

### Comprehensive Health Check

```python
from database import run_health_check
import json

def check_database_health():
    """Run comprehensive health check and report."""
    health = run_health_check()

    # Connection status
    conn = health['connection']
    print(f"Connection: {'OK' if conn['healthy'] else 'FAILED'}")
    if conn['latency_ms']:
        print(f"  Latency: {conn['latency_ms']} ms")

    # Table integrity
    tables = health['tables']
    print(f"Tables: {'OK' if tables['healthy'] else 'FAILED'}")
    print(f"  Checked: {tables['tables_checked']}")
    if tables['errors']:
        for error in tables['errors']:
            print(f"  ERROR: {error}")

    # Foreign keys
    fk = health['foreign_keys']
    print(f"Foreign Keys: {'OK' if fk['healthy'] else 'VIOLATIONS FOUND'}")
    if fk['violations']:
        for v in fk['violations']:
            print(f"  Violation: {v}")

    # Stats
    stats = health['stats']
    print(f"Database Size: {stats['size_mb']} MB")
    print(f"Total Records: {stats['total_records']}")

    # Performance
    perf = health['performance']
    print(f"Performance:")
    print(f"  Total Queries: {perf['total_queries']}")
    print(f"  Avg Duration: {perf['avg_duration_ms']} ms")
    print(f"  Slow Queries: {perf['slow_queries']}")

    # Return overall status
    return (
        conn['healthy'] and
        tables['healthy'] and
        fk['healthy']
    )
```

### Monitoring Integration

```python
# prometheus_metrics.py
from database import run_health_check, get_database_stats

def collect_metrics():
    """Collect metrics for Prometheus."""
    health = run_health_check()
    stats = get_database_stats()

    metrics = []

    # Connection health
    metrics.append(f'nerve_db_connection_healthy {1 if health["connection"]["healthy"] else 0}')

    # Connection latency
    if health['connection']['latency_ms']:
        metrics.append(f'nerve_db_connection_latency_ms {health["connection"]["latency_ms"]}')

    # Table integrity
    metrics.append(f'nerve_db_tables_healthy {1 if health["tables"]["healthy"] else 0}')
    metrics.append(f'nerve_db_tables_checked {health["tables"]["tables_checked"]}')

    # Database size
    metrics.append(f'nerve_db_size_bytes {stats["size_bytes"]}')
    metrics.append(f'nerve_db_total_records {stats["total_records"]}')

    # Per-table record counts
    for table, count in stats['table_counts'].items():
        metrics.append(f'nerve_db_table_records{{table="{table}"}} {count}')

    # Performance
    perf = health['performance']
    metrics.append(f'nerve_db_queries_total {perf["total_queries"]}')
    metrics.append(f'nerve_db_query_duration_avg_ms {perf["avg_duration_ms"]}')
    metrics.append(f'nerve_db_slow_queries {perf["slow_queries"]}')

    return '\n'.join(metrics)
```

### Alert Conditions

```python
def check_alerts():
    """Check for alert conditions."""
    from database import run_health_check, get_database_stats

    alerts = []
    health = run_health_check()
    stats = get_database_stats()

    # Critical: Connection failed
    if not health['connection']['healthy']:
        alerts.append({
            'severity': 'critical',
            'message': 'Database connection failed',
            'details': health['connection']['error']
        })

    # Warning: High latency
    if health['connection']['latency_ms'] and health['connection']['latency_ms'] > 100:
        alerts.append({
            'severity': 'warning',
            'message': f'High database latency: {health["connection"]["latency_ms"]}ms'
        })

    # Warning: Large database
    if stats['size_mb'] > 1000:  # 1GB
        alerts.append({
            'severity': 'warning',
            'message': f'Database size is {stats["size_mb"]}MB'
        })

    # Warning: Many slow queries
    if health['performance']['slow_queries'] > 10:
        alerts.append({
            'severity': 'warning',
            'message': f'{health["performance"]["slow_queries"]} slow queries detected'
        })

    # Critical: Table integrity issues
    if not health['tables']['healthy']:
        alerts.append({
            'severity': 'critical',
            'message': 'Table integrity check failed',
            'details': health['tables']['errors']
        })

    # Critical: Foreign key violations
    if not health['foreign_keys']['healthy']:
        alerts.append({
            'severity': 'critical',
            'message': 'Foreign key violations detected',
            'details': health['foreign_keys']['violations']
        })

    return alerts
```

---

## Performance Optimization

### Regular Optimization

```python
from database import optimize_database, get_performance_stats, clear_performance_log

def run_weekly_optimization():
    """Run weekly database optimization."""

    # Get pre-optimization stats
    pre_stats = get_performance_stats()
    print(f"Pre-optimization: {pre_stats['total_queries']} queries, "
          f"{pre_stats['avg_duration_ms']}ms avg")

    # Run optimization
    result = optimize_database()

    if result['success']:
        print(f"Optimization complete: {result['tasks_completed']}")
    else:
        print(f"Optimization failed: {result['error']}")
        return False

    # Clear performance log for fresh metrics
    clear_performance_log()
    print("Performance log cleared")

    return True
```

### Index Analysis

```python
def analyze_indexes():
    """Analyze index usage and suggest improvements."""
    import sqlite3
    from database import DB_PATH

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Get all indexes
    cursor.execute("SELECT name, tbl_name FROM sqlite_master WHERE type='index'")
    indexes = cursor.fetchall()

    print("Current Indexes:")
    for idx_name, table_name in indexes:
        cursor.execute(f"PRAGMA index_info({idx_name})")
        columns = [row[2] for row in cursor.fetchall()]
        print(f"  {table_name}.{idx_name}: {columns}")

    # Suggest indexes for common queries
    suggestions = []

    # Check for unindexed foreign keys
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cursor.fetchall()]

    for table in tables:
        cursor.execute(f"PRAGMA foreign_key_list({table})")
        fks = cursor.fetchall()

        for fk in fks:
            fk_column = fk[3]  # from column
            # Check if index exists
            has_index = False
            for idx_name, tbl in indexes:
                if tbl == table:
                    cursor.execute(f"PRAGMA index_info({idx_name})")
                    idx_cols = [row[2] for row in cursor.fetchall()]
                    if fk_column in idx_cols:
                        has_index = True
                        break

            if not has_index:
                suggestions.append(f"CREATE INDEX idx_{table}_{fk_column} ON {table}({fk_column})")

    if suggestions:
        print("\nSuggested Indexes:")
        for s in suggestions:
            print(f"  {s}")

    conn.close()
```

### Query Performance Analysis

```python
from database import get_slow_queries, get_performance_stats

def analyze_query_performance():
    """Analyze query performance and identify issues."""

    stats = get_performance_stats()
    print(f"Query Statistics:")
    print(f"  Total: {stats['total_queries']}")
    print(f"  Average: {stats['avg_duration_ms']}ms")
    print(f"  Maximum: {stats['max_duration_ms']}ms")
    print(f"  Slow (>1s): {stats['slow_queries']}")

    slow = get_slow_queries(threshold_ms=500)
    if slow:
        print(f"\nSlow Queries (>500ms):")
        for q in slow[:10]:  # Top 10
            print(f"  {q['duration_ms']}ms: {q['query'][:100]}...")
```

---

## Data Cleanup

### Session Cleanup

```python
from database import cleanup_expired_sessions

def cleanup_sessions():
    """Clean up expired sessions."""
    count = cleanup_expired_sessions()
    print(f"Cleaned up {count} expired sessions")
    return count
```

### Scan Data Cleanup

```python
from database import cleanup_old_scan_history, cleanup_expired_ai_scans

def cleanup_scan_data():
    """Clean up old scan data."""

    # Clean up AI scan results (48h expiry)
    cleanup_expired_ai_scans()

    # Clean up scan history older than 30 days
    cleanup_old_scan_history(days=30)

    print("Scan data cleanup complete")
```

### Soft-Deleted Records Cleanup

```python
from database import SessionLocal, User, Company
from datetime import datetime, timedelta, timezone

def purge_soft_deleted(days=90):
    """Permanently delete soft-deleted records older than N days."""

    session = SessionLocal()
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    # Tables with soft delete
    tables_with_soft_delete = [
        User, Company,
        # Add other models...
    ]

    total_purged = 0

    for model in tables_with_soft_delete:
        try:
            count = session.query(model).filter(
                model.deleted_at < cutoff,
                model.deleted_at.isnot(None)
            ).delete()
            total_purged += count
            print(f"Purged {count} records from {model.__tablename__}")
        except Exception as e:
            print(f"Error purging {model.__tablename__}: {e}")

    session.commit()
    session.close()

    print(f"Total purged: {total_purged} records")
    return total_purged
```

### Audit Log Rotation

```python
from database import SessionLocal, AuditLog
from datetime import datetime, timedelta, timezone

def rotate_audit_logs(keep_days=365):
    """Archive and delete old audit logs."""

    session = SessionLocal()
    cutoff = datetime.now(timezone.utc) - timedelta(days=keep_days)

    # Count records to be deleted
    count = session.query(AuditLog).filter(
        AuditLog.created_at < cutoff
    ).count()

    if count > 0:
        # Optional: Export to archive first
        # archive_audit_logs(cutoff)

        # Delete old records
        session.query(AuditLog).filter(
            AuditLog.created_at < cutoff
        ).delete()

        session.commit()
        print(f"Deleted {count} audit log entries older than {keep_days} days")

    session.close()
    return count
```

---

## Troubleshooting

### Common Issues

#### Database Locked

**Symptoms:** Operations fail with "database is locked" error.

**Solutions:**
```python
# Check for long-running connections
import sqlite3
from database import DB_PATH

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# Check if journal mode is WAL (better concurrency)
cursor.execute("PRAGMA journal_mode")
print(f"Journal mode: {cursor.fetchone()[0]}")

# Enable WAL mode if not already
cursor.execute("PRAGMA journal_mode=WAL")
conn.close()
```

#### Slow Queries

**Symptoms:** Operations take longer than expected.

**Solutions:**
```python
from database import get_slow_queries, optimize_database

# Find slow queries
slow = get_slow_queries(threshold_ms=100)
for q in slow:
    print(f"{q['duration_ms']}ms: {q['query'][:100]}")

# Run optimization
optimize_database()
```

#### Data Integrity Issues

**Symptoms:** Foreign key violations, missing records.

**Solutions:**
```python
from database import check_foreign_key_constraints, check_table_integrity

# Check constraints
fk = check_foreign_key_constraints()
if not fk['healthy']:
    for v in fk['violations']:
        print(f"FK violation: {v}")

# Check integrity
integrity = check_table_integrity()
if not integrity['healthy']:
    for e in integrity['errors']:
        print(f"Integrity error: {e}")
```

#### Connection Pool Exhaustion

**Symptoms:** "Too many connections" or timeout errors.

**Solutions:**
```python
# Monitor active sessions
from database import SessionLocal

# Ensure sessions are properly closed
from database import safe_db_session

with safe_db_session() as session:
    # Operations here
    pass
# Session automatically closed
```

### Database Repair

```python
import sqlite3
from database import DB_PATH, create_backup

def repair_database():
    """Attempt to repair a corrupted database."""

    # 1. Create backup first
    backup = create_backup()
    print(f"Backup created: {backup['backup_path']}")

    # 2. Connect and check integrity
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("PRAGMA integrity_check")
    result = cursor.fetchone()[0]

    if result == 'ok':
        print("Database integrity OK")
        conn.close()
        return True

    print(f"Integrity check: {result}")

    # 3. Export data to new database
    print("Attempting recovery...")

    new_db_path = DB_PATH + ".recovered"

    # Use .dump to export recoverable data
    with open('recovery.sql', 'w') as f:
        for line in conn.iterdump():
            f.write('%s\n' % line)

    conn.close()

    # Create new database from dump
    new_conn = sqlite3.connect(new_db_path)
    with open('recovery.sql', 'r') as f:
        new_conn.executescript(f.read())
    new_conn.close()

    print(f"Recovered database: {new_db_path}")
    print("Review recovered database before replacing original")

    return False
```

---

## Emergency Procedures

### Database Unresponsive

```bash
#!/bin/bash
# emergency_db_unresponsive.sh

echo "Emergency: Database Unresponsive"
echo "================================"

# 1. Check if file exists and is accessible
if [ -f "/path/to/data/ghost.db" ]; then
    echo "Database file exists"
    ls -la /path/to/data/ghost.db
else
    echo "ERROR: Database file not found!"
    exit 1
fi

# 2. Check for lock files
if [ -f "/path/to/data/ghost.db-wal" ]; then
    echo "WAL file exists (writes pending)"
fi

if [ -f "/path/to/data/ghost.db-shm" ]; then
    echo "SHM file exists (shared memory)"
fi

# 3. Check disk space
df -h /path/to/data/

# 4. Check file permissions
stat /path/to/data/ghost.db

# 5. Test with sqlite3 directly
echo "Testing database..."
sqlite3 /path/to/data/ghost.db "SELECT COUNT(*) FROM users;" 2>&1

# 6. If all else fails, restart with recovery
echo ""
echo "If database is still unresponsive:"
echo "1. Stop the application"
echo "2. Copy WAL file content: sqlite3 ghost.db 'PRAGMA wal_checkpoint(TRUNCATE);'"
echo "3. Start the application"
```

### Complete Recovery Procedure

```bash
#!/bin/bash
# complete_recovery.sh

echo "Complete Database Recovery"
echo "========================="

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DATA_DIR="/path/to/data"
BACKUP_DIR="$DATA_DIR/backups"

# 1. Stop application
echo "Step 1: Stopping application..."
systemctl stop nerve-app

# 2. Save current state
echo "Step 2: Saving current state..."
mkdir -p "$DATA_DIR/recovery_$TIMESTAMP"
cp "$DATA_DIR/ghost.db"* "$DATA_DIR/recovery_$TIMESTAMP/" 2>/dev/null

# 3. Find best backup
echo "Step 3: Finding best backup..."
LATEST_BACKUP=$(ls -t $BACKUP_DIR/nerve_backup_*.db 2>/dev/null | head -1)

if [ -z "$LATEST_BACKUP" ]; then
    echo "ERROR: No backups found!"
    exit 1
fi

echo "Latest backup: $LATEST_BACKUP"

# 4. Verify backup
echo "Step 4: Verifying backup..."
sqlite3 "$LATEST_BACKUP" "PRAGMA integrity_check;" 2>&1

# 5. Restore from backup
echo "Step 5: Restoring from backup..."
rm -f "$DATA_DIR/ghost.db" "$DATA_DIR/ghost.db-wal" "$DATA_DIR/ghost.db-shm"
cp "$LATEST_BACKUP" "$DATA_DIR/ghost.db"

# 6. Verify restored database
echo "Step 6: Verifying restored database..."
sqlite3 "$DATA_DIR/ghost.db" "PRAGMA integrity_check;"

# 7. Start application
echo "Step 7: Starting application..."
systemctl start nerve-app

# 8. Verify application health
echo "Step 8: Verifying application health..."
sleep 5
curl -s http://localhost:8000/api/health | jq

echo ""
echo "Recovery complete!"
echo "Original files saved to: $DATA_DIR/recovery_$TIMESTAMP/"
```

### Contact Information

For critical database issues:
- Check logs: `/var/log/nerve/database.log`
- Monitor dashboard: `http://monitoring.example.com/nerve`
- Emergency contact: [Team Contact Info]

---

*Last updated: January 2026*
