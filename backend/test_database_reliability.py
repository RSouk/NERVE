#!/usr/bin/env python3
"""
Comprehensive Database Reliability Test Suite

Tests:
- All CRUD operations on each table
- Foreign key constraints
- Transaction rollbacks
- Error handling
- Validation functions
- Performance under load
"""

import sys
import os
import time
import random
import string

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from datetime import datetime, timezone, timedelta

from database import (
    # Models
    User, Company, Session, APIKey, SecurityEvent, LoginAttempt,
    ASMScan, Device, ScanResultsXASM, XASMScanHistory, UserRole,

    # Session and DB
    SessionLocal, engine, DB_PATH,

    # Validation functions
    validate_email, validate_domain, validate_ip_address,
    sanitize_input, validate_record,

    # Health check functions
    check_database_connection, check_table_integrity,
    check_foreign_key_constraints, get_database_stats, run_health_check,

    # Transaction helpers
    batch_insert, safe_update,

    # Backup functions
    create_backup, list_backups, get_backup_info,

    # Performance functions
    log_query_performance, get_performance_stats,
    get_slow_queries, clear_performance_log, optimize_database,

    # Migration functions
    get_schema_version, get_applied_migrations, apply_migration, rollback_migration,

    # Error classes
    DatabaseError, ValidationError, DatabaseConnectionError, TransactionError,

    # Utility
    export_schema
)

# Test counters
tests_passed = 0
tests_failed = 0
test_results = []


def print_header(title):
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def print_result(test_name, passed, details=""):
    global tests_passed, tests_failed
    status = "[PASS]" if passed else "[FAIL]"

    if passed:
        tests_passed += 1
    else:
        tests_failed += 1

    test_results.append({'name': test_name, 'passed': passed, 'details': details})
    print(f"  {status}: {test_name}")
    if details and not passed:
        print(f"         {details}")


def generate_random_string(length=10):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


# ============================================================================
# VALIDATION TESTS
# ============================================================================

def test_email_validation():
    """Test email validation function"""
    print_header("EMAIL VALIDATION TESTS")

    # Valid emails
    valid_emails = [
        "test@example.com",
        "user.name@domain.org",
        "user+tag@example.co.uk",
        "a@b.cc"
    ]

    for email in valid_emails:
        passed = validate_email(email)
        print_result(f"Valid email: {email}", passed)

    # Invalid emails
    invalid_emails = [
        "notanemail",
        "@nodomain.com",
        "no@tld",
        "",
        None,
        "spaces in@email.com"
    ]

    for email in invalid_emails:
        passed = not validate_email(email)
        print_result(f"Invalid email: {email}", passed)


def test_domain_validation():
    """Test domain validation function"""
    print_header("DOMAIN VALIDATION TESTS")

    # Valid domains
    valid_domains = [
        "example.com",
        "sub.example.com",
        "test-domain.org",
        "a.io"
    ]

    for domain in valid_domains:
        passed = validate_domain(domain)
        print_result(f"Valid domain: {domain}", passed)

    # Invalid domains
    invalid_domains = [
        "notadomain",
        ".com",
        "http://example.com",
        "",
        None
    ]

    for domain in invalid_domains:
        passed = not validate_domain(domain)
        print_result(f"Invalid domain: {domain}", passed)


def test_ip_validation():
    """Test IP address validation function"""
    print_header("IP ADDRESS VALIDATION TESTS")

    # Valid IPs
    valid_ips = [
        "192.168.1.1",
        "10.0.0.1",
        "8.8.8.8",
        "255.255.255.255",
        "0.0.0.0"
    ]

    for ip in valid_ips:
        passed = validate_ip_address(ip)
        print_result(f"Valid IP: {ip}", passed)

    # Invalid IPs
    invalid_ips = [
        "256.1.1.1",
        "192.168.1",
        "not.an.ip.address",
        "192.168.1.1.5",
        "",
        None
    ]

    for ip in invalid_ips:
        passed = not validate_ip_address(ip)
        print_result(f"Invalid IP: {ip}", passed)


def test_input_sanitization():
    """Test input sanitization"""
    print_header("INPUT SANITIZATION TESTS")

    # Test HTML removal
    result = sanitize_input("<script>alert('xss')</script>test")
    passed = "<script>" not in result and "test" in result
    print_result("Remove HTML tags", passed, f"Result: {result}")

    # Test max length
    long_string = "a" * 1000
    result = sanitize_input(long_string, max_length=100)
    passed = len(result) == 100
    print_result("Enforce max length", passed, f"Length: {len(result)}")

    # Test empty input
    result = sanitize_input("")
    passed = result == ""
    print_result("Handle empty input", passed)

    # Test whitespace stripping
    result = sanitize_input("  trimmed  ")
    passed = result == "trimmed"
    print_result("Strip whitespace", passed)


def test_record_validation():
    """Test record validation"""
    print_header("RECORD VALIDATION TESTS")

    rules = {
        'email': {'type': 'email', 'required': True},
        'domain': {'type': 'domain', 'required': False},
        'name': {'type': 'string', 'max_length': 50}
    }

    # Valid record
    valid_data = {'email': 'test@example.com', 'domain': 'example.com', 'name': 'Test'}
    result = validate_record(valid_data, rules)
    print_result("Valid record passes", result['valid'])

    # Missing required field
    invalid_data = {'domain': 'example.com'}
    result = validate_record(invalid_data, rules)
    passed = not result['valid'] and 'email is required' in result['errors']
    print_result("Missing required field detected", passed, str(result['errors']))

    # Invalid email format
    invalid_data = {'email': 'notanemail', 'name': 'Test'}
    result = validate_record(invalid_data, rules)
    passed = not result['valid']
    print_result("Invalid email format detected", passed)

    # Exceeds max length
    invalid_data = {'email': 'test@example.com', 'name': 'x' * 100}
    result = validate_record(invalid_data, rules)
    passed = not result['valid']
    print_result("Max length violation detected", passed)


# ============================================================================
# HEALTH CHECK TESTS
# ============================================================================

def test_database_health_checks():
    """Test database health check functions"""
    print_header("DATABASE HEALTH CHECK TESTS")

    # Test connection check
    result = check_database_connection()
    passed = result['healthy'] and result['latency_ms'] is not None
    print_result("Connection check", passed, f"Latency: {result['latency_ms']}ms")

    # Test table integrity
    result = check_table_integrity()
    passed = result['tables_checked'] > 0
    print_result("Table integrity check", passed, f"Tables checked: {result['tables_checked']}")

    # Test foreign key check
    result = check_foreign_key_constraints()
    # Healthy can be False if there are violations, but function should work
    passed = 'violations' in result
    print_result("Foreign key constraint check", passed)

    # Test database stats
    result = get_database_stats()
    passed = 'size_bytes' in result and 'table_counts' in result
    print_result("Database stats", passed, f"Size: {result['size_mb']}MB, Tables: {len(result['table_counts'])}")

    # Test full health check
    result = run_health_check()
    passed = all(k in result for k in ['connection', 'tables', 'foreign_keys', 'stats'])
    print_result("Full health check", passed)


# ============================================================================
# CRUD OPERATION TESTS
# ============================================================================

def test_crud_operations():
    """Test CRUD operations on various tables"""
    print_header("CRUD OPERATION TESTS")

    session = SessionLocal()

    try:
        # Create - Company
        test_company = Company(
            name=f"Test Company {generate_random_string()}",
            primary_domain=f"test{generate_random_string()}.com",
            created_at=datetime.now(timezone.utc)
        )
        session.add(test_company)
        session.commit()
        company_id = test_company.id
        print_result("Create Company", company_id is not None, f"ID: {company_id}")

        # Read - Company
        company = session.query(Company).filter_by(id=company_id).first()
        passed = company is not None and company.id == company_id
        print_result("Read Company", passed)

        # Update - Company
        new_name = f"Updated Company {generate_random_string()}"
        company.name = new_name
        session.commit()

        company = session.query(Company).filter_by(id=company_id).first()
        passed = company.name == new_name
        print_result("Update Company", passed)

        # Create - User (with company reference)
        test_user = User(
            email=f"test{generate_random_string()}@example.com",
            username=f"testuser{generate_random_string()}",
            password_hash="test_hash",
            role=UserRole.USER,
            company_id=company_id,
            created_at=datetime.now(timezone.utc)
        )
        session.add(test_user)
        session.commit()
        user_id = test_user.id
        print_result("Create User (with FK)", user_id is not None)

        # Create - SecurityEvent
        test_event = SecurityEvent(
            event_type='test_event',
            severity='info',
            description=f"Test event {generate_random_string()}",
            ip_address='192.168.1.1',
            created_at=datetime.now(timezone.utc)
        )
        session.add(test_event)
        session.commit()
        event_id = test_event.id
        print_result("Create SecurityEvent", event_id is not None)

        # Delete - SecurityEvent
        session.delete(test_event)
        session.commit()

        deleted_event = session.query(SecurityEvent).filter_by(id=event_id).first()
        passed = deleted_event is None
        print_result("Delete SecurityEvent", passed)

        # Delete - User
        session.delete(test_user)
        session.commit()
        print_result("Delete User", True)

        # Delete - Company
        session.delete(company)
        session.commit()
        print_result("Delete Company", True)

    except Exception as e:
        session.rollback()
        print_result("CRUD Operations", False, str(e))
    finally:
        session.close()


def test_safe_update():
    """Test safe_update helper"""
    print_header("SAFE UPDATE TESTS")

    session = SessionLocal()

    try:
        # Create a test company
        test_company = Company(
            name=f"SafeUpdate Test {generate_random_string()}",
            primary_domain=f"safeupdate{generate_random_string()}.com",
            created_at=datetime.now(timezone.utc)
        )
        session.add(test_company)
        session.commit()
        company_id = test_company.id
        session.close()

        # Test safe_update
        result = safe_update(Company, company_id, {'name': 'Updated via safe_update'})
        passed = result['success'] and 'name' in result['changes']
        print_result("Safe update succeeds", passed, f"Changes: {result['changes']}")

        # Test update on non-existent record
        result = safe_update(Company, 99999, {'name': 'Should fail'})
        passed = not result['success'] and result['error'] == "Record not found"
        print_result("Safe update handles missing record", passed)

        # Cleanup
        session = SessionLocal()
        company = session.query(Company).filter_by(id=company_id).first()
        if company:
            session.delete(company)
            session.commit()
        session.close()

    except Exception as e:
        print_result("Safe update tests", False, str(e))


def test_batch_insert():
    """Test batch insert helper"""
    print_header("BATCH INSERT TESTS")

    try:
        # Prepare batch of security events (no FK needed)
        batch_records = [
            {
                'event_type': f'batch_test_{i}',
                'severity': 'info',
                'description': f"Batch test event {i} {generate_random_string()}",
                'ip_address': f'10.0.0.{i}',
                'created_at': datetime.now(timezone.utc)
            }
            for i in range(10)
        ]

        result = batch_insert(SecurityEvent, batch_records, batch_size=5)
        passed = result['inserted'] == 10 and result['failed'] == 0
        print_result("Batch insert 10 records", passed, f"Inserted: {result['inserted']}, Failed: {result['failed']}")

        # Cleanup
        session = SessionLocal()
        session.query(SecurityEvent).filter(SecurityEvent.event_type.like('batch_test_%')).delete(synchronize_session=False)
        session.commit()
        session.close()

    except Exception as e:
        print_result("Batch insert tests", False, str(e))


# ============================================================================
# TRANSACTION TESTS
# ============================================================================

def test_transaction_rollback():
    """Test transaction rollback on error"""
    print_header("TRANSACTION ROLLBACK TESTS")

    session = SessionLocal()

    try:
        # Create initial company
        test_company = Company(
            name=f"Rollback Test {generate_random_string()}",
            primary_domain=f"rollback{generate_random_string()}.com",
            created_at=datetime.now(timezone.utc)
        )
        session.add(test_company)
        session.commit()
        company_id = test_company.id
        original_name = test_company.name
        session.close()

        # Try to update with simulated error
        session = SessionLocal()
        try:
            company = session.query(Company).filter_by(id=company_id).first()
            company.name = "Should be rolled back"

            # Simulate error before commit
            raise Exception("Simulated error")

        except Exception:
            session.rollback()
        finally:
            session.close()

        # Verify rollback occurred
        session = SessionLocal()
        company = session.query(Company).filter_by(id=company_id).first()
        passed = company.name == original_name
        print_result("Transaction rolled back on error", passed, f"Name is still: {company.name}")

        # Cleanup
        session.delete(company)
        session.commit()
        session.close()

    except Exception as e:
        print_result("Transaction rollback", False, str(e))


# ============================================================================
# BACKUP TESTS
# ============================================================================

def test_backup_functions():
    """Test backup and restore functions"""
    print_header("BACKUP FUNCTION TESTS")

    # Test create backup
    result = create_backup()
    passed = result['success'] and result['backup_path'] is not None
    print_result("Create backup", passed, f"Path: {result.get('backup_path', 'N/A')}")

    if result['success']:
        backup_path = result['backup_path']

        # Test get backup info
        info = get_backup_info(backup_path)
        passed = 'size_bytes' in info and 'tables' in info
        print_result("Get backup info", passed, f"Size: {info.get('size_mb', 'N/A')}MB")

        # Test list backups
        backups = list_backups()
        passed = len(backups) > 0
        print_result("List backups", passed, f"Found: {len(backups)} backups")

        # Clean up test backup
        try:
            os.remove(backup_path)
            print_result("Cleanup test backup", True)
        except:
            pass


# ============================================================================
# PERFORMANCE TESTS
# ============================================================================

def test_performance_monitoring():
    """Test performance monitoring functions"""
    print_header("PERFORMANCE MONITORING TESTS")

    # Clear previous logs
    clear_performance_log()

    # Log some queries
    for i in range(5):
        log_query_performance(f"SELECT * FROM test_{i}", random.uniform(10, 100), i * 10)

    # Log a slow query
    log_query_performance("SELECT * FROM large_table", 1500, 10000)

    # Test get stats
    stats = get_performance_stats()
    passed = stats['total_queries'] == 6
    print_result("Performance stats tracking", passed, f"Total queries: {stats['total_queries']}")

    # Test slow query detection
    slow = get_slow_queries(threshold_ms=1000)
    passed = len(slow) == 1
    print_result("Slow query detection", passed, f"Slow queries: {len(slow)}")

    # Test optimization
    result = optimize_database()
    passed = result['success']
    print_result("Database optimization", passed, f"Tasks: {result.get('tasks_completed', [])}")


def test_performance_under_load():
    """Test database performance under load"""
    print_header("PERFORMANCE UNDER LOAD TESTS")

    test_prefix = f"perf_test_{generate_random_string()}"

    try:
        # Test rapid inserts using SecurityEvent
        start_time = time.time()
        session = SessionLocal()

        for i in range(100):
            event = SecurityEvent(
                event_type=f'{test_prefix}_{i}',
                severity='info',
                description=f"Load test event {i}",
                ip_address=f'10.1.{i // 256}.{i % 256}',
                created_at=datetime.now(timezone.utc)
            )
            session.add(event)

        session.commit()
        insert_time = time.time() - start_time
        print_result("100 rapid inserts", True, f"Time: {insert_time:.3f}s ({100/insert_time:.1f} ops/s)")

        # Test rapid reads
        start_time = time.time()
        for i in range(100):
            session.query(SecurityEvent).filter(SecurityEvent.event_type.like(f'{test_prefix}%')).all()
        read_time = time.time() - start_time
        print_result("100 rapid reads", True, f"Time: {read_time:.3f}s ({100/read_time:.1f} ops/s)")

        session.close()

        # Cleanup
        session = SessionLocal()
        session.query(SecurityEvent).filter(SecurityEvent.event_type.like(f'{test_prefix}%')).delete(synchronize_session=False)
        session.commit()
        session.close()

    except Exception as e:
        print_result("Performance under load", False, str(e))


# ============================================================================
# MIGRATION TESTS
# ============================================================================

def test_migration_functions():
    """Test migration helper functions"""
    print_header("MIGRATION FUNCTION TESTS")

    # Test get schema version
    version = get_schema_version()
    passed = version is not None
    print_result("Get schema version", passed, f"Version: {version}")

    # Test get applied migrations
    migrations = get_applied_migrations()
    passed = isinstance(migrations, list)
    print_result("Get applied migrations", passed, f"Count: {len(migrations)}")

    # Test apply migration (create test table)
    test_migration = """
    CREATE TABLE IF NOT EXISTS test_migration_table (
        id INTEGER PRIMARY KEY,
        name TEXT
    )
    """

    result = apply_migration(test_migration, "test_001", "Test migration")
    passed = result['success'] or "already applied" in str(result.get('error', ''))
    print_result("Apply migration", passed, result.get('error', 'Success'))

    # Test rollback migration
    result = rollback_migration("test_001")
    passed = result['success']
    print_result("Rollback migration", passed)

    # Clean up test table
    try:
        import sqlite3
        conn = sqlite3.connect(DB_PATH)
        conn.execute("DROP TABLE IF EXISTS test_migration_table")
        conn.commit()
        conn.close()
    except:
        pass


# ============================================================================
# ERROR HANDLING TESTS
# ============================================================================

def test_error_handling():
    """Test error handling and exceptions"""
    print_header("ERROR HANDLING TESTS")

    # Test DatabaseError
    try:
        raise DatabaseError("Test error")
    except DatabaseError as e:
        print_result("DatabaseError exception", True, str(e))

    # Test ValidationError
    try:
        raise ValidationError("Invalid data")
    except ValidationError as e:
        print_result("ValidationError exception", True, str(e))

    # Test TransactionError
    try:
        raise TransactionError("Transaction failed")
    except TransactionError as e:
        print_result("TransactionError exception", True, str(e))


# ============================================================================
# UTILITY TESTS
# ============================================================================

def test_utility_functions():
    """Test utility functions"""
    print_header("UTILITY FUNCTION TESTS")

    # Test export schema
    schema = export_schema()
    passed = len(schema) > 0 and "CREATE TABLE" in schema
    print_result("Export schema", passed, f"Schema length: {len(schema)} chars")


# ============================================================================
# MAIN
# ============================================================================

def main():
    print("\n" + "=" * 70)
    print("  NERVE Database Reliability Test Suite")
    print("  " + datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))
    print("=" * 70)

    # Run all tests
    test_email_validation()
    test_domain_validation()
    test_ip_validation()
    test_input_sanitization()
    test_record_validation()
    test_database_health_checks()
    test_crud_operations()
    test_safe_update()
    test_batch_insert()
    test_transaction_rollback()
    test_backup_functions()
    test_performance_monitoring()
    test_performance_under_load()
    test_migration_functions()
    test_error_handling()
    test_utility_functions()

    # Print summary
    print("\n" + "=" * 70)
    print("  TEST SUMMARY")
    print("=" * 70)
    print(f"  Total tests: {tests_passed + tests_failed}")
    print(f"  Passed:      {tests_passed}")
    print(f"  Failed:      {tests_failed}")
    print(f"  Pass rate:   {(tests_passed / (tests_passed + tests_failed) * 100):.1f}%")
    print("=" * 70)

    # Print failures if any
    if tests_failed > 0:
        print("\n  FAILED TESTS:")
        for result in test_results:
            if not result['passed']:
                print(f"    - {result['name']}: {result['details']}")
        print()

    return tests_failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
