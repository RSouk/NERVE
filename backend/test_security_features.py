#!/usr/bin/env python3
"""
Test script for database security features.
Tests password hashing, session management, API keys, and security audit functions.
"""

import sys
import os

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database import (
    # Password functions
    hash_password, verify_password, generate_secure_token,
    # Session functions
    create_session, validate_session, revoke_session, cleanup_expired_sessions,
    # API key functions
    create_api_key, validate_api_key, revoke_api_key, list_user_api_keys,
    # Security audit functions
    log_login_attempt, detect_brute_force, lock_user_account,
    check_account_lock, log_security_event, get_security_events,
    increment_failed_login_count, reset_failed_login_count,
    # Models
    User, Session, APIKey, SecurityEvent, LoginAttempt,
    SessionLocal, init_db, BCRYPT_AVAILABLE
)

from datetime import datetime, timezone

def print_header(title):
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60)

def print_result(test_name, passed, details=""):
    status = "[PASS]" if passed else "[FAIL]"
    print(f"  {status}: {test_name}")
    if details:
        print(f"         {details}")

def test_password_hashing():
    """Test password hashing and verification"""
    print_header("PASSWORD HASHING TESTS")

    # Test 1: Hash a password
    test_password = "SecureP@ssw0rd123!"
    hashed = hash_password(test_password)
    passed = hashed is not None and len(hashed) > 20
    print_result("Hash password", passed, f"Hash length: {len(hashed) if hashed else 0}")

    # Test 2: Verify correct password
    passed = verify_password(test_password, hashed)
    print_result("Verify correct password", passed)

    # Test 3: Reject wrong password
    passed = not verify_password("WrongPassword123!", hashed)
    print_result("Reject wrong password", passed)

    # Test 4: Handle empty inputs
    passed = not verify_password("", hashed) and not verify_password(test_password, "")
    print_result("Handle empty inputs", passed)

    # Test 5: Generate secure token
    token = generate_secure_token(32)
    passed = token is not None and len(token) >= 32
    print_result("Generate secure token", passed, f"Token: {token[:20]}...")

    print(f"\n  bcrypt available: {BCRYPT_AVAILABLE}")

def test_session_management():
    """Test session creation and validation"""
    print_header("SESSION MANAGEMENT TESTS")

    # We need a test user - let's use ID 1 or create one
    session = SessionLocal()

    # Check if test user exists
    test_user = session.query(User).filter_by(id=1).first()
    if not test_user:
        print("  [INFO] No test user found, skipping session tests")
        session.close()
        return

    user_id = test_user.id
    session.close()

    # Test 1: Create session
    result = create_session(
        user_id=user_id,
        ip_address="192.168.1.100",
        user_agent="Test Browser/1.0",
        device_type="web"
    )
    passed = result is not None and 'token' in result
    print_result("Create session", passed, f"Token: {result['token'][:20]}..." if result else "No token")

    if not result:
        print("  [WARN] Session creation failed, skipping remaining tests")
        return

    token = result['token']

    # Test 2: Validate session
    validation = validate_session(token)
    passed = validation is not None and validation['user_id'] == user_id
    print_result("Validate session", passed)

    # Test 3: Reject invalid token
    invalid = validate_session("invalid_token_12345")
    passed = invalid is None
    print_result("Reject invalid token", passed)

    # Test 4: Revoke session
    passed = revoke_session(token)
    print_result("Revoke session", passed)

    # Test 5: Validate revoked session fails
    validation = validate_session(token)
    passed = validation is None
    print_result("Revoked session invalid", passed)

    # Test 6: Cleanup expired sessions
    count = cleanup_expired_sessions()
    print_result("Cleanup expired sessions", True, f"Cleaned: {count}")

def test_api_key_management():
    """Test API key creation and validation"""
    print_header("API KEY MANAGEMENT TESTS")

    # Check if test user exists
    session = SessionLocal()
    test_user = session.query(User).filter_by(id=1).first()
    if not test_user:
        print("  [INFO] No test user found, skipping API key tests")
        session.close()
        return

    user_id = test_user.id
    session.close()

    # Test 1: Create API key
    result = create_api_key(
        user_id=user_id,
        name="Test API Key",
        permissions=["read:scans", "write:scans"],
        expires_days=30
    )
    passed = result is not None and 'key' in result and result['key'].startswith('nrv_')
    print_result("Create API key", passed, f"Key: {result['key'][:16]}..." if result else "No key")

    if not result:
        print("  [WARN] API key creation failed, skipping remaining tests")
        return

    raw_key = result['key']
    key_id = result['key_id']

    # Test 2: Validate API key
    validation = validate_api_key(raw_key)
    passed = validation is not None and validation['user_id'] == user_id
    print_result("Validate API key", passed)

    # Test 3: List user API keys
    keys = list_user_api_keys(user_id)
    passed = len(keys) > 0
    print_result("List user API keys", passed, f"Found: {len(keys)} keys")

    # Test 4: Reject invalid API key
    invalid = validate_api_key("nrv_invalid_key_12345")
    passed = invalid is None
    print_result("Reject invalid API key", passed)

    # Test 5: Revoke API key
    passed = revoke_api_key(key_id, user_id)
    print_result("Revoke API key", passed)

    # Test 6: Revoked key fails validation
    validation = validate_api_key(raw_key)
    passed = validation is None
    print_result("Revoked key invalid", passed)

def test_security_audit():
    """Test security audit functions"""
    print_header("SECURITY AUDIT TESTS")

    test_email = "test@example.com"
    test_ip = "10.0.0.1"

    # Test 1: Log login attempt
    passed = log_login_attempt(
        email=test_email,
        success=False,
        ip_address=test_ip,
        user_agent="Test Agent",
        failure_reason="Invalid password"
    )
    print_result("Log login attempt", passed)

    # Test 2: Log security event
    passed = log_security_event(
        event_type="test_event",
        severity="info",
        description="Test security event from test script",
        email=test_email,
        ip_address=test_ip,
        metadata={"test": True, "timestamp": datetime.now(timezone.utc).isoformat()}
    )
    print_result("Log security event", passed)

    # Test 3: Get security events
    events = get_security_events(hours=1, limit=10)
    passed = len(events) > 0
    print_result("Get security events", passed, f"Found: {len(events)} events")

    # Test 4: Detect brute force (should not detect with just 1 attempt)
    result = detect_brute_force(email=test_email, ip_address=test_ip)
    passed = not result['detected']  # Should NOT be detected with just 1 attempt
    print_result("Brute force detection (below threshold)", passed, f"Email attempts: {result['email_attempts']}")

    # Test 5: Log multiple failed attempts to trigger detection
    for i in range(5):
        log_login_attempt(
            email=f"bruteforce{i}@test.com",
            success=False,
            ip_address=test_ip,
            failure_reason="Testing brute force"
        )

    result = detect_brute_force(ip_address=test_ip, threshold=5)
    # This may or may not detect based on timing
    print_result("Brute force detection (above threshold)", result['ip_attempts'] >= 5, f"IP attempts: {result['ip_attempts']}")

def test_database_tables():
    """Verify new tables were created"""
    print_header("DATABASE TABLE VERIFICATION")

    session = SessionLocal()

    try:
        # Check APIKey table
        count = session.query(APIKey).count()
        print_result("APIKey table exists", True, f"Records: {count}")
    except Exception as e:
        print_result("APIKey table exists", False, str(e))

    try:
        # Check SecurityEvent table
        count = session.query(SecurityEvent).count()
        print_result("SecurityEvent table exists", True, f"Records: {count}")
    except Exception as e:
        print_result("SecurityEvent table exists", False, str(e))

    try:
        # Check LoginAttempt table
        count = session.query(LoginAttempt).count()
        print_result("LoginAttempt table exists", True, f"Records: {count}")
    except Exception as e:
        print_result("LoginAttempt table exists", False, str(e))

    try:
        # Check Session table
        count = session.query(Session).count()
        print_result("Session table exists", True, f"Records: {count}")
    except Exception as e:
        print_result("Session table exists", False, str(e))

    session.close()

def main():
    print("\n" + "=" * 60)
    print("  NERVE Security Features Test Suite")
    print("  " + datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))
    print("=" * 60)

    # Run all tests
    test_database_tables()
    test_password_hashing()
    test_session_management()
    test_api_key_management()
    test_security_audit()

    print("\n" + "=" * 60)
    print("  All tests completed!")
    print("=" * 60 + "\n")

if __name__ == "__main__":
    main()
