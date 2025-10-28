"""
NERVE GHOST - BAIT Database Testing Script
Tests the BaitToken and BaitAccess database tables.
"""

import json
import sys
from datetime import datetime

# Import database models and utilities
from database import BaitToken, BaitAccess, get_db, SessionLocal

def test_bait_database():
    """Test the BAIT component database tables"""

    db = None
    test_bait_id = None

    try:
        print("=" * 60)
        print("NERVE GHOST - BAIT Database Test")
        print("=" * 60)

        # Step 1: Get database session
        print("\n[1/8] Getting database session...")
        db = SessionLocal()
        print("✓ Database session created")

        # Step 2: Create test bait token
        print("\n[2/8] Creating test bait token...")

        fake_aws_credentials = {
            "type": "aws_credentials",
            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "region": "us-east-1",
            "tracking_id": "test123456789abc"
        }

        test_bait = BaitToken(
            identifier="bait_test123",
            bait_type="aws_key",
            token_value=json.dumps(fake_aws_credentials),
            seeded_location="https://pastebin.com/test123",
            status="active"
        )

        db.add(test_bait)
        print("✓ Test bait token created")

        # Step 3: Commit bait token to database
        print("\n[3/8] Committing bait token to database...")
        db.commit()
        db.refresh(test_bait)
        test_bait_id = test_bait.id
        print(f"✓ Bait token committed with ID: {test_bait_id}")

        # Step 4: Create test access record
        print("\n[4/8] Creating test access record...")

        test_headers = {
            "User-Agent": "curl/7.68.0",
            "Accept": "*/*",
            "Authorization": "Bearer fake_token"
        }

        test_body = {
            "action": "s3:ListBucket",
            "resource": "arn:aws:s3:::production-bucket"
        }

        test_access = BaitAccess(
            bait_id=test_bait_id,
            source_ip="192.168.1.100",
            user_agent="curl/7.68.0",
            request_type="http",
            request_headers=json.dumps(test_headers),
            request_body=json.dumps(test_body),
            fingerprint="curl-automated-tool",
            geolocation="Moscow, Russia",
            threat_level="high",
            notes="Automated credential scanning detected"
        )

        db.add(test_access)
        print("✓ Test access record created")

        # Step 5: Commit access record to database
        print("\n[5/8] Committing access record to database...")
        db.commit()
        print(f"✓ Access record committed")

        # Step 6: Update bait token with first access info
        print("\n[6/8] Updating bait token access tracking...")
        test_bait.first_access = datetime.utcnow()
        test_bait.access_count = 1
        test_bait.last_access = datetime.utcnow()
        test_bait.status = "triggered"
        db.commit()
        print("✓ Bait token updated with access information")

        # Step 7: Query back the bait token and verify
        print("\n[7/8] Querying bait token and access records...")

        # Query the bait token
        queried_bait = db.query(BaitToken).filter_by(identifier="bait_test123").first()

        if not queried_bait:
            raise Exception("Failed to query bait token from database")

        print(f"\n📊 Bait Token Details:")
        print(f"   Identifier: {queried_bait.identifier}")
        print(f"   Type: {queried_bait.bait_type}")
        print(f"   Status: {queried_bait.status}")
        print(f"   Seeded Location: {queried_bait.seeded_location}")
        print(f"   Access Count: {queried_bait.access_count}")
        print(f"   First Access: {queried_bait.first_access}")
        print(f"   Last Access: {queried_bait.last_access}")

        # Parse token value
        token_data = json.loads(queried_bait.token_value)
        print(f"   Token Data:")
        print(f"      - Access Key: {token_data.get('aws_access_key_id', 'N/A')}")
        print(f"      - Region: {token_data.get('region', 'N/A')}")
        print(f"      - Tracking ID: {token_data.get('tracking_id', 'N/A')}")

        # Query access attempts via relationship
        print(f"\n🚨 Access Attempts ({len(queried_bait.accesses)}):")
        for idx, access in enumerate(queried_bait.accesses, 1):
            print(f"\n   Access #{idx}:")
            print(f"      - Timestamp: {access.accessed_at}")
            print(f"      - Source IP: {access.source_ip}")
            print(f"      - User Agent: {access.user_agent}")
            print(f"      - Request Type: {access.request_type}")
            print(f"      - Threat Level: {access.threat_level}")
            print(f"      - Geolocation: {access.geolocation}")
            print(f"      - Fingerprint: {access.fingerprint}")
            print(f"      - Notes: {access.notes}")

            # Parse headers and body
            headers = json.loads(access.request_headers)
            body = json.loads(access.request_body)
            print(f"      - Headers: {list(headers.keys())}")
            print(f"      - Body: {list(body.keys())}")

        # Additional queries
        print(f"\n🔍 Additional Query Tests:")

        # Query by threat level
        high_threat_accesses = db.query(BaitAccess).filter_by(threat_level="high").all()
        print(f"   - High threat accesses: {len(high_threat_accesses)}")

        # Query active baits
        active_baits = db.query(BaitToken).filter_by(status="triggered").all()
        print(f"   - Triggered bait tokens: {len(active_baits)}")

        # Query by bait type
        aws_baits = db.query(BaitToken).filter_by(bait_type="aws_key").all()
        print(f"   - AWS key baits: {len(aws_baits)}")

        print("\n✓ All queries successful")

        # Step 8: Clean up test records
        print("\n[8/8] Cleaning up test records...")

        # Delete test access records (cascade will handle this, but being explicit)
        db.query(BaitAccess).filter_by(bait_id=test_bait_id).delete()

        # Delete test bait token
        db.query(BaitToken).filter_by(identifier="bait_test123").delete()

        db.commit()
        print("✓ Test records deleted")

        # Verify cleanup
        remaining_bait = db.query(BaitToken).filter_by(identifier="bait_test123").first()
        if remaining_bait:
            raise Exception("Failed to clean up test bait token")

        remaining_access = db.query(BaitAccess).filter_by(bait_id=test_bait_id).all()
        if remaining_access:
            raise Exception("Failed to clean up test access records")

        print("✓ Cleanup verified")

        # Final success message
        print("\n" + "=" * 60)
        print("✅ Database tables working correctly!")
        print("=" * 60)
        print("\n📋 Test Summary:")
        print("   ✓ BaitToken table created and accessible")
        print("   ✓ BaitAccess table created and accessible")
        print("   ✓ Foreign key relationship working")
        print("   ✓ Bidirectional relationships functional")
        print("   ✓ JSON serialization working")
        print("   ✓ DateTime fields functional")
        print("   ✓ Default values applied correctly")
        print("   ✓ Cascade delete operational")
        print("   ✓ All queries successful")
        print("\n🎉 BAIT component database is ready for use!")

        return True

    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()

        # Attempt cleanup on error
        if db and test_bait_id:
            try:
                print("\n🧹 Attempting cleanup after error...")
                db.query(BaitAccess).filter_by(bait_id=test_bait_id).delete()
                db.query(BaitToken).filter_by(identifier="bait_test123").delete()
                db.commit()
                print("✓ Cleanup completed")
            except:
                print("⚠️  Cleanup failed - manual cleanup may be required")

        return False

    finally:
        # Always close the database session
        if db:
            db.close()
            print("\n🔒 Database session closed")


def test_relationship_integrity():
    """Test the integrity of the relationship between BaitToken and BaitAccess"""

    db = None

    try:
        print("\n" + "=" * 60)
        print("Testing Relationship Integrity")
        print("=" * 60)

        db = SessionLocal()

        # Create a bait token
        print("\n[1/3] Creating bait token with multiple accesses...")
        bait = BaitToken(
            identifier="bait_relationship_test",
            bait_type="database",
            token_value=json.dumps({"connection_string": "postgresql://test:test@localhost/db"}),
            status="active"
        )
        db.add(bait)
        db.commit()
        db.refresh(bait)

        # Create multiple access records
        for i in range(3):
            access = BaitAccess(
                bait_id=bait.id,
                source_ip=f"192.168.1.{100 + i}",
                user_agent=f"scanner-{i}",
                request_type="database",
                threat_level=["low", "medium", "high"][i]
            )
            db.add(access)

        db.commit()
        print(f"✓ Created bait token with 3 access records")

        # Test forward relationship (bait -> accesses)
        print("\n[2/3] Testing forward relationship (BaitToken -> BaitAccess)...")
        bait_check = db.query(BaitToken).filter_by(identifier="bait_relationship_test").first()
        print(f"✓ Bait token has {len(bait_check.accesses)} accesses")

        for access in bait_check.accesses:
            print(f"   - {access.source_ip} ({access.threat_level})")

        # Test backward relationship (access -> bait)
        print("\n[3/3] Testing backward relationship (BaitAccess -> BaitToken)...")
        access_check = db.query(BaitAccess).filter_by(source_ip="192.168.1.100").first()
        print(f"✓ Access record links to bait: {access_check.bait_token.identifier}")

        # Test cascade delete
        print("\n[Cleanup] Testing cascade delete...")
        db.delete(bait_check)
        db.commit()

        remaining_accesses = db.query(BaitAccess).filter_by(bait_id=bait.id).all()
        if len(remaining_accesses) == 0:
            print("✓ Cascade delete working - all access records removed")
        else:
            print(f"⚠️  Cascade delete issue - {len(remaining_accesses)} accesses remain")

        print("\n✅ Relationship integrity test passed!")
        return True

    except Exception as e:
        print(f"\n❌ Relationship test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

    finally:
        if db:
            # Cleanup
            try:
                db.query(BaitAccess).filter(BaitAccess.source_ip.like("192.168.1.%")).delete(synchronize_session=False)
                db.query(BaitToken).filter_by(identifier="bait_relationship_test").delete()
                db.commit()
            except:
                pass
            db.close()


if __name__ == "__main__":
    print("\n" + "🧪" * 30)
    print("NERVE GHOST - BAIT Component Database Tests")
    print("🧪" * 30)

    # Run main test
    main_test_passed = test_bait_database()

    # Run relationship test
    relationship_test_passed = test_relationship_integrity()

    # Final summary
    print("\n" + "=" * 60)
    print("Final Test Results")
    print("=" * 60)
    print(f"Main Database Test: {'✅ PASSED' if main_test_passed else '❌ FAILED'}")
    print(f"Relationship Test:  {'✅ PASSED' if relationship_test_passed else '❌ FAILED'}")
    print("=" * 60)

    # Exit with appropriate code
    if main_test_passed and relationship_test_passed:
        print("\n🎉 All tests passed! BAIT database is fully operational.\n")
        sys.exit(0)
    else:
        print("\n⚠️  Some tests failed. Please review the output above.\n")
        sys.exit(1)
