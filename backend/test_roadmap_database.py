"""
Comprehensive Test Script for Roadmap Database Tables
======================================================
Tests all functionality of the Roadmap feature database layer.

Run: python test_roadmap_database.py
"""
import json
import sys
from datetime import datetime, timezone, timedelta
from sqlalchemy import inspect

# Import database components
from database import (
    SessionLocal, Base, engine,
    RoadmapProfile, RoadmapTask, RoadmapUserTask,
    RoadmapAchievement, RoadmapProgressHistory, RoadmapTaskLibraryMeta
)


class TestResults:
    """Track test results"""
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors = []

    def success(self, msg):
        self.passed += 1
        print(f'[PASS] {msg}')

    def fail(self, msg):
        self.failed += 1
        self.errors.append(msg)
        print(f'[FAIL] {msg}')

    def summary(self):
        total = self.passed + self.failed
        print(f'\n{"="*60}')
        print(f'Test Results: {self.passed}/{total} passed')
        if self.errors:
            print(f'\nFailed tests:')
            for err in self.errors:
                print(f'  - {err}')
        return self.failed == 0


def test_tables_exist(results):
    """Verify all 6 roadmap tables exist in database"""
    print('\n--- Testing Table Existence ---')

    inspector = inspect(engine)
    tables = inspector.get_table_names()

    expected_tables = [
        'roadmap_profiles',
        'roadmap_tasks',
        'roadmap_user_tasks',
        'roadmap_achievements',
        'roadmap_progress_history',
        'roadmap_task_library_meta'
    ]

    for table in expected_tables:
        if table in tables:
            results.success(f'Table {table} exists')
        else:
            results.fail(f'Table {table} NOT found')


def test_create_profile(session, results):
    """Test creating a roadmap profile"""
    print('\n--- Testing Profile Creation ---')

    try:
        # Clean up any existing test data
        session.query(RoadmapProgressHistory).delete()
        session.query(RoadmapAchievement).delete()
        session.query(RoadmapUserTask).delete()
        session.query(RoadmapProfile).delete()
        session.commit()

        # Create test profile
        profile = RoadmapProfile(
            company_name='Test Healthcare Inc',
            company_size='small',
            industry='healthcare',
            employee_count=25,
            handles_pii=True,
            handles_payment_data=False,
            handles_health_data=True,
            handles_financial_data=False,
            current_security_score=0,
            target_security_score=75,
            current_measures=json.dumps(['basic_firewall', 'antivirus']),
            compliance_requirements=json.dumps(['hipaa', 'soc2']),
            assessment_responses=json.dumps({
                'has_mfa': False,
                'has_backup': False,
                'has_security_training': False
            })
        )
        session.add(profile)
        session.commit()

        results.success(f'Created test profile (ID: {profile.id})')

        # Verify profile was created correctly
        loaded = session.query(RoadmapProfile).get(profile.id)

        if loaded.company_name == 'Test Healthcare Inc':
            results.success('Profile company_name correct')
        else:
            results.fail('Profile company_name incorrect')

        if loaded.industry == 'healthcare':
            results.success('Profile industry correct')
        else:
            results.fail('Profile industry incorrect')

        if loaded.handles_health_data == True:
            results.success('Profile handles_health_data flag correct')
        else:
            results.fail('Profile handles_health_data flag incorrect')

        # Test JSON field deserialization
        compliance = json.loads(loaded.compliance_requirements)
        if 'hipaa' in compliance:
            results.success('JSON fields serialize/deserialize correctly')
        else:
            results.fail('JSON fields not working correctly')

        return profile

    except Exception as e:
        results.fail(f'Error creating profile: {e}')
        return None


def test_assign_tasks(session, profile, results):
    """Test assigning tasks to a profile"""
    print('\n--- Testing Task Assignment ---')

    if not profile:
        results.fail('No profile available for task assignment')
        return []

    try:
        # Assign 5 tasks: 3 from profile assessment, 2 from simulated scans
        tasks_to_assign = [
            # From profile assessment
            {
                'task_id': 'TASK_CLOSE_ADMIN',
                'source': 'profile',
                'phase': 1,
                'priority_order': 1
            },
            {
                'task_id': 'TASK_PASSWORD_POLICY',
                'source': 'profile',
                'phase': 1,
                'priority_order': 2
            },
            {
                'task_id': 'TASK_MFA_ENABLE',
                'source': 'profile',
                'phase': 1,
                'priority_order': 3
            },
            # From simulated XASM scan
            {
                'task_id': 'TASK_UPDATE_SSL',
                'source': 'xasm_scan',
                'phase': 2,
                'priority_order': 1,
                'source_reference_id': 12345,
                'finding_type': 'expired_ssl_certificate',
                'finding_severity': 'high',
                'scan_domain': 'test-healthcare.com',
                'scan_date': datetime.now(timezone.utc)
            },
            # From simulated Lightbox scan
            {
                'task_id': 'TASK_AUTOMATED_BACKUP',
                'source': 'lightbox_scan',
                'phase': 2,
                'priority_order': 2,
                'source_reference_id': 67890,
                'finding_type': 'no_backup_detected',
                'finding_severity': 'medium',
                'scan_domain': 'test-healthcare.com',
                'scan_date': datetime.now(timezone.utc)
            }
        ]

        assigned_tasks = []
        for task_data in tasks_to_assign:
            user_task = RoadmapUserTask(
                profile_id=profile.id,
                **task_data
            )
            session.add(user_task)
            assigned_tasks.append(user_task)

        session.commit()

        results.success(f'Assigned {len(assigned_tasks)} tasks to profile')

        # Verify tasks were assigned
        profile_tasks = session.query(RoadmapUserTask).filter_by(profile_id=profile.id).all()

        if len(profile_tasks) == 5:
            results.success('Correct number of tasks assigned')
        else:
            results.fail(f'Expected 5 tasks, found {len(profile_tasks)}')

        # Verify sources are correct
        profile_source = [t for t in profile_tasks if t.source == 'profile']
        scan_source = [t for t in profile_tasks if t.source in ['xasm_scan', 'lightbox_scan']]

        if len(profile_source) == 3:
            results.success('3 tasks from profile source')
        else:
            results.fail(f'Expected 3 profile tasks, found {len(profile_source)}')

        if len(scan_source) == 2:
            results.success('2 tasks from scan sources')
        else:
            results.fail(f'Expected 2 scan tasks, found {len(scan_source)}')

        return assigned_tasks

    except Exception as e:
        results.fail(f'Error assigning tasks: {e}')
        import traceback
        traceback.print_exc()
        return []


def test_update_task_status(session, profile, results):
    """Test updating task status and simulating progress"""
    print('\n--- Testing Task Status Updates ---')

    if not profile:
        results.fail('No profile available for status updates')
        return

    try:
        # Mark TASK_CLOSE_ADMIN as completed
        close_admin = session.query(RoadmapUserTask).filter_by(
            profile_id=profile.id,
            task_id='TASK_CLOSE_ADMIN'
        ).first()

        if close_admin:
            close_admin.status = 'completed'
            close_admin.started_at = datetime.now(timezone.utc) - timedelta(hours=2)
            close_admin.completed_at = datetime.now(timezone.utc)
            close_admin.user_notes = 'Moved admin portal behind VPN'
            session.commit()

            results.success('Marked TASK_CLOSE_ADMIN as completed')
        else:
            results.fail('Could not find TASK_CLOSE_ADMIN')

        # Mark TASK_PASSWORD_POLICY as in_progress
        password_policy = session.query(RoadmapUserTask).filter_by(
            profile_id=profile.id,
            task_id='TASK_PASSWORD_POLICY'
        ).first()

        if password_policy:
            password_policy.status = 'in_progress'
            password_policy.started_at = datetime.now(timezone.utc)
            session.commit()

            results.success('Marked TASK_PASSWORD_POLICY as in_progress')
        else:
            results.fail('Could not find TASK_PASSWORD_POLICY')

        # Update profile security score
        # Get the score impact from the completed task
        task_template = session.query(RoadmapTask).filter_by(task_id='TASK_CLOSE_ADMIN').first()
        if task_template:
            new_score = profile.current_security_score + task_template.security_score_impact
            profile.current_security_score = new_score
            profile.last_recalculated = datetime.now(timezone.utc)
            session.commit()

            results.success(f'Updated security score: 0 -> {new_score}')
        else:
            results.fail('Could not find task template for score calculation')

        # Verify status updates
        completed_tasks = session.query(RoadmapUserTask).filter_by(
            profile_id=profile.id,
            status='completed'
        ).count()

        in_progress_tasks = session.query(RoadmapUserTask).filter_by(
            profile_id=profile.id,
            status='in_progress'
        ).count()

        if completed_tasks == 1:
            results.success('Correct completed task count')
        else:
            results.fail(f'Expected 1 completed, found {completed_tasks}')

        if in_progress_tasks == 1:
            results.success('Correct in_progress task count')
        else:
            results.fail(f'Expected 1 in_progress, found {in_progress_tasks}')

    except Exception as e:
        results.fail(f'Error updating task status: {e}')
        import traceback
        traceback.print_exc()


def test_create_progress_snapshot(session, profile, results):
    """Test creating a progress history snapshot"""
    print('\n--- Testing Progress Snapshot ---')

    if not profile:
        results.fail('No profile available for snapshot')
        return

    try:
        # Count tasks by status
        all_tasks = session.query(RoadmapUserTask).filter_by(profile_id=profile.id).all()
        completed = len([t for t in all_tasks if t.status == 'completed'])

        # Count by phase
        phase1 = len([t for t in all_tasks if t.phase == 1 and t.status == 'completed'])
        phase2 = len([t for t in all_tasks if t.phase == 2 and t.status == 'completed'])

        # Create snapshot
        snapshot = RoadmapProgressHistory(
            profile_id=profile.id,
            security_score=profile.current_security_score,
            tasks_completed=completed,
            tasks_total=len(all_tasks),
            phase1_completed=phase1,
            phase2_completed=phase2,
            phase3_completed=0,
            phase4_completed=0,
            snapshot_reason='task_completed'
        )
        session.add(snapshot)
        session.commit()

        results.success(f'Created progress snapshot (ID: {snapshot.id})')

        # Verify snapshot
        loaded = session.query(RoadmapProgressHistory).get(snapshot.id)

        if loaded.security_score == profile.current_security_score:
            results.success('Snapshot security_score correct')
        else:
            results.fail('Snapshot security_score incorrect')

        if loaded.tasks_completed == completed:
            results.success('Snapshot tasks_completed correct')
        else:
            results.fail('Snapshot tasks_completed incorrect')

        if loaded.snapshot_reason == 'task_completed':
            results.success('Snapshot reason correct')
        else:
            results.fail('Snapshot reason incorrect')

    except Exception as e:
        results.fail(f'Error creating progress snapshot: {e}')
        import traceback
        traceback.print_exc()


def test_unlock_achievement(session, profile, results):
    """Test unlocking an achievement"""
    print('\n--- Testing Achievement Unlock ---')

    if not profile:
        results.fail('No profile available for achievement')
        return

    try:
        # Create FIRST_STEPS achievement
        achievement = RoadmapAchievement(
            profile_id=profile.id,
            achievement_id='FIRST_STEPS',
            achievement_name='First Steps',
            achievement_description='Completed your first security task',
            achievement_icon='trophy',
            requirement_type='tasks_completed',
            requirement_value=1,
            rewards=json.dumps({
                'type': 'badge',
                'value': 'Security Beginner',
                'points': 100
            })
        )
        session.add(achievement)
        session.commit()

        results.success(f'Unlocked achievement: FIRST_STEPS')

        # Verify achievement
        loaded = session.query(RoadmapAchievement).filter_by(
            profile_id=profile.id,
            achievement_id='FIRST_STEPS'
        ).first()

        if loaded:
            results.success('Achievement saved correctly')
        else:
            results.fail('Achievement not found after creation')

        if loaded and loaded.unlocked_at is not None:
            results.success('Achievement has unlocked_at timestamp')
        else:
            results.fail('Achievement missing unlocked_at timestamp')

        # Test rewards JSON
        if loaded:
            rewards = json.loads(loaded.rewards)
            if rewards.get('type') == 'badge':
                results.success('Achievement rewards JSON works')
            else:
                results.fail('Achievement rewards JSON incorrect')

    except Exception as e:
        results.fail(f'Error unlocking achievement: {e}')
        import traceback
        traceback.print_exc()


def test_relationships(session, profile, results):
    """Test that all relationships work correctly"""
    print('\n--- Testing Relationships ---')

    if not profile:
        results.fail('No profile available for relationship tests')
        return

    try:
        # Reload profile with relationships
        profile = session.query(RoadmapProfile).get(profile.id)

        # Test profile -> user_tasks relationship
        if hasattr(profile, 'user_tasks') and len(profile.user_tasks) > 0:
            results.success(f'Profile -> user_tasks relationship works ({len(profile.user_tasks)} tasks)')
        else:
            results.fail('Profile -> user_tasks relationship broken')

        # Test profile -> achievements relationship
        if hasattr(profile, 'achievements') and len(profile.achievements) > 0:
            results.success(f'Profile -> achievements relationship works ({len(profile.achievements)} achievements)')
        else:
            results.fail('Profile -> achievements relationship broken')

        # Test profile -> progress_history relationship
        if hasattr(profile, 'progress_history') and len(profile.progress_history) > 0:
            results.success(f'Profile -> progress_history relationship works ({len(profile.progress_history)} snapshots)')
        else:
            results.fail('Profile -> progress_history relationship broken')

        # Test reverse relationship (task -> profile)
        if profile.user_tasks[0].profile == profile:
            results.success('Reverse relationship (task -> profile) works')
        else:
            results.fail('Reverse relationship (task -> profile) broken')

    except Exception as e:
        results.fail(f'Error testing relationships: {e}')
        import traceback
        traceback.print_exc()


def test_queries(session, profile, results):
    """Test various query patterns"""
    print('\n--- Testing Query Patterns ---')

    if not profile:
        results.fail('No profile available for query tests')
        return

    try:
        # Query 1: Get all tasks for profile
        all_tasks = session.query(RoadmapUserTask).filter_by(profile_id=profile.id).all()
        if len(all_tasks) > 0:
            results.success(f'Query: Get all tasks for profile ({len(all_tasks)} tasks)')
        else:
            results.fail('Query: Get all tasks for profile returned 0')

        # Query 2: Get completed tasks
        completed = session.query(RoadmapUserTask).filter_by(
            profile_id=profile.id,
            status='completed'
        ).all()
        if len(completed) > 0:
            results.success(f'Query: Get completed tasks ({len(completed)} tasks)')
        else:
            results.fail('Query: Get completed tasks returned 0')

        # Query 3: Get tasks by phase
        phase1_tasks = session.query(RoadmapUserTask).filter_by(
            profile_id=profile.id,
            phase=1
        ).all()
        if len(phase1_tasks) > 0:
            results.success(f'Query: Get tasks by phase ({len(phase1_tasks)} phase 1 tasks)')
        else:
            results.fail('Query: Get tasks by phase returned 0')

        # Query 4: Get tasks by source
        scan_tasks = session.query(RoadmapUserTask).filter(
            RoadmapUserTask.profile_id == profile.id,
            RoadmapUserTask.source.in_(['xasm_scan', 'lightbox_scan'])
        ).all()
        if len(scan_tasks) > 0:
            results.success(f'Query: Get tasks by source ({len(scan_tasks)} scan tasks)')
        else:
            results.fail('Query: Get tasks by source returned 0')

        # Query 5: Get progress over time
        history = session.query(RoadmapProgressHistory).filter_by(
            profile_id=profile.id
        ).order_by(RoadmapProgressHistory.snapshot_date.desc()).all()
        if len(history) > 0:
            results.success(f'Query: Get progress over time ({len(history)} snapshots)')
        else:
            results.fail('Query: Get progress over time returned 0')

        # Query 6: Get master task library
        master_tasks = session.query(RoadmapTask).filter_by(is_active=True).all()
        if len(master_tasks) >= 10:
            results.success(f'Query: Get master task library ({len(master_tasks)} tasks)')
        else:
            results.fail(f'Query: Get master task library returned {len(master_tasks)}, expected 10+')

        # Query 7: Get tasks by category
        auth_tasks = session.query(RoadmapTask).filter_by(task_category='authentication').all()
        if len(auth_tasks) > 0:
            results.success(f'Query: Get tasks by category ({len(auth_tasks)} auth tasks)')
        else:
            results.fail('Query: Get tasks by category returned 0')

        # Query 8: Get high-risk tasks
        high_risk = session.query(RoadmapTask).filter(
            RoadmapTask.risk_level.in_(['critical', 'high'])
        ).all()
        if len(high_risk) > 0:
            results.success(f'Query: Get high-risk tasks ({len(high_risk)} tasks)')
        else:
            results.fail('Query: Get high-risk tasks returned 0')

    except Exception as e:
        results.fail(f'Error in query tests: {e}')
        import traceback
        traceback.print_exc()


def print_summary(session, profile):
    """Print a summary of the test state"""
    print('\n' + '='*60)
    print('SUMMARY')
    print('='*60)

    if not profile:
        print('No profile created')
        return

    # Reload profile
    profile = session.query(RoadmapProfile).get(profile.id)

    print(f'\nProfile: {profile.company_name}')
    print(f'- Industry: {profile.industry}')
    print(f'- Size: {profile.company_size}')
    print(f'- Security Score: {profile.current_security_score}/{profile.target_security_score}')

    # Task counts
    all_tasks = session.query(RoadmapUserTask).filter_by(profile_id=profile.id).all()
    completed = len([t for t in all_tasks if t.status == 'completed'])
    in_progress = len([t for t in all_tasks if t.status == 'in_progress'])
    not_started = len([t for t in all_tasks if t.status == 'not_started'])

    print(f'- Tasks: {len(all_tasks)} assigned ({completed} completed, {in_progress} in progress, {not_started} not started)')

    print('\nAssigned Tasks:')
    for idx, task in enumerate(all_tasks, 1):
        status_icon = '[X]' if task.status == 'completed' else '[>]' if task.status == 'in_progress' else '[ ]'
        # Get task name from master library
        master = session.query(RoadmapTask).filter_by(task_id=task.task_id).first()
        name = master.task_name if master else task.task_id
        print(f'{idx}. {status_icon} {name} ({task.status})')

    # Achievements
    achievements = session.query(RoadmapAchievement).filter_by(profile_id=profile.id).all()
    if achievements:
        print('\nAchievements:')
        for ach in achievements:
            print(f'[*] {ach.achievement_id} - {ach.achievement_description}')


def main():
    """Run all tests"""
    print('='*60)
    print('ROADMAP DATABASE COMPREHENSIVE TEST')
    print('='*60)

    results = TestResults()
    session = SessionLocal()

    try:
        # Test 1: Tables exist
        test_tables_exist(results)

        # Test 2: Create profile
        profile = test_create_profile(session, results)

        # Test 3: Assign tasks
        tasks = test_assign_tasks(session, profile, results)

        # Test 4: Update task status
        test_update_task_status(session, profile, results)

        # Test 5: Create progress snapshot
        test_create_progress_snapshot(session, profile, results)

        # Test 6: Unlock achievement
        test_unlock_achievement(session, profile, results)

        # Test 7: Relationships
        test_relationships(session, profile, results)

        # Test 8: Queries
        test_queries(session, profile, results)

        # Print summary
        print_summary(session, profile)

        # Final results
        print('\n' + '='*60)
        if results.summary():
            print('\n[SUCCESS] ALL TESTS PASSED - Database ready for Roadmap feature!')
            return 0
        else:
            print('\n[FAILURE] SOME TESTS FAILED - Please review errors above')
            return 1

    except Exception as e:
        print(f'\n[CRITICAL] Test suite error: {e}')
        import traceback
        traceback.print_exc()
        return 1
    finally:
        session.close()


if __name__ == '__main__':
    sys.exit(main())
