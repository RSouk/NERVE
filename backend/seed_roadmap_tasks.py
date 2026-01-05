"""
Seed script for Roadmap task library
Creates the initial 10 tasks in the roadmap_tasks table
"""
import json
from database import SessionLocal, RoadmapTask, RoadmapTaskLibraryMeta
from datetime import datetime, timezone

def seed_tasks():
    session = SessionLocal()

    try:
        # Clear existing seed data if any
        session.query(RoadmapTask).delete()
        session.query(RoadmapTaskLibraryMeta).delete()
        session.commit()

        # Define 10 sample tasks
        tasks = [
            {
                'task_id': 'TASK_MFA_ENABLE',
                'task_name': 'Enable Multi-Factor Authentication',
                'task_category': 'authentication',
                'description': 'Enable MFA across all user accounts to add an extra layer of security beyond passwords.',
                'why_it_matters': 'MFA prevents 99.9% of account compromise attacks. Even if passwords are stolen, attackers cannot access accounts without the second factor.',
                'how_to_fix': '1. Choose an MFA provider (Authy, Google Authenticator, YubiKey)\n2. Enable MFA in your identity provider settings\n3. Enroll all users with their preferred method\n4. Set grace period for enrollment\n5. Enforce MFA requirement',
                'estimated_time_minutes': 120,
                'estimated_cost_min': 0,
                'estimated_cost_max': 50,
                'difficulty_level': 'medium',
                'security_score_impact': 12,
                'risk_level': 'high',
                'applies_to_industries': json.dumps(['all']),
                'applies_to_sizes': json.dumps(['all']),
                'requires_compliance': json.dumps(['soc2', 'hipaa', 'pci']),
                'documentation_url': 'https://example.com/docs/mfa-setup'
            },
            {
                'task_id': 'TASK_CLOSE_ADMIN',
                'task_name': 'Close Exposed Admin Portal',
                'task_category': 'access_control',
                'description': 'Remove public access to administrative interfaces and restrict access to authorized networks only.',
                'why_it_matters': 'Exposed admin portals are prime targets for attackers. They provide direct access to sensitive systems and data.',
                'how_to_fix': '1. Identify all admin portals exposed to the internet\n2. Move admin interfaces to internal network\n3. Implement VPN requirement for remote access\n4. Add IP whitelisting as additional layer\n5. Monitor access logs for anomalies',
                'estimated_time_minutes': 30,
                'estimated_cost_min': 0,
                'estimated_cost_max': 0,
                'difficulty_level': 'easy',
                'security_score_impact': 15,
                'risk_level': 'critical',
                'applies_to_industries': json.dumps(['all']),
                'applies_to_sizes': json.dumps(['all']),
                'requires_compliance': None
            },
            {
                'task_id': 'TASK_UPDATE_SSL',
                'task_name': 'Update SSL/TLS Certificate',
                'task_category': 'encryption',
                'description': 'Ensure all SSL/TLS certificates are valid, not expiring soon, and use modern encryption standards.',
                'why_it_matters': 'Invalid or weak SSL certificates expose traffic to interception and make your site vulnerable to man-in-the-middle attacks.',
                'how_to_fix': '1. Audit all SSL certificates for expiry dates\n2. Replace expired or expiring certificates\n3. Upgrade to TLS 1.3 where possible\n4. Disable weak cipher suites\n5. Set up automated certificate renewal',
                'estimated_time_minutes': 60,
                'estimated_cost_min': 50,
                'estimated_cost_max': 100,
                'difficulty_level': 'medium',
                'security_score_impact': 8,
                'risk_level': 'high',
                'applies_to_industries': json.dumps(['all']),
                'applies_to_sizes': json.dumps(['all']),
                'requires_compliance': json.dumps(['pci'])
            },
            {
                'task_id': 'TASK_PASSWORD_POLICY',
                'task_name': 'Implement Strong Password Policy',
                'task_category': 'authentication',
                'description': 'Enforce minimum password requirements including length, complexity, and rotation rules.',
                'why_it_matters': 'Weak passwords are the #1 entry point for attackers. Strong policies make credential attacks exponentially harder.',
                'how_to_fix': '1. Set minimum password length (12+ characters)\n2. Require mix of character types\n3. Block common/breached passwords\n4. Implement password history (prevent reuse)\n5. Consider passwordless options',
                'estimated_time_minutes': 60,
                'estimated_cost_min': 0,
                'estimated_cost_max': 0,
                'difficulty_level': 'easy',
                'security_score_impact': 10,
                'risk_level': 'high',
                'applies_to_industries': json.dumps(['all']),
                'applies_to_sizes': json.dumps(['all']),
                'requires_compliance': json.dumps(['soc2', 'hipaa'])
            },
            {
                'task_id': 'TASK_AUTOMATED_BACKUP',
                'task_name': 'Set Up Automated Backups',
                'task_category': 'data_protection',
                'description': 'Configure automated, encrypted backups with offsite storage and regular testing.',
                'why_it_matters': 'Backups are your last line of defense against ransomware and data loss. Without them, recovery may be impossible.',
                'how_to_fix': '1. Identify critical data and systems\n2. Choose backup solution (3-2-1 rule)\n3. Configure automated backup schedules\n4. Enable encryption for backup data\n5. Test restoration quarterly',
                'estimated_time_minutes': 180,
                'estimated_cost_min': 100,
                'estimated_cost_max': 300,
                'difficulty_level': 'medium',
                'security_score_impact': 12,
                'risk_level': 'high',
                'applies_to_industries': json.dumps(['all']),
                'applies_to_sizes': json.dumps(['all']),
                'requires_compliance': json.dumps(['soc2', 'hipaa', 'gdpr'])
            },
            {
                'task_id': 'TASK_SECURITY_HEADERS',
                'task_name': 'Enable Security Headers',
                'task_category': 'network',
                'description': 'Configure HTTP security headers to protect against common web attacks.',
                'why_it_matters': 'Security headers prevent XSS, clickjacking, and other browser-based attacks with minimal effort.',
                'how_to_fix': '1. Add Content-Security-Policy header\n2. Enable X-Frame-Options\n3. Set X-Content-Type-Options: nosniff\n4. Configure Strict-Transport-Security\n5. Add Referrer-Policy header',
                'estimated_time_minutes': 30,
                'estimated_cost_min': 0,
                'estimated_cost_max': 0,
                'difficulty_level': 'easy',
                'security_score_impact': 5,
                'risk_level': 'medium',
                'applies_to_industries': json.dumps(['all']),
                'applies_to_sizes': json.dumps(['all']),
                'requires_compliance': None
            },
            {
                'task_id': 'TASK_DEPLOY_EDR',
                'task_name': 'Deploy EDR Solution',
                'task_category': 'monitoring',
                'description': 'Install Endpoint Detection and Response software on all workstations and servers.',
                'why_it_matters': 'EDR provides real-time threat detection, investigation, and response capabilities beyond traditional antivirus.',
                'how_to_fix': '1. Evaluate EDR solutions (CrowdStrike, Carbon Black, SentinelOne)\n2. Plan deployment strategy\n3. Install agents on all endpoints\n4. Configure alerting and response policies\n5. Train security team on platform',
                'estimated_time_minutes': 480,
                'estimated_cost_min': 1000,
                'estimated_cost_max': 5000,
                'difficulty_level': 'hard',
                'security_score_impact': 20,
                'risk_level': 'medium',
                'applies_to_industries': json.dumps(['all']),
                'applies_to_sizes': json.dumps(['medium', 'large', 'enterprise']),
                'requires_compliance': json.dumps(['soc2'])
            },
            {
                'task_id': 'TASK_SECURITY_TRAINING',
                'task_name': 'Security Awareness Training',
                'task_category': 'human_factors',
                'description': 'Implement regular security awareness training for all employees.',
                'why_it_matters': 'Humans are the weakest link. Training reduces phishing susceptibility by 50%+ and creates a security-conscious culture.',
                'how_to_fix': '1. Select training platform (KnowBe4, Proofpoint)\n2. Create training schedule (quarterly minimum)\n3. Include phishing simulations\n4. Track completion and test scores\n5. Follow up with targeted training',
                'estimated_time_minutes': 240,
                'estimated_cost_min': 500,
                'estimated_cost_max': 2000,
                'difficulty_level': 'medium',
                'security_score_impact': 15,
                'risk_level': 'high',
                'applies_to_industries': json.dumps(['all']),
                'applies_to_sizes': json.dumps(['all']),
                'requires_compliance': json.dumps(['soc2', 'hipaa', 'gdpr'])
            },
            {
                'task_id': 'TASK_IR_PLAN',
                'task_name': 'Create Incident Response Plan',
                'task_category': 'governance',
                'description': 'Develop and document a comprehensive incident response plan with defined roles and procedures.',
                'why_it_matters': 'Without a plan, incident response is chaotic and slow. A good IR plan reduces breach costs by 35% on average.',
                'how_to_fix': '1. Define incident categories and severity levels\n2. Assign roles (incident commander, communications, technical)\n3. Document response procedures for each scenario\n4. Create communication templates\n5. Schedule tabletop exercises',
                'estimated_time_minutes': 600,
                'estimated_cost_min': 0,
                'estimated_cost_max': 0,
                'difficulty_level': 'hard',
                'security_score_impact': 18,
                'risk_level': 'medium',
                'applies_to_industries': json.dumps(['all']),
                'applies_to_sizes': json.dumps(['medium', 'large', 'enterprise']),
                'requires_compliance': json.dumps(['soc2', 'hipaa', 'gdpr', 'nis2'])
            },
            {
                'task_id': 'TASK_DEPLOY_SIEM',
                'task_name': 'Implement SIEM Solution',
                'task_category': 'monitoring',
                'description': 'Deploy Security Information and Event Management to centralize and analyze security logs.',
                'why_it_matters': 'SIEM provides visibility across your environment, enabling threat detection that would otherwise be impossible.',
                'how_to_fix': '1. Define logging requirements and use cases\n2. Select SIEM platform (Splunk, Elastic, Sentinel)\n3. Configure log sources and parsing\n4. Build detection rules and dashboards\n5. Establish SOC procedures',
                'estimated_time_minutes': 960,
                'estimated_cost_min': 5000,
                'estimated_cost_max': 20000,
                'difficulty_level': 'hard',
                'security_score_impact': 25,
                'risk_level': 'low',
                'applies_to_industries': json.dumps(['all']),
                'applies_to_sizes': json.dumps(['large', 'enterprise']),
                'requires_compliance': json.dumps(['soc2', 'hipaa', 'pci'])
            }
        ]

        # Insert tasks
        for task_data in tasks:
            task = RoadmapTask(**task_data)
            session.add(task)

        # Insert library metadata
        meta = RoadmapTaskLibraryMeta(
            library_version='1.0.0',
            total_tasks=len(tasks),
            changelog='Initial release with 10 foundational security tasks'
        )
        session.add(meta)

        session.commit()
        print(f'[OK] Successfully seeded {len(tasks)} tasks into roadmap_tasks')

        # Verify
        count = session.query(RoadmapTask).count()
        print(f'[OK] Verified: {count} tasks in database')

        # List task IDs
        print('\nSeeded tasks:')
        for task in session.query(RoadmapTask).all():
            print(f'  - {task.task_id}: {task.task_name}')

        return True

    except Exception as e:
        session.rollback()
        print(f'[ERROR] Error seeding tasks: {e}')
        return False
    finally:
        session.close()


if __name__ == '__main__':
    seed_tasks()
