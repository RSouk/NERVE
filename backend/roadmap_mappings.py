"""
Roadmap Task Mappings and Task Library

Maps XASM/Lightbox scan findings to remediation tasks.
Contains the master library of all security tasks.
"""

# ============================================================================
# VULNERABILITY TO TASK MAPPING
# ============================================================================
# Maps scan finding types to their corresponding remediation tasks

VULNERABILITY_TO_TASK_MAP = {
    # Network & Infrastructure
    'exposed_admin_panel': 'TASK_CLOSE_ADMIN',
    'admin_panel_exposed': 'TASK_CLOSE_ADMIN',
    'outdated_ssl': 'TASK_UPDATE_SSL',
    'ssl_expired': 'TASK_UPDATE_SSL',
    'ssl_weak': 'TASK_UPDATE_SSL',
    'missing_security_headers': 'TASK_SECURITY_HEADERS',
    'security_headers_missing': 'TASK_SECURITY_HEADERS',
    'outdated_software': 'TASK_UPDATE_SOFTWARE',
    'software_outdated': 'TASK_UPDATE_SOFTWARE',
    'open_ports': 'TASK_CLOSE_PORTS',
    'unnecessary_ports': 'TASK_CLOSE_PORTS',
    'exposed_database': 'TASK_SECURE_DATABASE',
    'database_exposed': 'TASK_SECURE_DATABASE',

    # Authentication & Access
    'no_mfa': 'TASK_MFA_ENABLE',
    'mfa_not_enabled': 'TASK_MFA_ENABLE',
    'weak_passwords': 'TASK_PASSWORD_POLICY',
    'password_policy_weak': 'TASK_PASSWORD_POLICY',
    'default_credentials': 'TASK_CHANGE_DEFAULT_CREDS',
    'exposed_credentials': 'TASK_ROTATE_CREDENTIALS',
    'credential_leak': 'TASK_ROTATE_CREDENTIALS',

    # Web Application Security
    'sql_injection': 'TASK_FIX_SQL_INJECTION',
    'sqli': 'TASK_FIX_SQL_INJECTION',
    'xss_vulnerability': 'TASK_FIX_XSS',
    'xss': 'TASK_FIX_XSS',
    'csrf_vulnerability': 'TASK_FIX_CSRF',
    'csrf': 'TASK_FIX_CSRF',
    'directory_listing': 'TASK_DISABLE_DIR_LISTING',
    'directory_traversal': 'TASK_FIX_PATH_TRAVERSAL',
    'path_traversal': 'TASK_FIX_PATH_TRAVERSAL',
    'file_inclusion': 'TASK_FIX_FILE_INCLUSION',
    'lfi': 'TASK_FIX_FILE_INCLUSION',
    'rfi': 'TASK_FIX_FILE_INCLUSION',

    # Sensitive Data Exposure
    'sensitive_file_exposed': 'TASK_SECURE_SENSITIVE_FILES',
    'backup_file_exposed': 'TASK_SECURE_BACKUPS',
    'config_file_exposed': 'TASK_SECURE_CONFIG',
    'api_key_exposed': 'TASK_ROTATE_API_KEYS',
    'env_file_exposed': 'TASK_SECURE_ENV_FILES',
    'git_exposed': 'TASK_SECURE_GIT',
    '.git_exposed': 'TASK_SECURE_GIT',

    # Infrastructure
    'no_backup': 'TASK_AUTOMATED_BACKUP',
    'backup_missing': 'TASK_AUTOMATED_BACKUP',
    'no_monitoring': 'TASK_SETUP_MONITORING',
    'dns_misconfiguration': 'TASK_FIX_DNS',
    'spf_missing': 'TASK_CONFIGURE_SPF',
    'dmarc_missing': 'TASK_CONFIGURE_DMARC',
    'dkim_missing': 'TASK_CONFIGURE_DKIM',

    # Lightbox Specific
    'Sensitive File Exposed': 'TASK_SECURE_SENSITIVE_FILES',
    'Directory Listing Enabled': 'TASK_DISABLE_DIR_LISTING',
    'Backup File Found': 'TASK_SECURE_BACKUPS',
    'Config File Exposed': 'TASK_SECURE_CONFIG',
    'Git Repository Exposed': 'TASK_SECURE_GIT',
    'Admin Panel Found': 'TASK_CLOSE_ADMIN',
    'Debug Mode Enabled': 'TASK_DISABLE_DEBUG',
    'phpinfo Exposed': 'TASK_REMOVE_PHPINFO',
    'Server Status Exposed': 'TASK_SECURE_SERVER_STATUS',
    'Default Page': 'TASK_REMOVE_DEFAULT_PAGES',
}


# ============================================================================
# ACHIEVEMENT DEFINITIONS
# ============================================================================

ACHIEVEMENTS = {
    'FIRST_STEPS': {
        'id': 'FIRST_STEPS',
        'name': 'First Steps',
        'description': 'Complete your first security task',
        'icon': 'trophy',
        'requirement_type': 'tasks_completed',
        'requirement_value': 1,
        'rewards': {'type': 'badge', 'value': 'Security Novice'}
    },
    'QUICK_WINS': {
        'id': 'QUICK_WINS',
        'name': 'Quick Wins',
        'description': 'Complete 5 security tasks',
        'icon': 'zap',
        'requirement_type': 'tasks_completed',
        'requirement_value': 5,
        'rewards': {'type': 'badge', 'value': 'Quick Learner'}
    },
    'HALFWAY_HERO': {
        'id': 'HALFWAY_HERO',
        'name': 'Halfway Hero',
        'description': 'Reach a security score of 50',
        'icon': 'shield',
        'requirement_type': 'score_reached',
        'requirement_value': 50,
        'rewards': {'type': 'badge', 'value': 'Security Defender'}
    },
    'SECURITY_CHAMPION': {
        'id': 'SECURITY_CHAMPION',
        'name': 'Security Champion',
        'description': 'Reach a security score of 75',
        'icon': 'award',
        'requirement_type': 'score_reached',
        'requirement_value': 75,
        'rewards': {'type': 'certificate', 'value': 'Security Champion'}
    },
    'PERFECT_SCORE': {
        'id': 'PERFECT_SCORE',
        'name': 'Perfect Score',
        'description': 'Reach a security score of 100',
        'icon': 'star',
        'requirement_type': 'score_reached',
        'requirement_value': 100,
        'rewards': {'type': 'certificate', 'value': 'Security Master'}
    },
    'PHASE_ONE_COMPLETE': {
        'id': 'PHASE_ONE_COMPLETE',
        'name': 'Foundation Secured',
        'description': 'Complete all Phase 1 tasks',
        'icon': 'check-circle',
        'requirement_type': 'phase_complete',
        'requirement_value': 1,
        'rewards': {'type': 'badge', 'value': 'Foundation Builder'}
    },
    'MFA_MASTER': {
        'id': 'MFA_MASTER',
        'name': 'MFA Master',
        'description': 'Enable MFA across all accounts',
        'icon': 'lock',
        'requirement_type': 'specific_task',
        'requirement_value': 'TASK_MFA_ENABLE',
        'rewards': {'type': 'badge', 'value': 'Authentication Pro'}
    },
    'SCAN_VERIFIED': {
        'id': 'SCAN_VERIFIED',
        'name': 'Verified Fix',
        'description': 'Verify a fix by re-scanning',
        'icon': 'check-square',
        'requirement_type': 'verified_tasks',
        'requirement_value': 1,
        'rewards': {'type': 'badge', 'value': 'Verified Fixer'}
    },
    'WEEK_STREAK': {
        'id': 'WEEK_STREAK',
        'name': 'Consistency King',
        'description': 'Complete tasks 7 days in a row',
        'icon': 'calendar',
        'requirement_type': 'streak',
        'requirement_value': 7,
        'rewards': {'type': 'badge', 'value': 'Consistent Defender'}
    },
    'CRITICAL_CRUSHER': {
        'id': 'CRITICAL_CRUSHER',
        'name': 'Critical Crusher',
        'description': 'Fix all critical vulnerabilities',
        'icon': 'alert-triangle',
        'requirement_type': 'severity_complete',
        'requirement_value': 'critical',
        'rewards': {'type': 'badge', 'value': 'Crisis Handler'}
    }
}


# ============================================================================
# MASTER TASK LIBRARY
# ============================================================================
# All possible security tasks with metadata

TASK_LIBRARY = {
    # ========== AUTHENTICATION & ACCESS CONTROL ==========
    'TASK_MFA_ENABLE': {
        'task_id': 'TASK_MFA_ENABLE',
        'task_name': 'Enable Multi-Factor Authentication',
        'category': 'authentication',
        'description': 'Enable MFA on all user accounts to prevent unauthorized access even if passwords are compromised.',
        'why_it_matters': 'Passwords alone are not enough. 80% of hacking-related breaches involve compromised credentials. MFA blocks 99.9% of automated attacks.',
        'how_to_fix': '''1. Identify all systems requiring authentication
2. Choose an MFA solution (authenticator app, hardware key, or SMS)
3. Enable MFA in admin settings for each platform
4. Require all users to enroll in MFA
5. Set up backup codes for account recovery
6. Monitor and enforce MFA compliance''',
        'estimated_time_minutes': 60,
        'estimated_cost_min': 0,
        'estimated_cost_max': 100,
        'difficulty_level': 'easy',
        'security_score_impact': 15,
        'risk_level': 'high',
        'applies_to_industries': ['all'],
        'applies_to_sizes': ['all'],
        'requires_compliance': ['soc2', 'hipaa', 'pci', 'iso27001'],
        'documentation_url': 'https://www.cisa.gov/mfa'
    },

    'TASK_PASSWORD_POLICY': {
        'task_id': 'TASK_PASSWORD_POLICY',
        'task_name': 'Implement Strong Password Policy',
        'category': 'authentication',
        'description': 'Enforce a password policy requiring minimum length, complexity, and regular rotation.',
        'why_it_matters': 'Weak passwords are the #1 cause of breaches. A strong policy prevents dictionary attacks and credential stuffing.',
        'how_to_fix': '''1. Set minimum password length to 12+ characters
2. Require mix of uppercase, lowercase, numbers, and symbols
3. Implement password history (prevent reuse of last 10 passwords)
4. Set maximum password age (90 days recommended)
5. Lock accounts after 5 failed attempts
6. Use a password strength meter on registration forms
7. Consider a password manager for your organization''',
        'estimated_time_minutes': 30,
        'estimated_cost_min': 0,
        'estimated_cost_max': 0,
        'difficulty_level': 'easy',
        'security_score_impact': 10,
        'risk_level': 'high',
        'applies_to_industries': ['all'],
        'applies_to_sizes': ['all'],
        'requires_compliance': ['soc2', 'hipaa', 'pci', 'iso27001']
    },

    'TASK_CHANGE_DEFAULT_CREDS': {
        'task_id': 'TASK_CHANGE_DEFAULT_CREDS',
        'task_name': 'Change Default Credentials',
        'category': 'authentication',
        'description': 'Change all default usernames and passwords on systems, applications, and devices.',
        'why_it_matters': 'Default credentials are publicly known. Attackers scan for devices using default logins as an easy entry point.',
        'how_to_fix': '''1. Inventory all systems, routers, IoT devices, and applications
2. Check each for default credentials (admin/admin, root/root, etc.)
3. Generate strong, unique passwords for each
4. Store credentials securely in a password manager
5. Document changes for IT team
6. Schedule quarterly reviews for new devices''',
        'estimated_time_minutes': 45,
        'estimated_cost_min': 0,
        'estimated_cost_max': 0,
        'difficulty_level': 'easy',
        'security_score_impact': 12,
        'risk_level': 'critical',
        'applies_to_industries': ['all'],
        'applies_to_sizes': ['all'],
        'requires_compliance': ['soc2', 'pci']
    },

    'TASK_ROTATE_CREDENTIALS': {
        'task_id': 'TASK_ROTATE_CREDENTIALS',
        'task_name': 'Rotate Exposed Credentials',
        'category': 'authentication',
        'description': 'Immediately rotate all credentials that may have been exposed in a breach or leak.',
        'why_it_matters': 'Exposed credentials can be used by attackers within minutes. Immediate rotation prevents account takeover.',
        'how_to_fix': '''1. Identify all potentially exposed accounts
2. Force password reset for affected users
3. Revoke all active sessions
4. Rotate API keys and tokens
5. Check for unauthorized access in audit logs
6. Notify affected users
7. Enable MFA if not already active''',
        'estimated_time_minutes': 30,
        'estimated_cost_min': 0,
        'estimated_cost_max': 0,
        'difficulty_level': 'easy',
        'security_score_impact': 15,
        'risk_level': 'critical',
        'applies_to_industries': ['all'],
        'applies_to_sizes': ['all'],
        'requires_compliance': ['soc2', 'hipaa', 'gdpr']
    },

    # ========== NETWORK & INFRASTRUCTURE ==========
    'TASK_CLOSE_ADMIN': {
        'task_id': 'TASK_CLOSE_ADMIN',
        'task_name': 'Secure Exposed Admin Portal',
        'category': 'access_control',
        'description': 'Restrict access to admin panels by implementing IP whitelisting, VPN requirements, or removing public access entirely.',
        'why_it_matters': 'Publicly accessible admin panels are prime targets for brute force attacks. They should never be accessible from the internet.',
        'how_to_fix': '''1. Identify the exposed admin URL
2. Add IP whitelist to allow only trusted IPs
3. Alternatively, require VPN connection for access
4. Change the default admin URL path
5. Implement rate limiting on login attempts
6. Add CAPTCHA to the login form
7. Set up monitoring for failed login attempts''',
        'estimated_time_minutes': 30,
        'estimated_cost_min': 0,
        'estimated_cost_max': 0,
        'difficulty_level': 'easy',
        'security_score_impact': 15,
        'risk_level': 'critical',
        'applies_to_industries': ['all'],
        'applies_to_sizes': ['all'],
        'requires_compliance': ['soc2', 'pci', 'hipaa']
    },

    'TASK_CLOSE_PORTS': {
        'task_id': 'TASK_CLOSE_PORTS',
        'task_name': 'Close Unnecessary Open Ports',
        'category': 'network',
        'description': 'Close all network ports that are not required for business operations.',
        'why_it_matters': 'Each open port is a potential entry point. Attackers scan for open ports to find vulnerable services.',
        'how_to_fix': '''1. Review list of open ports from scan
2. Identify which ports are needed for business
3. Disable unnecessary services (Telnet, FTP, etc.)
4. Configure firewall to block unused ports
5. Use private networking for internal services
6. Document all required open ports and their purpose
7. Schedule quarterly port audits''',
        'estimated_time_minutes': 60,
        'estimated_cost_min': 0,
        'estimated_cost_max': 0,
        'difficulty_level': 'medium',
        'security_score_impact': 12,
        'risk_level': 'high',
        'applies_to_industries': ['all'],
        'applies_to_sizes': ['all'],
        'requires_compliance': ['soc2', 'pci', 'iso27001']
    },

    'TASK_UPDATE_SSL': {
        'task_id': 'TASK_UPDATE_SSL',
        'task_name': 'Update SSL/TLS Certificate',
        'category': 'network',
        'description': 'Renew expired SSL certificates and upgrade to TLS 1.2 or higher.',
        'why_it_matters': 'Expired or weak SSL enables man-in-the-middle attacks. Users see security warnings, damaging trust.',
        'how_to_fix': '''1. Identify affected domains and certificates
2. Generate new certificate signing request (CSR)
3. Purchase or generate new certificate (Let\'s Encrypt is free)
4. Install new certificate on web server
5. Disable TLS 1.0 and 1.1
6. Enable TLS 1.2 and 1.3 only
7. Set up automatic certificate renewal
8. Test with SSL Labs (ssllabs.com)''',
        'estimated_time_minutes': 30,
        'estimated_cost_min': 0,
        'estimated_cost_max': 200,
        'difficulty_level': 'easy',
        'security_score_impact': 10,
        'risk_level': 'high',
        'applies_to_industries': ['all'],
        'applies_to_sizes': ['all'],
        'requires_compliance': ['soc2', 'pci', 'hipaa', 'gdpr']
    },

    'TASK_SECURE_DATABASE': {
        'task_id': 'TASK_SECURE_DATABASE',
        'task_name': 'Secure Exposed Database',
        'category': 'network',
        'description': 'Remove public database access and implement proper network segmentation.',
        'why_it_matters': 'Exposed databases are responsible for millions of record breaches annually. Never expose databases to the internet.',
        'how_to_fix': '''1. Immediately block public access to database ports
2. Move database to private subnet
3. Allow access only from application servers
4. Implement database firewall rules
5. Enable database authentication
6. Encrypt data at rest and in transit
7. Set up database access monitoring
8. Implement least-privilege access''',
        'estimated_time_minutes': 120,
        'estimated_cost_min': 0,
        'estimated_cost_max': 500,
        'difficulty_level': 'medium',
        'security_score_impact': 20,
        'risk_level': 'critical',
        'applies_to_industries': ['all'],
        'applies_to_sizes': ['all'],
        'requires_compliance': ['soc2', 'pci', 'hipaa', 'gdpr']
    },

    # ========== WEB APPLICATION SECURITY ==========
    'TASK_SECURITY_HEADERS': {
        'task_id': 'TASK_SECURITY_HEADERS',
        'task_name': 'Add Security Headers',
        'category': 'web_security',
        'description': 'Implement HTTP security headers to protect against common web attacks.',
        'why_it_matters': 'Security headers prevent XSS, clickjacking, and other client-side attacks with minimal effort.',
        'how_to_fix': '''Add these headers to your web server configuration:

Content-Security-Policy: default-src 'self'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()

Test with securityheaders.com after implementation.''',
        'estimated_time_minutes': 30,
        'estimated_cost_min': 0,
        'estimated_cost_max': 0,
        'difficulty_level': 'easy',
        'security_score_impact': 8,
        'risk_level': 'medium',
        'applies_to_industries': ['all'],
        'applies_to_sizes': ['all'],
        'requires_compliance': ['soc2', 'pci']
    },

    'TASK_FIX_SQL_INJECTION': {
        'task_id': 'TASK_FIX_SQL_INJECTION',
        'task_name': 'Fix SQL Injection Vulnerability',
        'category': 'web_security',
        'description': 'Remediate SQL injection vulnerabilities using parameterized queries.',
        'why_it_matters': 'SQL injection allows attackers to read, modify, or delete your entire database. It\'s the #1 web application vulnerability.',
        'how_to_fix': '''1. Identify all SQL injection points from scan
2. Replace string concatenation with parameterized queries
3. Use prepared statements in all database queries
4. Implement input validation and sanitization
5. Use an ORM where possible
6. Apply least-privilege database accounts
7. Enable database query logging
8. Test with automated SQL injection tools''',
        'estimated_time_minutes': 240,
        'estimated_cost_min': 0,
        'estimated_cost_max': 2000,
        'difficulty_level': 'hard',
        'security_score_impact': 20,
        'risk_level': 'critical',
        'applies_to_industries': ['all'],
        'applies_to_sizes': ['all'],
        'requires_compliance': ['soc2', 'pci', 'hipaa']
    },

    'TASK_FIX_XSS': {
        'task_id': 'TASK_FIX_XSS',
        'task_name': 'Fix Cross-Site Scripting (XSS)',
        'category': 'web_security',
        'description': 'Implement proper output encoding and CSP to prevent XSS attacks.',
        'why_it_matters': 'XSS allows attackers to steal sessions, deface websites, and redirect users to malicious sites.',
        'how_to_fix': '''1. Identify all XSS vulnerable endpoints
2. Implement output encoding for all user-generated content
3. Use HTML entity encoding (&lt;, &gt;, &amp;, etc.)
4. Implement Content-Security-Policy header
5. Use HTTPOnly and Secure flags on cookies
6. Validate and sanitize all input
7. Use a template engine with auto-escaping
8. Test with XSS scanner tools''',
        'estimated_time_minutes': 180,
        'estimated_cost_min': 0,
        'estimated_cost_max': 1500,
        'difficulty_level': 'medium',
        'security_score_impact': 15,
        'risk_level': 'high',
        'applies_to_industries': ['all'],
        'applies_to_sizes': ['all'],
        'requires_compliance': ['soc2', 'pci']
    },

    'TASK_FIX_CSRF': {
        'task_id': 'TASK_FIX_CSRF',
        'task_name': 'Implement CSRF Protection',
        'category': 'web_security',
        'description': 'Add CSRF tokens to all state-changing requests.',
        'why_it_matters': 'CSRF tricks users into performing unwanted actions. An attacker could transfer funds or change settings without user consent.',
        'how_to_fix': '''1. Generate unique CSRF tokens per session
2. Include tokens in all forms as hidden fields
3. Validate tokens on server for all POST/PUT/DELETE requests
4. Use SameSite cookie attribute
5. Verify Origin and Referer headers
6. Implement double-submit cookie pattern if needed
7. Test with CSRF testing tools''',
        'estimated_time_minutes': 120,
        'estimated_cost_min': 0,
        'estimated_cost_max': 500,
        'difficulty_level': 'medium',
        'security_score_impact': 10,
        'risk_level': 'medium',
        'applies_to_industries': ['all'],
        'applies_to_sizes': ['all'],
        'requires_compliance': ['soc2', 'pci']
    },

    'TASK_DISABLE_DIR_LISTING': {
        'task_id': 'TASK_DISABLE_DIR_LISTING',
        'task_name': 'Disable Directory Listing',
        'category': 'web_security',
        'description': 'Disable automatic directory listing on web servers to prevent information disclosure.',
        'why_it_matters': 'Directory listing reveals your file structure, backup files, and potentially sensitive data to attackers.',
        'how_to_fix': '''Apache: Add "Options -Indexes" to .htaccess or httpd.conf
Nginx: Ensure "autoindex off;" in nginx.conf
IIS: Disable "Directory Browsing" in features

Also:
1. Add index.html to all directories
2. Remove or rename backup files
3. Audit for sensitive files in web root''',
        'estimated_time_minutes': 15,
        'estimated_cost_min': 0,
        'estimated_cost_max': 0,
        'difficulty_level': 'easy',
        'security_score_impact': 5,
        'risk_level': 'medium',
        'applies_to_industries': ['all'],
        'applies_to_sizes': ['all'],
        'requires_compliance': ['soc2']
    },

    'TASK_FIX_PATH_TRAVERSAL': {
        'task_id': 'TASK_FIX_PATH_TRAVERSAL',
        'task_name': 'Fix Path Traversal Vulnerability',
        'category': 'web_security',
        'description': 'Prevent directory traversal attacks that allow access to files outside the web root.',
        'why_it_matters': 'Path traversal can expose system files, configuration, and source code containing secrets.',
        'how_to_fix': '''1. Validate and sanitize all file path inputs
2. Use a whitelist of allowed files/directories
3. Remove "../" and similar sequences from input
4. Use chroot or similar sandboxing
5. Never use user input directly in file paths
6. Canonicalize paths before using
7. Implement proper access controls''',
        'estimated_time_minutes': 120,
        'estimated_cost_min': 0,
        'estimated_cost_max': 1000,
        'difficulty_level': 'medium',
        'security_score_impact': 12,
        'risk_level': 'high',
        'applies_to_industries': ['all'],
        'applies_to_sizes': ['all'],
        'requires_compliance': ['soc2', 'pci']
    },

    'TASK_FIX_FILE_INCLUSION': {
        'task_id': 'TASK_FIX_FILE_INCLUSION',
        'task_name': 'Fix File Inclusion Vulnerability',
        'category': 'web_security',
        'description': 'Remediate Local/Remote File Inclusion vulnerabilities.',
        'why_it_matters': 'LFI/RFI can lead to remote code execution, the most severe type of vulnerability.',
        'how_to_fix': '''1. Never use user input for file includes
2. Use a whitelist of allowed include files
3. Disable allow_url_include in PHP
4. Validate file extensions
5. Use absolute paths with basedir restrictions
6. Implement proper access controls
7. Consider using an application firewall''',
        'estimated_time_minutes': 180,
        'estimated_cost_min': 0,
        'estimated_cost_max': 1500,
        'difficulty_level': 'hard',
        'security_score_impact': 18,
        'risk_level': 'critical',
        'applies_to_industries': ['all'],
        'applies_to_sizes': ['all'],
        'requires_compliance': ['soc2', 'pci', 'hipaa']
    },

    # ========== SENSITIVE DATA PROTECTION ==========
    'TASK_SECURE_SENSITIVE_FILES': {
        'task_id': 'TASK_SECURE_SENSITIVE_FILES',
        'task_name': 'Secure Exposed Sensitive Files',
        'category': 'data_protection',
        'description': 'Remove or restrict access to sensitive files exposed on the web server.',
        'why_it_matters': 'Exposed sensitive files can reveal passwords, API keys, database credentials, and business data.',
        'how_to_fix': '''1. Remove sensitive files from web-accessible directories
2. Move configuration files outside web root
3. Add .htaccess rules to block access to sensitive extensions
4. Block access to: .env, .git, .sql, .bak, .config
5. Set proper file permissions (600 for sensitive files)
6. Implement file integrity monitoring
7. Audit web root regularly''',
        'estimated_time_minutes': 45,
        'estimated_cost_min': 0,
        'estimated_cost_max': 0,
        'difficulty_level': 'easy',
        'security_score_impact': 12,
        'risk_level': 'high',
        'applies_to_industries': ['all'],
        'applies_to_sizes': ['all'],
        'requires_compliance': ['soc2', 'pci', 'hipaa', 'gdpr']
    },

    'TASK_SECURE_BACKUPS': {
        'task_id': 'TASK_SECURE_BACKUPS',
        'task_name': 'Secure Backup Files',
        'category': 'data_protection',
        'description': 'Remove backup files from public directories and implement secure backup storage.',
        'why_it_matters': 'Backup files often contain complete database dumps, source code, and configuration with credentials.',
        'how_to_fix': '''1. Remove all .bak, .sql, .tar.gz, .zip from web root
2. Store backups in non-web-accessible location
3. Encrypt backup files
4. Implement secure offsite backup storage
5. Set up automated backup rotation
6. Block backup extensions in web server config
7. Regular scan for exposed backup files''',
        'estimated_time_minutes': 30,
        'estimated_cost_min': 0,
        'estimated_cost_max': 100,
        'difficulty_level': 'easy',
        'security_score_impact': 10,
        'risk_level': 'high',
        'applies_to_industries': ['all'],
        'applies_to_sizes': ['all'],
        'requires_compliance': ['soc2', 'hipaa', 'gdpr']
    },

    'TASK_SECURE_CONFIG': {
        'task_id': 'TASK_SECURE_CONFIG',
        'task_name': 'Secure Configuration Files',
        'category': 'data_protection',
        'description': 'Protect configuration files containing database credentials and API keys.',
        'why_it_matters': 'Config files contain the keys to your kingdom - database passwords, API keys, and encryption secrets.',
        'how_to_fix': '''1. Move config files outside web root
2. Set file permissions to 600 (owner read/write only)
3. Block access via web server config
4. Use environment variables instead of config files
5. Implement secrets management (Vault, AWS Secrets Manager)
6. Never commit config files to version control
7. Rotate any exposed credentials immediately''',
        'estimated_time_minutes': 60,
        'estimated_cost_min': 0,
        'estimated_cost_max': 0,
        'difficulty_level': 'easy',
        'security_score_impact': 12,
        'risk_level': 'critical',
        'applies_to_industries': ['all'],
        'applies_to_sizes': ['all'],
        'requires_compliance': ['soc2', 'pci', 'hipaa']
    },

    'TASK_ROTATE_API_KEYS': {
        'task_id': 'TASK_ROTATE_API_KEYS',
        'task_name': 'Rotate Exposed API Keys',
        'category': 'data_protection',
        'description': 'Immediately rotate all API keys that may have been exposed.',
        'why_it_matters': 'Exposed API keys can lead to data breaches, financial loss, and service abuse.',
        'how_to_fix': '''1. Identify all exposed API keys
2. Generate new keys from each service provider
3. Update application configuration with new keys
4. Revoke old keys immediately
5. Check API logs for unauthorized usage
6. Implement API key rotation schedule
7. Use environment variables, not hardcoded keys
8. Set up alerts for unusual API activity''',
        'estimated_time_minutes': 45,
        'estimated_cost_min': 0,
        'estimated_cost_max': 0,
        'difficulty_level': 'easy',
        'security_score_impact': 15,
        'risk_level': 'critical',
        'applies_to_industries': ['all'],
        'applies_to_sizes': ['all'],
        'requires_compliance': ['soc2', 'pci']
    },

    'TASK_SECURE_ENV_FILES': {
        'task_id': 'TASK_SECURE_ENV_FILES',
        'task_name': 'Secure Environment Files',
        'category': 'data_protection',
        'description': 'Remove .env files from public access and secure environment variable handling.',
        'why_it_matters': '.env files contain your application secrets - database passwords, API keys, and encryption keys.',
        'how_to_fix': '''1. Remove .env from web-accessible directories
2. Add .env to .htaccess deny rules
3. Block .env extension in web server config
4. Ensure .env is in .gitignore
5. Use proper environment variable injection
6. Consider secrets management solutions
7. Rotate all credentials in exposed .env files''',
        'estimated_time_minutes': 30,
        'estimated_cost_min': 0,
        'estimated_cost_max': 0,
        'difficulty_level': 'easy',
        'security_score_impact': 15,
        'risk_level': 'critical',
        'applies_to_industries': ['all'],
        'applies_to_sizes': ['all'],
        'requires_compliance': ['soc2', 'pci', 'hipaa']
    },

    'TASK_SECURE_GIT': {
        'task_id': 'TASK_SECURE_GIT',
        'task_name': 'Secure Exposed Git Repository',
        'category': 'data_protection',
        'description': 'Remove .git directory from production servers to prevent source code exposure.',
        'why_it_matters': 'An exposed .git directory allows attackers to download your entire source code including history and secrets.',
        'how_to_fix': '''1. Delete .git directory from production servers
2. Block .git access in web server config
3. Use deployment processes that exclude .git
4. Check git history for committed secrets
5. Rotate any secrets found in git history
6. Implement proper CI/CD pipeline
7. Never deploy directly from git clone''',
        'estimated_time_minutes': 30,
        'estimated_cost_min': 0,
        'estimated_cost_max': 0,
        'difficulty_level': 'easy',
        'security_score_impact': 15,
        'risk_level': 'critical',
        'applies_to_industries': ['all'],
        'applies_to_sizes': ['all'],
        'requires_compliance': ['soc2']
    },

    # ========== SOFTWARE & UPDATES ==========
    'TASK_UPDATE_SOFTWARE': {
        'task_id': 'TASK_UPDATE_SOFTWARE',
        'task_name': 'Update Outdated Software',
        'category': 'maintenance',
        'description': 'Update all software with known vulnerabilities to their latest secure versions.',
        'why_it_matters': 'Unpatched software is the #2 cause of breaches. Attackers actively scan for known vulnerabilities.',
        'how_to_fix': '''1. Inventory all software and versions
2. Check CVE databases for known vulnerabilities
3. Test updates in staging environment
4. Apply security patches promptly
5. Enable automatic security updates where possible
6. Implement vulnerability scanning
7. Create maintenance windows for updates
8. Document all version changes''',
        'estimated_time_minutes': 180,
        'estimated_cost_min': 0,
        'estimated_cost_max': 500,
        'difficulty_level': 'medium',
        'security_score_impact': 15,
        'risk_level': 'high',
        'applies_to_industries': ['all'],
        'applies_to_sizes': ['all'],
        'requires_compliance': ['soc2', 'pci', 'hipaa', 'iso27001']
    },

    'TASK_DISABLE_DEBUG': {
        'task_id': 'TASK_DISABLE_DEBUG',
        'task_name': 'Disable Debug Mode',
        'category': 'web_security',
        'description': 'Disable debug/development mode in production environments.',
        'why_it_matters': 'Debug mode exposes error messages, stack traces, environment variables, and internal paths.',
        'how_to_fix': '''1. Set DEBUG=False in production
2. Configure proper error pages (500.html)
3. Log errors to files, not browser
4. Remove development tools from production
5. Disable verbose error messages
6. Implement proper logging infrastructure
7. Test error handling in production''',
        'estimated_time_minutes': 15,
        'estimated_cost_min': 0,
        'estimated_cost_max': 0,
        'difficulty_level': 'easy',
        'security_score_impact': 8,
        'risk_level': 'medium',
        'applies_to_industries': ['all'],
        'applies_to_sizes': ['all'],
        'requires_compliance': ['soc2']
    },

    'TASK_REMOVE_PHPINFO': {
        'task_id': 'TASK_REMOVE_PHPINFO',
        'task_name': 'Remove phpinfo() Exposure',
        'category': 'web_security',
        'description': 'Remove or restrict access to phpinfo() pages that reveal server configuration.',
        'why_it_matters': 'phpinfo() reveals PHP version, modules, paths, and configuration - a goldmine for attackers.',
        'how_to_fix': '''1. Delete all phpinfo.php files from production
2. Disable phpinfo() function in php.ini
3. Search for phpinfo() calls in codebase
4. Block phpinfo pattern in web server config
5. Use alternative monitoring for PHP info
6. Regular scans for information disclosure''',
        'estimated_time_minutes': 15,
        'estimated_cost_min': 0,
        'estimated_cost_max': 0,
        'difficulty_level': 'easy',
        'security_score_impact': 5,
        'risk_level': 'medium',
        'applies_to_industries': ['all'],
        'applies_to_sizes': ['all'],
        'requires_compliance': ['soc2']
    },

    'TASK_SECURE_SERVER_STATUS': {
        'task_id': 'TASK_SECURE_SERVER_STATUS',
        'task_name': 'Secure Server Status Pages',
        'category': 'web_security',
        'description': 'Restrict access to server status and monitoring pages.',
        'why_it_matters': 'Server status pages reveal active connections, server load, and internal IP addresses.',
        'how_to_fix': '''1. Disable mod_status or nginx status in production
2. If needed, restrict to localhost only
3. Require authentication for status pages
4. Block /server-status, /nginx_status URLs
5. Use internal monitoring solutions instead
6. Review all exposed diagnostic endpoints''',
        'estimated_time_minutes': 15,
        'estimated_cost_min': 0,
        'estimated_cost_max': 0,
        'difficulty_level': 'easy',
        'security_score_impact': 5,
        'risk_level': 'low',
        'applies_to_industries': ['all'],
        'applies_to_sizes': ['all'],
        'requires_compliance': ['soc2']
    },

    'TASK_REMOVE_DEFAULT_PAGES': {
        'task_id': 'TASK_REMOVE_DEFAULT_PAGES',
        'task_name': 'Remove Default Installation Pages',
        'category': 'web_security',
        'description': 'Remove default pages that reveal software versions and configurations.',
        'why_it_matters': 'Default pages identify exact software versions, making it easy to find matching exploits.',
        'how_to_fix': '''1. Remove default welcome/installation pages
2. Replace with custom branded pages
3. Hide server version headers
4. Remove installation scripts after setup
5. Custom 404 and error pages
6. Remove setup wizards and installers''',
        'estimated_time_minutes': 20,
        'estimated_cost_min': 0,
        'estimated_cost_max': 0,
        'difficulty_level': 'easy',
        'security_score_impact': 3,
        'risk_level': 'low',
        'applies_to_industries': ['all'],
        'applies_to_sizes': ['all'],
        'requires_compliance': []
    },

    # ========== EMAIL SECURITY ==========
    'TASK_CONFIGURE_SPF': {
        'task_id': 'TASK_CONFIGURE_SPF',
        'task_name': 'Configure SPF Record',
        'category': 'email_security',
        'description': 'Set up SPF DNS record to prevent email spoofing.',
        'why_it_matters': 'Without SPF, attackers can send emails pretending to be from your domain.',
        'how_to_fix': '''1. Identify all servers that send email for your domain
2. Create SPF TXT record in DNS:
   v=spf1 include:_spf.google.com include:servers.mcsv.net -all
3. Include all legitimate sending sources
4. End with "-all" to reject unauthorized senders
5. Test with SPF checker tools
6. Monitor DMARC reports for failures''',
        'estimated_time_minutes': 30,
        'estimated_cost_min': 0,
        'estimated_cost_max': 0,
        'difficulty_level': 'easy',
        'security_score_impact': 5,
        'risk_level': 'medium',
        'applies_to_industries': ['all'],
        'applies_to_sizes': ['all'],
        'requires_compliance': ['soc2']
    },

    'TASK_CONFIGURE_DMARC': {
        'task_id': 'TASK_CONFIGURE_DMARC',
        'task_name': 'Configure DMARC Record',
        'category': 'email_security',
        'description': 'Set up DMARC to protect against email spoofing and phishing.',
        'why_it_matters': 'DMARC prevents phishing attacks using your domain and provides visibility into email abuse.',
        'how_to_fix': '''1. Ensure SPF and DKIM are configured first
2. Create DMARC TXT record in DNS:
   _dmarc.yourdomain.com
   v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com
3. Start with p=none to monitor
4. Review DMARC reports
5. Gradually increase to p=quarantine then p=reject
6. Monitor for legitimate email issues''',
        'estimated_time_minutes': 45,
        'estimated_cost_min': 0,
        'estimated_cost_max': 0,
        'difficulty_level': 'medium',
        'security_score_impact': 7,
        'risk_level': 'medium',
        'applies_to_industries': ['all'],
        'applies_to_sizes': ['all'],
        'requires_compliance': ['soc2']
    },

    'TASK_CONFIGURE_DKIM': {
        'task_id': 'TASK_CONFIGURE_DKIM',
        'task_name': 'Configure DKIM Signing',
        'category': 'email_security',
        'description': 'Set up DKIM to cryptographically sign outgoing emails.',
        'why_it_matters': 'DKIM proves emails actually came from your domain and haven\'t been modified.',
        'how_to_fix': '''1. Generate DKIM key pair (your email provider may do this)
2. Add DKIM public key as DNS TXT record:
   selector._domainkey.yourdomain.com
3. Configure email server to sign with private key
4. Test with DKIM validator tools
5. Rotate keys annually
6. Monitor DMARC reports for DKIM failures''',
        'estimated_time_minutes': 45,
        'estimated_cost_min': 0,
        'estimated_cost_max': 0,
        'difficulty_level': 'medium',
        'security_score_impact': 6,
        'risk_level': 'medium',
        'applies_to_industries': ['all'],
        'applies_to_sizes': ['all'],
        'requires_compliance': ['soc2']
    },

    # ========== BACKUP & RECOVERY ==========
    'TASK_AUTOMATED_BACKUP': {
        'task_id': 'TASK_AUTOMATED_BACKUP',
        'task_name': 'Implement Automated Backups',
        'category': 'backup_recovery',
        'description': 'Set up automated, encrypted backups with offsite storage.',
        'why_it_matters': 'Without backups, ransomware or hardware failure means permanent data loss.',
        'how_to_fix': '''1. Identify critical data requiring backup
2. Choose backup solution (cloud or local)
3. Configure daily automated backups
4. Encrypt backups at rest
5. Store copies offsite (3-2-1 rule: 3 copies, 2 media, 1 offsite)
6. Test restore process monthly
7. Document recovery procedures
8. Monitor backup success/failure alerts''',
        'estimated_time_minutes': 120,
        'estimated_cost_min': 0,
        'estimated_cost_max': 200,
        'difficulty_level': 'medium',
        'security_score_impact': 10,
        'risk_level': 'high',
        'applies_to_industries': ['all'],
        'applies_to_sizes': ['all'],
        'requires_compliance': ['soc2', 'hipaa', 'pci', 'iso27001']
    },

    # ========== MONITORING & LOGGING ==========
    'TASK_SETUP_MONITORING': {
        'task_id': 'TASK_SETUP_MONITORING',
        'task_name': 'Set Up Security Monitoring',
        'category': 'monitoring',
        'description': 'Implement security monitoring and alerting for suspicious activities.',
        'why_it_matters': 'The average breach goes undetected for 200+ days. Monitoring enables rapid response.',
        'how_to_fix': '''1. Enable logging on all critical systems
2. Centralize logs (SIEM or log aggregator)
3. Set up alerts for:
   - Failed login attempts
   - Unusual access patterns
   - Configuration changes
   - Privilege escalation
4. Create dashboards for visibility
5. Establish incident response procedures
6. Regular log review schedule''',
        'estimated_time_minutes': 240,
        'estimated_cost_min': 0,
        'estimated_cost_max': 500,
        'difficulty_level': 'medium',
        'security_score_impact': 12,
        'risk_level': 'high',
        'applies_to_industries': ['all'],
        'applies_to_sizes': ['medium', 'large', 'enterprise'],
        'requires_compliance': ['soc2', 'hipaa', 'pci', 'iso27001']
    },

    'TASK_FIX_DNS': {
        'task_id': 'TASK_FIX_DNS',
        'task_name': 'Fix DNS Misconfiguration',
        'category': 'network',
        'description': 'Correct DNS misconfigurations that could enable attacks.',
        'why_it_matters': 'DNS misconfigurations can enable subdomain takeover, email spoofing, and data exfiltration.',
        'how_to_fix': '''1. Audit all DNS records
2. Remove dangling CNAME records
3. Ensure no wildcard records pointing to external services
4. Verify all A/AAAA records point to owned IPs
5. Check for zone transfer restrictions
6. Enable DNSSEC if possible
7. Regular DNS audit schedule''',
        'estimated_time_minutes': 60,
        'estimated_cost_min': 0,
        'estimated_cost_max': 0,
        'difficulty_level': 'medium',
        'security_score_impact': 8,
        'risk_level': 'medium',
        'applies_to_industries': ['all'],
        'applies_to_sizes': ['all'],
        'requires_compliance': ['soc2']
    },
}


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def map_scan_to_tasks(scan_results, scan_type='xasm'):
    """
    Map scan findings to remediation tasks.

    Args:
        scan_results: XASM or Lightbox scan results dict
        scan_type: 'xasm' or 'lightbox'

    Returns:
        List of task assignments with details
    """
    tasks = []

    if scan_type == 'xasm':
        # Process XASM results
        # Check for exposed services
        port_results = scan_results.get('port_scan_results', [])
        for port in port_results:
            # Check for admin panels
            if port.get('service', '').lower() in ['http-admin', 'admin', 'webmin']:
                if 'TASK_CLOSE_ADMIN' not in [t['task_id'] for t in tasks]:
                    tasks.append({
                        'task_id': 'TASK_CLOSE_ADMIN',
                        'finding_type': 'exposed_admin_panel',
                        'finding_severity': 'critical',
                        'source_details': f"Port {port.get('port')}: {port.get('service')}"
                    })

            # Check for exposed databases
            if port.get('port') in [3306, 5432, 27017, 6379, 1433]:
                if 'TASK_SECURE_DATABASE' not in [t['task_id'] for t in tasks]:
                    tasks.append({
                        'task_id': 'TASK_SECURE_DATABASE',
                        'finding_type': 'exposed_database',
                        'finding_severity': 'critical',
                        'source_details': f"Port {port.get('port')} exposed"
                    })

        # Check for CVEs/vulnerabilities
        if scan_results.get('cve_statistics', {}).get('total_cves', 0) > 0:
            tasks.append({
                'task_id': 'TASK_UPDATE_SOFTWARE',
                'finding_type': 'outdated_software',
                'finding_severity': 'high' if scan_results.get('cve_statistics', {}).get('critical_cves', 0) > 0 else 'medium',
                'source_details': f"{scan_results.get('cve_statistics', {}).get('total_cves')} CVEs found"
            })

        # Check for SSL issues
        ssl_results = scan_results.get('ssl_results', {})
        if ssl_results.get('expired') or ssl_results.get('weak_cipher'):
            tasks.append({
                'task_id': 'TASK_UPDATE_SSL',
                'finding_type': 'ssl_expired' if ssl_results.get('expired') else 'ssl_weak',
                'finding_severity': 'high',
                'source_details': 'SSL certificate issues detected'
            })

    elif scan_type == 'lightbox':
        # Process Lightbox results
        findings = scan_results.get('findings', [])
        if isinstance(findings, str):
            import json
            try:
                findings = json.loads(findings)
            except:
                findings = []

        for finding in findings:
            finding_type = finding.get('finding_type') or finding.get('type', '')
            severity = finding.get('severity', 'medium').lower()

            # Map to task
            task_id = VULNERABILITY_TO_TASK_MAP.get(finding_type)
            if task_id and task_id not in [t['task_id'] for t in tasks]:
                tasks.append({
                    'task_id': task_id,
                    'finding_type': finding_type,
                    'finding_severity': severity,
                    'source_details': finding.get('url', finding.get('description', ''))
                })

    return tasks


def get_task_details(task_id):
    """Get full details for a task from the library."""
    return TASK_LIBRARY.get(task_id)


def get_tasks_for_profile(industry, company_size, compliance_requirements=None):
    """
    Get recommended tasks based on company profile.

    Args:
        industry: Company industry (healthcare, finance, retail, tech, etc.)
        company_size: small, medium, large, enterprise
        compliance_requirements: List of compliance frameworks (soc2, hipaa, etc.)

    Returns:
        List of recommended task IDs
    """
    recommended = []

    for task_id, task in TASK_LIBRARY.items():
        # Check industry applicability
        industries = task.get('applies_to_industries', ['all'])
        if 'all' not in industries and industry not in industries:
            continue

        # Check size applicability
        sizes = task.get('applies_to_sizes', ['all'])
        if 'all' not in sizes and company_size not in sizes:
            continue

        # Check compliance requirements
        if compliance_requirements:
            task_compliance = task.get('requires_compliance', [])
            if task_compliance and not any(c in task_compliance for c in compliance_requirements):
                continue

        recommended.append(task_id)

    return recommended


def calculate_security_score(completed_tasks, total_possible_score=100):
    """
    Calculate security score based on completed tasks.

    Args:
        completed_tasks: List of completed task IDs
        total_possible_score: Maximum possible score (default 100)

    Returns:
        Current security score
    """
    total_impact = sum(
        TASK_LIBRARY.get(task_id, {}).get('security_score_impact', 0)
        for task_id in completed_tasks
    )

    # Cap at total possible score
    return min(total_impact, total_possible_score)


def get_achievement_progress(profile_data, user_tasks):
    """
    Check which achievements are earned and their progress.

    Args:
        profile_data: User's profile data
        user_tasks: List of user's tasks with status

    Returns:
        Dict of achievement statuses
    """
    completed_tasks = [t for t in user_tasks if t.get('status') == 'completed']
    score = profile_data.get('current_security_score', 0)

    achievement_status = {}

    for ach_id, ach in ACHIEVEMENTS.items():
        status = {
            'id': ach_id,
            'unlocked': False,
            'progress': 0,
            'requirement': ach['requirement_value']
        }

        if ach['requirement_type'] == 'tasks_completed':
            status['progress'] = len(completed_tasks)
            status['unlocked'] = len(completed_tasks) >= ach['requirement_value']

        elif ach['requirement_type'] == 'score_reached':
            status['progress'] = score
            status['unlocked'] = score >= ach['requirement_value']

        elif ach['requirement_type'] == 'phase_complete':
            phase_tasks = [t for t in user_tasks if t.get('phase') == ach['requirement_value']]
            phase_completed = [t for t in phase_tasks if t.get('status') == 'completed']
            status['progress'] = len(phase_completed)
            status['requirement'] = len(phase_tasks)
            status['unlocked'] = len(phase_tasks) > 0 and len(phase_completed) == len(phase_tasks)

        elif ach['requirement_type'] == 'verified_tasks':
            verified = [t for t in completed_tasks if t.get('verified_at')]
            status['progress'] = len(verified)
            status['unlocked'] = len(verified) >= ach['requirement_value']

        achievement_status[ach_id] = status

    return achievement_status


def prioritize_tasks(tasks, profile_data):
    """
    Assign phases and priority order to tasks.

    Phase 1: Critical findings + scan-based issues (This Week)
    Phase 2: High priority generic tasks (This Month)
    Phase 3: Medium priority tasks (This Quarter)
    Phase 4: Low priority / advanced tasks (This Year)
    """
    prioritized = []

    for task in tasks:
        task_details = TASK_LIBRARY.get(task.get('task_id'), {})

        # Determine phase based on risk level and source
        risk_level = task.get('finding_severity') or task_details.get('risk_level', 'medium')
        source = task.get('source', 'profile')

        if source in ['xasm_scan', 'lightbox_scan'] or risk_level == 'critical':
            phase = 1
        elif risk_level == 'high':
            phase = 2
        elif risk_level == 'medium':
            phase = 3
        else:
            phase = 4

        # Calculate priority within phase
        score_impact = task_details.get('security_score_impact', 5)
        difficulty = {'easy': 1, 'medium': 2, 'hard': 3}.get(
            task_details.get('difficulty_level', 'medium'), 2
        )

        # Higher impact + lower difficulty = higher priority
        priority_score = (score_impact * 2) - difficulty

        task['phase'] = phase
        task['priority_score'] = priority_score
        prioritized.append(task)

    # Sort by phase, then priority score
    prioritized.sort(key=lambda x: (x['phase'], -x['priority_score']))

    # Assign priority order within phase
    current_phase = 0
    order = 0
    for task in prioritized:
        if task['phase'] != current_phase:
            current_phase = task['phase']
            order = 0
        order += 1
        task['priority_order'] = order

    return prioritized
