"""
Compliance Mappings - Map vulnerabilities to compliance framework controls

This module maps common vulnerability types found by XASM and Lightbox scans
to their corresponding compliance framework controls (SOC2, ISO27001, GDPR, NIS2).
"""

# Vulnerability to Compliance Control Mappings
# Keys are vulnerability identifiers/patterns from scan results
# Values contain the control IDs affected in each framework

VULNERABILITY_MAPPINGS = {
    # =========================================================================
    # SSL/TLS VULNERABILITIES
    # =========================================================================
    'outdated_ssl': {
        'name': 'Outdated SSL/TLS Version',
        'description': 'Server supports outdated SSL/TLS versions (SSLv3, TLS 1.0, TLS 1.1)',
        'severity': 'high',
        'soc2': ['CC6.1.b', 'CC6.7.a', 'CC6.7.b'],
        'iso27001': ['A.10.1.1', '8.24'],
        'gdpr': ['Article 32'],
        'nis2': ['Article 21']
    },
    'weak_cipher': {
        'name': 'Weak Cipher Suite',
        'description': 'Server supports weak cipher suites (DES, RC4, export ciphers)',
        'severity': 'high',
        'soc2': ['CC6.1.b', 'CC6.7.a'],
        'iso27001': ['A.10.1.1', '8.24'],
        'gdpr': ['Article 32'],
        'nis2': ['Article 21']
    },
    'expired_certificate': {
        'name': 'Expired SSL Certificate',
        'description': 'SSL certificate has expired or is about to expire',
        'severity': 'critical',
        'soc2': ['CC6.7.b', 'CC7.1.a'],
        'iso27001': ['A.10.1.2', '8.24'],
        'gdpr': ['Article 32'],
        'nis2': ['Article 21']
    },
    'self_signed_cert': {
        'name': 'Self-Signed Certificate',
        'description': 'Server uses a self-signed SSL certificate',
        'severity': 'medium',
        'soc2': ['CC6.7.b'],
        'iso27001': ['A.10.1.2'],
        'gdpr': ['Article 32'],
        'nis2': ['Article 21']
    },
    'missing_https': {
        'name': 'Missing HTTPS',
        'description': 'Service accessible over unencrypted HTTP',
        'severity': 'high',
        'soc2': ['CC6.1.b', 'CC6.7.a', 'CC6.7.b'],
        'iso27001': ['A.10.1.1', 'A.13.1.1'],
        'gdpr': ['Article 32', 'Article 25'],
        'nis2': ['Article 21']
    },

    # =========================================================================
    # ACCESS CONTROL VULNERABILITIES
    # =========================================================================
    'exposed_admin_panel': {
        'name': 'Exposed Admin Panel',
        'description': 'Administrative interface accessible without proper protection',
        'severity': 'critical',
        'soc2': ['CC6.1.a', 'CC6.1.c', 'CC6.2.a', 'CC6.3.a'],
        'iso27001': ['A.9.1.2', 'A.9.2.3', 'A.9.4.1'],
        'gdpr': ['Article 32', 'Article 25'],
        'nis2': ['Article 21']
    },
    'default_credentials': {
        'name': 'Default Credentials',
        'description': 'Service using default or common credentials',
        'severity': 'critical',
        'soc2': ['CC6.1.a', 'CC6.1.c', 'CC6.2.a'],
        'iso27001': ['A.9.2.1', 'A.9.2.4', 'A.9.4.3'],
        'gdpr': ['Article 32'],
        'nis2': ['Article 21']
    },
    'weak_authentication': {
        'name': 'Weak Authentication',
        'description': 'Service has weak or missing authentication mechanisms',
        'severity': 'high',
        'soc2': ['CC6.1.a', 'CC6.1.c', 'CC6.2.a'],
        'iso27001': ['A.9.2.1', 'A.9.4.2'],
        'gdpr': ['Article 32'],
        'nis2': ['Article 21']
    },
    'missing_mfa': {
        'name': 'Missing Multi-Factor Authentication',
        'description': 'Critical service lacks MFA requirement',
        'severity': 'medium',
        'soc2': ['CC6.1.c', 'CC6.2.a'],
        'iso27001': ['A.9.4.2'],
        'gdpr': ['Article 32'],
        'nis2': ['Article 21']
    },
    'open_port_sensitive': {
        'name': 'Sensitive Port Exposed',
        'description': 'Sensitive service port exposed to internet (SSH, RDP, DB)',
        'severity': 'high',
        'soc2': ['CC6.1.a', 'CC6.6.a', 'CC6.6.b'],
        'iso27001': ['A.13.1.1', 'A.13.1.3'],
        'gdpr': ['Article 32'],
        'nis2': ['Article 21']
    },

    # =========================================================================
    # DATA PROTECTION VULNERABILITIES
    # =========================================================================
    'data_exposure': {
        'name': 'Sensitive Data Exposure',
        'description': 'Sensitive data exposed in responses or public files',
        'severity': 'critical',
        'soc2': ['CC6.1.d', 'CC6.5.a', 'CC6.7.c'],
        'iso27001': ['A.8.2.3', 'A.13.2.1'],
        'gdpr': ['Article 5', 'Article 32', 'Article 25'],
        'nis2': ['Article 21']
    },
    'directory_listing': {
        'name': 'Directory Listing Enabled',
        'description': 'Web server exposes directory contents',
        'severity': 'medium',
        'soc2': ['CC6.1.d', 'CC6.5.a'],
        'iso27001': ['A.12.6.1', 'A.14.1.2'],
        'gdpr': ['Article 32'],
        'nis2': ['Article 21']
    },
    'backup_file_exposed': {
        'name': 'Backup Files Exposed',
        'description': 'Backup or configuration files publicly accessible',
        'severity': 'high',
        'soc2': ['CC6.1.d', 'CC6.5.a', 'CC6.7.c'],
        'iso27001': ['A.12.3.1', 'A.14.1.2'],
        'gdpr': ['Article 32', 'Article 25'],
        'nis2': ['Article 21']
    },
    'api_key_exposed': {
        'name': 'API Key Exposed',
        'description': 'API keys or secrets found in public resources',
        'severity': 'critical',
        'soc2': ['CC6.1.d', 'CC6.5.a', 'CC6.7.c'],
        'iso27001': ['A.9.4.3', 'A.10.1.2'],
        'gdpr': ['Article 32'],
        'nis2': ['Article 21']
    },
    'pii_exposure': {
        'name': 'PII Exposure',
        'description': 'Personal Identifiable Information found in public resources',
        'severity': 'critical',
        'soc2': ['CC6.1.d', 'CC6.5.a', 'P3.1', 'P4.1'],
        'iso27001': ['A.8.2.3', 'A.18.1.4'],
        'gdpr': ['Article 5', 'Article 6', 'Article 32', 'Article 33'],
        'nis2': ['Article 21', 'Article 23']
    },

    # =========================================================================
    # SOFTWARE & CONFIGURATION VULNERABILITIES
    # =========================================================================
    'outdated_software': {
        'name': 'Outdated Software Version',
        'description': 'Service running outdated software with known vulnerabilities',
        'severity': 'high',
        'soc2': ['CC6.1.e', 'CC7.1.a', 'CC7.1.b'],
        'iso27001': ['A.12.6.1', 'A.14.2.2'],
        'gdpr': ['Article 32'],
        'nis2': ['Article 21']
    },
    'known_cve': {
        'name': 'Known CVE Vulnerability',
        'description': 'Service affected by known CVE vulnerability',
        'severity': 'critical',
        'soc2': ['CC6.1.e', 'CC7.1.a', 'CC7.1.b', 'CC7.2.a'],
        'iso27001': ['A.12.6.1', 'A.14.2.2', 'A.16.1.3'],
        'gdpr': ['Article 32'],
        'nis2': ['Article 21', 'Article 23']
    },
    'misconfiguration': {
        'name': 'Security Misconfiguration',
        'description': 'Service has insecure default or missing security configuration',
        'severity': 'medium',
        'soc2': ['CC6.1.e', 'CC6.6.a'],
        'iso27001': ['A.12.1.1', 'A.14.2.5'],
        'gdpr': ['Article 32', 'Article 25'],
        'nis2': ['Article 21']
    },
    'debug_mode_enabled': {
        'name': 'Debug Mode Enabled',
        'description': 'Application running in debug mode in production',
        'severity': 'high',
        'soc2': ['CC6.1.e', 'CC6.6.a'],
        'iso27001': ['A.12.1.4', 'A.14.2.5'],
        'gdpr': ['Article 32'],
        'nis2': ['Article 21']
    },
    'missing_security_headers': {
        'name': 'Missing Security Headers',
        'description': 'HTTP security headers not configured (CSP, HSTS, X-Frame-Options)',
        'severity': 'medium',
        'soc2': ['CC6.1.e', 'CC6.6.a'],
        'iso27001': ['A.14.1.2', 'A.14.2.5'],
        'gdpr': ['Article 32'],
        'nis2': ['Article 21']
    },

    # =========================================================================
    # NETWORK & INFRASTRUCTURE VULNERABILITIES
    # =========================================================================
    'dns_misconfiguration': {
        'name': 'DNS Misconfiguration',
        'description': 'DNS zone transfer enabled or other DNS security issues',
        'severity': 'medium',
        'soc2': ['CC6.6.a', 'CC6.6.b'],
        'iso27001': ['A.13.1.1', 'A.13.1.2'],
        'gdpr': ['Article 32'],
        'nis2': ['Article 21']
    },
    'subdomain_takeover': {
        'name': 'Subdomain Takeover Risk',
        'description': 'Subdomain pointing to unclaimed resource',
        'severity': 'high',
        'soc2': ['CC6.6.a', 'CC6.6.b', 'CC7.2.a'],
        'iso27001': ['A.13.1.1', 'A.12.6.1'],
        'gdpr': ['Article 32'],
        'nis2': ['Article 21']
    },
    'open_database': {
        'name': 'Database Exposed',
        'description': 'Database service accessible from internet without authentication',
        'severity': 'critical',
        'soc2': ['CC6.1.a', 'CC6.1.d', 'CC6.6.b'],
        'iso27001': ['A.9.1.2', 'A.13.1.3', 'A.18.1.3'],
        'gdpr': ['Article 32', 'Article 33'],
        'nis2': ['Article 21', 'Article 23']
    },
    'smtp_open_relay': {
        'name': 'SMTP Open Relay',
        'description': 'Mail server configured as open relay',
        'severity': 'high',
        'soc2': ['CC6.6.a', 'CC6.6.b'],
        'iso27001': ['A.13.2.1', 'A.13.2.3'],
        'gdpr': ['Article 32'],
        'nis2': ['Article 21']
    },

    # =========================================================================
    # APPLICATION VULNERABILITIES (from Lightbox deep scans)
    # =========================================================================
    'xss_vulnerability': {
        'name': 'Cross-Site Scripting (XSS)',
        'description': 'Application vulnerable to XSS attacks',
        'severity': 'high',
        'soc2': ['CC6.1.e', 'CC6.6.a', 'CC7.2.a'],
        'iso27001': ['A.14.1.2', 'A.14.2.5'],
        'gdpr': ['Article 32'],
        'nis2': ['Article 21']
    },
    'sql_injection': {
        'name': 'SQL Injection',
        'description': 'Application vulnerable to SQL injection attacks',
        'severity': 'critical',
        'soc2': ['CC6.1.d', 'CC6.1.e', 'CC6.6.a', 'CC7.2.a'],
        'iso27001': ['A.14.1.2', 'A.14.2.5', 'A.18.1.3'],
        'gdpr': ['Article 32', 'Article 33'],
        'nis2': ['Article 21', 'Article 23']
    },
    'csrf_vulnerability': {
        'name': 'Cross-Site Request Forgery (CSRF)',
        'description': 'Application vulnerable to CSRF attacks',
        'severity': 'medium',
        'soc2': ['CC6.1.e', 'CC6.6.a'],
        'iso27001': ['A.14.1.2', 'A.14.2.5'],
        'gdpr': ['Article 32'],
        'nis2': ['Article 21']
    },
    'ssrf_vulnerability': {
        'name': 'Server-Side Request Forgery (SSRF)',
        'description': 'Application vulnerable to SSRF attacks',
        'severity': 'high',
        'soc2': ['CC6.1.e', 'CC6.6.a', 'CC7.2.a'],
        'iso27001': ['A.14.1.2', 'A.14.2.5'],
        'gdpr': ['Article 32'],
        'nis2': ['Article 21']
    },
    'file_upload_vulnerability': {
        'name': 'Insecure File Upload',
        'description': 'Application allows upload of dangerous file types',
        'severity': 'high',
        'soc2': ['CC6.1.e', 'CC6.6.a', 'CC7.2.a'],
        'iso27001': ['A.12.2.1', 'A.14.1.2'],
        'gdpr': ['Article 32'],
        'nis2': ['Article 21']
    },

    # =========================================================================
    # LOGGING & MONITORING GAPS
    # =========================================================================
    'missing_logging': {
        'name': 'Insufficient Logging',
        'description': 'Critical security events not being logged',
        'severity': 'medium',
        'soc2': ['CC7.2.a', 'CC7.2.b', 'CC7.3.a'],
        'iso27001': ['A.12.4.1', 'A.12.4.3'],
        'gdpr': ['Article 32', 'Article 33'],
        'nis2': ['Article 21', 'Article 23']
    },
    'missing_intrusion_detection': {
        'name': 'No Intrusion Detection',
        'description': 'No evidence of intrusion detection/prevention systems',
        'severity': 'medium',
        'soc2': ['CC7.2.a', 'CC7.2.b'],
        'iso27001': ['A.12.4.1', 'A.13.1.1'],
        'gdpr': ['Article 32'],
        'nis2': ['Article 21']
    },

    # =========================================================================
    # THIRD-PARTY & SUPPLY CHAIN
    # =========================================================================
    'vulnerable_dependency': {
        'name': 'Vulnerable Third-Party Dependency',
        'description': 'Application uses libraries with known vulnerabilities',
        'severity': 'high',
        'soc2': ['CC6.1.e', 'CC7.1.b', 'CC9.2.a'],
        'iso27001': ['A.14.2.1', 'A.15.1.1'],
        'gdpr': ['Article 28', 'Article 32'],
        'nis2': ['Article 21']
    },
    'unverified_cdn': {
        'name': 'Unverified CDN Resources',
        'description': 'Loading resources from CDN without integrity verification',
        'severity': 'low',
        'soc2': ['CC6.1.e', 'CC9.2.a'],
        'iso27001': ['A.14.2.1', 'A.15.1.2'],
        'gdpr': ['Article 28', 'Article 32'],
        'nis2': ['Article 21']
    }
}

# Severity rankings for prioritization
SEVERITY_ORDER = {
    'critical': 1,
    'high': 2,
    'medium': 3,
    'low': 4,
    'info': 5
}

# Scan finding type to vulnerability mapping
# Maps the actual finding types from XASM/Lightbox scans to our vulnerability keys
SCAN_FINDING_TO_VULN = {
    # SSL/TLS findings
    'ssl_grade_f': 'outdated_ssl',
    'ssl_grade_c': 'weak_cipher',
    'ssl_grade_b': 'weak_cipher',
    'tls_1_0': 'outdated_ssl',
    'tls_1_1': 'outdated_ssl',
    'ssl_v3': 'outdated_ssl',
    'weak_cipher_suite': 'weak_cipher',
    'expired_cert': 'expired_certificate',
    'cert_expiring_soon': 'expired_certificate',
    'self_signed': 'self_signed_cert',
    'no_https': 'missing_https',
    'http_only': 'missing_https',

    # Access control findings
    'admin_panel': 'exposed_admin_panel',
    'login_panel': 'exposed_admin_panel',
    'wp_admin': 'exposed_admin_panel',
    'phpmyadmin': 'exposed_admin_panel',
    'default_creds': 'default_credentials',
    'weak_password': 'weak_authentication',
    'no_auth': 'weak_authentication',
    'basic_auth': 'weak_authentication',
    'no_mfa': 'missing_mfa',

    # Port/service findings
    'ssh_exposed': 'open_port_sensitive',
    'rdp_exposed': 'open_port_sensitive',
    'mysql_exposed': 'open_database',
    'postgres_exposed': 'open_database',
    'mongodb_exposed': 'open_database',
    'redis_exposed': 'open_database',
    'elasticsearch_exposed': 'open_database',
    'ftp_exposed': 'open_port_sensitive',
    'telnet_exposed': 'open_port_sensitive',

    # Data exposure findings
    'sensitive_file': 'data_exposure',
    'config_exposed': 'backup_file_exposed',
    'backup_exposed': 'backup_file_exposed',
    'git_exposed': 'data_exposure',
    'env_exposed': 'api_key_exposed',
    'api_key': 'api_key_exposed',
    'directory_listing': 'directory_listing',
    'pii_found': 'pii_exposure',
    'email_leak': 'pii_exposure',

    # Software findings
    'outdated_wordpress': 'outdated_software',
    'outdated_plugin': 'outdated_software',
    'outdated_server': 'outdated_software',
    'cve_found': 'known_cve',
    'vuln_library': 'vulnerable_dependency',
    'debug_enabled': 'debug_mode_enabled',

    # Header findings
    'missing_csp': 'missing_security_headers',
    'missing_hsts': 'missing_security_headers',
    'missing_xfo': 'missing_security_headers',
    'missing_xcto': 'missing_security_headers',

    # Network findings
    'dns_zone_transfer': 'dns_misconfiguration',
    'spf_missing': 'dns_misconfiguration',
    'dmarc_missing': 'dns_misconfiguration',
    'subdomain_takeover': 'subdomain_takeover',
    'open_relay': 'smtp_open_relay',

    # Application findings
    'xss': 'xss_vulnerability',
    'sqli': 'sql_injection',
    'csrf': 'csrf_vulnerability',
    'ssrf': 'ssrf_vulnerability',
    'file_upload': 'file_upload_vulnerability'
}


def get_affected_controls(vulnerability_key, framework=None):
    """
    Get the compliance controls affected by a vulnerability.

    Args:
        vulnerability_key: The vulnerability identifier
        framework: Optional framework filter ('soc2', 'iso27001', 'gdpr', 'nis2')

    Returns:
        dict: Affected controls by framework, or list if framework specified
    """
    if vulnerability_key not in VULNERABILITY_MAPPINGS:
        return {} if framework is None else []

    vuln = VULNERABILITY_MAPPINGS[vulnerability_key]

    if framework:
        return vuln.get(framework, [])

    return {
        'soc2': vuln.get('soc2', []),
        'iso27001': vuln.get('iso27001', []),
        'gdpr': vuln.get('gdpr', []),
        'nis2': vuln.get('nis2', [])
    }


def get_vulnerability_info(vulnerability_key):
    """
    Get full information about a vulnerability type.

    Args:
        vulnerability_key: The vulnerability identifier

    Returns:
        dict: Vulnerability information or None
    """
    return VULNERABILITY_MAPPINGS.get(vulnerability_key)


def map_scan_finding_to_vulnerability(finding_type):
    """
    Map a scan finding type to a vulnerability key.

    Args:
        finding_type: The finding type from XASM/Lightbox scan

    Returns:
        str: Vulnerability key or None
    """
    finding_lower = finding_type.lower().replace(' ', '_').replace('-', '_')
    return SCAN_FINDING_TO_VULN.get(finding_lower)


def analyze_scan_findings(findings):
    """
    Analyze a list of scan findings and return affected compliance controls.

    Args:
        findings: List of finding dicts with 'type' or 'finding_type' key

    Returns:
        dict: {
            'affected_controls': {framework: [control_ids]},
            'vulnerabilities': [vulnerability info],
            'severity_summary': {severity: count}
        }
    """
    affected = {
        'soc2': set(),
        'iso27001': set(),
        'gdpr': set(),
        'nis2': set()
    }

    vulnerabilities = []
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

    for finding in findings:
        finding_type = finding.get('type') or finding.get('finding_type') or finding.get('name', '')

        vuln_key = map_scan_finding_to_vulnerability(finding_type)
        if not vuln_key:
            # Try direct match
            vuln_key = finding_type.lower().replace(' ', '_').replace('-', '_')

        if vuln_key in VULNERABILITY_MAPPINGS:
            vuln_info = VULNERABILITY_MAPPINGS[vuln_key]
            vulnerabilities.append({
                'key': vuln_key,
                'name': vuln_info['name'],
                'description': vuln_info['description'],
                'severity': vuln_info['severity'],
                'finding': finding
            })

            severity_counts[vuln_info['severity']] = severity_counts.get(vuln_info['severity'], 0) + 1

            for framework in ['soc2', 'iso27001', 'gdpr', 'nis2']:
                affected[framework].update(vuln_info.get(framework, []))

    return {
        'affected_controls': {k: list(v) for k, v in affected.items()},
        'vulnerabilities': sorted(vulnerabilities, key=lambda x: SEVERITY_ORDER.get(x['severity'], 5)),
        'severity_summary': severity_counts
    }


def get_control_vulnerabilities(control_id, framework):
    """
    Get all vulnerabilities that affect a specific control.

    Args:
        control_id: The control ID (e.g., 'CC6.1.a', 'A.9.1.2', 'Article 32')
        framework: The framework ('soc2', 'iso27001', 'gdpr', 'nis2')

    Returns:
        list: List of vulnerability keys that affect this control
    """
    affecting_vulns = []

    for vuln_key, vuln_info in VULNERABILITY_MAPPINGS.items():
        if control_id in vuln_info.get(framework, []):
            affecting_vulns.append({
                'key': vuln_key,
                'name': vuln_info['name'],
                'severity': vuln_info['severity']
            })

    return sorted(affecting_vulns, key=lambda x: SEVERITY_ORDER.get(x['severity'], 5))
