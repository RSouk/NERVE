"""
Lightbox Automated Security Testing
Tests discovered assets for common exposures and misconfigurations

TODO - FRONTEND PHASE (UI Overhaul):

LIVE PROGRESS TRACKING:
- Add endpoint: /api/ghost/lightbox/scan-progress
- Poll every 2 seconds from frontend
- Display:
  * "Testing asset 5/17..." (current subdomain)
  * "Default credentials: 2/5 panels tested"
  * "Security headers: 10/17 checked"
  * Progress bar: 0-100%
  * Findings counter (updates live)

REAL-TIME FINDINGS:
- Stream findings as discovered (don't wait for scan end)
- Show spinner on current check
- Highlight critical findings in red immediately

ESTIMATED TIME:
- Show: "Estimated time remaining: 8 minutes"
- Based on: assets × checks × avg response time
"""

import requests
import subprocess
import json
import os
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3

# Suppress HTTPS warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Import modular test classes
from modules.ghost.lightbox.tests.api_security import APISecurityTests
from modules.ghost.lightbox.tests.business_logic import BusinessLogicTests


# Remediation guidance for all findings
REMEDIATION_GUIDES = {
    'Admin Panel Accessible': {
        'fix_steps': [
            '1. Restrict access by IP whitelist',
            '2. Require VPN for admin access',
            '3. Enable multi-factor authentication',
            '4. Change admin panel URL from default path'
        ],
        'nginx_config': '''location /admin {
    allow 10.0.0.0/8;  # Your office IP range
    deny all;
}''',
        'apache_config': '''<Location /admin>
    Require ip 10.0.0.0/8
</Location>''',
        'impact': 'Prevents unauthorized admin access and brute force attacks',
        'compliance': ['PCI-DSS 2.2.2', 'HIPAA §164.312(a)(1)']
    },

    'Sensitive File Exposed': {
        'fix_steps': [
            '1. Move sensitive files outside web root',
            '2. Add access denial rules',
            '3. Review all configuration files for exposure',
            '4. Implement proper file permissions (600 or 400)'
        ],
        'nginx_config': r'''location ~* \.(env|config|conf|log|sql|key)$ {
    deny all;
}''',
        'apache_config': r'''<FilesMatch "\.(env|config|conf|log|sql|key)$">
    Require all denied
</FilesMatch>''',
        'impact': 'Prevents credential theft and database compromise',
        'compliance': ['PCI-DSS 6.5.3', 'HIPAA §164.308(a)(4)']
    },

    'Default Credentials': {
        'fix_steps': [
            '1. Change password immediately',
            '2. Disable or delete default accounts',
            '3. Enable multi-factor authentication',
            '4. Implement password complexity requirements',
            '5. Force password rotation every 90 days'
        ],
        'impact': 'CRITICAL - Immediate system compromise possible',
        'compliance': ['PCI-DSS 8.2.1', 'HIPAA §164.308(a)(5)(ii)(D)']
    },

    'Missing Security Header': {
        'HSTS': {
            'fix_steps': ['Add Strict-Transport-Security header to force HTTPS'],
            'nginx_config': 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
            'apache_config': 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
            'impact': 'Prevents SSL stripping and downgrade attacks',
            'compliance': ['PCI-DSS 4.1']
        },
        'X-Frame-Options': {
            'fix_steps': ['Add X-Frame-Options header to prevent clickjacking'],
            'nginx_config': 'add_header X-Frame-Options "SAMEORIGIN" always;',
            'apache_config': 'Header always set X-Frame-Options "SAMEORIGIN"',
            'impact': 'Prevents clickjacking attacks',
            'compliance': ['OWASP Top 10']
        },
        'Content-Security-Policy': {
            'fix_steps': ['Add CSP header to prevent XSS attacks'],
            'nginx_config': r'add_header Content-Security-Policy "default-src \'self\'; script-src \'self\' \'unsafe-inline\'; style-src \'self\' \'unsafe-inline\';" always;',
            'apache_config': r'Header always set Content-Security-Policy "default-src \'self\'; script-src \'self\' \'unsafe-inline\'"',
            'impact': 'Prevents cross-site scripting (XSS) attacks',
            'compliance': ['PCI-DSS 6.5.7']
        },
        'X-Content-Type-Options': {
            'fix_steps': ['Add X-Content-Type-Options header to prevent MIME sniffing'],
            'nginx_config': 'add_header X-Content-Type-Options "nosniff" always;',
            'apache_config': 'Header always set X-Content-Type-Options "nosniff"',
            'impact': 'Prevents MIME-type confusion attacks',
            'compliance': ['OWASP Top 10']
        }
    },

    'Insecure Cookie': {
        'fix_steps': [
            '1. Add Secure flag to all cookies',
            '2. Add HttpOnly flag to session cookies',
            '3. Set SameSite=Strict for CSRF protection',
            '4. Use short cookie expiration times'
        ],
        'php_config': 'session_set_cookie_params(["secure" => true, "httponly" => true, "samesite" => "Strict"]);',
        'impact': 'Prevents session hijacking and XSS cookie theft',
        'compliance': ['PCI-DSS 6.5.10', 'HIPAA §164.312(a)(2)(iv)']
    },

    'Open Redirect': {
        'fix_steps': [
            '1. Validate all redirect URLs against whitelist',
            '2. Use relative URLs instead of absolute',
            '3. Implement strict URL validation',
            '4. Remove user-controllable redirect parameters'
        ],
        'impact': 'Prevents phishing attacks via trusted domain',
        'compliance': ['OWASP Top 10 A01:2021']
    },

    'XXE Vulnerability Possible': {
        'fix_steps': [
            '1. Disable XML external entity processing',
            '2. Use JSON instead of XML when possible',
            '3. Update XML parser libraries',
            '4. Implement XML input validation'
        ],
        'php_config': 'libxml_disable_entity_loader(true);',
        'impact': 'Prevents file disclosure and SSRF attacks',
        'compliance': ['OWASP Top 10 A05:2021']
    },

    'SSRF Vulnerability Possible': {
        'fix_steps': [
            '1. Validate and whitelist allowed URLs',
            '2. Block internal IP ranges (RFC 1918)',
            '3. Disable URL redirects',
            '4. Use DNS resolution validation'
        ],
        'impact': 'Prevents access to internal services and cloud metadata',
        'compliance': ['OWASP Top 10 A10:2021']
    },

    'Database Auth Required (Vulnerable)': {
        'fix_steps': [
            '1. Move database behind firewall (block port 3306 externally)',
            '2. Update to latest database version',
            '3. Use strong passwords (20+ characters)',
            '4. Enable SSL/TLS for connections',
            '5. Patch CVEs immediately'
        ],
        'impact': 'Database exposed + CVEs = Remote code execution possible',
        'compliance': ['PCI-DSS 2.2.2', 'HIPAA §164.312(a)(1)']
    },

    'Technology Disclosure': {
        'fix_steps': [
            '1. Remove X-Powered-By header',
            '2. Remove Server version header',
            '3. Customize error pages to hide versions'
        ],
        'nginx_config': 'server_tokens off;',
        'apache_config': r'ServerTokens Prod\nServerSignature Off',
        'php_config': 'expose_php = Off',
        'impact': 'Prevents attackers from targeting version-specific exploits',
        'compliance': ['CIS Benchmark']
    }
}


def get_vulnerability_explanation(finding_type, path=None):
    """
    Get detailed explanation for vulnerability type

    Args:
        finding_type (str): Type of vulnerability
        path (str): Optional path/file for context

    Returns:
        str: Detailed explanation
    """
    explanations = {
        'Sensitive File Exposed': f"Sensitive file '{path}' is publicly accessible. This could expose credentials, API keys, or configuration secrets to attackers.",
        'Directory Listing Enabled': f"Directory listing is enabled at '{path}'. Attackers can browse files and discover sensitive information or vulnerabilities.",
        'Admin Panel Accessible': f"Admin panel found at '{path}'. This is a high-value target for brute force attacks and unauthorized access.",
        'Default Installation Page': f"Default installation page detected at '{path}'. Unpatched default installations often contain known vulnerabilities."
    }

    return explanations.get(finding_type, f"Security issue detected: {finding_type}")


def categorize_finding_type(finding):
    """
    Categorize finding into CVE, configuration, or active_test

    Args:
        finding (dict): Finding dictionary with 'type' key

    Returns:
        str: 'cve-based', 'config-issue', or 'active-test'
    """
    finding_type = finding.get('type', '').lower()

    # CVE-based findings
    if 'cve' in finding_type or 'vulnerable' in finding_type:
        return 'cve-based'

    # Configuration issues
    config_types = [
        'missing security header',
        'insecure cookie',
        'cookie accessible to javascript',
        'technology disclosure',
        'server version disclosure',
        'open redirect',
        'header',
        'ssl',
        'tls',
        'cookie',
        'security',
        'configuration',
        'misconfiguration',
        'weak',
        'insecure',
        'cors',
        'csp'
    ]

    if any(ct in finding_type for ct in config_types):
        return 'config-issue'

    # Active test findings
    active_types = [
        'xxe vulnerability',
        'ssrf vulnerability',
        'file upload',
        'directory traversal',
        'sensitive file exposed',
        'directory listing enabled'
    ]

    if any(at in finding_type for at in active_types):
        return 'active-test'

    # Default to active-test
    return 'active-test'


def is_real_file_exposure(response, expected_filename):
    """
    Detect if HTTP 200 is actual file or generic HTML page
    Returns: True if real exposure, False if false positive

    Args:
        response: HTTP response object
        expected_filename (str): The filename/path we were looking for

    Returns:
        bool: True if real file exposure, False if false positive
    """
    # Check 1: Content-Type must match expected file
    content_type = response.headers.get('content-type', '').lower()

    # HTML pages are NOT config files
    if 'text/html' in content_type:
        # If we're looking for .env, .sql, .key files but getting HTML
        non_html_files = ['.env', '.sql', '.key', 'id_rsa', '.git',
                          '.aws', '.ssh', 'backup', 'dump', 'database',
                          'config.php', 'wp-config.php']

        if any(f in expected_filename for f in non_html_files):
            return False  # It's HTML, not the file we want

    # Check 2: Content length analysis
    content_length = int(response.headers.get('content-length', 0))

    # cPanel login page = 37,452 bytes
    # Generic error pages = usually 1000-50000 bytes
    # Real .env files = usually < 1000 bytes
    # Real SQL dumps = usually > 100,000 bytes or < 10,000 bytes

    if 'text/html' in content_type and 10000 < content_length < 50000:
        return False  # Likely a generic page, not real file

    # Check 3: Look for HTML tags in content (first 500 chars)
    try:
        content_preview = response.text[:500].lower()

        # If it has HTML structure, it's not a sensitive file
        html_indicators = ['<!doctype', '<html', '<head>', '<body>', '<meta']
        if any(indicator in content_preview for indicator in html_indicators):
            return False

        # Check for actual file content indicators
        if '.env' in expected_filename:
            # Real .env files have KEY=VALUE format
            if any(indicator in content_preview for indicator in
                   ['db_password=', 'api_key=', 'secret=', 'app_key=']):
                return True  # Real .env file

        if '.sql' in expected_filename or 'dump' in expected_filename:
            # Real SQL has these
            if any(indicator in content_preview for indicator in
                   ['create table', 'insert into', '-- mysql', 'drop table']):
                return True  # Real SQL dump

        if 'id_rsa' in expected_filename or '.key' in expected_filename:
            # Real SSH keys start with this
            if '-----begin' in content_preview or 'ssh-rsa' in content_preview:
                return True  # Real key file

    except:
        pass

    # If we get here and it's HTML, it's probably false positive
    if 'text/html' in content_type:
        return False

    # Default: if not HTML and passes other checks, assume real
    return True


def get_worker_count(asset_count):
    """
    Dynamically determine optimal worker count based on asset count

    Args:
        asset_count (int): Number of assets to scan

    Returns:
        int: Optimal number of parallel workers
    """
    # PERFORMANCE OPTIMIZED: Doubled worker counts for faster scans
    if asset_count <= 30:
        return 10  # Increased from 5
    elif asset_count <= 75:
        return 15  # Increased from 8
    elif asset_count <= 150:
        return 20  # Increased from 10
    else:
        return 30  # Max workers for very large scans (increased from 20)


def deduplicate_findings(findings):
    """
    Remove duplicate findings by URL + type

    Args:
        findings (list): List of findings

    Returns:
        list: Deduplicated findings
    """
    seen = {}
    unique = []

    for finding in findings:
        # Create unique key from URL + type
        key = f"{finding.get('url', '')}_{finding.get('type', '')}"

        if key not in seen:
            seen[key] = True
            unique.append(finding)

    return unique


def smart_deduplicate(findings):
    """
    Group findings by type + path, track affected assets

    Args:
        findings (list): List of findings

    Returns:
        list: Deduplicated findings with grouped assets
    """
    from urllib.parse import urlparse

    grouped = {}

    for finding in findings:
        url = finding.get('url', '')
        finding_type = finding.get('type', '')

        # Extract path from URL
        try:
            path = urlparse(url).path
        except:
            path = url

        # Create grouping key
        key = f"{finding_type}_{path}"

        if key not in grouped:
            grouped[key] = finding.copy()
            grouped[key]['affected_assets'] = [finding.get('asset', 'unknown')]
        else:
            # Add to affected assets list
            asset = finding.get('asset', 'unknown')
            if asset not in grouped[key]['affected_assets']:
                grouped[key]['affected_assets'].append(asset)

    # Convert back to list, update explanations
    result = []
    for key, finding in grouped.items():
        asset_count = len(finding['affected_assets'])
        if asset_count > 1:
            # Handle both 'explanation' and 'description' fields
            if 'explanation' in finding:
                finding['explanation'] += f" (Affects {asset_count} assets)"
            elif 'description' in finding:
                finding['description'] += f" (Affects {asset_count} assets)"
            finding['asset'] = ', '.join(finding['affected_assets'][:3])
            if asset_count > 3:
                finding['asset'] += f' +{asset_count - 3} more'
        result.append(finding)

    return result


def get_exposure_remediation(filepath):
    """Get remediation steps for exposed files"""

    remediations = {
        '.env': '''Steps:
* 1. Move .env files outside web root immediately
* 2. Add web server rules to block .env access
* 3. Rotate all exposed credentials
* 4. Review all environment files for exposure

Nginx:
location ~* \\.env {
    deny all;
}

Apache:
<Files ".env">
    Require all denied
</Files>''',

        '.git': '''Steps:
* 1. Remove .git folder from production web root
* 2. Add .git to web server deny rules
* 3. Review git history for exposed secrets
* 4. Rotate any credentials in git history

Nginx:
location ~* /\\.git {
    deny all;
}''',

        '.aws': '''Steps:
* 1. Revoke exposed AWS credentials immediately via AWS Console
* 2. Remove credentials file from web server
* 3. Use IAM roles instead of static credentials
* 4. Enable AWS CloudTrail to audit credential usage''',

        'config.php': '''Steps:
* 1. Move config files outside web root
* 2. Use environment variables for sensitive data
* 3. Set proper file permissions (chmod 600)
* 4. Add web server deny rules for config files''',

        'id_rsa': '''Steps:
* 1. Revoke compromised SSH key immediately
* 2. Generate new SSH key pair
* 3. Remove all SSH keys from web-accessible directories
* 4. Audit all servers for unauthorized access''',

        '.sql': '''Steps:
* 1. Remove all database dumps from web server
* 2. Store backups in secure, non-web-accessible location
* 3. Encrypt database backups
* 4. Review backup for exposed user data''',

        'phpinfo.php': '''Steps:
* 1. Delete phpinfo.php from production servers
* 2. Use environment-specific debug pages
* 3. Implement IP whitelisting for debug endpoints
* 4. Never expose phpinfo() in production''',
    }

    # Match remediation by file pattern
    for pattern, remediation in remediations.items():
        if pattern in filepath:
            return remediation

    return '''Steps:
* 1. Remove or restrict access to sensitive file
* 2. Review file for exposed credentials
* 3. Implement proper access controls
* 4. Rotate any exposed secrets'''


def check_data_exposure(assets):
    """
    Check for exposed sensitive files with content validation

    Args:
        assets (list): List of assets (subdomains/IPs) to check

    Returns:
        dict: Results with category, files checked, findings, and status
    """
    findings = []

    # Sensitive files to check with content validators
    sensitive_files = {
        # Environment files
        '/.env': {
            'severity': 'CRITICAL',
            'description': 'Environment file with passwords and secrets in plaintext',
            'validators': ['=', 'DB_', 'API_', 'SECRET', 'PASSWORD', 'KEY']
        },
        '/.env.local': {
            'severity': 'HIGH',
            'description': 'Local environment file with database credentials and API keys',
            'validators': ['=', 'DB_', 'API_', 'SECRET']
        },
        '/.env.production': {
            'severity': 'HIGH',
            'description': 'Production environment file with sensitive production secrets',
            'validators': ['=', 'DB_', 'API_', 'SECRET']
        },
        '/.env.development': {
            'severity': 'HIGH',
            'description': 'Development environment file',
            'validators': ['=']
        },

        # Git exposure
        '/.git/': {
            'severity': 'CRITICAL',
            'description': 'Git repository exposing source code and commit history',
            'validators': ['ref:', 'HEAD', 'refs/']
        },
        '/.git/config': {
            'severity': 'HIGH',
            'description': 'Git configuration with repository URLs and credentials',
            'validators': ['[core]', '[remote', 'url =']
        },
        '/.git/HEAD': {
            'severity': 'HIGH',
            'description': 'Git HEAD file',
            'validators': ['ref:', 'refs/heads/']
        },

        # AWS credentials
        '/.aws/credentials': {
            'severity': 'CRITICAL',
            'description': 'AWS keys providing full cloud access to infrastructure',
            'validators': ['aws_access_key_id', 'aws_secret_access_key']
        },

        # Config files
        '/config.php': {
            'severity': 'HIGH',
            'description': 'Configuration file containing database passwords and API keys',
            'validators': ['<?php', 'password', 'db_']
        },
        '/wp-config.php': {
            'severity': 'HIGH',
            'description': 'WordPress config with database credentials and security salts',
            'validators': ['DB_NAME', 'DB_USER', 'DB_PASSWORD']
        },
        '/web.config': {
            'severity': 'HIGH',
            'description': 'ASP.NET config with database credentials and API keys',
            'validators': ['<configuration', 'connectionString']
        },

        # SSH keys
        '/.ssh/id_rsa': {
            'severity': 'HIGH',
            'description': 'SSH private key providing root server access',
            'validators': ['BEGIN RSA PRIVATE KEY', 'BEGIN OPENSSH PRIVATE KEY']
        },
        '/id_rsa': {
            'severity': 'HIGH',
            'description': 'SSH private key for server access - full system compromise possible',
            'validators': ['BEGIN RSA PRIVATE KEY', 'BEGIN OPENSSH PRIVATE KEY']
        },

        # Database backups
        '/backup.sql': {
            'severity': 'HIGH',
            'description': 'Database backup with all user data and credentials',
            'validators': ['CREATE TABLE', 'INSERT INTO', 'DROP TABLE']
        },
        '/database.sql': {
            'severity': 'HIGH',
            'description': 'Database dump with sensitive user and application data',
            'validators': ['CREATE TABLE', 'INSERT INTO']
        },
        '/dump.sql': {
            'severity': 'HIGH',
            'description': 'SQL dump file',
            'validators': ['CREATE TABLE', 'INSERT INTO']
        },

        # PHP info
        '/phpinfo.php': {
            'severity': 'HIGH',
            'description': 'PHP info page exposing server configuration and paths',
            'validators': ['phpinfo()', 'PHP Version', 'System']
        },

        # Htaccess
        '/.htaccess': {
            'severity': 'HIGH',
            'description': 'Apache config file',
            'validators': ['RewriteRule', 'RewriteCond', 'Require']
        },
        '/.htpasswd': {
            'severity': 'HIGH',
            'description': 'Password file with hashed credentials for brute forcing',
            'validators': [':', '$apr1$', '$2y$']
        }
    }

    # Browser-like headers for requests
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive'
    }

    print(f"[DATA EXPOSURE] Checking for exposed sensitive files on {len(assets)} assets...")

    for asset in assets:
        for filepath, config in sensitive_files.items():
            try:
                # Try both HTTP and HTTPS
                for protocol in ['https', 'http']:
                    url = f"{protocol}://{asset}{filepath}"

                    response = requests.get(url, headers=headers, timeout=5, verify=False)

                    if response.status_code == 200:
                        content = response.text.upper()

                        # CRITICAL: Validate content is actually the sensitive file
                        validators = config['validators']
                        matches = sum(1 for validator in validators if validator.upper() in content)

                        # Need at least 2 validators to match (prevents false positives)
                        min_matches = 2 if len(validators) > 2 else 1

                        # Also check for common false positive patterns
                        false_positive_indicators = [
                            'ROUTE NOT',
                            'NOT FOUND',
                            'PAGE NOT FOUND',
                            '404',
                            'NOT IMPLEMENTED',
                            'COMING SOON',
                            'UNDER CONSTRUCTION',
                            'ACCESS DENIED',
                            'FORBIDDEN',
                            'UNAUTHORIZED'
                        ]

                        is_false_positive = any(indicator in content for indicator in false_positive_indicators)

                        # Only report if validators match AND not a false positive
                        if matches >= min_matches and not is_false_positive:
                            findings.append({
                                'type': 'Sensitive File Exposed',
                                'test': 'Data Exposure Check',
                                'severity': config['severity'],
                                'description': config['description'],
                                'explanation': f"Validated exposure: {filepath} contains {matches}/{len(validators)} expected patterns",
                                'evidence': url,
                                'url': url,
                                'asset': asset,
                                'file': filepath,
                                'finding_type': 'active-test',
                                'remediation': get_exposure_remediation(filepath),
                                'cve': None,
                                'cvss': 9.0 if config['severity'] == 'CRITICAL' else 7.5
                            })

                            print(f"[DATA EXPOSURE] 🚨 VALIDATED: {url} ({matches}/{len(validators)} patterns matched)")
                            break  # Found via one protocol, skip the other
                        elif response.status_code == 200 and matches < min_matches:
                            print(f"[DATA EXPOSURE] ℹ️  Skipped false positive: {url} (validators: {matches}/{len(validators)})")

            except Exception as e:
                continue

    print(f"[DATA EXPOSURE] Content validation complete: {len(findings)} actual exposures found")

    return {
        'category': 'Data Exposure',
        'files_checked': len(assets) * len(sensitive_files),
        'findings': findings,
        'status': 'failed' if findings else 'passed'
    }


def run_lightbox_scan(discovered_assets, domain, progress_callback=None):
    """
    Automated security testing on discovered assets with optional progress tracking

    Args:
        discovered_assets (dict): Assets from ASM scan (subdomains, cloud_assets, etc.)
        domain (str): Target domain being scanned
        progress_callback (callable, optional): Function to call with progress updates

    Returns:
        dict: Lightbox findings categorized by severity
    """
    def report_progress(step, progress, total_steps=100):
        """Report progress back to API"""
        if progress_callback:
            progress_callback({
                'status': 'running',
                'progress': progress,
                'current_step': step,
                'total_steps': total_steps
            })

    print(f"\n{'='*60}")
    print(f"[LIGHTBOX] Starting automated security testing...")
    print(f"{'='*60}\n")

    report_progress("Initializing scan", 0)

    findings = {
        'critical': [],
        'high': [],
        'medium': [],
        'low': [],
        'total_tests': 0,
        'total_findings': 0
    }

    # Test subdomains
    subdomains_to_test = []

    # Collect DNS subdomains
    for sub in discovered_assets.get('subdomains', []):
        subdomains_to_test.append(sub.get('subdomain'))

    # Collect crt.sh subdomains (limit to first 10 for testing)
    for sub in discovered_assets.get('crt_subdomains', [])[:10]:
        subdomains_to_test.append(sub.get('subdomain'))

    # Collect discovered IPs
    discovered_ips = discovered_assets.get('discovered_ips', [])
    for ip_entry in discovered_ips:
        # IP entries might be strings or dicts
        if isinstance(ip_entry, dict):
            ip = ip_entry.get('ip')
        else:
            ip = ip_entry
        if ip and ip not in subdomains_to_test:
            subdomains_to_test.append(ip)

    # PERFORMANCE OPTIMIZATION: Filter out unreachable hosts early
    report_progress("Filtering reachable assets", 5)
    print(f"[LIGHTBOX] Filtering {len(subdomains_to_test)} assets for reachability...")
    reachable_assets = []
    unreachable_count = 0

    # Browser-like headers to bypass basic bot detection
    reachability_headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    }

    for asset in subdomains_to_test:
        reachable = False

        # Try HTTPS first
        try:
            url = f"https://{asset}"
            response = requests.get(url, headers=reachability_headers, timeout=5, verify=False)
            if response.status_code < 500:
                reachable = True
                reachable_assets.append(asset)
        except requests.exceptions.SSLError:
            # SSL errors often mean the host is reachable, just has cert issues
            reachable = True
            reachable_assets.append(asset)
        except:
            pass

        # If HTTPS failed, try HTTP
        if not reachable:
            try:
                url = f"http://{asset}"
                response = requests.get(url, headers=reachability_headers, timeout=5, verify=False)
                if response.status_code < 500:
                    reachable = True
                    reachable_assets.append(asset)
            except:
                pass

        if not reachable:
            print(f"[LIGHTBOX] ⏩ Skipping unreachable: {asset}")
            unreachable_count += 1

    subdomains_to_test = reachable_assets
    print(f"[LIGHTBOX] ✓ {len(reachable_assets)} reachable, {unreachable_count} skipped\n")

    report_progress("Testing HTTP security", 10)

    # DYNAMIC PARALLEL SCALING: Adjust workers based on asset count
    optimal_workers = get_worker_count(len(subdomains_to_test))

    subdomain_count = len([a for a in subdomains_to_test if not a.replace('.', '').isdigit()])
    ip_count = len([a for a in subdomains_to_test if a.replace('.', '').isdigit()])

    print(f"[LIGHTBOX] Testing {len(subdomains_to_test)} total assets ({subdomain_count} domains + {ip_count} IPs)...\n")
    print(f"[LIGHTBOX] 🚀 DYNAMIC SCALING: {optimal_workers} parallel workers for optimal speed\n")

    # PARALLEL TESTING: Dynamic worker count using ThreadPoolExecutor
    def test_single_asset(subdomain):
        """Test a single asset with all checks"""
        print(f"[LIGHTBOX] Testing: {subdomain}")

        # Local findings for this asset (thread-safe)
        local_findings = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'total_tests': 0
        }

        # Test common exposures
        local_findings = test_sensitive_files(subdomain, local_findings)
        local_findings = test_directory_listing(subdomain, local_findings)
        local_findings = test_admin_access(subdomain, local_findings)
        local_findings = test_default_pages(subdomain, local_findings)

        return local_findings

    # Execute tests in parallel (dynamic worker count)
    with ThreadPoolExecutor(max_workers=optimal_workers) as executor:
        # Submit all tasks
        future_to_subdomain = {
            executor.submit(test_single_asset, subdomain): subdomain
            for subdomain in subdomains_to_test
        }

        # Collect results as they complete
        for future in as_completed(future_to_subdomain):
            subdomain = future_to_subdomain[future]
            try:
                local_findings = future.result()

                # Merge local findings into main findings (thread-safe merge)
                for severity in ['critical', 'high', 'medium', 'low']:
                    findings[severity].extend(local_findings[severity])
                findings['total_tests'] += local_findings['total_tests']

            except Exception as e:
                print(f"[LIGHTBOX] ❌ Error testing {subdomain}: {e}")

    # Count total findings from manual tests
    manual_findings = (
        len(findings['critical']) +
        len(findings['high']) +
        len(findings['medium']) +
        len(findings['low'])
    )

    print(f"\n{'='*60}")
    print(f"[LIGHTBOX] HTTP Security Testing Complete!")
    print(f"[LIGHTBOX] HTTP Security Checks: {findings['total_tests']}")
    print(f"[LIGHTBOX] HTTP Security Findings: {manual_findings}")
    print(f"{'='*60}\n")

    report_progress("Testing default credentials", 30)

    # Test default credentials on discovered admin panels
    print(f"[LIGHTBOX] Testing default credentials on admin panels...")
    admin_panels = [f for f in findings['high'] if f['type'] == 'Admin Panel Accessible']
    if admin_panels:
        cred_findings = test_default_credentials(admin_panels)
        findings['critical'].extend(cred_findings)
        print(f"[LIGHTBOX] Default credential tests: {len(admin_panels)} panels tested, {len(cred_findings)} successful logins")
    else:
        print(f"[LIGHTBOX] No admin panels found to test credentials")

    report_progress("Checking security headers", 40)

    # Check security headers
    print(f"[LIGHTBOX] Checking security headers on {len(subdomains_to_test)} assets...")
    header_findings = check_security_headers(subdomains_to_test)

    # Categorize header findings by severity
    for finding in header_findings:
        severity = finding['severity'].lower()
        findings[severity].append(finding)

    print(f"[LIGHTBOX] Security header checks: {len(header_findings)} issues found\n")

    report_progress("Checking SSL/TLS configuration", 50)

    # Check SSL/TLS vulnerabilities
    print(f"[LIGHTBOX] Checking SSL/TLS configurations on {len(subdomains_to_test)} assets...")
    ssl_findings = check_ssl_vulnerabilities(subdomains_to_test)

    # Categorize SSL findings by severity
    for finding in ssl_findings:
        severity = finding['severity'].lower()
        findings[severity].append(finding)

    print(f"[LIGHTBOX] SSL/TLS checks: {len(ssl_findings)} issues found\n")

    # Check for open redirects
    print(f"[LIGHTBOX] Testing for open redirects on {len(subdomains_to_test)} assets...")
    redirect_findings = check_open_redirects(subdomains_to_test)

    # Categorize redirect findings by severity
    for finding in redirect_findings:
        severity = finding['severity'].lower()
        findings[severity].append(finding)

    print(f"[LIGHTBOX] Open redirect checks: {len(redirect_findings)} vulnerabilities found\n")

    # Check for cookie security issues
    print(f"[LIGHTBOX] Checking cookie security on {len(subdomains_to_test)} assets...")
    cookie_findings = check_cookie_security(subdomains_to_test)

    # Categorize cookie findings by severity
    for finding in cookie_findings:
        severity = finding['severity'].lower()
        findings[severity].append(finding)

    # Check for information disclosure
    print(f"[LIGHTBOX] Checking for information disclosure on {len(subdomains_to_test)} assets...")
    info_findings = check_information_disclosure(subdomains_to_test)

    # Categorize info findings by severity
    for finding in info_findings:
        severity = finding['severity'].lower()
        findings[severity].append(finding)

    print(f"[LIGHTBOX] Cookie/Info checks: {len(cookie_findings) + len(info_findings)} issues found\n")

    # Test database and SSH exploitability (if port scan results available)
    port_scan_results = discovered_assets.get('port_scan_results', [])
    if port_scan_results:
        print(f"[LIGHTBOX] Testing database exploitability on {len([p for p in port_scan_results if p.get('port') in [3306, 5432, 1433, 27017]])} database ports...")
        db_exploits = test_database_exploitability(port_scan_results)

        print(f"[LIGHTBOX] Testing SSH exploitability on {len([p for p in port_scan_results if p.get('port') == 22])} SSH ports...")
        ssh_exploits = test_ssh_exploitability(port_scan_results)

        # Categorize exploitability findings by severity
        for finding in db_exploits + ssh_exploits:
            severity = finding['severity'].lower()
            findings[severity].append(finding)

        print(f"[LIGHTBOX] Exploitability: {len(db_exploits) + len(ssh_exploits)} findings\n")
    else:
        print(f"[LIGHTBOX] No port scan results available for exploitability testing\n")

    # Test file upload vulnerabilities
    print(f"[LIGHTBOX] Testing file upload endpoints on {len(subdomains_to_test)} assets...")
    upload_vulns = test_file_upload_vulnerabilities(subdomains_to_test)

    # Test directory traversal vulnerabilities
    print(f"[LIGHTBOX] Testing directory traversal on {len(subdomains_to_test)} assets...")
    traversal_vulns = test_directory_traversal(subdomains_to_test)

    # Categorize upload and traversal findings by severity
    for finding in upload_vulns + traversal_vulns:
        severity = finding['severity'].lower()
        findings[severity].append(finding)

    print(f"[LIGHTBOX] Upload/Traversal: {len(upload_vulns) + len(traversal_vulns)} findings\n")

    report_progress("Testing injection vulnerabilities", 65)

    # Test XXE vulnerabilities
    print(f"[LIGHTBOX] Testing XXE vulnerabilities on {len(subdomains_to_test)} assets...")
    xxe_vulns = test_xxe_vulnerabilities(subdomains_to_test)

    # Test SSRF vulnerabilities
    print(f"[LIGHTBOX] Testing SSRF vulnerabilities on {len(subdomains_to_test)} assets...")
    ssrf_vulns = test_ssrf_vulnerabilities(subdomains_to_test)

    # Categorize XXE and SSRF findings by severity
    for finding in xxe_vulns + ssrf_vulns:
        severity = finding['severity'].lower()
        findings[severity].append(finding)

    print(f"[LIGHTBOX] XXE/SSRF: {len(xxe_vulns) + len(ssrf_vulns)} findings\n")

    report_progress("Running API Security tests", 70)

    # Run API Security and Business Logic tests on reachable assets
    print(f"[LIGHTBOX] Running API Security and Business Logic tests...")
    api_security_findings = []
    business_logic_findings = []
    api_tests_run = 0
    logic_tests_run = 0

    # Create a session for the tests
    test_session = requests.Session()
    test_session.verify = False
    test_session.timeout = 5

    for subdomain in subdomains_to_test[:10]:  # Limit to first 10 for performance
        for protocol in ['https', 'http']:
            target = f"{protocol}://{subdomain}"
            try:
                # API Security Tests
                api_tests = APISecurityTests(target, test_session)
                api_results = api_tests.run_all_tests()
                api_tests_run += api_results.get('tests_run', 0)

                for finding in api_results.get('findings', []):
                    severity = finding.get('severity', 'INFO').lower()
                    finding['asset'] = subdomain
                    finding['url'] = target
                    finding['type'] = finding.get('test', 'API Security Issue')
                    finding['finding_type'] = 'active-test'
                    api_security_findings.append(finding)

                # Business Logic Tests
                logic_tests = BusinessLogicTests(target, test_session)
                logic_results = logic_tests.run_all_tests()
                logic_tests_run += logic_results.get('tests_run', 0)

                for finding in logic_results.get('findings', []):
                    severity = finding.get('severity', 'INFO').lower()
                    finding['asset'] = subdomain
                    finding['url'] = target
                    finding['type'] = finding.get('test', 'Business Logic Issue')
                    finding['finding_type'] = 'active-test'
                    business_logic_findings.append(finding)

                break  # Found working protocol, skip the other
            except Exception as e:
                continue

    # Categorize API Security findings by severity
    for finding in api_security_findings:
        severity = finding.get('severity', 'INFO').lower()
        if severity in findings:
            findings[severity].append(finding)

    # Categorize Business Logic findings by severity
    for finding in business_logic_findings:
        severity = finding.get('severity', 'INFO').lower()
        if severity in findings:
            findings[severity].append(finding)

    print(f"[LIGHTBOX] API Security: {len(api_security_findings)} findings")
    print(f"[LIGHTBOX] Business Logic: {len(business_logic_findings)} findings\n")

    report_progress("Running Nuclei template scans", 75)

    # Run template scan
    print(f"[LIGHTBOX] Running template vulnerability scans...")
    nuclei_results = run_nuclei_scan(discovered_assets)

    # Merge template scan results with HTTP security check results
    for severity in ['critical', 'high', 'medium', 'low']:
        findings[severity].extend(nuclei_results.get(severity, []))

    # Add info findings from template scans
    findings['info'] = nuclei_results.get('info', [])

    # Update total counts
    findings['total_findings'] = (
        len(findings['critical']) +
        len(findings['high']) +
        len(findings['medium']) +
        len(findings['low']) +
        len(findings.get('info', []))
    )
    findings['template_findings'] = nuclei_results.get('total_findings', 0)
    findings['http_security_findings'] = manual_findings
    findings['templates_used'] = nuclei_results.get('total_templates_used', 0)

    # ============================================================================
    # BUILD COMPREHENSIVE TEST_RESULTS DICTIONARY
    # ============================================================================
    # This tracks ALL test categories for accurate total_tests calculation

    # Calculate test counts for each category
    http_security_tests = findings.get('total_tests', 0)  # From parallel scans (sensitive files, dirs, admin, defaults)

    # Authentication: panels tested for default credentials
    panels_tested = len(admin_panels) if admin_panels else 0

    # Injection tests: XXE + SSRF endpoints tested
    # XXE tests 6 endpoints per subdomain, SSRF tests 5 params per subdomain
    injection_tests_count = len(subdomains_to_test) * 6 + len(subdomains_to_test) * 5

    # Data Exposure: sensitive files checked (already in http_security_tests, but track separately)
    # 44 sensitive paths tested per asset
    files_checked = len(subdomains_to_test) * 44

    # Network: services tested (SSL + open ports)
    services_tested = len(subdomains_to_test)  # SSL checks
    if port_scan_results:
        services_tested += len(port_scan_results)  # Port-based tests

    # Nuclei templates
    nuclei_templates = nuclei_results.get('total_templates_used', 0)

    # Build the test_results dictionary for organized tracking
    test_results = {
        'http_security': {
            'tests_run': http_security_tests,
            'description': 'Sensitive files, directory listing, admin panels, default pages'
        },
        'authentication': {
            'panels_tested': panels_tested,
            'description': 'Default credentials tested on admin panels'
        },
        'injection': {
            'tests_run': injection_tests_count,
            'description': 'XXE and SSRF vulnerability tests'
        },
        'data_exposure': {
            'files_checked': files_checked,
            'description': 'Sensitive file exposure checks'
        },
        'network': {
            'services_tested': services_tested,
            'description': 'SSL/TLS and network service tests'
        },
        'api_security': {
            'tests_run': api_tests_run,
            'description': 'API security tests (GraphQL, REST, Swagger)'
        },
        'business_logic': {
            'tests_run': logic_tests_run,
            'description': 'Business logic tests (IDOR, price manipulation)'
        },
        'nuclei': {
            'templates_used': nuclei_templates,
            'description': 'Nuclei vulnerability template scans'
        }
    }

    # Store test_results in findings for reference
    findings['test_results'] = test_results

    # ============================================================================
    # CALCULATE TOTAL TESTS FROM ALL CATEGORIES
    # ============================================================================
    total_tests_count = 0

    # HTTP Security (tests_run)
    if 'http_security' in test_results:
        total_tests_count += test_results['http_security'].get('tests_run', 0)

    # Authentication (panels_tested)
    if 'authentication' in test_results:
        total_tests_count += test_results['authentication'].get('panels_tested', 0)

    # Injection (tests_run)
    if 'injection' in test_results:
        total_tests_count += test_results['injection'].get('tests_run', 0)

    # Data Exposure (files_checked) - NOTE: May overlap with http_security, use conservative count
    # Skip to avoid double-counting with http_security

    # Network (services_tested)
    if 'network' in test_results:
        total_tests_count += test_results['network'].get('services_tested', 0)

    # API Security (tests_run)
    if 'api_security' in test_results:
        total_tests_count += test_results['api_security'].get('tests_run', 0)

    # Business Logic (tests_run)
    if 'business_logic' in test_results:
        total_tests_count += test_results['business_logic'].get('tests_run', 0)

    # Nuclei (templates_used)
    if 'nuclei' in test_results:
        total_tests_count += test_results['nuclei'].get('templates_used', 0)

    # Store final total
    findings['total_tests'] = total_tests_count

    # Store individual test counts for backward compatibility
    findings['api_tests_run'] = api_tests_run
    findings['logic_tests_run'] = logic_tests_run

    print(f"\n[LIGHTBOX] Total tests calculated: {total_tests_count}")

    print(f"\n{'='*60}")
    print(f"[LIGHTBOX] Complete Scan Summary")
    print(f"{'='*60}")
    print(f"[LIGHTBOX] HTTP Security Checks: {test_results['http_security']['tests_run']}")
    print(f"[LIGHTBOX] Authentication Tests: {test_results['authentication']['panels_tested']}")
    print(f"[LIGHTBOX] Injection Tests: {test_results['injection']['tests_run']}")
    print(f"[LIGHTBOX] Network Services: {test_results['network']['services_tested']}")
    print(f"[LIGHTBOX] API Security Tests: {test_results['api_security']['tests_run']}")
    print(f"[LIGHTBOX] Business Logic Tests: {test_results['business_logic']['tests_run']}")
    print(f"[LIGHTBOX] Nuclei Templates: {test_results['nuclei']['templates_used']}")
    print(f"[LIGHTBOX] ─────────────────────────────────────────────────────────")
    print(f"[LIGHTBOX] TOTAL TESTS: {findings['total_tests']}")
    print(f"[LIGHTBOX] HTTP Security Findings: {manual_findings}")
    print(f"[LIGHTBOX] Template Scan Findings: {findings['template_findings']}")
    print(f"[LIGHTBOX] Templates Used: {findings['templates_used']}")
    print(f"\n[LIGHTBOX] Total Findings: {findings['total_findings']}")
    print(f"[LIGHTBOX]   Critical: {len(findings['critical'])}")
    print(f"[LIGHTBOX]   High: {len(findings['high'])}")
    print(f"[LIGHTBOX]   Medium: {len(findings['medium'])}")
    print(f"[LIGHTBOX]   Low: {len(findings['low'])}")
    print(f"[LIGHTBOX]   Info: {len(findings.get('info', []))}")
    print(f"{'='*60}\n")

    report_progress("Deduplicating findings", 90)

    # Deduplicate findings by URL + type
    print(f"[LIGHTBOX] Deduplicating findings...")
    for severity in ['critical', 'high', 'medium', 'low', 'info']:
        if severity in findings and isinstance(findings[severity], list):
            original_count = len(findings[severity])
            findings[severity] = deduplicate_findings(findings[severity])
            dedupe_count = original_count - len(findings[severity])
            if dedupe_count > 0:
                print(f"[LIGHTBOX]   {severity.capitalize()}: Removed {dedupe_count} duplicates")

    # Apply smart deduplication (group by type + path, track affected assets)
    print(f"[LIGHTBOX] Applying smart deduplication (grouping by type + path)...")
    for severity in ['critical', 'high', 'medium', 'low', 'info']:
        if severity in findings and isinstance(findings[severity], list):
            original_count = len(findings[severity])
            findings[severity] = smart_deduplicate(findings[severity])
            smart_dedupe_count = original_count - len(findings[severity])
            if smart_dedupe_count > 0:
                print(f"[LIGHTBOX]   {severity.capitalize()}: Grouped {smart_dedupe_count} similar findings")

    # Recalculate total after deduplication
    findings['total_findings'] = (
        len(findings['critical']) +
        len(findings['high']) +
        len(findings['medium']) +
        len(findings['low']) +
        len(findings.get('info', []))
    )

    print(f"[LIGHTBOX] After smart deduplication: {findings['total_findings']} unique findings\n")

    # Add finding_type badges to all findings
    print(f"[LIGHTBOX] Categorizing findings by type...")
    for severity in ['critical', 'high', 'medium', 'low', 'info']:
        if severity in findings and isinstance(findings[severity], list):
            for finding in findings[severity]:
                if 'finding_type' not in finding:
                    # Categorize using helper function
                    finding['finding_type'] = categorize_finding_type(finding)

    report_progress("Scan complete", 100)

    # Save scan to history
    try:
        import time
        from database import save_lightbox_scan as db_save_lightbox_scan
        scan_id = f"lightbox_{int(time.time())}_{domain.replace('.', '_').replace('/', '_')}"
        db_save_lightbox_scan(
            scan_id=scan_id,
            target=domain,
            results=findings,
            user_id=None  # Will add user tracking later with auth
        )
        findings['history_scan_id'] = scan_id
        print(f"[LIGHTBOX] Saved to history: {scan_id}")
    except Exception as e:
        print(f"[LIGHTBOX] Warning: Failed to save to history: {e}")

    return findings


def test_sensitive_files(subdomain, findings):
    """
    Test for exposed sensitive files (.env, .git, etc.)
    FULL SCAN: All 37+ vulnerability checks

    Args:
        subdomain (str): Domain to test
        findings (dict): Findings dictionary to update

    Returns:
        dict: Updated findings
    """
    # Enhanced explanations for specific file types
    FILE_EXPLANATIONS = {
        '/.env': 'Environment file with passwords and secrets in plaintext',
        '/.env.local': 'Local environment file with database credentials and API keys',
        '/.env.production': 'Production environment file with sensitive production secrets',
        '/wp-config.php': 'WordPress config with database credentials and security salts',
        '/web.config': 'ASP.NET config with database credentials and API keys',
        '/config.php': 'Configuration file containing database passwords and API keys',
        '/.aws/credentials': 'AWS keys providing full cloud access to infrastructure',
        '/.azure/credentials': 'Azure credentials providing cloud infrastructure access',
        '/backup.sql': 'Database backup with all user data and credentials',
        '/database.sql': 'Database dump with sensitive user and application data',
        '/id_rsa': 'SSH private key for server access - full system compromise possible',
        '/.ssh/id_rsa': 'SSH private key providing root server access',
        '/server.key': 'SSL/TLS private key allowing MITM attacks',
        '/private.key': 'Private encryption key exposing encrypted data',
        '/.git/': 'Git repository exposing source code and commit history',
        '/.git/config': 'Git configuration with repository URLs and credentials',
        '/phpinfo.php': 'PHP info page exposing server configuration and paths',
        '/.htpasswd': 'Password file with hashed credentials for brute forcing'
    }

    # FULL 37+ VULNERABILITY CHECKS (comprehensive coverage)
    sensitive_paths = [
        # Environment & Configuration
        '/.env',
        '/.env.local',
        '/.env.production',
        '/.env.development',
        '/config.php',
        '/configuration.php',
        '/wp-config.php',
        '/web.config',
        '/app.config',
        '/settings.py',
        '/.htaccess',
        '/.htpasswd',

        # Git & Version Control
        '/.git/',
        '/.git/config',
        '/.git/HEAD',
        '/.gitignore',
        '/.svn/',
        '/.hg/',

        # Cloud Credentials
        '/.aws/credentials',
        '/.azure/credentials',
        '/gcloud.json',
        '/firebase.json',

        # SSH Keys
        '/.ssh/id_rsa',
        '/.ssh/id_rsa.pub',
        '/.ssh/known_hosts',
        '/id_rsa',
        '/id_rsa.pub',
        '/server.key',
        '/private.key',

        # Database Backups
        '/backup.sql',
        '/database.sql',
        '/dump.sql',
        '/db.sql',
        '/backup.zip',
        '/backup.tar.gz',

        # PHP Info & Debug
        '/phpinfo.php',
        '/info.php',
        '/test.php',

        # MacOS
        '/.DS_Store'
    ]

    for path in sensitive_paths:
        findings['total_tests'] += 1

        for protocol in ['https', 'http']:
            url = f"{protocol}://{subdomain}{path}"

            try:
                # Standard timeout for reliable testing
                response = requests.get(url, timeout=5, allow_redirects=False, verify=False)

                # SKIP 401: HTTP 401 = requires auth = protected = NOT a vulnerability
                if response.status_code == 401:
                    continue

                # Only flag 200 (public access) with SMART DETECTION
                if response.status_code == 200:
                    # SMART DETECTION: Filter out false positives
                    if is_real_file_exposure(response, path):
                        severity = 'critical' if path in ['/.env', '/.git/', '/.aws/credentials'] else 'high'

                        # Use enhanced explanations if available, fallback to generic
                        explanation = FILE_EXPLANATIONS.get(path, f'Sensitive file exposed: {path}')

                        findings[severity].append({
                            'type': 'Sensitive File Exposed',
                            'finding_type': 'active-test',  # Active security test
                            'asset': subdomain,
                            'url': url,
                            'description': f"Sensitive file publicly accessible: {path} (HTTP {response.status_code})",
                            'explanation': explanation,
                            'status_code': response.status_code,
                            'severity': severity.upper(),
                            'remediation': REMEDIATION_GUIDES.get('Sensitive File Exposed', {})
                        })

                        print(f"[LIGHTBOX] 🚨 REAL EXPOSURE: {url} (HTTP {response.status_code})")
                        break  # Found via one protocol, no need to test the other
                    # If not real, silently skip (no log spam)

            except requests.exceptions.RequestException:
                pass  # Connection failed, expected for most tests

    return findings


def test_directory_listing(subdomain, findings):
    """
    Test for directory listing enabled

    Args:
        subdomain (str): Domain to test
        findings (dict): Findings dictionary to update

    Returns:
        dict: Updated findings
    """
    common_dirs = [
        '/uploads/',
        '/images/',
        '/files/',
        '/backup/',
        '/logs/',
        '/admin/',
        '/assets/',
        '/static/',
        '/media/'
    ]

    for dir_path in common_dirs:
        findings['total_tests'] += 1

        for protocol in ['https', 'http']:
            url = f"{protocol}://{subdomain}{dir_path}"

            try:
                # Standard timeout for reliable testing
                response = requests.get(url, timeout=5, allow_redirects=False, verify=False)

                # SKIP 401: Protected directories are not vulnerable
                if response.status_code == 401:
                    continue

                # Check for directory listing indicators (only 200 - directory must be accessible)
                if response.status_code == 200:
                    content = response.text.lower()

                    # Common directory listing indicators
                    indicators = [
                        'index of',
                        'parent directory',
                        'directory listing',
                        '<title>index of'
                    ]

                    # Check if it's a real directory listing (not a generic HTML page)
                    if any(indicator in content for indicator in indicators):
                        # Additional verification: ensure it's not a fake page
                        content_type = response.headers.get('content-type', '').lower()

                        # Directory listings are usually text/html but should contain file links
                        # Skip if it's a login page or generic error page
                        skip_indicators = [
                            'login',
                            'sign in',
                            'authentication required',
                            'access denied'
                        ]

                        if not any(skip in content for skip in skip_indicators):
                            explanation = get_vulnerability_explanation('Directory Listing Enabled', dir_path)

                            findings['medium'].append({
                                'type': 'Directory Listing Enabled',
                                'asset': subdomain,
                                'url': url,
                                'description': f"Directory listing enabled at {dir_path} (HTTP {response.status_code})",
                                'explanation': explanation,
                                'status_code': response.status_code,
                                'severity': 'MEDIUM'
                            })

                            print(f"[LIGHTBOX] ⚠️  Directory Listing: {url} (HTTP {response.status_code})")
                            break

            except requests.exceptions.RequestException:
                pass

    return findings


def test_admin_access(subdomain, findings):
    """
    Test for accessible admin panels

    Args:
        subdomain (str): Domain to test
        findings (dict): Findings dictionary to update

    Returns:
        dict: Updated findings
    """
    # Enhanced explanations for admin panel types
    ADMIN_PANEL_EXPLANATIONS = {
        '/wp-admin': 'WordPress admin panel publicly accessible - should be IP restricted or behind VPN',
        '/wp-login.php': 'WordPress login page exposed - target for brute force attacks',
        '/phpmyadmin': 'phpMyAdmin database interface exposed - critical database access point',
        '/cpanel': 'cPanel control panel accessible - full server management interface',
        '/admin': 'Admin panel publicly accessible - should be IP restricted or protected',
        '/administrator': 'Administrator interface exposed - high-value target for attacks',
        '/console': 'Admin console accessible - application management interface exposed',
        '/dashboard': 'Dashboard interface publicly accessible - should require authentication'
    }

    admin_paths = [
        '/admin',
        '/admin/',
        '/admin/login',
        '/administrator',
        '/wp-admin',
        '/wp-login.php',
        '/phpmyadmin',
        '/cpanel',
        '/login',
        '/console',
        '/dashboard'
    ]

    for path in admin_paths:
        findings['total_tests'] += 1

        for protocol in ['https', 'http']:
            url = f"{protocol}://{subdomain}{path}"

            try:
                # Standard timeout for reliable testing
                response = requests.get(url, timeout=5, allow_redirects=True, verify=False)

                # Only flag 200 (actual exposure) - 401 is protected, NOT vulnerable
                if response.status_code == 401:
                    # Protected with authentication - NOT a vulnerability
                    continue

                # Check if admin panel is accessible (only 200 = publicly accessible)
                if response.status_code == 200:
                    content = response.text.lower()

                    # Look for login/admin indicators
                    admin_indicators = [
                        'login',
                        'password',
                        'username',
                        'admin',
                        'dashboard',
                        'sign in'
                    ]

                    # SMART DETECTION: Only flag if it's a real admin panel
                    if any(indicator in content for indicator in admin_indicators):
                        # Additional verification: Check content length and type
                        content_type = response.headers.get('content-type', '').lower()

                        # Filter out generic error pages and redirects
                        # Real admin panels typically have forms
                        has_form = '<form' in content or 'type="password"' in content or 'type="text"' in content

                        # Skip if it looks like a generic error or info page
                        error_indicators = [
                            'page not found',
                            '404',
                            'not available',
                            'under construction'
                        ]

                        is_error_page = any(err in content for err in error_indicators)

                        # Only flag if it has form elements and is not an error page
                        if has_form and not is_error_page:
                            # Use enhanced explanations if available, fallback to generic
                            explanation = ADMIN_PANEL_EXPLANATIONS.get(
                                path,
                                f'Admin panel at {path} publicly accessible - should be IP restricted'
                            )

                            findings['high'].append({
                                'type': 'Admin Panel Accessible',
                                'asset': subdomain,
                                'url': url,
                                'description': f"Admin panel found at {path} (HTTP {response.status_code})",
                                'explanation': explanation,
                                'status_code': response.status_code,
                                'severity': 'HIGH',
                                'remediation': REMEDIATION_GUIDES.get('Admin Panel Accessible', {})
                            })

                            print(f"[LIGHTBOX] ⚠️  Admin Panel: {url} (HTTP {response.status_code})")
                            break

            except requests.exceptions.RequestException:
                pass

    return findings


def test_default_pages(subdomain, findings):
    """
    Test for default installation pages

    Args:
        subdomain (str): Domain to test
        findings (dict): Findings dictionary to update

    Returns:
        dict: Updated findings
    """
    default_indicators = {
        'apache': ['It works!', 'Apache2 Debian Default Page', 'Apache2 Ubuntu Default Page'],
        'nginx': ['Welcome to nginx!', 'nginx default page'],
        'iis': ['Welcome to IIS', 'Internet Information Services'],
        'tomcat': ['Apache Tomcat', 'Tomcat Default Page'],
        'jenkins': ['Dashboard [Jenkins]', 'Welcome to Jenkins'],
        'gitlab': ['GitLab', 'Sign in · GitLab']
    }

    for protocol in ['https', 'http']:
        findings['total_tests'] += 1
        url = f"{protocol}://{subdomain}/"

        try:
            # FASTER TIMEOUT: 2s instead of 5s
            response = requests.get(url, timeout=2, allow_redirects=True, verify=False)

            # SKIP 401: Protected pages are not vulnerable
            if response.status_code == 401:
                continue

            # Only flag 200 responses for default pages
            if response.status_code == 200:
                content = response.text

                for service, indicators in default_indicators.items():
                    if any(indicator in content for indicator in indicators):
                        # SMART DETECTION: Verify it's actually a default page
                        content_type = response.headers.get('content-type', '').lower()

                        # Ensure it's HTML content
                        if 'text/html' not in content_type:
                            continue

                        # Additional check: Default pages are usually small and simple
                        # Skip if it looks like a custom production site
                        custom_site_indicators = [
                            'cookie consent',
                            'privacy policy',
                            'terms of service',
                            'copyright 20',  # Production sites have copyright notices
                            'all rights reserved'
                        ]

                        is_custom_site = any(ind in content.lower() for ind in custom_site_indicators)

                        # Only flag if it's truly a default installation page (not a custom site)
                        if not is_custom_site:
                            explanation = get_vulnerability_explanation('Default Installation Page', f'{service} at /')

                            findings['low'].append({
                                'type': 'Default Installation Page',
                                'asset': subdomain,
                                'url': url,
                                'description': f"Default {service} installation page detected (HTTP {response.status_code})",
                                'explanation': explanation,
                                'status_code': response.status_code,
                                'severity': 'LOW'
                            })

                            print(f"[LIGHTBOX] ℹ️  Default Page: {url} ({service}, HTTP {response.status_code})")
                            break

        except requests.exceptions.RequestException:
            pass

    return findings


def test_default_credentials(admin_panels):
    """
    Test default credentials with smart deduplication

    Args:
        admin_panels (list): List of admin panel findings from test_admin_access

    Returns:
        list: Findings with successful credential matches
    """
    findings = []

    # STEP 1: Deduplicate panels by content signature
    print(f"[LIGHTBOX] Deduplicating {len(admin_panels)} admin panels before testing...")

    unique_panels = {}
    for panel in admin_panels:
        url = panel['url']
        try:
            response = requests.get(url, timeout=5, verify=False)
            # Create signature from response
            signature = f"{response.status_code}_{len(response.text)}"

            if signature not in unique_panels:
                unique_panels[signature] = panel
        except:
            continue

    unique_panel_list = list(unique_panels.values())
    print(f"[LIGHTBOX] Testing {len(unique_panel_list)} unique panels (skipped {len(admin_panels) - len(unique_panel_list)} duplicates)")

    # STEP 2: Test credentials ONLY on unique panels
    credentials = [
        ('admin', 'admin'),
        ('admin', 'password'),
        ('administrator', 'administrator')
    ]

    for panel in unique_panel_list:
        url = panel['url']
        subdomain = panel['asset']

        for username, password in credentials:
            try:
                response = requests.post(
                    url,
                    data={
                        'username': username, 'password': password,
                        'user': username, 'pass': password,
                        'log': username, 'pwd': password
                    },
                    timeout=5,
                    verify=False,
                    allow_redirects=True
                )

                # SUCCESS ONLY IF:
                # 1. URL changed (redirected)
                # 2. Response has "logout" button
                if (response.url != url and
                    'logout' in response.text.lower()):

                    findings.append({
                        'type': 'Default Credentials',
                        'severity': 'CRITICAL',
                        'asset': subdomain,
                        'url': url,
                        'credentials': f"{username}:{password}",
                        'status_code': response.status_code,
                        'explanation': f"Admin panel accepts default credentials ({username}/{password}). Full system access.",
                        'remediation': REMEDIATION_GUIDES.get('Default Credentials', {})
                    })
                    print(f"[LIGHTBOX] 🚨 CRITICAL: Default credentials work on {url} ({username}/{password})")
                    break  # Found working creds, stop testing this panel

            except:
                continue

    return findings


def check_security_headers(subdomains):
    """
    Check for missing security headers

    Args:
        subdomains (list): List of subdomains to test

    Returns:
        list: Findings for missing security headers
    """
    findings = []

    headers_to_check = {
        'Strict-Transport-Security': ('MEDIUM', 'HSTS missing - allows SSL stripping attacks'),
        'X-Frame-Options': ('MEDIUM', 'Clickjacking protection missing'),
        'Content-Security-Policy': ('MEDIUM', 'No XSS protection'),
        'X-Content-Type-Options': ('LOW', 'MIME sniffing allowed')
    }

    print(f"[HEADERS] Starting checks on {len(subdomains)} subdomains")

    for subdomain in subdomains:
        print(f"[HEADERS] Checking {subdomain}...")
        try:
            response = requests.get(f"https://{subdomain}", timeout=5, verify=False)

            for header, (severity, explanation) in headers_to_check.items():
                if header not in response.headers:
                    print(f"[HEADERS]   Missing: {header}")
                    # Map header name to remediation key
                    header_key = 'HSTS' if header == 'Strict-Transport-Security' else header
                    remediation = REMEDIATION_GUIDES.get('Missing Security Header', {}).get(header_key, {})
                    findings.append({
                        'type': 'Missing Security Header',
                        'severity': severity,
                        'asset': subdomain,
                        'url': f'https://{subdomain}',
                        'header': header,
                        'explanation': explanation,
                        'remediation': remediation
                    })
        except Exception as e:
            print(f"[HEADERS]   Error: {e}")
            continue

    print(f"[HEADERS] Total findings: {len(findings)}")

    return findings


def check_ssl_vulnerabilities(subdomains):
    """
    Check SSL/TLS configuration for vulnerabilities

    Args:
        subdomains (list): List of subdomains to test

    Returns:
        list: Findings for SSL/TLS vulnerabilities
    """
    import ssl
    import socket
    from datetime import datetime

    findings = []

    for subdomain in subdomains:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((subdomain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=subdomain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()

                    # Weak ciphers
                    weak_ciphers = ['RC4', 'DES', '3DES', 'MD5']
                    if any(weak in cipher[0] for weak in weak_ciphers):
                        findings.append({
                            'type': 'Weak Encryption',
                            'severity': 'HIGH',
                            'asset': subdomain,
                            'url': f'https://{subdomain}',
                            'cipher': cipher[0],
                            'explanation': f'Weak cipher {cipher[0]} allows traffic decryption'
                        })
                        print(f"[LIGHTBOX] ⚠️  Weak cipher detected on {subdomain}: {cipher[0]}")

                    # Expired cert
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    if not_after < datetime.now():
                        findings.append({
                            'type': 'Expired SSL Certificate',
                            'severity': 'MEDIUM',
                            'asset': subdomain,
                            'url': f'https://{subdomain}',
                            'explanation': 'Certificate expired - browsers show warnings'
                        })
                        print(f"[LIGHTBOX] ⚠️  Expired SSL certificate on {subdomain}")
        except:
            continue

    return findings


def check_open_redirects(subdomains):
    """
    Test for open redirect vulnerabilities

    Args:
        subdomains (list): List of subdomains to test

    Returns:
        list: Findings for open redirect vulnerabilities
    """
    findings = []
    redirect_params = ['redirect', 'url', 'next', 'return']

    for subdomain in subdomains:
        for param in redirect_params:
            try:
                test_url = f"https://{subdomain}/login?{param}=https://evil.com"
                response = requests.get(test_url, allow_redirects=False,
                                       timeout=5, verify=False)

                if response.status_code in [301, 302, 303, 307]:
                    location = response.headers.get('Location', '')
                    if 'evil.com' in location:
                        findings.append({
                            'type': 'Open Redirect',
                            'severity': 'MEDIUM',
                            'asset': subdomain,
                            'url': test_url,
                            'parameter': param,
                            'explanation': f'Open redirect via ?{param}= - enables phishing attacks',
                            'remediation': REMEDIATION_GUIDES.get('Open Redirect', {})
                        })
                        print(f"[LIGHTBOX] ⚠️  Open redirect found on {subdomain} via {param} parameter")
                        break
            except:
                continue

    return findings


def check_cookie_security(subdomains):
    """
    Check for insecure cookie configurations

    Args:
        subdomains (list): List of subdomains to test

    Returns:
        list: Findings for insecure cookies
    """
    findings = []

    for subdomain in subdomains:
        try:
            response = requests.get(f"https://{subdomain}", timeout=5, verify=False)

            for cookie in response.cookies:
                # Missing Secure flag
                if not cookie.secure:
                    findings.append({
                        'type': 'Insecure Cookie',
                        'severity': 'MEDIUM',
                        'asset': subdomain,
                        'url': f'https://{subdomain}',
                        'cookie': cookie.name,
                        'explanation': f'Cookie {cookie.name} missing Secure flag - can be intercepted over HTTP',
                        'remediation': REMEDIATION_GUIDES.get('Insecure Cookie', {})
                    })

                # Missing HttpOnly flag
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    findings.append({
                        'type': 'Cookie Accessible to JavaScript',
                        'severity': 'MEDIUM',
                        'asset': subdomain,
                        'url': f'https://{subdomain}',
                        'cookie': cookie.name,
                        'explanation': f'Cookie {cookie.name} missing HttpOnly - vulnerable to XSS',
                        'remediation': REMEDIATION_GUIDES.get('Insecure Cookie', {})
                    })
        except:
            continue

    return findings


def check_information_disclosure(subdomains):
    """
    Check for information leaks

    Args:
        subdomains (list): List of subdomains to test

    Returns:
        list: Findings for information disclosure
    """
    findings = []

    for subdomain in subdomains:
        try:
            response = requests.get(f"https://{subdomain}", timeout=5, verify=False)

            # Server version disclosure
            server_header = response.headers.get('Server', '')
            if any(v in server_header for v in ['Apache/2', 'nginx/', 'IIS/']):
                findings.append({
                    'type': 'Server Version Disclosure',
                    'severity': 'LOW',
                    'asset': subdomain,
                    'url': f'https://{subdomain}',
                    'server': server_header,
                    'explanation': f'Server version exposed: {server_header}',
                    'remediation': REMEDIATION_GUIDES.get('Technology Disclosure', {})
                })

            # X-Powered-By disclosure
            powered_by = response.headers.get('X-Powered-By', '')
            if powered_by:
                findings.append({
                    'type': 'Technology Disclosure',
                    'severity': 'LOW',
                    'asset': subdomain,
                    'url': f'https://{subdomain}',
                    'technology': powered_by,
                    'explanation': f'X-Powered-By reveals: {powered_by}',
                    'remediation': REMEDIATION_GUIDES.get('Technology Disclosure', {})
                })
        except:
            continue

    return findings


def test_database_exploitability(port_results):
    """
    Test if database CVEs are actually exploitable

    Args:
        port_results (list): List of port scan results with CVE data

    Returns:
        list: Exploitability findings for database services
    """
    findings = []

    for port in port_results:
        if port['port'] in [3306, 5432, 1433, 27017]:
            cves = port.get('cves', [])
            if not cves:
                continue

            # Test MySQL anonymous access
            if port['port'] == 3306:
                try:
                    import mysql.connector
                    conn = mysql.connector.connect(
                        host=port['ip'],
                        port=3306,
                        user='',
                        password='',
                        connect_timeout=5
                    )

                    # Extract CVE IDs with robust field name detection
                    cve_list = cves
                    cve_ids = []

                    for cve in cve_list:
                        # Try different possible field names for CVE ID
                        cve_id = None

                        if isinstance(cve, dict):
                            # Try common field names
                            cve_id = cve.get('id') or cve.get('cve_id') or cve.get('cve') or cve.get('vulnerability_id')
                        elif isinstance(cve, str):
                            # If CVE is just a string
                            cve_id = cve

                        if cve_id and cve_id != 'Unknown':
                            cve_ids.append(cve_id)

                    # Build description based on what we found
                    if len(cve_ids) > 0:
                        cve_display = ', '.join(cve_ids[:5])
                        if len(cve_ids) > 5:
                            cve_display += f' (+{len(cve_ids)-5} more)'
                        description = f'Database accessible without credentials + {len(cve_ids)} CVEs: {cve_display}. Immediate RCE possible.'
                    else:
                        description = f'Database accessible without credentials + {len(cve_list)} CVEs. Immediate RCE possible.'

                    finding = {
                        'type': 'Database Anonymous Access',
                        'severity': 'CRITICAL',
                        'asset': port['ip'],
                        'url': f"mysql://{port['ip']}:3306",
                        'exploitable': 'IMMEDIATE',
                        'explanation': description,
                        'cves': cve_ids if len(cve_ids) > 0 else [],
                        'finding_type': 'cve-based'
                    }
                    findings.append(finding)
                    conn.close()

                    print(f"[LIGHTBOX] 🚨 CRITICAL: MySQL anonymous access on {port['ip']} + {len(cve_list)} CVEs")

                except Exception as e:
                    if "Access denied" in str(e):
                        # Extract CVE IDs with robust field name detection
                        cve_list = cves
                        cve_ids = []

                        for cve in cve_list:
                            # Try different possible field names for CVE ID
                            cve_id = None

                            if isinstance(cve, dict):
                                # Try common field names
                                cve_id = cve.get('id') or cve.get('cve_id') or cve.get('cve') or cve.get('vulnerability_id')
                            elif isinstance(cve, str):
                                # If CVE is just a string
                                cve_id = cve

                            if cve_id and cve_id != 'Unknown':
                                cve_ids.append(cve_id)

                        # Build description based on what we found
                        if len(cve_ids) > 0:
                            cve_display = ', '.join(cve_ids[:5])
                            if len(cve_ids) > 5:
                                cve_display += f' (+{len(cve_ids)-5} more)'
                            description = f'Requires auth but has {len(cve_ids)} CVEs: {cve_display}. RCE possible if password obtained.'
                        else:
                            description = f'Requires auth but has {len(cve_list)} CVEs. RCE possible if password obtained.'

                        finding = {
                            'type': 'Database Auth Required (Vulnerable)',
                            'severity': 'HIGH',
                            'asset': port['ip'],
                            'url': f"mysql://{port['ip']}:3306",
                            'exploitable': 'WITH_CREDENTIALS',
                            'explanation': description,
                            'cves': cve_ids if len(cve_ids) > 0 else [],
                            'finding_type': 'cve-based',
                            'remediation': REMEDIATION_GUIDES.get('Database Auth Required (Vulnerable)', {})
                        }
                        findings.append(finding)

                        print(f"[LIGHTBOX] ⚠️  MySQL requires auth but has {len(cve_list)} CVEs on {port['ip']}")

    return findings


def test_ssh_exploitability(port_results):
    """
    Test SSH auth methods and exploitability
    PERFORMANCE OPTIMIZED: Skip if no CVEs present

    Args:
        port_results (list): List of port scan results with CVE data

    Returns:
        list: Exploitability findings for SSH services
    """
    findings = []

    for port in port_results:
        if port['port'] == 22:
            cves = port.get('cves', [])

            # PERFORMANCE OPTIMIZATION: Skip if no CVEs - not worth testing
            if not cves:
                print(f"[LIGHTBOX] ⏩ Skipping SSH on {port['ip']} (no CVEs)")
                continue

            try:
                import paramiko
                transport = paramiko.Transport((port['ip'], 22))
                transport.connect()

                # Test if password auth enabled
                try:
                    transport.auth_password('test', 'test')
                except paramiko.AuthenticationException as e:
                    if "password" in str(e).lower():
                        # Extract CVE IDs with robust field name detection
                        cve_list = cves
                        cve_ids = []

                        for cve in cve_list:
                            # Try different possible field names for CVE ID
                            cve_id = None

                            if isinstance(cve, dict):
                                # Try common field names
                                cve_id = cve.get('id') or cve.get('cve_id') or cve.get('cve') or cve.get('vulnerability_id')
                            elif isinstance(cve, str):
                                # If CVE is just a string
                                cve_id = cve

                            if cve_id and cve_id != 'Unknown':
                                cve_ids.append(cve_id)

                        # Build description based on what we found
                        if len(cve_ids) > 0:
                            cve_display = ', '.join(cve_ids[:5])
                            if len(cve_ids) > 5:
                                cve_display += f' (+{len(cve_ids)-5} more)'
                            description = f'SSH has {len(cve_ids)} CVEs: {cve_display} + password auth. Brute force + exploit possible.'
                        else:
                            description = f'SSH has {len(cve_list)} CVEs + password auth. Brute force + exploit possible.'

                        finding = {
                            'type': 'SSH Password Auth Enabled',
                            'severity': 'HIGH',
                            'asset': port['ip'],
                            'url': f"ssh://{port['ip']}:22",
                            'exploitable': 'BRUTE_FORCE',
                            'explanation': description,
                            'cves': cve_ids if len(cve_ids) > 0 else [],
                            'finding_type': 'cve-based'
                        }
                        findings.append(finding)

                        print(f"[LIGHTBOX] ⚠️  SSH password auth enabled + {len(cve_list)} CVEs on {port['ip']}")

                transport.close()
            except:
                pass

    return findings


def test_file_upload_vulnerabilities(subdomains):
    """
    Test for unrestricted file upload endpoints

    Args:
        subdomains (list): List of subdomains to test

    Returns:
        list: Findings for file upload vulnerabilities
    """
    findings = []

    upload_endpoints = [
        '/upload.php',
        '/upload/',
        '/admin/upload',
        '/wp-admin/upload.php',
        '/api/upload',
        '/files/upload'
    ]

    for subdomain in subdomains:
        for endpoint in upload_endpoints:
            try:
                url = f"https://{subdomain}{endpoint}"

                # Check if endpoint exists
                response = requests.head(url, timeout=5, verify=False)

                if response.status_code in [200, 405]:  # 405 = exists but wrong method
                    # Check allowed methods
                    options = requests.options(url, timeout=5, verify=False)

                    if 'POST' in options.headers.get('Allow', ''):
                        findings.append({
                            'type': 'File Upload Endpoint',
                            'severity': 'HIGH',
                            'asset': subdomain,
                            'url': url,
                            'exploitable': 'NEEDS_VALIDATION',
                            'explanation': f"Upload endpoint at {endpoint}. May allow malicious file upload → RCE."
                        })
                        print(f"[LIGHTBOX] ⚠️  File upload endpoint found: {url}")
            except:
                continue

    return findings


def test_directory_traversal(subdomains):
    """
    Test for path traversal vulnerabilities

    Args:
        subdomains (list): List of subdomains to test

    Returns:
        list: Findings for directory traversal vulnerabilities
    """
    findings = []

    # Safe payloads (don't actually read files)
    test_paths = [
        '/download?file=../../../test',
        '/image?path=....//....//test',
        '/api/file?name=..%2f..%2ftest'
    ]

    for subdomain in subdomains:
        for path in test_paths:
            try:
                url = f"https://{subdomain}{path}"
                response = requests.get(url, timeout=5, verify=False)

                # Look for traversal indicators
                if response.status_code == 200 and len(response.text) < 5000:
                    findings.append({
                        'type': 'Directory Traversal Possible',
                        'severity': 'HIGH',
                        'asset': subdomain,
                        'url': url.split('?')[0],
                        'exploitable': 'LIKELY',
                        'explanation': 'Path traversal detected. Attacker could read sensitive server files.'
                    })
                    print(f"[LIGHTBOX] ⚠️  Directory traversal possible: {url.split('?')[0]}")
                    break  # One per subdomain
            except:
                continue

    return findings


def test_xxe_vulnerabilities(subdomains):
    """
    Test for XXE with parallel execution

    Args:
        subdomains (list): List of subdomains to test

    Returns:
        list: Findings for XXE vulnerabilities
    """
    all_findings = []

    def test_single_subdomain(subdomain):
        findings = []
        api_endpoints = ['/api', '/api/upload', '/api/parse', '/xml', '/upload', '/process']

        xxe_payload = '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<root>&xxe;</root>'''

        for endpoint in api_endpoints:
            try:
                url = f"https://{subdomain}{endpoint}"
                response = requests.post(
                    url,
                    data=xxe_payload,
                    headers={'Content-Type': 'application/xml'},
                    timeout=5,
                    verify=False
                )

                if response.status_code in [200, 400, 500]:
                    if any(keyword in response.text.lower() for keyword in ['xml', 'entity', 'dtd', 'parse error', 'syntax error']):
                        findings.append({
                            'type': 'XXE Vulnerability Possible',
                            'severity': 'HIGH',
                            'asset': subdomain,
                            'url': url.split('?')[0],
                            'status_code': response.status_code,
                            'exploitable': 'NEEDS_VALIDATION',
                            'explanation': 'Endpoint processes XML. May allow XXE → read server files, SSRF.',
                            'remediation': REMEDIATION_GUIDES.get('XXE Vulnerability Possible', {})
                        })
                        print(f"[LIGHTBOX] ⚠️  Potential XXE vulnerability: {url.split('?')[0]}")
                        break
            except:
                continue
        return findings

    # Test subdomains in parallel
    with ThreadPoolExecutor(max_workers=5) as executor:
        results = executor.map(test_single_subdomain, subdomains)
        for result in results:
            all_findings.extend(result)

    return all_findings


def test_ssrf_vulnerabilities(subdomains):
    """
    Test for SSRF with parallel execution

    Args:
        subdomains (list): List of subdomains to test

    Returns:
        list: Findings for SSRF vulnerabilities
    """
    all_findings = []

    def test_single_subdomain(subdomain):
        findings = []
        ssrf_tests = [
            ('/fetch', 'url', 'http://127.0.0.1'),
            ('/proxy', 'url', 'http://localhost'),
            ('/download', 'url', 'http://169.254.169.254'),
            ('/api/fetch', 'target', 'http://metadata.google.internal'),
            ('/webhook', 'url', 'http://internal')
        ]

        for path, param, value in ssrf_tests:
            try:
                url = f"https://{subdomain}{path}?{param}={value}"
                response = requests.get(
                    url,
                    timeout=5,
                    verify=False,
                    allow_redirects=False
                )

                if response.status_code in [200, 302, 500]:
                    findings.append({
                        'type': 'SSRF Vulnerability Possible',
                        'severity': 'HIGH',
                        'asset': subdomain,
                        'url': url.split('?')[0],
                        'status_code': response.status_code,
                        'exploitable': 'NEEDS_VALIDATION',
                        'explanation': 'Endpoint may allow SSRF. Attacker could access internal services.',
                        'remediation': REMEDIATION_GUIDES.get('SSRF Vulnerability Possible', {})
                    })
                    print(f"[LIGHTBOX] ⚠️  Potential SSRF vulnerability: {url.split('?')[0]}")
                    break
            except:
                continue
        return findings

    # Test subdomains in parallel
    with ThreadPoolExecutor(max_workers=5) as executor:
        results = executor.map(test_single_subdomain, subdomains)
        for result in results:
            all_findings.extend(result)

    return all_findings


def run_nuclei_scan(discovered_assets):
    """
    Run Nuclei vulnerability scanner with curated templates.
    Uses ~500 high-value curated templates for fast, comprehensive security testing.

    Args:
        discovered_assets (dict): Assets from ASM scan (subdomains, cloud_assets, etc.)

    Returns:
        dict: Nuclei findings categorized by severity with breakdown stats
    """
    from pathlib import Path

    print(f"\n{'='*60}")
    print(f"[NUCLEI] Starting Nuclei vulnerability scan with curated templates...")
    print(f"{'='*60}\n")

    findings = {
        'critical': [],
        'high': [],
        'medium': [],
        'low': [],
        'info': [],
        'total_findings': 0,
        'total_templates_used': 500,
        'severity_breakdown': {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0
        },
        'type_breakdown': {}
    }

    # Check for nuclei binary
    nuclei_path = os.path.join(os.path.dirname(__file__), '..', '..', 'bin', 'nuclei.exe')

    if not os.path.exists(nuclei_path):
        print(f"[NUCLEI] Warning: Nuclei binary not found at {nuclei_path}")
        return findings

    # Template base path
    template_base = Path(os.path.expanduser('~/nuclei-templates'))

    # Verify templates exist
    if not template_base.exists():
        print(f"[NUCLEI] ERROR: Templates not found at {template_base}")
        findings['status'] = 'error'
        findings['error'] = 'Templates not installed'
        return findings

    print(f"[NUCLEI] Using curated templates from: {template_base}")
    print(f"[NUCLEI] Scanning with latest CVEs (2025-2024-2023) + exposures")

    # Curated high-value templates (~500 total, runs in 2-3 minutes)
    template_paths = [
        # Latest CVEs (2025-2024-2023 - most relevant 3 years)
        str(template_base / 'http/cves/2025/'),
        str(template_base / 'http/cves/2024/'),
        str(template_base / 'http/cves/2023/'),

        # Exposures (configs, tokens, keys)
        str(template_base / 'http/exposures/configs/'),
        str(template_base / 'http/exposures/tokens/'),
        str(template_base / 'http/exposures/apis/'),
        str(template_base / 'http/exposures/backups/'),
        str(template_base / 'http/exposures/logs/'),

        # Misconfigurations
        str(template_base / 'http/misconfiguration/'),

        # Takeovers
        str(template_base / 'http/takeovers/'),

        # Default logins
        str(template_base / 'http/default-logins/'),

        # Exposed panels
        str(template_base / 'http/exposed-panels/'),

        # Key technologies
        str(template_base / 'http/technologies/wordpress/'),
        str(template_base / 'http/technologies/joomla/'),
        str(template_base / 'http/technologies/drupal/'),

        # Network
        str(template_base / 'network/'),

        # SSL
        str(template_base / 'ssl/'),
    ]

    # Collect subdomains to scan
    subdomains_to_scan = []

    # Collect DNS subdomains
    for sub in discovered_assets.get('subdomains', []):
        subdomain = sub.get('subdomain')
        if subdomain:
            subdomains_to_scan.append(subdomain)

    # Collect crt.sh subdomains (limit to 20 for comprehensive testing)
    for sub in discovered_assets.get('crt_subdomains', [])[:20]:
        subdomain = sub.get('subdomain')
        if subdomain and subdomain not in subdomains_to_scan:
            subdomains_to_scan.append(subdomain)

    # Limit to max 20 subdomains total for comprehensive testing
    subdomains_to_scan = subdomains_to_scan[:20]

    if not subdomains_to_scan:
        print(f"[NUCLEI] No subdomains to scan")
        return findings

    print(f"\n[NUCLEI] ╔════════════════════════════════════════════════════════════╗")
    print(f"[NUCLEI] ║ CURATED TEMPLATE SCAN: {len(subdomains_to_scan)} subdomains, 500+ templates   ║")
    print(f"[NUCLEI] ╚════════════════════════════════════════════════════════════╝")

    for i, subdomain in enumerate(subdomains_to_scan, 1):
        print(f"[NUCLEI] -> Testing subdomain {i}/{len(subdomains_to_scan)}: {subdomain}")

    print(f"\n[NUCLEI] === Running curated template vulnerability scan ===")

    # Build template arguments from directory paths
    template_args = []
    for template_path in template_paths:
        template_args.extend(['-t', template_path])

    # Scan each target individually for better reliability
    for subdomain in subdomains_to_scan:
        for protocol in ['https', 'http']:
            target = f"{protocol}://{subdomain}"

            try:
                nuclei_cmd = [
                    nuclei_path,
                    '-u', target,
                    *template_args,
                    '-severity', 'critical,high,medium,low,info',
                    '-jsonl',
                    '-silent',
                    '-timeout', '10',
                    '-retries', '1',
                    '-rate-limit', '150',
                    '-c', '25',
                    '-no-color',
                    '-no-update-check'
                ]

                print(f"[NUCLEI] Scanning: {target}")

                # Run nuclei
                result = subprocess.run(
                    nuclei_cmd,
                    capture_output=True,
                    text=True,
                    timeout=600  # 10 minute timeout per target
                )

                print(f"[NUCLEI] Return code: {result.returncode}")

                # Return code 0 or 1 is normal (1 just means some templates didn't match)
                if result.returncode > 1 and result.stderr:
                    print(f"[NUCLEI] Warning - stderr: {result.stderr[:200]}")

                # Parse JSON output line by line
                for line in result.stdout.split('\n'):
                    if line.strip():
                        try:
                            vuln = json.loads(line)

                            # Extract relevant fields
                            severity = vuln.get('info', {}).get('severity', 'info').lower()
                            template_id = vuln.get('template-id', 'unknown')
                            template_name = vuln.get('info', {}).get('name', 'Unknown')
                            matched_at = vuln.get('matched-at', vuln.get('host', target))
                            description = vuln.get('info', {}).get('description', '')
                            remediation = vuln.get('info', {}).get('remediation', 'See template documentation')
                            finding_type = vuln.get('type', 'http')

                            # Extract CVE/CWE if present
                            classification = vuln.get('info', {}).get('classification', {})
                            cve = None

                            if classification.get('cve-id'):
                                cve_id = classification['cve-id']
                                cve = cve_id[0] if isinstance(cve_id, list) else cve_id
                            elif classification.get('cwe-id'):
                                cwe_id = classification['cwe-id']
                                cwe_val = cwe_id[0] if isinstance(cwe_id, list) else cwe_id
                                cve = f"CWE-{cwe_val}" if not str(cwe_val).startswith('CWE') else cwe_val

                            cvss = classification.get('cvss-score', 0)

                            # Categorize by severity
                            if severity not in findings:
                                severity = 'info'

                            # Create user-friendly explanation
                            explanation = description if description else f"Vulnerability detected by Nuclei template: {template_name}. Check template documentation for details."

                            finding = {
                                'type': template_name,
                                'asset': matched_at,
                                'url': matched_at,
                                'description': description[:500] if description else template_name,
                                'explanation': explanation[:500] if len(explanation) > 500 else explanation,
                                'severity': severity.upper(),
                                'template_id': template_id,
                                'template': template_id,
                                'matcher_name': vuln.get('matcher-name', ''),
                                'finding_type': finding_type,
                                'cve': cve,
                                'cvss': cvss,
                                'remediation': remediation,
                                'raw_data': vuln
                            }

                            findings[severity].append(finding)
                            findings['total_findings'] += 1

                            # Update severity breakdown
                            sev_key = severity.upper()
                            if sev_key in findings['severity_breakdown']:
                                findings['severity_breakdown'][sev_key] += 1

                            # Update type breakdown
                            if finding_type not in findings['type_breakdown']:
                                findings['type_breakdown'][finding_type] = 0
                            findings['type_breakdown'][finding_type] += 1

                            print(f"[NUCLEI] [{severity.upper()}] {template_name} - {matched_at}")

                        except json.JSONDecodeError:
                            continue

            except subprocess.TimeoutExpired:
                print(f"[NUCLEI] Timeout for {target} (10 min limit)")
                continue
            except Exception as e:
                print(f"[NUCLEI] Error scanning {target}: {e}")
                import traceback
                traceback.print_exc()
                continue

    # Set status
    if findings['total_findings'] > 0:
        findings['status'] = 'failed'
    else:
        findings['status'] = 'passed'

    print(f"\n[NUCLEI] ╔════════════════════════════════════════════════════════════╗")
    print(f"[NUCLEI] ║ Curated Scan Complete! (500+ templates)                    ║")
    print(f"[NUCLEI] ╚════════════════════════════════════════════════════════════╝")
    print(f"[NUCLEI] Scanned with {len(template_paths)} template categories")
    print(f"[NUCLEI] Total Findings: {findings['total_findings']}")
    print(f"[NUCLEI]   Critical: {len(findings['critical'])}")
    print(f"[NUCLEI]   High: {len(findings['high'])}")
    print(f"[NUCLEI]   Medium: {len(findings['medium'])}")
    print(f"[NUCLEI]   Low: {len(findings['low'])}")
    print(f"[NUCLEI]   Info: {len(findings['info'])}")

    if findings['type_breakdown']:
        print(f"[NUCLEI] Detection Types: {', '.join(f'{k}:{v}' for k,v in findings['type_breakdown'].items())}")

    if findings['total_findings'] > 0:
        print(f"[NUCLEI] Found {findings['total_findings']} vulnerabilities")
    else:
        print(f"[NUCLEI] No vulnerabilities found")
    print(f"{'='*60}\n")

    return findings


# Test function
if __name__ == '__main__':
    # Test with sample assets
    test_assets = {
        'subdomains': [
            {'subdomain': 'example.com'},
            {'subdomain': 'www.example.com'}
        ],
        'crt_subdomains': []
    }

    print("\n🔬 Testing Lightbox Scanner\n")
    results = run_lightbox_scan(test_assets)

    print("\n" + "="*60)
    print("LIGHTBOX SCAN RESULTS")
    print("="*60)
    print(f"Total Tests: {results['total_tests']}")
    print(f"Total Findings: {results['total_findings']}")
    print(f"  Critical: {len(results['critical'])}")
    print(f"  High: {len(results['high'])}")
    print(f"  Medium: {len(results['medium'])}")
    print(f"  Low: {len(results['low'])}")
    print("="*60 + "\n")
