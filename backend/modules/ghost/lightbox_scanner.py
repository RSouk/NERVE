"""
Lightbox Automated Security Testing
Tests discovered assets for common exposures and misconfigurations
"""

import requests
from datetime import datetime


def run_lightbox_scan(discovered_assets):
    """
    Automated security testing on discovered assets

    Args:
        discovered_assets (dict): Assets from ASM scan (subdomains, cloud_assets, etc.)

    Returns:
        dict: Lightbox findings categorized by severity
    """
    print(f"\n{'='*60}")
    print(f"[LIGHTBOX] Starting automated security testing...")
    print(f"{'='*60}\n")

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

    print(f"[LIGHTBOX] Testing {len(subdomains_to_test)} assets...\n")

    # Test each subdomain
    for subdomain in subdomains_to_test:
        print(f"[LIGHTBOX] Testing: {subdomain}")

        # Test common exposures
        findings = test_sensitive_files(subdomain, findings)
        findings = test_directory_listing(subdomain, findings)
        findings = test_admin_access(subdomain, findings)
        findings = test_default_pages(subdomain, findings)

    # Count total findings
    findings['total_findings'] = (
        len(findings['critical']) +
        len(findings['high']) +
        len(findings['medium']) +
        len(findings['low'])
    )

    print(f"\n{'='*60}")
    print(f"[LIGHTBOX] Scan Complete!")
    print(f"[LIGHTBOX] Total Tests: {findings['total_tests']}")
    print(f"[LIGHTBOX] Total Findings: {findings['total_findings']}")
    print(f"[LIGHTBOX]   Critical: {len(findings['critical'])}")
    print(f"[LIGHTBOX]   High: {len(findings['high'])}")
    print(f"[LIGHTBOX]   Medium: {len(findings['medium'])}")
    print(f"[LIGHTBOX]   Low: {len(findings['low'])}")
    print(f"{'='*60}\n")

    return findings


def test_sensitive_files(subdomain, findings):
    """
    Test for exposed sensitive files (.env, .git, etc.)

    Args:
        subdomain (str): Domain to test
        findings (dict): Findings dictionary to update

    Returns:
        dict: Updated findings
    """
    sensitive_paths = [
        '/.env',
        '/.git/',
        '/.git/config',
        '/.aws/credentials',
        '/config.php',
        '/configuration.php',
        '/wp-config.php',
        '/web.config',
        '/.htaccess',
        '/phpinfo.php',
        '/info.php',
        '/.DS_Store',
        '/backup.sql',
        '/database.sql',
        '/dump.sql'
    ]

    for path in sensitive_paths:
        findings['total_tests'] += 1

        for protocol in ['https', 'http']:
            url = f"{protocol}://{subdomain}{path}"

            try:
                response = requests.get(url, timeout=5, allow_redirects=False, verify=False)

                # Check if file is accessible
                if response.status_code == 200:
                    severity = 'critical' if path in ['/.env', '/.git/', '/.aws/credentials'] else 'high'

                    findings[severity].append({
                        'type': 'Sensitive File Exposed',
                        'asset': subdomain,
                        'url': url,
                        'description': f"Sensitive file accessible: {path}",
                        'status_code': response.status_code,
                        'severity': severity.upper()
                    })

                    print(f"[LIGHTBOX] ⚠️  FOUND: {url} ({response.status_code})")
                    break  # Found via one protocol, no need to test the other

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
                response = requests.get(url, timeout=5, allow_redirects=False, verify=False)

                # Check for directory listing indicators
                if response.status_code == 200:
                    content = response.text.lower()

                    # Common directory listing indicators
                    indicators = [
                        'index of',
                        'parent directory',
                        'directory listing',
                        '<title>index of'
                    ]

                    if any(indicator in content for indicator in indicators):
                        findings['medium'].append({
                            'type': 'Directory Listing Enabled',
                            'asset': subdomain,
                            'url': url,
                            'description': f"Directory listing enabled at {dir_path}",
                            'status_code': response.status_code,
                            'severity': 'MEDIUM'
                        })

                        print(f"[LIGHTBOX] ⚠️  Directory Listing: {url}")
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
                response = requests.get(url, timeout=5, allow_redirects=True, verify=False)

                # Check if admin panel is accessible
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

                    if any(indicator in content for indicator in admin_indicators):
                        findings['high'].append({
                            'type': 'Admin Panel Accessible',
                            'asset': subdomain,
                            'url': url,
                            'description': f"Admin panel found at {path}",
                            'status_code': response.status_code,
                            'severity': 'HIGH'
                        })

                        print(f"[LIGHTBOX] ⚠️  Admin Panel: {url}")
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
            response = requests.get(url, timeout=5, allow_redirects=True, verify=False)

            if response.status_code == 200:
                content = response.text

                for service, indicators in default_indicators.items():
                    if any(indicator in content for indicator in indicators):
                        findings['low'].append({
                            'type': 'Default Installation Page',
                            'asset': subdomain,
                            'url': url,
                            'description': f"Default {service} installation page detected",
                            'status_code': response.status_code,
                            'severity': 'LOW'
                        })

                        print(f"[LIGHTBOX] ℹ️  Default Page: {url} ({service})")
                        break

        except requests.exceptions.RequestException:
            pass

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
