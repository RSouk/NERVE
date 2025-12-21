"""
Attack Surface Management Scanner
Subdomain discovery, Shodan integration, DNS enumeration,
Certificate Transparency, and Cloud Asset Discovery
"""

import os
import dns.resolver
import shodan
import socket
import requests
import json
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize Shodan API
SHODAN_API_KEY = os.getenv('SHODAN_API_KEY')


def scan_domain(domain):
    """
    Perform comprehensive attack surface scan on a domain

    Args:
        domain (str): Target domain (e.g., "example.com")

    Returns:
        dict: Scan results with subdomains, Shodan data, DNS records, and risk score
    """
    print(f"\n{'='*60}")
    print(f"[ASM SCANNER] Starting scan for: {domain}")
    print(f"{'='*60}\n")

    results = {
        'domain': domain,
        'scan_time': datetime.utcnow().isoformat(),
        'subdomains': [],
        'crt_subdomains': [],
        'cloud_assets': [],
        'shodan_results': [],
        'dns_records': {},
        'risk_score': 0,
        'risk_level': 'low',
        'vulnerabilities_found': 0,
        'open_ports_count': 0,
        'critical_findings': [],
        'errors': []
    }

    # 1. Subdomain Discovery (DNS)
    print(f"[ASM] Step 1: Subdomain Discovery (DNS)")
    results['subdomains'] = discover_subdomains(domain)
    print(f"[ASM] Found {len(results['subdomains'])} subdomains via DNS\n")

    # 2. Certificate Transparency (crt.sh)
    print(f"[ASM] Step 2: Certificate Transparency (crt.sh)")
    results['crt_subdomains'] = crt_sh_search(domain)
    print(f"[ASM] Found {len(results['crt_subdomains'])} subdomains via crt.sh\n")

    # 3. Cloud Asset Enumeration
    print(f"[ASM] Step 3: Cloud Asset Enumeration")
    company_name = domain.split('.')[0]  # Extract company name from domain
    results['cloud_assets'] = enumerate_cloud_assets(company_name, domain)
    print(f"[ASM] Found {len(results['cloud_assets'])} cloud assets\n")

    # 4. DNS Enumeration
    print(f"[ASM] Step 4: DNS Enumeration")
    results['dns_records'] = enumerate_dns(domain)
    print(f"[ASM] Collected DNS records\n")

    # 5. Enhanced Shodan Search
    print(f"[ASM] Step 5: Shodan Intelligence")
    if SHODAN_API_KEY and SHODAN_API_KEY != 'your_shodan_api_key_here':
        results['shodan_results'] = enhanced_shodan_search(domain, company_name)
        print(f"[ASM] Found {len(results['shodan_results'])} Shodan results\n")
    else:
        print(f"[ASM] ⚠️  Shodan API key not configured, skipping\n")
        results['errors'].append('Shodan API key not configured')

    # 6. Risk Assessment & Categorization
    print(f"[ASM] Step 6: Risk Assessment")
    results['risk_score'] = calculate_risk_score(results)
    results['risk_level'] = categorize_risk_level(results['risk_score'])
    results['vulnerabilities_found'] = count_vulnerabilities(results)
    results['open_ports_count'] = count_open_ports(results)
    results['critical_findings'] = identify_critical_findings(results)

    print(f"\n{'='*60}")
    print(f"[ASM SCANNER] Scan Complete!")
    print(f"[ASM] Risk Score: {results['risk_score']}/100")
    print(f"[ASM] Vulnerabilities: {results['vulnerabilities_found']}")
    print(f"[ASM] Open Ports: {results['open_ports_count']}")
    print(f"{'='*60}\n")

    return results


def discover_subdomains(domain):
    """
    Discover subdomains using DNS queries

    Args:
        domain (str): Target domain

    Returns:
        list: List of discovered subdomains with IPs
    """
    print(f"[SUBDOMAIN] Scanning for common subdomains...")

    # Common subdomain prefixes to check
    common_subdomains = [
        'www', 'api', 'admin', 'dev', 'staging', 'test',
        'mail', 'webmail', 'smtp', 'pop', 'imap',
        'vpn', 'remote', 'gateway',
        'ftp', 'sftp', 'files',
        'blog', 'shop', 'store', 'portal',
        'cdn', 'assets', 'static', 'media',
        'app', 'mobile', 'dashboard',
        'db', 'database', 'sql', 'mysql',
        'git', 'gitlab', 'github',
        'jenkins', 'ci', 'build',
        'status', 'monitoring', 'metrics'
    ]

    discovered = []

    for subdomain_prefix in common_subdomains:
        full_domain = f"{subdomain_prefix}.{domain}"

        try:
            # Try to resolve the subdomain
            answers = dns.resolver.resolve(full_domain, 'A')

            ips = [str(rdata) for rdata in answers]

            discovered.append({
                'subdomain': full_domain,
                'ips': ips,
                'type': 'A'
            })

            print(f"[SUBDOMAIN] ✓ Found: {full_domain} -> {', '.join(ips)}")

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
            # Subdomain doesn't exist or no A record
            pass
        except Exception as e:
            print(f"[SUBDOMAIN] ⚠️  Error checking {full_domain}: {e}")

    # Also try to get the root domain
    try:
        answers = dns.resolver.resolve(domain, 'A')
        ips = [str(rdata) for rdata in answers]

        discovered.insert(0, {
            'subdomain': domain,
            'ips': ips,
            'type': 'A (root)'
        })

        print(f"[SUBDOMAIN] ✓ Root domain: {domain} -> {', '.join(ips)}")

    except Exception as e:
        print(f"[SUBDOMAIN] ⚠️  Error resolving root domain: {e}")

    return discovered


def enumerate_dns(domain):
    """
    Enumerate DNS records for a domain

    Args:
        domain (str): Target domain

    Returns:
        dict: DNS records (A, MX, NS, TXT, etc.)
    """
    print(f"[DNS] Enumerating DNS records for {domain}...")

    dns_records = {
        'A': [],
        'AAAA': [],
        'MX': [],
        'NS': [],
        'TXT': [],
        'SOA': [],
        'CNAME': []
    }

    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']

    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)

            if record_type == 'MX':
                dns_records[record_type] = [
                    {'priority': rdata.preference, 'server': str(rdata.exchange)}
                    for rdata in answers
                ]
            elif record_type == 'SOA':
                for rdata in answers:
                    dns_records[record_type].append({
                        'mname': str(rdata.mname),
                        'rname': str(rdata.rname),
                        'serial': rdata.serial
                    })
            else:
                dns_records[record_type] = [str(rdata) for rdata in answers]

            print(f"[DNS] ✓ {record_type}: {len(dns_records[record_type])} records")

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            print(f"[DNS] - {record_type}: No records found")
        except Exception as e:
            print(f"[DNS] ⚠️  Error querying {record_type}: {e}")

    return dns_records


def shodan_search(domain):
    """
    Search Shodan for hosts related to the domain

    Args:
        domain (str): Target domain

    Returns:
        list: Shodan results with IPs, ports, services, and vulnerabilities
    """
    print(f"[SHODAN] Searching for hosts related to {domain}...")

    if not SHODAN_API_KEY or SHODAN_API_KEY == 'your_shodan_api_key_here':
        print(f"[SHODAN] ⚠️  API key not configured")
        return []

    try:
        api = shodan.Shodan(SHODAN_API_KEY)

        # Search for hosts with this hostname
        query = f'hostname:{domain}'
        print(f"[SHODAN] Query: {query}")

        results = api.search(query, limit=10)

        print(f"[SHODAN] Found {results['total']} total results (showing first 10)")

        shodan_data = []

        for match in results['matches']:
            ip = match.get('ip_str', 'Unknown')
            port = match.get('port', 0)

            # Extract services and banners
            service = match.get('product', 'Unknown')
            version = match.get('version', '')
            banner = match.get('data', '')[:200]  # First 200 chars

            # Extract hostnames
            hostnames = match.get('hostnames', [])

            # Extract vulnerabilities (CVEs)
            vulns = match.get('vulns', {})
            cves = list(vulns.keys()) if vulns else []

            # Extract organization
            org = match.get('org', 'Unknown')

            # Extract location
            location = {
                'country': match.get('location', {}).get('country_name', 'Unknown'),
                'city': match.get('location', {}).get('city', 'Unknown')
            }

            shodan_data.append({
                'ip': ip,
                'port': port,
                'service': service,
                'version': version,
                'banner': banner,
                'hostnames': hostnames,
                'vulnerabilities': cves,
                'organization': org,
                'location': location
            })

            vuln_str = f" [{len(cves)} CVEs]" if cves else ""
            print(f"[SHODAN] ✓ {ip}:{port} - {service} {version}{vuln_str}")

        return shodan_data

    except shodan.APIError as e:
        print(f"[SHODAN] ❌ API Error: {e}")
        return []
    except Exception as e:
        print(f"[SHODAN] ❌ Error: {e}")
        return []


def calculate_risk_score(results):
    """
    Calculate risk score based on scan results

    Args:
        results (dict): Scan results

    Returns:
        int: Risk score (0-100)
    """
    score = 0

    # Base score for having any exposure
    if results['subdomains']:
        score += 10

    # Add points for each subdomain (indicates larger attack surface)
    score += min(len(results['subdomains']) * 2, 20)

    # Add points for Shodan findings
    score += min(len(results['shodan_results']) * 5, 30)

    # Add points for vulnerabilities
    vuln_count = 0
    for shodan_result in results['shodan_results']:
        vuln_count += len(shodan_result.get('vulnerabilities', []))

    score += min(vuln_count * 10, 30)

    # Add points for sensitive subdomains
    sensitive_keywords = ['admin', 'dev', 'test', 'staging', 'vpn', 'db', 'database', 'jenkins', 'git']
    for subdomain_data in results['subdomains']:
        subdomain = subdomain_data['subdomain'].lower()
        if any(keyword in subdomain for keyword in sensitive_keywords):
            score += 5

    # Cap at 100
    score = min(score, 100)

    return score


def count_vulnerabilities(results):
    """
    Count total vulnerabilities found

    Args:
        results (dict): Scan results

    Returns:
        int: Total vulnerability count
    """
    count = 0
    for shodan_result in results['shodan_results']:
        count += len(shodan_result.get('vulnerabilities', []))
    return count


def count_open_ports(results):
    """
    Count unique open ports found

    Args:
        results (dict): Scan results

    Returns:
        int: Unique open port count
    """
    ports = set()
    for shodan_result in results['shodan_results']:
        ports.add(shodan_result.get('port'))
    return len(ports)


def crt_sh_search(domain):
    """
    Search Certificate Transparency logs via crt.sh

    Args:
        domain (str): Target domain

    Returns:
        list: Discovered subdomains from CT logs
    """
    print(f"[CRT.SH] Querying Certificate Transparency logs...")

    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=30)

        if response.status_code == 200:
            data = response.json()

            # Extract unique subdomains
            subdomains = set()
            for entry in data:
                name = entry.get('name_value', '')
                # Handle wildcards and multiple names
                for subdomain in name.split('\n'):
                    subdomain = subdomain.strip().replace('*', '').replace('.', '', 1).strip('.')
                    if subdomain and subdomain.endswith(domain):
                        subdomains.add(subdomain)

            subdomains_list = sorted(list(subdomains))
            print(f"[CRT.SH] ✓ Found {len(subdomains_list)} unique subdomains")

            return [{'subdomain': sub, 'source': 'crt.sh'} for sub in subdomains_list[:50]]  # Limit to 50

        else:
            print(f"[CRT.SH] ⚠️  HTTP {response.status_code}")
            return []

    except Exception as e:
        print(f"[CRT.SH] ❌ Error: {e}")
        return []


def enumerate_cloud_assets(company_name, domain):
    """
    Enumerate potential cloud assets (S3 buckets, Azure blobs)

    Args:
        company_name (str): Company name extracted from domain
        domain (str): Target domain

    Returns:
        list: Discovered cloud assets with accessibility status
    """
    print(f"[CLOUD] Enumerating cloud assets for {company_name}...")

    cloud_assets = []

    # Common bucket naming patterns
    patterns = [
        company_name,
        f"{company_name}-backup",
        f"{company_name}-data",
        f"{company_name}-files",
        f"{company_name}-assets",
        f"{company_name}-logs",
        f"{company_name}-prod",
        f"{company_name}-dev",
        domain.replace('.', '-')
    ]

    # Check AWS S3 buckets
    for pattern in patterns:
        bucket_url = f"https://{pattern}.s3.amazonaws.com"
        accessible, status = check_cloud_asset_access(bucket_url)

        if accessible or status == 403:  # 403 means bucket exists but not public
            cloud_assets.append({
                'type': 'AWS S3',
                'name': pattern,
                'url': bucket_url,
                'accessible': accessible,
                'status': 'Public' if accessible else 'Private/Exists',
                'risk': 'CRITICAL' if accessible else 'LOW'
            })
            print(f"[CLOUD] ✓ Found S3: {pattern} ({'Public' if accessible else 'Private'})")

    # Check Azure Blob Storage
    for pattern in patterns:
        blob_url = f"https://{pattern}.blob.core.windows.net"
        accessible, status = check_cloud_asset_access(blob_url)

        if accessible or status == 403:
            cloud_assets.append({
                'type': 'Azure Blob',
                'name': pattern,
                'url': blob_url,
                'accessible': accessible,
                'status': 'Public' if accessible else 'Private/Exists',
                'risk': 'CRITICAL' if accessible else 'LOW'
            })
            print(f"[CLOUD] ✓ Found Azure: {pattern} ({'Public' if accessible else 'Private'})")

    print(f"[CLOUD] Total cloud assets found: {len(cloud_assets)}")
    return cloud_assets


def check_cloud_asset_access(url):
    """
    Check if a cloud asset is publicly accessible

    Args:
        url (str): URL to check

    Returns:
        tuple: (accessible: bool, status_code: int)
    """
    try:
        response = requests.head(url, timeout=5, allow_redirects=True)
        # 200 = public, 403 = exists but private, 404 = doesn't exist
        accessible = response.status_code == 200
        return accessible, response.status_code
    except requests.exceptions.RequestException:
        return False, 0


def enhanced_shodan_search(domain, company_name):
    """
    Enhanced Shodan search using org query (single credit)

    Args:
        domain (str): Target domain
        company_name (str): Company name for org search

    Returns:
        list: Shodan results with detailed information
    """
    print(f"[SHODAN] Enhanced search for {domain} (org:{company_name})...")

    if not SHODAN_API_KEY or SHODAN_API_KEY == 'your_shodan_api_key_here':
        print(f"[SHODAN] ⚠️  API key not configured")
        return []

    try:
        api = shodan.Shodan(SHODAN_API_KEY)

        shodan_data = []

        # Try hostname search first
        try:
            query = f'hostname:{domain}'
            print(f"[SHODAN] Query 1: {query}")
            results = api.search(query, limit=10)

            for match in results['matches']:
                shodan_data.append(parse_shodan_match(match))

        except Exception as e:
            print(f"[SHODAN] Hostname search: {e}")

        # Try org search if available
        try:
            query = f'org:"{company_name}"'
            print(f"[SHODAN] Query 2: {query}")
            results = api.search(query, limit=5)

            for match in results['matches']:
                shodan_data.append(parse_shodan_match(match))

        except Exception as e:
            print(f"[SHODAN] Org search: {e}")

        # Remove duplicates by IP
        unique_data = []
        seen_ips = set()
        for item in shodan_data:
            if item['ip'] not in seen_ips:
                unique_data.append(item)
                seen_ips.add(item['ip'])

        print(f"[SHODAN] ✓ Found {len(unique_data)} unique results")
        return unique_data

    except shodan.APIError as e:
        print(f"[SHODAN] ❌ API Error: {e}")
        return []
    except Exception as e:
        print(f"[SHODAN] ❌ Error: {e}")
        return []


def parse_shodan_match(match):
    """
    Parse a Shodan match result

    Args:
        match (dict): Shodan match object

    Returns:
        dict: Parsed Shodan data
    """
    ip = match.get('ip_str', 'Unknown')
    port = match.get('port', 0)
    service = match.get('product', 'Unknown')
    version = match.get('version', '')
    banner = match.get('data', '')[:200]
    hostnames = match.get('hostnames', [])
    vulns = match.get('vulns', {})
    cves = list(vulns.keys()) if vulns else []
    org = match.get('org', 'Unknown')
    location = {
        'country': match.get('location', {}).get('country_name', 'Unknown'),
        'city': match.get('location', {}).get('city', 'Unknown')
    }

    # Determine risk level
    risk = 'LOW'
    if cves:
        risk = 'CRITICAL'
    elif port in [22, 3389, 23]:  # SSH, RDP, Telnet
        risk = 'HIGH'
    elif port in [21, 3306, 5432, 1433]:  # FTP, MySQL, PostgreSQL, MSSQL
        risk = 'HIGH'

    return {
        'ip': ip,
        'port': port,
        'service': service,
        'version': version,
        'banner': banner,
        'hostnames': hostnames,
        'vulnerabilities': cves,
        'organization': org,
        'location': location,
        'risk': risk
    }


def categorize_risk_level(risk_score):
    """
    Categorize risk score into levels

    Args:
        risk_score (int): Risk score 0-100

    Returns:
        str: Risk level (low, medium, high, critical)
    """
    if risk_score >= 75:
        return 'critical'
    elif risk_score >= 50:
        return 'high'
    elif risk_score >= 25:
        return 'medium'
    else:
        return 'low'


def identify_critical_findings(results):
    """
    Identify critical security findings

    Args:
        results (dict): Scan results

    Returns:
        list: Critical findings with descriptions
    """
    critical = []

    # Check for admin subdomains
    sensitive_keywords = ['admin', 'vpn', 'dev', 'test', 'staging', 'db', 'database']
    for sub in results['subdomains']:
        subdomain = sub['subdomain'].lower()
        for keyword in sensitive_keywords:
            if keyword in subdomain:
                critical.append({
                    'type': 'Sensitive Subdomain',
                    'description': f"Exposed {keyword} subdomain: {sub['subdomain']}",
                    'severity': 'CRITICAL' if keyword in ['admin', 'vpn', 'db'] else 'HIGH'
                })
                break

    # Check for SSH/RDP exposure
    for shodan_result in results['shodan_results']:
        port = shodan_result.get('port')
        if port == 22:
            critical.append({
                'type': 'SSH Exposed',
                'description': f"SSH open on {shodan_result['ip']}:{port}",
                'severity': 'HIGH'
            })
        elif port == 3389:
            critical.append({
                'type': 'RDP Exposed',
                'description': f"RDP open on {shodan_result['ip']}:{port}",
                'severity': 'CRITICAL'
            })

    # Check for CVEs
    for shodan_result in results['shodan_results']:
        if shodan_result.get('vulnerabilities'):
            for cve in shodan_result['vulnerabilities']:
                critical.append({
                    'type': 'Vulnerability',
                    'description': f"{cve} on {shodan_result['ip']}:{shodan_result['port']}",
                    'severity': 'CRITICAL'
                })

    # Check for public cloud assets
    for asset in results['cloud_assets']:
        if asset.get('accessible'):
            critical.append({
                'type': 'Public Cloud Asset',
                'description': f"Publicly accessible {asset['type']}: {asset['name']}",
                'severity': 'CRITICAL'
            })

    return critical[:20]  # Limit to top 20


# Test function
if __name__ == '__main__':
    # Test with a domain
    test_domain = 'stripe.com'
    print(f"\n🔍 Testing Enhanced ASM Scanner with {test_domain}\n")

    results = scan_domain(test_domain)

    print("\n" + "="*60)
    print("SCAN RESULTS")
    print("="*60)
    print(f"Domain: {results['domain']}")
    print(f"Subdomains (DNS): {len(results['subdomains'])}")
    print(f"Subdomains (crt.sh): {len(results['crt_subdomains'])}")
    print(f"Cloud Assets: {len(results['cloud_assets'])}")
    print(f"Shodan Results: {len(results['shodan_results'])}")
    print(f"Vulnerabilities: {results['vulnerabilities_found']}")
    print(f"Open Ports: {results['open_ports_count']}")
    print(f"Risk Score: {results['risk_score']}/100 ({results['risk_level'].upper()})")
    print(f"Critical Findings: {len(results['critical_findings'])}")
    print("="*60 + "\n")
