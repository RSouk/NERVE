"""
CVE Intelligence Layer
Maps services to CVEs using NVD API, checks CISA KEV list, and ExploitDB
"""

import os
import requests
import time
import json
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# NVD API Configuration
NVD_API_KEY = os.getenv('NVD_API_KEY')
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# CISA KEV Configuration
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# ExploitDB Configuration
EXPLOITDB_CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

# Cache for KEV and ExploitDB data (24 hour cache)
_kev_cache = {'data': None, 'timestamp': None}
_exploitdb_cache = {'data': None, 'timestamp': None}

# Rate limiting for NVD API (50 requests per 30 seconds)
_nvd_request_times = []
NVD_RATE_LIMIT = 50
NVD_RATE_WINDOW = 30  # seconds

# CVE Context - Human-readable explanations of why vulnerabilities matter
CVE_CONTEXT = {
    'MySQL': {
        'exposed': 'Database contains sensitive data (user info, passwords, business data)',
        'impact': 'Full database access allows data theft, modification, or deletion',
        'fix': 'Move behind firewall, require VPN for access, use strong passwords'
    },
    'MariaDB': {
        'exposed': 'Database contains sensitive data (user info, passwords, business data)',
        'impact': 'Full database access allows data theft, modification, or deletion',
        'fix': 'Move behind firewall, require VPN for access, use strong passwords'
    },
    'PostgreSQL': {
        'exposed': 'Database contains sensitive data (user info, passwords, business data)',
        'impact': 'Full database access allows data theft, modification, or deletion',
        'fix': 'Move behind firewall, require VPN for access, use strong passwords'
    },
    'MSSQL': {
        'exposed': 'Microsoft SQL Server contains business-critical data',
        'impact': 'Database compromise leads to data breach and potential ransomware',
        'fix': 'Restrict to internal network only, enable TLS, use Windows Authentication'
    },
    'MongoDB': {
        'exposed': 'NoSQL database with application data and user information',
        'impact': 'Attackers can dump entire database, modify records, or hold data for ransom',
        'fix': 'Enable authentication, bind to localhost only, use VPN for remote access'
    },
    'Redis': {
        'exposed': 'In-memory cache often contains session tokens and sensitive data',
        'impact': 'Session hijacking, data leakage, or server compromise via command injection',
        'fix': 'Bind to localhost, require authentication, disable dangerous commands'
    },
    'Elasticsearch': {
        'exposed': 'Search engine often indexing sensitive application data',
        'impact': 'Data exposure, deletion of indices, or cluster takeover',
        'fix': 'Enable authentication, restrict network access, use TLS encryption'
    },
    'OpenSSH': {
        'exposed': 'Server remote access point - primary target for attackers',
        'impact': 'Successful exploit = full server control and lateral movement',
        'fix': 'Disable password auth, use SSH keys only, update to latest version, use fail2ban'
    },
    'IIS': {
        'exposed': 'Microsoft web server hosting your application',
        'impact': 'RCE vulnerabilities allow attacker to run commands on server',
        'fix': 'Update IIS, implement WAF, restrict admin panel access'
    },
    'Apache': {
        'exposed': 'Web server hosting your application and APIs',
        'impact': 'Path traversal and RCE allow full server compromise',
        'fix': 'Update Apache, disable unused modules, implement WAF'
    },
    'nginx': {
        'exposed': 'Web server and reverse proxy for your infrastructure',
        'impact': 'Vulnerabilities can expose backend services or allow RCE',
        'fix': 'Update nginx, review proxy configurations, implement rate limiting'
    },
    'Exim': {
        'exposed': 'Mail server handling email communications',
        'impact': 'RCE vulnerabilities enable spam relay or server takeover',
        'fix': 'Update to latest version, restrict relay access, use SPF/DKIM'
    },
    'RabbitMQ': {
        'exposed': 'Message queue processing application events',
        'impact': 'Message manipulation, queue poisoning, or authentication bypass',
        'fix': 'Enable authentication, use TLS, restrict management interface'
    }
}


def map_service_to_cves(service_name, version):
    """
    Map a service and version to CVEs using the NVD API

    Args:
        service_name (str): Service name (e.g., "Apache httpd", "OpenSSH")
        version (str): Version number (e.g., "2.4.49", "8.0")

    Returns:
        list: List of CVE dictionaries with ID, CVSS score, severity, description, published date
              [{cve_id, cvss_score, severity, description, published, url}, ...]
    """
    if not service_name or not version:
        return []

    print(f"[CVE] Mapping {service_name} {version} to CVEs...")

    # Apply rate limiting
    _apply_nvd_rate_limit()

    # Clean version: Strip platform-specific info
    # "7.2p2 Ubuntu 4ubuntu2.10" → "7.2"
    # "10.0" → "10.0" (already clean)
    # "4.99-S2G" → "4.99"
    clean_version = version.split()[0]  # Take first part only
    clean_version = clean_version.split('-')[0]  # Remove suffixes like -S2G

    # Handle special version patterns
    if 'p' in clean_version and clean_version.index('p') > 0:
        # OpenSSH pattern: "7.2p2" → "7.2"
        clean_version = clean_version.split('p')[0]

    # Strip product-specific suffixes from service name
    service_keywords = {
        'Microsoft IIS httpd': 'IIS',
        'Exim smtpd': 'Exim',
        'OpenSSH': 'OpenSSH',
        'MariaDB': 'MariaDB',
        'Apache httpd': 'Apache',
        'nginx': 'nginx',
        'MySQL': 'MySQL',
        'PostgreSQL': 'PostgreSQL'
    }

    clean_service = service_keywords.get(service_name, service_name.split()[0])

    # Build search query with cleaned values
    keyword_search = f"{clean_service} {clean_version}"

    print(f"[CVE] Original: {service_name} {version}")
    print(f"[CVE] Cleaned query: {keyword_search}")

    try:
        # Query NVD API
        headers = {}
        if NVD_API_KEY:
            headers['apiKey'] = NVD_API_KEY

        params = {
            'keywordSearch': keyword_search,
            'resultsPerPage': 20  # Limit results to avoid overwhelming data
        }

        # DEBUG LOGGING: Query details
        print(f"\n[NVD] ==================== DEBUG: NVD API QUERY ====================")
        print(f"[NVD] Service: {service_name}")
        print(f"[NVD] Version: {version}")
        print(f"[NVD] Keyword Search: {keyword_search}")
        print(f"[NVD] API URL: {NVD_BASE_URL}")
        print(f"[NVD] Params: {params}")
        print(f"[NVD] API Key Configured: {'Yes' if NVD_API_KEY else 'No'}")
        if NVD_API_KEY:
            print(f"[NVD] API Key: {NVD_API_KEY[:10]}...{NVD_API_KEY[-10:]}")
        print(f"[NVD] Headers Being Sent: {list(headers.keys())}")
        print(f"[NVD] Rate Limit: {NVD_RATE_LIMIT} requests per {NVD_RATE_WINDOW} seconds")
        print(f"[NVD] Recent Requests: {len(_nvd_request_times)}/{NVD_RATE_LIMIT}")
        print(f"[NVD] ================================================================\n")

        response = requests.get(
            NVD_BASE_URL,
            params=params,
            headers=headers,
            timeout=10
        )

        # DEBUG LOGGING: Response details
        print(f"\n[NVD] ==================== DEBUG: NVD API RESPONSE ===================")
        print(f"[NVD] Status Code: {response.status_code}")
        print(f"[NVD] Response Headers: {dict(response.headers)}")
        print(f"[NVD] Response Size: {len(response.content)} bytes")

        if response.status_code == 200:
            try:
                response_json = response.json()
                print(f"[NVD] Response JSON Keys: {list(response_json.keys())}")
                print(f"[NVD] Vulnerabilities Count: {len(response_json.get('vulnerabilities', []))}")
                print(f"[NVD] Results Per Page: {response_json.get('resultsPerPage', 'N/A')}")
                print(f"[NVD] Total Results: {response_json.get('totalResults', 'N/A')}")
                print(f"[NVD] Response Preview (first 500 chars): {json.dumps(response_json, indent=2)[:500]}...")
            except Exception as parse_error:
                print(f"[NVD] ⚠️  JSON Parse Error: {parse_error}")
                print(f"[NVD] Raw Response Preview: {response.text[:500]}")
        else:
            print(f"[NVD] ⚠️  Non-200 Status Code")
            print(f"[NVD] Error Response: {response.text[:500]}")
        print(f"[NVD] ================================================================\n")

        if response.status_code == 200:
            data = response.json()

            # Extract CVEs from response
            cves = []
            vulnerabilities = data.get('vulnerabilities', [])

            print(f"[CVE] Found {len(vulnerabilities)} potential CVEs")

            for vuln in vulnerabilities:
                cve_item = vuln.get('cve', {})

                # Extract CVE ID
                cve_id = cve_item.get('id', 'Unknown')

                # Extract CVSS score and severity
                cvss_score = 0.0
                severity = 'UNKNOWN'

                # Try CVSS v3.1 first, then v3.0, then v2.0
                metrics = cve_item.get('metrics', {})

                if 'cvssMetricV31' in metrics and len(metrics['cvssMetricV31']) > 0:
                    cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                    cvss_score = cvss_data.get('baseScore', 0.0)
                    severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                elif 'cvssMetricV30' in metrics and len(metrics['cvssMetricV30']) > 0:
                    cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                    cvss_score = cvss_data.get('baseScore', 0.0)
                    severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                elif 'cvssMetricV2' in metrics and len(metrics['cvssMetricV2']) > 0:
                    cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                    cvss_score = cvss_data.get('baseScore', 0.0)
                    # Map v2 score to severity
                    if cvss_score >= 7.0:
                        severity = 'HIGH'
                    elif cvss_score >= 4.0:
                        severity = 'MEDIUM'
                    else:
                        severity = 'LOW'

                # Extract description
                descriptions = cve_item.get('descriptions', [])
                description = 'No description available'
                for desc in descriptions:
                    if desc.get('lang') == 'en':
                        description = desc.get('value', 'No description available')
                        break

                # Extract published date
                published = cve_item.get('published', 'Unknown')
                if published != 'Unknown':
                    try:
                        # Parse ISO format date
                        published_dt = datetime.fromisoformat(published.replace('Z', '+00:00'))
                        published = published_dt.strftime('%Y-%m-%d')
                    except:
                        pass

                # Build CVE record
                cve_record = {
                    'cve_id': cve_id,
                    'cvss_score': cvss_score,
                    'severity': severity,
                    'description': description[:200] + '...' if len(description) > 200 else description,
                    'published': published,
                    'url': f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                }

                cves.append(cve_record)

                print(f"[CVE]   ✓ {cve_id}: CVSS {cvss_score} ({severity})")

            # Sort by CVSS score (highest first)
            cves.sort(key=lambda x: x['cvss_score'], reverse=True)

            return cves[:10]  # Return top 10 most severe CVEs

        elif response.status_code == 403:
            print(f"[CVE] ⚠️  Access denied - check API key")
            return []
        elif response.status_code == 429:
            print(f"[CVE] ⚠️  Rate limit exceeded")
            return []
        else:
            print(f"[CVE] ⚠️  HTTP {response.status_code}")
            return []

    except requests.exceptions.Timeout:
        print(f"[CVE] ⚠️  Request timeout")
        return []
    except Exception as e:
        print(f"[CVE] ⚠️  Error: {e}")
        return []


def check_cisa_kev(cve_id):
    """
    Check if a CVE is in the CISA Known Exploited Vulnerabilities (KEV) catalog

    Args:
        cve_id (str): CVE ID (e.g., "CVE-2021-41773")

    Returns:
        dict: KEV information
              {in_kev: bool, known_ransomware: bool, required_action: str, due_date: str}
    """
    # Load KEV data (cached for 24 hours)
    kev_data = _get_kev_data()

    if not kev_data:
        return {
            'in_kev': False,
            'known_ransomware': False,
            'required_action': None,
            'due_date': None
        }

    # Search for CVE in KEV list
    vulnerabilities = kev_data.get('vulnerabilities', [])

    for vuln in vulnerabilities:
        if vuln.get('cveID') == cve_id:
            print(f"[KEV] 🚨 {cve_id} is in CISA KEV list!")

            return {
                'in_kev': True,
                'known_ransomware': vuln.get('knownRansomwareCampaignUse', 'Unknown').lower() == 'known',
                'required_action': vuln.get('requiredAction', 'N/A'),
                'due_date': vuln.get('dueDate', 'N/A'),
                'vendor_project': vuln.get('vendorProject', 'N/A'),
                'vulnerability_name': vuln.get('vulnerabilityName', 'N/A')
            }

    return {
        'in_kev': False,
        'known_ransomware': False,
        'required_action': None,
        'due_date': None
    }


def check_exploit_availability(cve_id):
    """
    Check if a public exploit exists for a CVE in ExploitDB

    Args:
        cve_id (str): CVE ID (e.g., "CVE-2021-41773")

    Returns:
        dict: Exploit information
              {exploit_exists: bool, exploit_url: str, exploit_type: str, exploit_count: int}
    """
    # Load ExploitDB data (cached for 24 hours)
    exploitdb_data = _get_exploitdb_data()

    if not exploitdb_data:
        return {
            'exploit_exists': False,
            'exploit_url': None,
            'exploit_type': None,
            'exploit_count': 0
        }

    # Search for CVE in ExploitDB CSV
    # CSV format: id,file,description,date,author,type,platform,port
    # We need to parse the description field for CVE references

    exploits = []

    for line in exploitdb_data.split('\n'):
        if cve_id.upper() in line.upper():
            try:
                parts = line.split(',')
                if len(parts) >= 7:
                    exploit_id = parts[0]
                    exploit_type = parts[5] if len(parts) > 5 else 'Unknown'

                    exploits.append({
                        'exploit_id': exploit_id,
                        'exploit_type': exploit_type,
                        'exploit_url': f"https://www.exploit-db.com/exploits/{exploit_id}"
                    })
            except:
                continue

    if exploits:
        print(f"[EXPLOITDB] 🎯 Found {len(exploits)} public exploit(s) for {cve_id}")

        return {
            'exploit_exists': True,
            'exploit_url': exploits[0]['exploit_url'],  # Return first exploit
            'exploit_type': exploits[0]['exploit_type'],
            'exploit_count': len(exploits),
            'exploits': exploits[:5]  # Return up to 5 exploits
        }

    return {
        'exploit_exists': False,
        'exploit_url': None,
        'exploit_type': None,
        'exploit_count': 0
    }


def enrich_cve(cve_record):
    """
    Enrich a CVE record with CISA KEV and ExploitDB data

    Args:
        cve_record (dict): CVE record from map_service_to_cves

    Returns:
        dict: Enriched CVE record with KEV and exploit data
    """
    cve_id = cve_record.get('cve_id')

    if not cve_id:
        return cve_record

    # Check CISA KEV
    kev_data = check_cisa_kev(cve_id)
    cve_record['kev'] = kev_data

    # Check ExploitDB
    exploit_data = check_exploit_availability(cve_id)
    cve_record['exploit'] = exploit_data

    # Calculate enhanced risk score
    risk_score = cve_record.get('cvss_score', 0.0)

    # Boost risk if in CISA KEV
    if kev_data['in_kev']:
        risk_score = min(risk_score + 2.0, 10.0)  # Boost by 2 points
        cve_record['enhanced_severity'] = 'CRITICAL'

    # Boost risk if exploit exists
    if exploit_data['exploit_exists']:
        risk_score = min(risk_score + 1.0, 10.0)  # Boost by 1 point

    cve_record['enhanced_cvss_score'] = round(risk_score, 1)

    return cve_record


def add_cve_context(cve, service_name, port):
    """
    Add human-readable context to CVE explaining why it matters

    Args:
        cve (dict): CVE record with enriched data
        service_name (str): Service name (e.g., "MySQL", "OpenSSH")
        port (int): Port number

    Returns:
        dict: CVE with added context fields (why_it_matters, how_to_fix, urgency)
    """
    # Get service context from CVE_CONTEXT dictionary
    context = CVE_CONTEXT.get(service_name, {})

    # Build "Why it matters" explanation
    cve_id = cve.get('cve_id', 'Unknown')
    cvss_score = cve.get('cvss_score', 0.0)
    description = cve.get('description', '')[:100]

    exposed_msg = context.get('exposed', 'Service exposed to internet')
    impact_msg = context.get('impact', 'Could lead to system compromise')

    cve['why_it_matters'] = (
        f"{exposed_msg}. "
        f"{cve_id} (CVSS {cvss_score}) allows: {description}. "
        f"{impact_msg}."
    )

    # Add "How to fix" guidance
    cve['how_to_fix'] = context.get('fix', 'Update software and restrict network access')

    # Calculate urgency level
    is_critical = cvss_score >= 9.0
    has_exploit = cve.get('exploit', {}).get('exploit_exists', False)
    in_kev = cve.get('kev', {}).get('in_kev', False)

    if is_critical and has_exploit:
        cve['urgency'] = 'IMMEDIATE - Critical vulnerability with public exploit'
    elif is_critical or in_kev:
        cve['urgency'] = 'HIGH - Critical vulnerability or actively exploited'
    elif has_exploit:
        cve['urgency'] = 'HIGH - Public exploit available'
    elif cvss_score >= 7.0:
        cve['urgency'] = 'MEDIUM - High severity, patch soon'
    else:
        cve['urgency'] = 'MEDIUM - Patch when possible'

    return cve


def _apply_nvd_rate_limit():
    """Apply rate limiting for NVD API (50 requests per 30 seconds)"""
    global _nvd_request_times

    current_time = time.time()

    # Remove requests older than 30 seconds
    _nvd_request_times = [t for t in _nvd_request_times if current_time - t < NVD_RATE_WINDOW]

    # Check if we've hit the rate limit
    if len(_nvd_request_times) >= NVD_RATE_LIMIT:
        # Calculate how long to wait
        oldest_request = _nvd_request_times[0]
        wait_time = NVD_RATE_WINDOW - (current_time - oldest_request)

        if wait_time > 0:
            print(f"[CVE] Rate limit reached, waiting {wait_time:.1f} seconds...")
            time.sleep(wait_time)
            _nvd_request_times = []

    # Record this request
    _nvd_request_times.append(time.time())


def _get_kev_data():
    """Get CISA KEV data (cached for 24 hours)"""
    global _kev_cache

    current_time = datetime.now()

    # Check if cache is valid (less than 24 hours old)
    if _kev_cache['data'] and _kev_cache['timestamp']:
        age = current_time - _kev_cache['timestamp']
        if age < timedelta(hours=24):
            print(f"[KEV] Using cached data (age: {age.seconds // 3600}h)")
            return _kev_cache['data']

    # Download fresh KEV data
    print(f"[KEV] Downloading CISA KEV catalog...")

    try:
        response = requests.get(KEV_URL, timeout=15)

        if response.status_code == 200:
            kev_data = response.json()

            # Update cache
            _kev_cache['data'] = kev_data
            _kev_cache['timestamp'] = current_time

            vuln_count = len(kev_data.get('vulnerabilities', []))
            print(f"[KEV] ✓ Downloaded {vuln_count} known exploited vulnerabilities")

            return kev_data
        else:
            print(f"[KEV] ⚠️  HTTP {response.status_code}")
            return None

    except Exception as e:
        print(f"[KEV] ⚠️  Error downloading KEV data: {e}")
        return None


def _get_exploitdb_data():
    """Get ExploitDB CSV data (cached for 24 hours)"""
    global _exploitdb_cache

    current_time = datetime.now()

    # Check if cache is valid (less than 24 hours old)
    if _exploitdb_cache['data'] and _exploitdb_cache['timestamp']:
        age = current_time - _exploitdb_cache['timestamp']
        if age < timedelta(hours=24):
            print(f"[EXPLOITDB] Using cached data (age: {age.seconds // 3600}h)")
            return _exploitdb_cache['data']

    # Download fresh ExploitDB data
    print(f"[EXPLOITDB] Downloading ExploitDB CSV...")

    try:
        response = requests.get(EXPLOITDB_CSV_URL, timeout=30)

        if response.status_code == 200:
            csv_data = response.text

            # Update cache
            _exploitdb_cache['data'] = csv_data
            _exploitdb_cache['timestamp'] = current_time

            line_count = len(csv_data.split('\n'))
            print(f"[EXPLOITDB] ✓ Downloaded {line_count} exploit records")

            return csv_data
        else:
            print(f"[EXPLOITDB] ⚠️  HTTP {response.status_code}")
            return None

    except Exception as e:
        print(f"[EXPLOITDB] ⚠️  Error downloading ExploitDB data: {e}")
        return None


# Test function
if __name__ == '__main__':
    print("\n🔍 Testing CVE Intelligence Layer\n")

    # Test 1: Map Apache httpd 2.4.49 (known vulnerable version)
    print("="*60)
    print("TEST 1: Apache httpd 2.4.49")
    print("="*60)
    cves = map_service_to_cves("Apache httpd", "2.4.49")

    if cves:
        for cve in cves[:3]:  # Show top 3
            print(f"\nCVE: {cve['cve_id']}")
            print(f"CVSS: {cve['cvss_score']} ({cve['severity']})")
            print(f"Published: {cve['published']}")
            print(f"Description: {cve['description']}")

            # Enrich with KEV and ExploitDB
            enriched = enrich_cve(cve)

            if enriched['kev']['in_kev']:
                print(f"🚨 IN CISA KEV: {enriched['kev']['vulnerability_name']}")
                print(f"   Required Action: {enriched['kev']['required_action']}")

            if enriched['exploit']['exploit_exists']:
                print(f"🎯 PUBLIC EXPLOIT AVAILABLE: {enriched['exploit']['exploit_url']}")

    # Test 2: Check specific CVE in KEV
    print("\n" + "="*60)
    print("TEST 2: Check CVE-2021-41773 in CISA KEV")
    print("="*60)
    kev_result = check_cisa_kev("CVE-2021-41773")
    print(json.dumps(kev_result, indent=2))

    # Test 3: Check exploit availability
    print("\n" + "="*60)
    print("TEST 3: Check CVE-2021-41773 in ExploitDB")
    print("="*60)
    exploit_result = check_exploit_availability("CVE-2021-41773")
    print(json.dumps(exploit_result, indent=2))
