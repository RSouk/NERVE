"""
Pulsedive API Integration for Threat Intelligence Enrichment
Queries Pulsedive for IP threat intelligence, risk scores, and malicious indicators
"""

import os
import time
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


def enrich_ips(ip_addresses):
    """
    Enrich IP addresses with Pulsedive threat intelligence

    Args:
        ip_addresses (list): List of IP addresses to enrich

    Returns:
        list: List of dictionaries with threat intelligence data
              [{ip, risk, risk_level, threats, malicious, feeds}, ...]
    """
    try:
        import pulsedive
    except ImportError:
        print("[PULSEDIVE] ⚠️  pulsedive package not installed. Run: pip install pulsedive")
        return []

    # Get API key from environment
    api_key = os.getenv('PULSEDIVE_API_KEY', '')

    if not api_key:
        print("[PULSEDIVE] ⚠️  PULSEDIVE_API_KEY not found in environment variables")
        print("[PULSEDIVE] Please add PULSEDIVE_API_KEY=YOUR_KEY to .env")
        return []

    print(f"\n[PULSEDIVE] Starting threat intelligence enrichment for {len(ip_addresses)} IPs")
    print(f"[PULSEDIVE] API Key: {api_key[:10]}...{api_key[-10:]}")

    threat_results = []

    try:
        # Initialize Pulsedive client
        pud = pulsedive.Pulsedive(api_key)
        print(f"[PULSEDIVE] ✓ Successfully initialized Pulsedive client")

    except Exception as e:
        print(f"[PULSEDIVE] ❌ Failed to initialize Pulsedive client: {e}")
        return []

    # Query each IP
    for idx, ip in enumerate(ip_addresses, 1):
        try:
            print(f"\n[PULSEDIVE] [{idx}/{len(ip_addresses)}] Querying {ip}...")

            # Query Pulsedive for IP indicator
            indicator_data = pud.indicator(value=ip)

            if not indicator_data:
                print(f"[PULSEDIVE]   - No data found for {ip}")

                # Add default safe record
                threat_results.append({
                    'ip': ip,
                    'risk': 'none',
                    'risk_level': 'safe',
                    'risk_score': 0,
                    'threats': [],
                    'malicious': False,
                    'feeds': [],
                    'details': 'No threat intelligence available'
                })
                continue

            # Extract threat data
            risk = indicator_data.get('risk', 'unknown')
            risk_level = categorize_risk(risk)
            threats = indicator_data.get('threats', [])
            feeds = indicator_data.get('feeds', [])

            # Determine if malicious
            malicious = risk in ['high', 'critical'] or len(threats) > 0

            # Extract threat details
            threat_names = []
            if isinstance(threats, list):
                for threat in threats:
                    if isinstance(threat, dict):
                        threat_names.append(threat.get('name', 'Unknown threat'))
                    else:
                        threat_names.append(str(threat))

            # Extract feed information
            feed_names = []
            if isinstance(feeds, list):
                for feed in feeds:
                    if isinstance(feed, dict):
                        feed_names.append(feed.get('name', 'Unknown feed'))
                    else:
                        feed_names.append(str(feed))

            # Build threat record
            threat_record = {
                'ip': ip,
                'risk': risk,
                'risk_level': risk_level,
                'risk_score': calculate_risk_score(risk),
                'threats': threat_names,
                'malicious': malicious,
                'feeds': feed_names,
                'details': indicator_data.get('summary', 'No details available')
            }

            threat_results.append(threat_record)

            # Print status
            status_icon = '🚨' if malicious else '✓'
            print(f"[PULSEDIVE]   {status_icon} {ip}: Risk={risk.upper()} | Threats={len(threat_names)} | Malicious={malicious}")

            if threat_names:
                print(f"[PULSEDIVE]     Threats detected: {', '.join(threat_names[:3])}")

            # RATE LIMITING: Pulsedive free tier = 30 requests/minute
            # Sleep 2 seconds between requests to stay under limit
            if idx < len(ip_addresses):  # Don't sleep after last request
                time.sleep(2)

        except Exception as e:
            error_msg = str(e)

            # Handle rate limiting
            if '429' in error_msg or 'rate limit' in error_msg.lower():
                print(f"[PULSEDIVE]   ⚠️  Rate limit reached for {ip}")
                print(f"[PULSEDIVE]   Consider upgrading your Pulsedive plan")
                break

            # Handle not found
            elif '404' in error_msg or 'not found' in error_msg.lower():
                print(f"[PULSEDIVE]   - IP not found in threat database: {ip}")

                # Add safe record
                threat_results.append({
                    'ip': ip,
                    'risk': 'none',
                    'risk_level': 'safe',
                    'risk_score': 0,
                    'threats': [],
                    'malicious': False,
                    'feeds': [],
                    'details': 'Not found in threat database (likely safe)'
                })

            # Handle other errors
            else:
                print(f"[PULSEDIVE]   ⚠️  Error querying {ip}: {error_msg}")

                # Add unknown record
                threat_results.append({
                    'ip': ip,
                    'risk': 'unknown',
                    'risk_level': 'unknown',
                    'risk_score': 0,
                    'threats': [],
                    'malicious': False,
                    'feeds': [],
                    'details': f'Error: {error_msg}'
                })

            continue

    print(f"\n[PULSEDIVE] ✓ Threat enrichment complete: {len(threat_results)} IPs analyzed")

    # Summary statistics
    malicious_count = sum(1 for r in threat_results if r['malicious'])
    print(f"[PULSEDIVE] 🚨 Malicious IPs: {malicious_count}/{len(threat_results)}")

    return threat_results


def categorize_risk(risk_value):
    """
    Categorize Pulsedive risk value into standardized levels

    Args:
        risk_value (str): Risk value from Pulsedive (none, low, medium, high, critical)

    Returns:
        str: Standardized risk level
    """
    risk_mapping = {
        'none': 'safe',
        'low': 'low',
        'medium': 'medium',
        'high': 'high',
        'critical': 'critical',
        'unknown': 'unknown'
    }

    return risk_mapping.get(str(risk_value).lower(), 'unknown')


def calculate_risk_score(risk_value):
    """
    Convert risk level to numeric score (0-100)

    Args:
        risk_value (str): Risk value from Pulsedive

    Returns:
        int: Numeric risk score
    """
    risk_scores = {
        'none': 0,
        'low': 25,
        'medium': 50,
        'high': 75,
        'critical': 100,
        'unknown': 0
    }

    return risk_scores.get(str(risk_value).lower(), 0)


def test_pulsedive_connection():
    """
    Test Pulsedive API connectivity and credentials

    Returns:
        bool: True if connection successful, False otherwise
    """
    try:
        import pulsedive
    except ImportError:
        print("[PULSEDIVE] ⚠️  pulsedive package not installed")
        return False

    # Get API key
    api_key = os.getenv('PULSEDIVE_API_KEY', '')

    if not api_key:
        print("[PULSEDIVE] ❌ Missing API key")
        return False

    try:
        pud = pulsedive.Pulsedive(api_key)

        # Test with a known malicious IP (example - replace with safe test IP)
        test_ip = "8.8.8.8"  # Google DNS (safe IP for testing)
        result = pud.indicator(value=test_ip)

        print(f"[PULSEDIVE] ✓ Connection test successful")
        return True

    except Exception as e:
        print(f"[PULSEDIVE] ❌ Connection test failed: {e}")
        return False


def get_threat_badge(threat_data):
    """
    Get a threat badge HTML for displaying in frontend

    Args:
        threat_data (dict): Threat data from enrich_ips

    Returns:
        str: HTML badge code
    """
    if threat_data['malicious']:
        badge_color = 'red'
        badge_text = f"MALICIOUS ({threat_data['risk'].upper()})"
    elif threat_data['risk_level'] in ['medium', 'high']:
        badge_color = 'orange'
        badge_text = threat_data['risk'].upper()
    else:
        badge_color = 'green'
        badge_text = 'SAFE'

    return f'<span class="badge badge-{badge_color}">{badge_text}</span>'


# Test function
if __name__ == '__main__':
    print("\n🔍 Testing Pulsedive Integration\n")

    # Test connection
    if test_pulsedive_connection():
        print("\n✓ Pulsedive API is configured correctly")

        # Test IP lookup
        test_ips = ["8.8.8.8", "1.1.1.1"]
        results = enrich_ips(test_ips)

        print(f"\n{'='*60}")
        print("PULSEDIVE THREAT INTELLIGENCE RESULTS")
        print(f"{'='*60}")
        for result in results:
            print(f"IP: {result['ip']}")
            print(f"Risk Level: {result['risk_level']}")
            print(f"Risk Score: {result['risk_score']}/100")
            print(f"Malicious: {result['malicious']}")
            print(f"Threats: {', '.join(result['threats']) if result['threats'] else 'None'}")
            print(f"Feeds: {', '.join(result['feeds']) if result['feeds'] else 'None'}")
            print(f"Details: {result['details']}")
            print("-" * 60)
    else:
        print("\n❌ Pulsedive API configuration failed")
        print("Please check your PULSEDIVE_API_KEY in .env")
