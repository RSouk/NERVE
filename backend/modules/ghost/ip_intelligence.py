"""
IP Reputation Intelligence Module
Queries AbuseIPDB and IPQualityScore APIs to assess IP reputation and threat level
"""

import os
import requests
from typing import Dict, Any


def check_ip_reputation(ip_address: str) -> Dict[str, Any]:
    """
    Check IP reputation using AbuseIPDB and IPQualityScore APIs

    Args:
        ip_address: IP address to check

    Returns:
        Combined intelligence report with threat assessment
    """
    # Get API keys from environment
    abuseipdb_key = os.getenv('ABUSEIPDB_API_KEY')
    ipqs_key = os.getenv('IPQUALITYSCORE_API_KEY')

    print(f"[IP INTEL] Checking reputation for {ip_address}")
    print(f"[IP INTEL] AbuseIPDB key configured: {bool(abuseipdb_key)}")
    print(f"[IP INTEL] IPQualityScore key configured: {bool(ipqs_key)}")

    # Initialize result with defaults
    result = {
        'ip': ip_address,
        'is_vpn': False,
        'is_proxy': False,
        'is_tor': False,
        'is_residential': False,
        'is_hosting': False,
        'abuse_score': 0,
        'fraud_score': 0,
        'reports_count': 0,
        'isp': 'Unknown',
        'country': 'Unknown',
        'city': 'Unknown',
        'threat_level': 'low',
        'attribution_confidence': 'low',
        'summary': 'IP reputation check failed',
        'errors': []
    }

    # Query AbuseIPDB
    abuseipdb_data = None
    if abuseipdb_key:
        try:
            print(f"[IP INTEL] Querying AbuseIPDB...")
            abuseipdb_url = 'https://api.abuseipdb.com/api/v2/check'
            headers = {
                'Accept': 'application/json',
                'Key': abuseipdb_key
            }
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': '90'
            }

            response = requests.get(abuseipdb_url, headers=headers, params=params, timeout=10)
            print(f"[IP INTEL] AbuseIPDB response status: {response.status_code}")
            response.raise_for_status()
            abuseipdb_data = response.json().get('data', {})

            # Extract AbuseIPDB data
            result['abuse_score'] = abuseipdb_data.get('abuseConfidenceScore', 0)
            result['reports_count'] = abuseipdb_data.get('totalReports', 0)
            result['is_tor'] = abuseipdb_data.get('isTor', False)
            result['country'] = abuseipdb_data.get('countryCode', 'Unknown')
            result['isp'] = abuseipdb_data.get('isp', 'Unknown')

            usage_type = abuseipdb_data.get('usageType', '').lower()
            if 'data center' in usage_type or 'hosting' in usage_type:
                result['is_hosting'] = True

            print(f"[IP INTEL] AbuseIPDB query successful - Score: {result['abuse_score']}, Reports: {result['reports_count']}")

        except requests.exceptions.HTTPError as e:
            error_msg = f'AbuseIPDB HTTP error: {e.response.status_code} - {e.response.text[:200]}'
            print(f"[IP INTEL] {error_msg}")
            result['errors'].append(error_msg)
        except requests.exceptions.RequestException as e:
            error_msg = f'AbuseIPDB network error: {str(e)}'
            print(f"[IP INTEL] {error_msg}")
            result['errors'].append(error_msg)
        except Exception as e:
            error_msg = f'AbuseIPDB error: {str(e)}'
            print(f"[IP INTEL] {error_msg}")
            import traceback
            traceback.print_exc()
            result['errors'].append(error_msg)
    else:
        print(f"[IP INTEL] AbuseIPDB API key not configured")
        result['errors'].append('AbuseIPDB API key not configured')

    # Query IPQualityScore
    ipqs_data = None
    if ipqs_key:
        try:
            print(f"[IP INTEL] Querying IPQualityScore...")
            ipqs_url = f'https://www.ipqualityscore.com/api/json/ip/{ipqs_key}/{ip_address}'

            response = requests.get(ipqs_url, timeout=10)
            print(f"[IP INTEL] IPQualityScore response status: {response.status_code}")
            response.raise_for_status()
            ipqs_data = response.json()

            # Extract IPQualityScore data
            if ipqs_data.get('success'):
                result['fraud_score'] = ipqs_data.get('fraud_score', 0)
                result['is_proxy'] = ipqs_data.get('proxy', False)
                result['is_vpn'] = ipqs_data.get('vpn', False)
                result['is_tor'] = result['is_tor'] or ipqs_data.get('tor', False)

                # Update ISP and location if not set by AbuseIPDB
                if result['isp'] == 'Unknown':
                    result['isp'] = ipqs_data.get('ISP', 'Unknown')
                if result['country'] == 'Unknown':
                    result['country'] = ipqs_data.get('country_code', 'Unknown')
                result['city'] = ipqs_data.get('city', 'Unknown')

                # Check connection type
                connection_type = ipqs_data.get('connection_type', '').lower()
                if 'residential' in connection_type:
                    result['is_residential'] = True
                elif 'data center' in connection_type or 'corporate' in connection_type:
                    result['is_hosting'] = True

                # Store additional useful data
                result['recent_abuse'] = ipqs_data.get('recent_abuse', False)
                result['is_crawler'] = ipqs_data.get('is_crawler', False)
                result['bot_status'] = ipqs_data.get('bot_status', False)
                result['organization'] = ipqs_data.get('organization', '')

                print(f"[IP INTEL] IPQualityScore query successful - Fraud: {result['fraud_score']}, VPN: {result['is_vpn']}, Proxy: {result['is_proxy']}")
            else:
                error_msg = f'IPQualityScore returned success=false: {ipqs_data.get("message", "Unknown error")}'
                print(f"[IP INTEL] {error_msg}")
                result['errors'].append(error_msg)

        except requests.exceptions.HTTPError as e:
            error_msg = f'IPQualityScore HTTP error: {e.response.status_code} - {e.response.text[:200]}'
            print(f"[IP INTEL] {error_msg}")
            result['errors'].append(error_msg)
        except requests.exceptions.RequestException as e:
            error_msg = f'IPQualityScore network error: {str(e)}'
            print(f"[IP INTEL] {error_msg}")
            result['errors'].append(error_msg)
        except Exception as e:
            error_msg = f'IPQualityScore error: {str(e)}'
            print(f"[IP INTEL] {error_msg}")
            import traceback
            traceback.print_exc()
            result['errors'].append(error_msg)
    else:
        print(f"[IP INTEL] IPQualityScore API key not configured")
        result['errors'].append('IPQualityScore API key not configured')

    # Calculate threat level
    abuse_score = result['abuse_score']
    fraud_score = result['fraud_score']
    recent_abuse = result.get('recent_abuse', False)

    if abuse_score > 80 or fraud_score > 80:
        result['threat_level'] = 'critical'
    elif abuse_score > 50 or fraud_score > 50 or recent_abuse:
        result['threat_level'] = 'high'
    elif result['is_proxy'] or result['is_vpn'] or result['is_hosting']:
        result['threat_level'] = 'medium'
    else:
        result['threat_level'] = 'low'

    # Calculate attribution confidence
    if result['is_residential'] and not (result['is_vpn'] or result['is_proxy'] or result['is_tor']):
        result['attribution_confidence'] = 'high'
        attribution_reason = 'Residential IP - ISP can provide subscriber information'
    elif result['is_hosting'] and result['reports_count'] > 0:
        result['attribution_confidence'] = 'medium'
        attribution_reason = 'Datacenter IP with abuse history - hosting provider may cooperate'
    else:
        result['attribution_confidence'] = 'low'
        attribution_reason = 'VPN/Tor/Proxy detected - identity likely hidden'

    # Generate summary
    if result['errors'] and len(result['errors']) >= 2:
        result['summary'] = 'Unable to check IP reputation - API errors'
    elif result['threat_level'] == 'critical':
        result['summary'] = f'CRITICAL THREAT: High abuse/fraud score ({max(abuse_score, fraud_score)}/100). {attribution_reason}'
    elif result['threat_level'] == 'high':
        result['summary'] = f'HIGH RISK: Abuse detected or suspicious activity. {attribution_reason}'
    elif result['threat_level'] == 'medium':
        if result['is_vpn']:
            result['summary'] = f'VPN detected - identity hidden. {result["isp"]}'
        elif result['is_proxy']:
            result['summary'] = f'Proxy detected - identity hidden. {result["isp"]}'
        elif result['is_tor']:
            result['summary'] = f'Tor exit node - identity strongly hidden'
        else:
            result['summary'] = f'Datacenter/hosting IP. {result["isp"]}'
    else:
        result['summary'] = f'Clean residential IP. {attribution_reason}'

    # Log final results
    print(f"[IP INTEL] Reputation check complete for {ip_address}")
    print(f"[IP INTEL] Errors encountered: {len(result['errors'])}")
    if result['errors']:
        for error in result['errors']:
            print(f"[IP INTEL]   - {error}")
    print(f"[IP INTEL] Final threat level: {result['threat_level']}")
    print(f"[IP INTEL] Final attribution confidence: {result['attribution_confidence']}")

    return result


def get_ip_badge_type(reputation: Dict[str, Any]) -> str:
    """
    Determine which badge type to display for an IP

    Args:
        reputation: IP reputation data from check_ip_reputation()

    Returns:
        Badge type: 'high_attribution', 'known_threat', 'hidden_identity', 'datacenter'
    """
    if reputation['threat_level'] in ['critical', 'high']:
        return 'known_threat'
    elif reputation['is_vpn'] or reputation['is_proxy'] or reputation['is_tor']:
        return 'hidden_identity'
    elif reputation['attribution_confidence'] == 'high':
        return 'high_attribution'
    else:
        return 'datacenter'
