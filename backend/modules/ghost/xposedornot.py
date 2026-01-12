"""
XposedOrNot API Integration for NERVE Ghost Search
https://xposedornot.com/

Provides breach checking capabilities:
- Email breach lookup (free, no API key required)
- Breach analytics with risk scoring (free, no API key required)
- Password exposure check (free, anonymous via hash prefix)
- Domain breach checks (requires API key)
"""

import os
import hashlib
import requests
from dotenv import load_dotenv

load_dotenv()


class XposedOrNotAPI:
    """XposedOrNot API integration for breach checking"""

    BASE_URL = "https://api.xposedornot.com/v1"
    PASSWORD_URL = "https://passwords.xposedornot.com/v1"

    def __init__(self, api_key=None):
        """
        Initialize XposedOrNot API client
        api_key is optional - only needed for domain breach checks
        """
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'NERVE-Security-Platform/1.0'
        })

    def check_email_breach(self, email):
        """
        Check if email has been in any data breaches
        Returns: Dict with breach info or None on error
        """
        try:
            url = f"{self.BASE_URL}/check-email/{email}"
            response = self.session.get(url, timeout=10)

            if response.status_code == 200:
                data = response.json()
                if 'breaches' in data and data['breaches']:
                    # Flatten the nested list if needed
                    breaches = data['breaches'][0] if isinstance(data['breaches'][0], list) else data['breaches']
                    return {
                        'found': True,
                        'breach_count': len(breaches),
                        'breaches': breaches,
                        'source': 'xposedornot'
                    }

            return {'found': False, 'breach_count': 0, 'breaches': []}

        except requests.exceptions.Timeout:
            print("[XON] Email breach check timeout")
            return None
        except requests.exceptions.RequestException as e:
            print(f"[XON] Email breach check network error: {e}")
            return None
        except Exception as e:
            print(f"[XON] Email breach check error: {e}")
            return None

    def get_breach_analytics(self, email):
        """
        Get detailed breach analytics for email
        Returns: Comprehensive breach data with risk scoring
        """
        try:
            url = f"{self.BASE_URL}/breach-analytics"
            params = {'email': email}
            response = self.session.get(url, params=params, timeout=15)

            if response.status_code == 200:
                data = response.json()

                # Check if no breaches found
                if data.get('Error') == 'Not found':
                    return {'found': False, 'email': email, 'source': 'xposedornot'}

                # Extract key metrics
                result = {
                    'email': email,
                    'found': True,
                    'summary': {},
                    'exposed_breaches': [],
                    'risk_analysis': {},
                    'source': 'xposedornot'
                }

                # Breach summary
                if 'BreachesSummary' in data:
                    summary = data['BreachesSummary']
                    result['summary'] = {
                        'site': summary.get('site', 'Unknown'),
                        'first_breach': summary.get('first_breach'),
                        'last_breach': summary.get('last_breach'),
                        'total_breaches': summary.get('total_breaches', 0)
                    }

                # Detailed breach info
                if 'ExposedBreaches' in data and data['ExposedBreaches']:
                    breaches_data = data['ExposedBreaches']
                    breaches = breaches_data.get('breaches_details', [])

                    for breach in breaches:
                        # Parse data exposed field (semicolon separated)
                        data_exposed_raw = breach.get('xposed_data', '')
                        data_exposed = [d.strip() for d in data_exposed_raw.split(';') if d.strip()]

                        result['exposed_breaches'].append({
                            'name': breach.get('breach', 'Unknown'),
                            'domain': breach.get('domain', ''),
                            'date': breach.get('xposed_date', 'Unknown'),
                            'records': breach.get('xposed_records', 0),
                            'data_exposed': data_exposed,
                            'password_risk': breach.get('password_risk', 'Unknown'),
                            'searchable': breach.get('searchable', 'No'),
                            'industry': breach.get('industry', 'Unknown'),
                            'description': breach.get('details', '')
                        })

                # Risk metrics
                if 'BreachMetrics' in data:
                    metrics = data['BreachMetrics']

                    # Risk score
                    if 'risk' in metrics and metrics['risk']:
                        risk_data = metrics['risk'][0] if isinstance(metrics['risk'], list) else metrics['risk']
                        result['risk_analysis'] = {
                            'risk_score': risk_data.get('risk_score', 0),
                            'risk_label': risk_data.get('risk_label', 'Unknown')
                        }

                    # Passwords at risk
                    if 'passwords_strength' in metrics:
                        result['password_metrics'] = metrics['passwords_strength']

                    # Year-wise breakdown
                    if 'yearwise_details' in metrics and metrics['yearwise_details']:
                        result['year_breakdown'] = metrics['yearwise_details'][0] if isinstance(metrics['yearwise_details'], list) else metrics['yearwise_details']

                return result

            elif response.status_code == 404:
                return {'found': False, 'email': email, 'source': 'xposedornot'}
            else:
                print(f"[XON] Breach analytics returned status {response.status_code}")
                return None

        except requests.exceptions.Timeout:
            print("[XON] Breach analytics timeout")
            return None
        except requests.exceptions.RequestException as e:
            print(f"[XON] Breach analytics network error: {e}")
            return None
        except Exception as e:
            print(f"[XON] Breach analytics error: {e}")
            return None

    def check_password_exposure(self, password):
        """
        Check if password has been exposed in breaches (anonymously)
        Uses SHA3-512 (Keccak) hash for privacy - only first 10 chars sent
        """
        try:
            # Hash password with SHA3-512 (Keccak)
            keccak_hash = hashlib.sha3_512(password.encode()).hexdigest()

            # Use first 10 characters for anonymous search (k-anonymity)
            hash_prefix = keccak_hash[:10]

            url = f"{self.PASSWORD_URL}/pass/anon/{hash_prefix}"
            response = self.session.get(url, timeout=10)

            if response.status_code == 200:
                data = response.json()
                if 'SearchPassAnon' in data:
                    result = data['SearchPassAnon']
                    return {
                        'exposed': True,
                        'exposure_count': int(result.get('count', 0)),
                        'characteristics': result.get('char', ''),
                        'source': 'xposedornot'
                    }

            # Not found or other status
            return {'exposed': False, 'exposure_count': 0, 'source': 'xposedornot'}

        except requests.exceptions.Timeout:
            print("[XON] Password check timeout")
            return None
        except requests.exceptions.RequestException as e:
            print(f"[XON] Password check network error: {e}")
            return None
        except Exception as e:
            print(f"[XON] Password check error: {e}")
            return None

    def check_domain_breaches(self, domain):
        """
        Check for breaches affecting an entire domain
        Requires API key
        """
        if not self.api_key:
            print("[XON] Domain breach check requires API key")
            return None

        try:
            url = f"{self.BASE_URL}/domain-breaches/"
            headers = {
                'x-api-key': self.api_key,
                'Content-Length': '0'
            }
            params = {'domain': domain}

            response = self.session.post(url, headers=headers, params=params, timeout=15)

            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success' and 'metrics' in data:
                    metrics = data['metrics']
                    return {
                        'found': True,
                        'domain': domain,
                        'breach_summary': metrics.get('Breach_Summary', {}),
                        'domain_summary': metrics.get('Domain_Summary', {}),
                        'yearly_metrics': metrics.get('Yearly_Metrics', {}),
                        'breach_details': metrics.get('Breaches_Details', []),
                        'source': 'xposedornot'
                    }

            return {'found': False, 'domain': domain, 'source': 'xposedornot'}

        except requests.exceptions.Timeout:
            print("[XON] Domain breach check timeout")
            return None
        except requests.exceptions.RequestException as e:
            print(f"[XON] Domain breach check network error: {e}")
            return None
        except Exception as e:
            print(f"[XON] Domain breach check error: {e}")
            return None


# Singleton instance
_xon_client = None


def get_xon_client():
    """Get or create XposedOrNot client"""
    global _xon_client
    if _xon_client is None:
        # API key is optional - only needed for domain checks
        api_key = os.getenv('XPOSEDORNOT_API_KEY')
        _xon_client = XposedOrNotAPI(api_key=api_key)
    return _xon_client


def check_xposedornot_email(email):
    """
    Convenience function for unified search
    Returns: (breach_list, count) tuple matching other API patterns
    """
    client = get_xon_client()
    result = client.get_breach_analytics(email)

    if result is None:
        return None, -3  # Network/API error

    if not result.get('found'):
        return [], 0

    # Format breaches to match unified search expected format
    breach_list = []
    for breach in result.get('exposed_breaches', []):
        breach_list.append({
            'name': breach.get('name', 'Unknown'),
            'date': breach.get('date', 'Unknown'),
            'data_types': breach.get('data_exposed', []),
            'records': breach.get('records', 0),
            'password_risk': breach.get('password_risk', 'Unknown'),
            'industry': breach.get('industry', 'Unknown')
        })

    return breach_list, len(breach_list)


def check_xposedornot_password(password):
    """
    Convenience function for password exposure check
    Returns: (result_dict, exposure_count) tuple
    """
    client = get_xon_client()
    result = client.check_password_exposure(password)

    if result is None:
        return None, -3  # Network/API error

    if not result.get('exposed'):
        return {'exposed': False, 'count': 0}, 0

    return result, result.get('exposure_count', 0)


def check_xposedornot_domain(domain):
    """
    Convenience function for domain breach check
    Returns: (result_dict, breach_count) tuple
    """
    client = get_xon_client()
    result = client.check_domain_breaches(domain)

    if result is None:
        return None, -3  # Network/API error

    if not result.get('found'):
        return [], 0

    # Return domain breach details
    breach_details = result.get('breach_details', [])
    return result, len(breach_details)


if __name__ == "__main__":
    # Test the XposedOrNot integration
    print("Testing XposedOrNot API integration...")
    print("=" * 60)

    client = get_xon_client()

    # Test email breach check
    test_email = "test@example.com"
    print(f"\n1. Testing email breach check: {test_email}")
    result = client.check_email_breach(test_email)
    if result:
        print(f"   Found: {result.get('found')}")
        print(f"   Breach count: {result.get('breach_count', 0)}")
    else:
        print("   Error or no data")

    # Test breach analytics
    print(f"\n2. Testing breach analytics: {test_email}")
    analytics = client.get_breach_analytics(test_email)
    if analytics and analytics.get('found'):
        print(f"   Total breaches: {len(analytics.get('exposed_breaches', []))}")
        print(f"   Risk score: {analytics.get('risk_analysis', {}).get('risk_score', 'N/A')}")
        print(f"   Risk label: {analytics.get('risk_analysis', {}).get('risk_label', 'N/A')}")
    else:
        print("   No breach analytics found or error")

    # Test password exposure (with a known-bad password)
    test_password = "password123"
    print(f"\n3. Testing password exposure check")
    pw_result = client.check_password_exposure(test_password)
    if pw_result:
        print(f"   Exposed: {pw_result.get('exposed')}")
        print(f"   Exposure count: {pw_result.get('exposure_count', 0)}")
    else:
        print("   Error checking password")

    print("\n" + "=" * 60)
    print("XposedOrNot integration test complete")
