"""
Censys API Integration for IP Enrichment
Queries Censys database for exposed services, ports, protocols, and banners
"""

import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


def censys_lookup_ips(ip_addresses):
    """
    Lookup IP addresses in Censys database to discover services, ports, and banners

    Args:
        ip_addresses (list): List of IP addresses to lookup

    Returns:
        list: List of dictionaries with IP enrichment data
              [{ip, port, service, protocol, banner, censys_data}, ...]
    """
    try:
        from censys.search import CensysHosts
    except ImportError:
        print("[CENSYS] ⚠️  censys package not installed. Run: pip install censys")
        return []

    # Get API key from environment
    api_key = os.getenv('CENSYS_API_KEY', '')

    if not api_key:
        print("[CENSYS] ⚠️  CENSYS_API_KEY not found in environment variables")
        print("[CENSYS] Please add CENSYS_API_KEY=YOUR_API_ID_YOUR_SECRET to .env")
        return []

    # Parse API key format: API_ID_SECRET
    # Split on first underscore only
    if '_' not in api_key:
        print("[CENSYS] ⚠️  Invalid API key format. Expected: API_ID_SECRET")
        return []

    api_id, api_secret = api_key.split('_', 1)

    print(f"\n[CENSYS] Starting IP enrichment for {len(ip_addresses)} IPs")
    print(f"[CENSYS] API ID: {api_id}")
    print(f"[CENSYS] API Secret: {api_secret[:10]}...")

    enrichment_results = []

    try:
        # Initialize Censys Hosts client
        h = CensysHosts(api_id=api_id, api_secret=api_secret)
        print(f"[CENSYS] ✓ Successfully initialized Censys client")

    except Exception as e:
        print(f"[CENSYS] ❌ Failed to initialize Censys client: {e}")
        print(f"[CENSYS] Please verify your API credentials")
        return []

    # Query each IP
    for idx, ip in enumerate(ip_addresses, 1):
        try:
            print(f"\n[CENSYS] [{idx}/{len(ip_addresses)}] Querying {ip}...")

            # Lookup IP in Censys database
            host_data = h.view(ip)

            if not host_data:
                print(f"[CENSYS]   - No data found for {ip}")
                continue

            # Extract services from response
            services = host_data.get('services', [])

            if not services:
                print(f"[CENSYS]   - No services found for {ip}")
                continue

            print(f"[CENSYS]   ✓ Found {len(services)} services on {ip}")

            # Parse each service
            for service in services:
                port = service.get('port', 0)
                protocol = service.get('transport_protocol', 'tcp').upper()
                service_name = service.get('service_name', 'Unknown')

                # Extract banner data
                banner = None
                if 'banner' in service:
                    banner = service.get('banner', '')
                elif 'http' in service:
                    http_data = service.get('http', {})
                    banner = http_data.get('response', {}).get('headers', {}).get('Server', '')
                elif 'ssh' in service:
                    ssh_data = service.get('ssh', {})
                    banner = ssh_data.get('server_host_key', {}).get('fingerprint_sha256', '')

                # Build enrichment record
                enrichment_record = {
                    'ip': ip,
                    'port': port,
                    'service': service_name,
                    'protocol': protocol,
                    'banner': banner or 'N/A',
                    'censys_data': {
                        'software': service.get('software', []),
                        'extended_service_name': service.get('extended_service_name', ''),
                        'observed_at': service.get('observed_at', ''),
                    }
                }

                enrichment_results.append(enrichment_record)

                banner_preview = banner[:50] if banner else 'N/A'
                print(f"[CENSYS]     ✓ {ip}:{port}/{protocol} - {service_name} | Banner: {banner_preview}")

        except Exception as e:
            error_msg = str(e)

            # Handle rate limiting
            if '429' in error_msg or 'rate limit' in error_msg.lower():
                print(f"[CENSYS]   ⚠️  Rate limit reached for {ip}")
                print(f"[CENSYS]   Consider upgrading your Censys plan for higher rate limits")
                break

            # Handle not found
            elif '404' in error_msg or 'not found' in error_msg.lower():
                print(f"[CENSYS]   - IP not found in Censys database: {ip}")

            # Handle other errors
            else:
                print(f"[CENSYS]   ⚠️  Error querying {ip}: {error_msg}")

            continue

    print(f"\n[CENSYS] ✓ Enrichment complete: {len(enrichment_results)} services enriched")

    return enrichment_results


def test_censys_connection():
    """
    Test Censys API connectivity and credentials

    Returns:
        bool: True if connection successful, False otherwise
    """
    try:
        from censys.search import CensysHosts
    except ImportError:
        print("[CENSYS] ⚠️  censys package not installed")
        return False

    # Get API key
    api_key = os.getenv('CENSYS_API_KEY', '')

    if not api_key or '_' not in api_key:
        print("[CENSYS] ❌ Invalid or missing API key")
        return False

    api_id, api_secret = api_key.split('_', 1)

    try:
        h = CensysHosts(api_id=api_id, api_secret=api_secret)

        # Test with a known public IP (Google DNS)
        test_ip = "8.8.8.8"
        result = h.view(test_ip)

        if result:
            print(f"[CENSYS] ✓ Connection test successful")
            return True
        else:
            print(f"[CENSYS] ⚠️  Connection test returned no data")
            return False

    except Exception as e:
        print(f"[CENSYS] ❌ Connection test failed: {e}")
        return False


# Test function
if __name__ == '__main__':
    print("\n🔍 Testing Censys Integration\n")

    # Test connection
    if test_censys_connection():
        print("\n✓ Censys API is configured correctly")

        # Test IP lookup
        test_ips = ["8.8.8.8", "1.1.1.1"]
        results = censys_lookup_ips(test_ips)

        print(f"\n{'='*60}")
        print("CENSYS RESULTS")
        print(f"{'='*60}")
        for result in results:
            print(f"IP: {result['ip']}")
            print(f"Port: {result['port']}")
            print(f"Service: {result['service']}")
            print(f"Protocol: {result['protocol']}")
            print(f"Banner: {result['banner']}")
            print("-" * 60)
    else:
        print("\n❌ Censys API configuration failed")
        print("Please check your CENSYS_API_KEY in .env")
