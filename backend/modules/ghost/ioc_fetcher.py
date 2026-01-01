import requests
import json
import os
from datetime import datetime
from pathlib import Path

class IOCFetcher:
    def __init__(self):
        self.otx_api_key = os.getenv('ALIENVAULT_OTX_API_KEY')
        self.cache_dir = Path('data/ioc_cache')
        self.cache_dir.mkdir(exist_ok=True)
        self.cache_max_age = 30  # days

    def get_cache_path(self, apt_name):
        """Get cache file path for APT"""
        safe_name = apt_name.lower().replace(' ', '_').replace('/', '_')
        return self.cache_dir / f"{safe_name}_iocs.json"

    def is_cache_valid(self, cache_path):
        """Check if cache exists and is fresh"""
        if not cache_path.exists():
            return False

        try:
            with open(cache_path, 'r') as f:
                data = json.load(f)

            cached_time = datetime.fromisoformat(data.get('cached_at', '2000-01-01'))
            age = datetime.now() - cached_time

            return age.days < self.cache_max_age
        except:
            return False

    def fetch_alienvault_otx(self, apt_name):
        """Fetch IOCs from AlienVault OTX"""
        if not self.otx_api_key:
            print("[IOC] AlienVault OTX API key not found")
            return None

        try:
            headers = {'X-OTX-API-KEY': self.otx_api_key}
            search_url = "https://otx.alienvault.com/api/v1/search/pulses"

            # Try multiple search variations
            search_terms = [
                apt_name,
                apt_name.replace(' ', ''),
                apt_name.split('(')[0].strip() if '(' in apt_name else apt_name
            ]

            all_iocs = {'ips': [], 'domains': [], 'hashes': [], 'urls': []}

            for search_term in search_terms[:2]:
                try:
                    params = {'q': search_term, 'limit': 5}

                    print(f"[IOC] Searching AlienVault OTX for: {search_term}")
                    response = requests.get(search_url, headers=headers, params=params, timeout=30)

                    if response.status_code != 200:
                        print(f"[IOC] AlienVault error: {response.status_code}")
                        continue

                    data = response.json()
                    pulses = data.get('results', [])

                    if not pulses:
                        print(f"[IOC] No pulses found for: {search_term}")
                        continue

                    print(f"[IOC] Found {len(pulses)} pulses for: {search_term}")

                    # Fetch indicators from first 3 pulses
                    for pulse in pulses[:3]:
                        try:
                            pulse_id = pulse.get('id')
                            indicators_url = f"https://otx.alienvault.com/api/v1/pulses/{pulse_id}/indicators"

                            ind_response = requests.get(indicators_url, headers=headers, timeout=20)

                            if ind_response.status_code == 200:
                                indicators = ind_response.json().get('results', [])

                                for ind in indicators[:100]:
                                    ind_type = ind.get('type')
                                    ind_value = ind.get('indicator')

                                    if ind_type == 'IPv4':
                                        all_iocs['ips'].append({
                                            'value': ind_value,
                                            'context': pulse.get('name', 'Unknown'),
                                            'last_seen': pulse.get('modified', 'Unknown')[:10]
                                        })
                                    elif ind_type in ['domain', 'hostname']:
                                        all_iocs['domains'].append({
                                            'value': ind_value,
                                            'context': pulse.get('name', 'Unknown'),
                                            'last_seen': pulse.get('modified', 'Unknown')[:10]
                                        })
                                    elif ind_type in ['FileHash-MD5', 'FileHash-SHA1', 'FileHash-SHA256']:
                                        hash_type = ind_type.replace('FileHash-', '')
                                        all_iocs['hashes'].append({
                                            'type': hash_type,
                                            'value': ind_value,
                                            'context': pulse.get('name', 'Unknown'),
                                            'last_seen': pulse.get('modified', 'Unknown')[:10]
                                        })
                                    elif ind_type == 'URL':
                                        all_iocs['urls'].append({
                                            'value': ind_value,
                                            'context': pulse.get('name', 'Unknown'),
                                            'last_seen': pulse.get('modified', 'Unknown')[:10]
                                        })
                        except Exception as e:
                            print(f"[IOC] Error fetching pulse {pulse_id}: {e}")
                            continue

                    # If we found IOCs, stop searching
                    if any([all_iocs['ips'], all_iocs['domains'], all_iocs['hashes']]):
                        break

                except requests.exceptions.Timeout:
                    print(f"[IOC] AlienVault timeout for: {search_term}")
                    continue
                except Exception as e:
                    print(f"[IOC] AlienVault error for {search_term}: {e}")
                    continue

            # Deduplicate
            all_iocs['ips'] = list({ioc['value']: ioc for ioc in all_iocs['ips']}.values())
            all_iocs['domains'] = list({ioc['value']: ioc for ioc in all_iocs['domains']}.values())
            all_iocs['hashes'] = list({ioc['value']: ioc for ioc in all_iocs['hashes']}.values())
            all_iocs['urls'] = list({ioc['value']: ioc for ioc in all_iocs['urls']}.values())

            print(f"[IOC] AlienVault: {len(all_iocs['ips'])} IPs, {len(all_iocs['domains'])} domains, {len(all_iocs['hashes'])} hashes")

            if not any([all_iocs['ips'], all_iocs['domains'], all_iocs['hashes'], all_iocs['urls']]):
                return None

            return all_iocs

        except Exception as e:
            print(f"[IOC] AlienVault error: {e}")
            return None

    def fetch_threatfox(self, apt_name):
        """Fetch IOCs from ThreatFox (recent IOCs, no auth needed)"""
        try:
            # ThreatFox API endpoint
            url = "https://threatfox-api.abuse.ch/api/v1/"

            # Search variations
            search_terms = [
                apt_name.lower(),
                apt_name.lower().replace(' ', ''),
                apt_name.split('(')[0].strip().lower() if '(' in apt_name else apt_name.lower()
            ]

            all_iocs = {'ips': [], 'domains': [], 'urls': []}

            for search_term in search_terms[:2]:
                try:
                    # Search by malware/threat name
                    data = {'query': 'search_ioc', 'search_term': search_term}

                    print(f"[IOC] Searching ThreatFox for: {search_term}")
                    response = requests.post(url, json=data, timeout=10)

                    if response.status_code != 200:
                        print(f"[IOC] ThreatFox error: {response.status_code}")
                        continue

                    result = response.json()

                    if result.get('query_status') != 'ok':
                        print(f"[IOC] ThreatFox: No data for: {search_term}")
                        continue

                    iocs = result.get('data', [])
                    print(f"[IOC] ThreatFox found {len(iocs)} IOCs for: {search_term}")

                    for ioc in iocs[:50]:
                        ioc_type = ioc.get('ioc_type', '').lower()
                        ioc_value = ioc.get('ioc')
                        malware = ioc.get('malware_printable', 'Unknown')

                        if ioc_type in ['ip:port', 'ip']:
                            # Extract just IP (remove port if present)
                            ip = ioc_value.split(':')[0] if ':' in ioc_value else ioc_value
                            all_iocs['ips'].append({
                                'value': ip,
                                'context': malware,
                                'last_seen': ioc.get('first_seen_utc', 'Unknown')[:10]
                            })
                        elif ioc_type in ['domain', 'url']:
                            if ioc_type == 'domain':
                                all_iocs['domains'].append({
                                    'value': ioc_value,
                                    'context': malware,
                                    'last_seen': ioc.get('first_seen_utc', 'Unknown')[:10]
                                })
                            else:
                                all_iocs['urls'].append({
                                    'value': ioc_value,
                                    'context': malware,
                                    'last_seen': ioc.get('first_seen_utc', 'Unknown')[:10]
                                })

                    if any([all_iocs['ips'], all_iocs['domains'], all_iocs['urls']]):
                        break

                except Exception as e:
                    print(f"[IOC] ThreatFox error for {search_term}: {e}")
                    continue

            # Deduplicate
            all_iocs['ips'] = list({ioc['value']: ioc for ioc in all_iocs['ips']}.values())
            all_iocs['domains'] = list({ioc['value']: ioc for ioc in all_iocs['domains']}.values())
            all_iocs['urls'] = list({ioc['value']: ioc for ioc in all_iocs['urls']}.values())

            print(f"[IOC] ThreatFox: {len(all_iocs['ips'])} IPs, {len(all_iocs['domains'])} domains, {len(all_iocs['urls'])} URLs")

            return all_iocs if any(all_iocs.values()) else {}

        except Exception as e:
            print(f"[IOC] ThreatFox error: {e}")
            return {}

    def fetch_iocs(self, apt_name, force_refresh=False):
        """Fetch IOCs for APT with caching"""
        cache_path = self.get_cache_path(apt_name)

        if not force_refresh and self.is_cache_valid(cache_path):
            print(f"[IOC] Loading from cache: {apt_name}")
            with open(cache_path, 'r') as f:
                return json.load(f)

        print(f"[IOC] Fetching fresh IOCs for: {apt_name}")

        # Fetch from both sources
        otx_iocs = self.fetch_alienvault_otx(apt_name)
        threatfox_iocs = self.fetch_threatfox(apt_name)

        combined = {
            'apt_name': apt_name,
            'cached_at': datetime.now().isoformat(),
            'sources': [],
            'iocs': {'ips': [], 'domains': [], 'urls': [], 'hashes': []},
            'stats': {'total_ips': 0, 'total_domains': 0, 'total_urls': 0, 'total_hashes': 0}
        }

        # Combine OTX data
        if otx_iocs:
            combined['sources'].append('AlienVault OTX')
            combined['iocs']['ips'].extend(otx_iocs.get('ips', []))
            combined['iocs']['domains'].extend(otx_iocs.get('domains', []))
            combined['iocs']['urls'].extend(otx_iocs.get('urls', []))
            combined['iocs']['hashes'].extend(otx_iocs.get('hashes', []))

        # Combine ThreatFox data
        if threatfox_iocs:
            combined['sources'].append('ThreatFox')
            combined['iocs']['ips'].extend(threatfox_iocs.get('ips', []))
            combined['iocs']['domains'].extend(threatfox_iocs.get('domains', []))
            combined['iocs']['urls'].extend(threatfox_iocs.get('urls', []))

        # Deduplicate combined results
        combined['iocs']['ips'] = list({ioc['value']: ioc for ioc in combined['iocs']['ips']}.values())
        combined['iocs']['domains'] = list({ioc['value']: ioc for ioc in combined['iocs']['domains']}.values())
        combined['iocs']['urls'] = list({ioc['value']: ioc for ioc in combined['iocs']['urls']}.values())
        combined['iocs']['hashes'] = list({ioc['value']: ioc for ioc in combined['iocs']['hashes']}.values())

        # Calculate stats
        combined['stats']['total_ips'] = len(combined['iocs']['ips'])
        combined['stats']['total_domains'] = len(combined['iocs']['domains'])
        combined['stats']['total_urls'] = len(combined['iocs']['urls'])
        combined['stats']['total_hashes'] = len(combined['iocs']['hashes'])

        # Cache results
        with open(cache_path, 'w') as f:
            json.dump(combined, f, indent=2)

        total = sum(combined['stats'].values())
        print(f"[IOC] Total IOCs found: {total}")

        if total == 0:
            print(f"[IOC] No IOCs found for {apt_name}")

        return combined

    def cleanup_old_cache(self):
        """Remove cache files older than max age"""
        count = 0
        for cache_file in self.cache_dir.glob('*_iocs.json'):
            if not self.is_cache_valid(cache_file):
                cache_file.unlink()
                count += 1

        if count > 0:
            print(f"[IOC] Cleaned up {count} old cache files")
