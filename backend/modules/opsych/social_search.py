"""
OPSYCH Social Search - Professional Identity Search
Uses Hunter.io and Twitter/X for comprehensive identity searches.

WORKING APIS:
- Hunter.io: Email/Domain searches - finds company employees
- Twitter/X: Username searches - finds social profiles

ROUTING:
- EMAIL -> Hunter domain search + Twitter username
- DOMAIN -> Hunter domain search
- USERNAME -> Twitter search
- NAME -> No working APIs available
- PHONE -> No APIs implemented
"""

import re
import json
import requests
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple, Optional
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get API keys from environment
HUNTER_API_KEY = os.getenv('HUNTER_API_KEY', '')
TWITTER_BEARER_TOKEN = os.getenv('TWITTER_BEARER_TOKEN', '')



def detect_input_type(query: str) -> str:
    """
    Detect the type of input query.
    Returns: 'email', 'username', 'phone', 'name', or 'domain'
    """
    query = query.strip()

    # Email pattern
    if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', query):
        return 'email'

    # Domain pattern (no @ but has dot and TLD)
    if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', query) and '@' not in query:
        return 'domain'

    # Phone pattern (various formats)
    if re.match(r'^[\+\d][\d\-\(\)\s]{7,}$', query):
        return 'phone'

    # Username pattern (alphanumeric with underscores/dots/hyphens, single word)
    if re.match(r'^[a-zA-Z0-9._-]+$', query) and len(query) <= 30 and ' ' not in query:
        return 'username'

    # Everything else is treated as a name
    return 'name'


def parse_query_input(query_input: str) -> List[Tuple[str, str]]:
    """
    Parse comma-separated inputs and detect their types.
    Returns list of (query, type) tuples.
    """
    queries = []
    parts = [part.strip() for part in query_input.split(',') if part.strip()]

    for part in parts:
        query_type = detect_input_type(part)
        queries.append((part, query_type))

    return queries


def search_hunter_domain(domain: str) -> List[Dict]:
    """
    Use Hunter.io to find all emails at a domain.
    Returns list of people at the company.
    """
    results = []

    try:
        print(f"\n[HUNTER] ===== Domain search for: {domain} =====")

        url = 'https://api.hunter.io/v2/domain-search'
        params = {
            'domain': domain,
            'api_key': HUNTER_API_KEY,
            'limit': 10
        }

        print(f"[HUNTER] Making request to: {url}")
        print(f"[HUNTER] Params: domain={domain}, limit=10")

        response = requests.get(url, params=params, timeout=15)
        print(f"[HUNTER] Response status: {response.status_code}")

        if response.status_code in [400, 401, 403]:
            print(f"[HUNTER] ERROR: API error")
            print(f"[HUNTER] Response body: {response.text[:500]}")
            return results

        if response.status_code == 200:
            data = response.json()
            print(f"[HUNTER] Response preview: {json.dumps(data, indent=2)[:500]}")

            if data.get('data', {}).get('emails'):
                for person in data['data']['emails'][:10]:  # Limit to 10
                    result = {
                        'platform': 'Hunter.io',
                        'username': person.get('value', '').split('@')[0],
                        'email': person.get('value', ''),
                        'name': f"{person.get('first_name', '')} {person.get('last_name', '')}".strip(),
                        'title': person.get('position', ''),
                        'company': data['data'].get('organization', domain),
                        'location': '',
                        'linkedin': person.get('linkedin', ''),
                        'twitter': person.get('twitter', ''),
                        'url': f"https://hunter.io/search/{person.get('value', '')}",
                        'bio': f"{person.get('position', 'Professional')} at {data['data'].get('organization', domain)}",
                        'source': 'Hunter.io Domain Search'
                    }
                    results.append(result)
                    print(f"[HUNTER] Found: {result.get('name')} - {result.get('email')}")

        print(f"[HUNTER] ===== Completed: Found {len(results)} profiles =====\n")

    except Exception as e:
        print(f"[HUNTER] ERROR: {str(e)}")
        import traceback
        traceback.print_exc()

    return results


def search_twitter(username: str) -> List[Dict]:
    """
    Use Twitter/X API to find user by username.
    Returns Twitter profile data.
    """
    results = []

    try:
        print(f"\n[TWITTER] ===== Username search for: {username} =====")

        url = f'https://api.x.com/2/users/by/username/{username}'
        headers = {
            'Authorization': f'Bearer {TWITTER_BEARER_TOKEN}'
        }
        params = {
            'user.fields': 'created_at,description,location,name,protected,public_metrics,url,verified'
        }

        print(f"[TWITTER] Making request to: {url}")
        print(f"[TWITTER] Headers: Authorization: Bearer {TWITTER_BEARER_TOKEN[:30]}...")

        response = requests.get(url, headers=headers, params=params, timeout=10)
        print(f"[TWITTER] Response status: {response.status_code}")

        if response.status_code in [400, 401, 403]:
            print(f"[TWITTER] ERROR: API error")
            print(f"[TWITTER] Response body: {response.text[:500]}")
            return results

        if response.status_code == 200:
            data = response.json()
            print(f"[TWITTER] Response preview: {json.dumps(data, indent=2)[:500]}")

            if data.get('data'):
                user = data['data']
                result = {
                    'platform': 'Twitter/X',
                    'username': user.get('username', ''),
                    'name': user.get('name', ''),
                    'twitter': f"https://twitter.com/{user.get('username', '')}",
                    'url': f"https://twitter.com/{user.get('username', '')}",
                    'bio': user.get('description', ''),
                    'location': user.get('location', ''),
                    'created_at': user.get('created_at', ''),
                    'verified': user.get('verified', False),
                    'followers': user.get('public_metrics', {}).get('followers_count', 0),
                    'source': 'Twitter API'
                }
                results.append(result)
                print(f"[TWITTER] Found profile: @{result.get('username')} - {result.get('followers')} followers")

        print(f"[TWITTER] ===== Completed: Found {len(results)} profiles =====\n")

    except Exception as e:
        print(f"[TWITTER] ERROR: {str(e)}")
        import traceback
        traceback.print_exc()

    return results




def merge_and_dedupe_results(all_results: List[Dict]) -> List[Dict]:
    """
    Merge results from different sources and deduplicate by email/linkedin.
    Combines data from multiple sources for the same person.
    """
    print(f"\n[MERGE] ===== Merging and deduplicating {len(all_results)} results =====")

    # Group by email or linkedin URL
    merged = {}

    for result in all_results:
        # Create unique key based on email or linkedin
        email = result.get('email', '').lower().strip()
        linkedin = result.get('linkedin', '').lower().strip()

        # Generate key - prefer email, fallback to linkedin
        if email:
            key = f"email:{email}"
        elif linkedin:
            key = f"linkedin:{linkedin}"
        else:
            # No email or linkedin, use name+company as fallback
            name = result.get('name', '').lower().strip()
            company = result.get('company', '').lower().strip()
            if name:
                key = f"name:{name}:{company}"
            else:
                # Last resort: use username+platform
                username = result.get('username', '').lower().strip()
                platform = result.get('platform', '').lower().strip()
                key = f"user:{platform}:{username}"

        if key in merged:
            # Merge data - keep non-empty fields from both
            existing = merged[key]
            for field, value in result.items():
                if value and not existing.get(field):
                    existing[field] = value
            # Append sources
            if 'sources' in existing:
                existing['sources'].append(result.get('source', ''))
            else:
                existing['sources'] = [existing.get('source', ''), result.get('source', '')]
            print(f"[MERGE] Merged data for: {existing.get('name') or existing.get('email') or existing.get('username')}")
        else:
            result['sources'] = [result.get('source', '')]
            merged[key] = result
            print(f"[MERGE] Added new entry: {result.get('name') or result.get('email') or result.get('username')}")

    unique_results = list(merged.values())

    print(f"[MERGE] ===== Completed: {len(all_results)} results -> {len(unique_results)} unique profiles =====\n")

    return unique_results


def fast_search(query_input: str) -> Dict:
    """
    Main search function that orchestrates parallel searches across all APIs.

    Args:
        query_input: Comma-separated list of emails, usernames, domains, names

    Returns:
        Dictionary with profiles, emails, phones, aliases, and total_found count
    """
    print(f"\n{'='*80}")
    print(f"[FAST_SEARCH] Starting search for: {query_input}")
    print(f"{'='*80}\n")

    # Parse input queries
    queries = parse_query_input(query_input)
    print(f"[FAST_SEARCH] Parsed queries: {queries}\n")

    if not queries:
        return {
            'profiles': [],
            'emails': [],
            'phones': [],
            'aliases': [],
            'total_found': 0
        }

    all_profiles = []
    all_emails = set()
    all_phones = set()
    all_aliases = set()

    # Run searches in parallel
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []

        for query, query_type in queries:
            print(f"[FAST_SEARCH] Scheduling searches for: {query} (type: {query_type})")

            if query_type == 'email':
                # EMAIL ROUTING: Hunter domain search + Twitter/GitHub with username
                all_emails.add(query)

                # Extract domain and search Hunter domain
                domain = query.split('@')[1]
                futures.append(executor.submit(search_hunter_domain, domain))

                # Extract username (before @) and search Twitter
                username = query.split('@')[0]
                futures.append(executor.submit(search_twitter, username))

                print(f"[FAST_SEARCH] EMAIL route: Hunter domain ({domain}) + Twitter username ({username})")

            elif query_type == 'domain':
                # DOMAIN ROUTING: Hunter domain search only
                futures.append(executor.submit(search_hunter_domain, query))
                print(f"[FAST_SEARCH] DOMAIN route: Hunter domain search")

            elif query_type == 'username':
                # USERNAME ROUTING: Twitter only
                all_aliases.add(query)
                futures.append(executor.submit(search_twitter, query))
                print(f"[FAST_SEARCH] USERNAME route: Twitter only")

            elif query_type == 'name':
                # NAME ROUTING: No name search APIs available
                print(f"[FAST_SEARCH] NAME route: SKIPPED - No working name search APIs available")

            elif query_type == 'phone':
                all_phones.add(query)
                print(f"[FAST_SEARCH] PHONE route: No APIs support phone search yet")

        # Collect results
        print(f"\n[FAST_SEARCH] Waiting for {len(futures)} search tasks to complete...\n")
        for i, future in enumerate(as_completed(futures), 1):
            try:
                results = future.result()
                if results:
                    all_profiles.extend(results)
                    print(f"[FAST_SEARCH] Task {i}/{len(futures)} completed: {len(results)} results")
                else:
                    print(f"[FAST_SEARCH] Task {i}/{len(futures)} completed: 0 results")
            except Exception as e:
                print(f"[FAST_SEARCH] Task {i}/{len(futures)} FAILED: {str(e)}")

    # Merge and deduplicate profiles
    unique_profiles = merge_and_dedupe_results(all_profiles)

    # Extract emails and phones from results
    for profile in unique_profiles:
        if profile.get('email'):
            all_emails.add(profile['email'])
        if profile.get('phone'):
            all_phones.add(profile['phone'])

    print(f"\n{'='*80}")
    print(f"[FAST_SEARCH] SEARCH COMPLETE")
    print(f"[FAST_SEARCH] Total unique profiles: {len(unique_profiles)}")
    print(f"[FAST_SEARCH] Emails: {list(all_emails)}")
    print(f"[FAST_SEARCH] Phones: {list(all_phones)}")
    print(f"[FAST_SEARCH] Aliases: {list(all_aliases)}")
    print(f"{'='*80}\n")

    return {
        'profiles': unique_profiles,
        'emails': list(all_emails),
        'phones': list(all_phones),
        'aliases': list(all_aliases),
        'total_found': len(unique_profiles)
    }


if __name__ == "__main__":
    # Test the search
    import sys
    if len(sys.argv) > 1:
        query = ' '.join(sys.argv[1:])
        results = fast_search(query)
        print(json.dumps(results, indent=2))
    else:
        print("Usage: python social_search.py <query>")
        print("\nExamples:")
        print("  Email:    python social_search.py john@company.com")
        print("  Domain:   python social_search.py company.com")
        print("  Username: python social_search.py elonmusk")
        print("  Name:     python social_search.py Elon Musk")
        print("  Name+Co:  python social_search.py Elon Musk at Tesla")
