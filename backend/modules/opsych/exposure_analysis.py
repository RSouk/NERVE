"""
OPSYCH Exposure Analysis - Comprehensive Person Intelligence
Calculates human exposure and risk scores using multiple intelligence sources.

DATA SOURCES:
- Hunter.io: Work email/company enrichment
- Ghost Database: Breach data (credentials, passwords, SSN, credit cards)
- DuckDuckGo: OSINT searches (documents, mentions, social)
- Google Custom Search: News articles, LinkedIn, social media

RETURN STRUCTURE:
{
    'professional': {...},
    'breaches': {...},
    'mentions': {...},
    'social': {...},
    'risk_score': 0-100,
    'confidence': 0-100
}
"""

import os
import re
import json
import requests
from typing import Dict, List, Optional
from datetime import datetime, timezone
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor, as_completed

# Load environment variables
load_dotenv()

# API Keys
HUNTER_API_KEY = os.getenv('HUNTER_API_KEY', '')
GOOGLE_CSE_ID = os.getenv('GOOGLE_CSE_ID', '')
GOOGLE_API_KEY = os.getenv('GOOGLE_API_KEY', '')

# Database imports
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
from database import SessionLocal, UploadedCredential, GitHubFinding, PasteBinFinding


def generate_username_variations(email: str = None, name: str = None) -> List[str]:
    """
    Generate likely username variations from email/name.

    Examples:
    - John Doe → johndoe, john.doe, j.doe, jdoe, johnd, doejohn
    - john.doe@company.com → john.doe, johndoe, jdoe
    """
    usernames = []

    if email:
        local_part = email.split('@')[0]
        usernames.append(local_part)
        usernames.append(local_part.replace('.', ''))
        usernames.append(local_part.replace('_', ''))
        usernames.append(local_part.replace('-', ''))

    if name:
        # Clean name
        name = name.lower().strip()
        parts = name.split()

        if len(parts) >= 2:
            first = parts[0]
            last = parts[-1]

            # Common patterns
            usernames.append(f"{first}{last}")  # johndoe
            usernames.append(f"{first}.{last}")  # john.doe
            usernames.append(f"{first}_{last}")  # john_doe
            usernames.append(f"{first}-{last}")  # john-doe
            usernames.append(f"{first[0]}{last}")  # jdoe
            usernames.append(f"{first[0]}.{last}")  # j.doe
            usernames.append(f"{first}{last[0]}")  # johnd
            usernames.append(f"{last}{first}")  # doejohn

            # With numbers
            for num in ['1', '123', '2024']:
                usernames.append(f"{first}{last}{num}")
                usernames.append(f"{first}{num}")

        elif len(parts) == 1:
            usernames.append(parts[0])
            usernames.append(f"{parts[0]}1")
            usernames.append(f"{parts[0]}123")

    # Deduplicate and filter
    usernames = list(set(usernames))
    usernames = [u for u in usernames if len(u) >= 3 and len(u) <= 30]

    return usernames[:15]  # Limit to 15 most likely


def check_github_username(username: str) -> Optional[Dict]:
    """
    Check if username exists on GitHub.
    Returns profile data if found.
    """
    try:
        print(f"[GITHUB] Checking username: {username}")
        url = f'https://api.github.com/users/{username}'
        headers = {'User-Agent': 'Mozilla/5.0'}

        response = requests.get(url, headers=headers, timeout=5)

        if response.status_code == 200:
            data = response.json()
            print(f"[GITHUB] ✓ Found: {username}")
            return {
                'platform': 'GitHub',
                'username': username,
                'url': data.get('html_url', ''),
                'name': data.get('name', ''),
                'bio': data.get('bio', ''),
                'followers': data.get('followers', 0),
                'public_repos': data.get('public_repos', 0),
                'created_at': data.get('created_at', ''),
                'source': 'GitHub API'
            }
    except Exception as e:
        pass

    return None


def check_twitter_username(username: str) -> Optional[Dict]:
    """
    Check if username exists on Twitter/X.
    Uses web scraping (no API key needed).
    """
    try:
        print(f"[TWITTER] Checking username: {username}")
        url = f'https://twitter.com/{username}'
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }

        response = requests.get(url, headers=headers, timeout=5, allow_redirects=False)

        # If not redirected to login/suspended, user likely exists
        if response.status_code == 200:
            print(f"[TWITTER] ✓ Found: {username}")
            return {
                'platform': 'Twitter',
                'username': username,
                'url': f'https://twitter.com/{username}',
                'source': 'Twitter Web Check'
            }
    except Exception as e:
        pass

    return None


def check_instagram_username(username: str) -> Optional[Dict]:
    """
    Check if username exists on Instagram.
    Uses web scraping.
    """
    try:
        print(f"[INSTAGRAM] Checking username: {username}")
        url = f'https://www.instagram.com/{username}/'
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }

        response = requests.get(url, headers=headers, timeout=5, allow_redirects=False)

        if response.status_code == 200:
            print(f"[INSTAGRAM] ✓ Found: {username}")
            return {
                'platform': 'Instagram',
                'username': username,
                'url': f'https://www.instagram.com/{username}/',
                'source': 'Instagram Web Check'
            }
    except Exception as e:
        pass

    return None


def check_reddit_username(username: str) -> Optional[Dict]:
    """
    Check if username exists on Reddit.
    Uses Reddit API (no auth needed for public data).
    """
    try:
        print(f"[REDDIT] Checking username: {username}")
        url = f'https://www.reddit.com/user/{username}/about.json'
        headers = {'User-Agent': 'Mozilla/5.0'}

        response = requests.get(url, headers=headers, timeout=5)

        if response.status_code == 200:
            data = response.json()
            if 'data' in data:
                user_data = data['data']
                print(f"[REDDIT] ✓ Found: {username}")
                return {
                    'platform': 'Reddit',
                    'username': username,
                    'url': f'https://www.reddit.com/user/{username}',
                    'karma': user_data.get('total_karma', 0),
                    'created_utc': user_data.get('created_utc', 0),
                    'is_gold': user_data.get('is_gold', False),
                    'source': 'Reddit API'
                }
    except Exception as e:
        pass

    return None


def enumerate_social_accounts(email: str = None, name: str = None, username: str = None) -> List[Dict]:
    """
    Enumerate social media accounts by checking username variations.
    Returns list of found accounts across GitHub, Twitter, Instagram, Reddit.
    """
    print(f"\n[USERNAME ENUMERATION] Starting")

    # Generate username variations
    usernames = generate_username_variations(email, name)

    # Add provided username
    if username and username not in usernames:
        usernames.insert(0, username)

    print(f"[USERNAME ENUMERATION] Testing {len(usernames)} username variations")
    print(f"[USERNAME ENUMERATION] Usernames: {usernames[:10]}")  # Show first 10

    found_accounts = []

    # Check each username on each platform (in parallel)
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []

        for user in usernames[:10]:  # Limit to 10 usernames to avoid rate limits
            futures.append(executor.submit(check_github_username, user))
            futures.append(executor.submit(check_twitter_username, user))
            futures.append(executor.submit(check_instagram_username, user))
            futures.append(executor.submit(check_reddit_username, user))

        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    found_accounts.append(result)
            except Exception as e:
                pass

    print(f"[USERNAME ENUMERATION] Found {len(found_accounts)} accounts")
    return found_accounts


def extract_name_from_email(email: str) -> str:
    """
    Extract probable name from email address.
    Examples:
    - john.doe@company.com -> john doe
    - reece.soukoroff1@gmail.com -> reece soukoroff
    """
    if not email or '@' not in email:
        return ''

    # Get the part before @
    local_part = email.split('@')[0]

    # Remove numbers
    local_part = re.sub(r'\d+', '', local_part)

    # Replace dots, underscores, hyphens with spaces
    name = re.sub(r'[._-]', ' ', local_part)

    # Clean up multiple spaces
    name = ' '.join(name.split())

    return name.strip()


def search_hunter_email(email: str) -> Dict:
    """
    Use Hunter.io to enrich email information.
    Returns company, position, social profiles.

    Uses two API calls:
    1. Email Verifier - checks if email is valid
    2. Email Finder - gets enrichment data
    """
    result = {
        'email': email,
        'name': '',
        'position': '',
        'company': '',
        'company_domain': '',
        'linkedin': '',
        'twitter': '',
        'phone': '',
        'confidence': 0
    }

    try:
        if not HUNTER_API_KEY:
            print("[HUNTER] No API key configured")
            return result

        print(f"[HUNTER] Searching for: {email}")

        # Step 1: Email Verifier
        verifier_url = 'https://api.hunter.io/v2/email-verifier'
        verifier_params = {
            'email': email,
            'api_key': HUNTER_API_KEY
        }

        response = requests.get(verifier_url, params=verifier_params, timeout=15)
        print(f"[HUNTER] Verifier response status: {response.status_code}")

        if response.status_code == 200:
            data = response.json()
            print(f"[HUNTER] Verifier response: {json.dumps(data, indent=2)[:500]}")

            if data.get('data'):
                email_data = data['data']
                sources = email_data.get('sources', [])

                # Extract domain and company
                if email_data.get('domain'):
                    result['company_domain'] = email_data['domain']
                    result['company'] = email_data['domain'].split('.')[0].title()

                # Extract info from sources
                for source in sources:
                    if source.get('domain'):
                        result['company'] = source.get('domain', '').split('.')[0].title()
                    if source.get('uri') and 'linkedin.com' in source.get('uri', ''):
                        result['linkedin'] = source['uri']
                    if source.get('uri') and 'twitter.com' in source.get('uri', ''):
                        result['twitter'] = source['uri']

                # Check if email is valid
                if email_data.get('status') in ['valid', 'accept_all']:
                    result['confidence'] = 80
                elif email_data.get('status') == 'risky':
                    result['confidence'] = 50
                else:
                    result['confidence'] = 20

        # Step 2: Try to get more enrichment data from domain search
        if result['company_domain']:
            print(f"[HUNTER] Searching domain: {result['company_domain']}")
            domain_url = 'https://api.hunter.io/v2/domain-search'
            domain_params = {
                'domain': result['company_domain'],
                'api_key': HUNTER_API_KEY,
                'limit': 10
            }

            domain_response = requests.get(domain_url, params=domain_params, timeout=15)
            print(f"[HUNTER] Domain search response status: {domain_response.status_code}")

            if domain_response.status_code == 200:
                domain_data = domain_response.json()
                print(f"[HUNTER] Domain search response: {json.dumps(domain_data, indent=2)[:500]}")

                if domain_data.get('data', {}).get('emails'):
                    # Find matching email in results
                    for person in domain_data['data']['emails']:
                        if person.get('value', '').lower() == email.lower():
                            # Found exact match!
                            result['name'] = f"{person.get('first_name', '')} {person.get('last_name', '')}".strip()
                            result['position'] = person.get('position', '')
                            result['company'] = domain_data['data'].get('organization', result['company'])
                            result['linkedin'] = person.get('linkedin', result['linkedin'])
                            result['twitter'] = person.get('twitter', result['twitter'])
                            result['phone'] = person.get('phone_number', '')
                            print(f"[HUNTER] Found exact match: {result['name']} - {result['position']}")
                            break

        print(f"[HUNTER] Final result: {result['name'] or 'No name'} at {result['company'] or 'Unknown'} (confidence: {result['confidence']})")

    except Exception as e:
        print(f"[HUNTER] ERROR: {str(e)}")
        import traceback
        traceback.print_exc()

    return result


def search_ghost_breaches(email: str = None, username: str = None, name: str = None) -> Dict:
    """
    Enhanced Ghost database search - extracts ALL sensitive data.
    Searches ALL tables: uploaded_credentials, github_findings, pastebin_findings.
    Returns: passwords, SSNs, phone numbers, addresses, credit cards.
    """
    result = {
        'total_breaches': 0,
        'passwords': [],
        'credentials': [],
        'github_leaks': [],
        'pastebin_leaks': [],
        'ssns': [],
        'phones': [],
        'addresses': [],
        'credit_cards': [],
        'sensitive_data': [],
        'risk_level': 'low'
    }

    try:
        db = SessionLocal()

        # Search uploaded credentials by email
        if email:
            print(f"[GHOST] Searching uploaded credentials for: {email}")
            creds = db.query(UploadedCredential).filter(
                UploadedCredential.email.ilike(f'%{email}%')
            ).limit(50).all()

            for cred in creds:
                result['passwords'].append(cred.password)
                result['credentials'].append({
                    'email': cred.email,
                    'password': cred.password,
                    'source': 'Uploaded Credentials',
                    'upload_id': cred.upload_id,
                    'additional_data': cred.additional_data
                })

                # Extract structured data from additional_data field
                if cred.additional_data:
                    result['sensitive_data'].append({
                        'type': 'Additional Data',
                        'value': cred.additional_data[:200]
                    })

            print(f"[GHOST] Found {len(creds)} uploaded credentials")

        # Search uploaded credentials by name
        if name:
            print(f"[GHOST] Searching uploaded credentials by name: {name}")
            name_parts = name.split()
            for part in name_parts:
                if len(part) > 3:  # Skip short words
                    name_creds = db.query(UploadedCredential).filter(
                        UploadedCredential.email.ilike(f'%{part}%')
                    ).limit(20).all()

                    for cred in name_creds:
                        if cred.email not in [c['email'] for c in result['credentials']]:
                            result['credentials'].append({
                                'email': cred.email,
                                'password': cred.password,
                                'source': 'Uploaded Credentials (Name Match)',
                                'upload_id': cred.upload_id
                            })

        # Search GitHub findings
        search_terms = []
        if email:
            search_terms.append(email)
        if username:
            search_terms.append(username)
        if name:
            search_terms.extend(name.split())

        for term in search_terms:
            if len(term) > 3:
                github_findings = db.query(GitHubFinding).filter(
                    GitHubFinding.query_term.ilike(f'%{term}%')
                ).limit(20).all()

                for finding in github_findings:
                    leak_data = {
                        'url': finding.gist_url,
                        'credential_type': finding.credential_type,
                        'credential_value': finding.credential_value,
                        'context': finding.context[:300] if finding.context else '',
                        'created_at': finding.created_at.isoformat() if finding.created_at else None,
                        'query_term': finding.query_term
                    }

                    # Avoid duplicates
                    if leak_data not in result['github_leaks']:
                        result['github_leaks'].append(leak_data)

                print(f"[GHOST] Found {len(github_findings)} GitHub leaks for term: {term}")

        # Search PasteBin findings
        for term in search_terms:
            if len(term) > 3:
                pastebin_findings = db.query(PasteBinFinding).filter(
                    PasteBinFinding.query_term.ilike(f'%{term}%')
                ).limit(20).all()

                for finding in pastebin_findings:
                    leak_data = {
                        'url': finding.paste_url,
                        'title': finding.paste_title,
                        'password': finding.credential_password,
                        'context': finding.context[:300] if finding.context else '',
                        'posted_date': finding.posted_date,
                        'query_term': finding.query_term
                    }

                    # Avoid duplicates
                    if leak_data not in result['pastebin_leaks']:
                        result['pastebin_leaks'].append(leak_data)

                print(f"[GHOST] Found {len(pastebin_findings)} PasteBin leaks for term: {term}")

        # Calculate totals
        result['total_breaches'] = (
            len(result['credentials']) +
            len(result['github_leaks']) +
            len(result['pastebin_leaks'])
        )

        # Extract sensitive data from ALL contexts
        sensitive_patterns = {
            'SSN': r'\b\d{3}-\d{2}-\d{4}\b',
            'Credit Card': r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
            'Phone': r'\b(?:\+?1)?[\s-]?\(?(\d{3})\)?[\s-]?(\d{3})[\s-]?(\d{4})\b',
            'Address': r'\b\d{1,5}\s+\w+\s+(?:street|st|avenue|ave|road|rd|drive|dr|lane|ln|court|ct|boulevard|blvd)\b',
            'Zip Code': r'\b\d{5}(?:-\d{4})?\b'
        }

        # Collect all text to search
        all_contexts = []
        all_contexts.extend([l.get('context', '') for l in result['github_leaks']])
        all_contexts.extend([l.get('context', '') for l in result['pastebin_leaks']])
        all_contexts.extend([c.get('additional_data', '') for c in result['credentials'] if c.get('additional_data')])

        for context in all_contexts:
            if not context:
                continue

            for data_type, pattern in sensitive_patterns.items():
                matches = re.findall(pattern, context, re.IGNORECASE)
                if matches:
                    for match in matches[:5]:  # Limit to 5 per type per context
                        if isinstance(match, tuple):
                            match = '-'.join(match)

                        # Add to appropriate category
                        if data_type == 'SSN' and match not in result['ssns']:
                            result['ssns'].append(match)
                        elif data_type == 'Phone' and match not in result['phones']:
                            result['phones'].append(match)
                        elif data_type == 'Credit Card' and match not in result['credit_cards']:
                            result['credit_cards'].append(match)
                        elif data_type in ['Address', 'Zip Code'] and match not in result['addresses']:
                            result['addresses'].append(match)

                        # Also add to sensitive_data for display
                        result['sensitive_data'].append({
                            'type': data_type,
                            'value': match
                        })

        # Determine risk level
        if result['total_breaches'] >= 10 or len(result['ssns']) > 0 or len(result['credit_cards']) > 0:
            result['risk_level'] = 'critical'
        elif result['total_breaches'] >= 5 or len(result['phones']) > 2:
            result['risk_level'] = 'high'
        elif result['total_breaches'] >= 1 or len(result['phones']) > 0:
            result['risk_level'] = 'medium'
        else:
            result['risk_level'] = 'low'

        print(f"[GHOST] Total breaches: {result['total_breaches']}")
        print(f"[GHOST] SSNs: {len(result['ssns'])}, Phones: {len(result['phones'])}, Cards: {len(result['credit_cards'])}")

        db.close()

    except Exception as e:
        print(f"[GHOST] ERROR: {str(e)}")
        import traceback
        traceback.print_exc()

    return result


def search_duckduckgo(query: str, max_results: int = 5) -> List[Dict]:
    """
    Search DuckDuckGo for OSINT data.
    Returns documents, news, and mentions.
    """
    results = []

    try:
        print(f"[DUCKDUCKGO] Searching for: {query}")

        # Use DuckDuckGo HTML endpoint
        url = 'https://html.duckduckgo.com/html/'
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        data = {
            'q': query,
            'b': '',
            'kl': 'us-en'
        }

        response = requests.post(url, headers=headers, data=data, timeout=10)

        if response.status_code == 200:
            # Parse HTML for results (basic extraction)
            from html.parser import HTMLParser

            class DDGParser(HTMLParser):
                def __init__(self):
                    super().__init__()
                    self.results = []
                    self.current_title = ''
                    self.current_url = ''
                    self.in_result = False

                def handle_starttag(self, tag, attrs):
                    attrs_dict = dict(attrs)
                    if tag == 'a' and attrs_dict.get('class') == 'result__a':
                        self.current_url = attrs_dict.get('href', '')
                        self.in_result = True

                def handle_data(self, data):
                    if self.in_result and data.strip():
                        self.current_title = data.strip()

                def handle_endtag(self, tag):
                    if tag == 'a' and self.in_result:
                        if self.current_title and self.current_url:
                            self.results.append({
                                'title': self.current_title,
                                'url': self.current_url,
                                'source': 'DuckDuckGo'
                            })
                        self.in_result = False
                        self.current_title = ''
                        self.current_url = ''

            parser = DDGParser()
            parser.feed(response.text)
            results = parser.results[:max_results]

            print(f"[DUCKDUCKGO] Found {len(results)} results")

    except Exception as e:
        print(f"[DUCKDUCKGO] ERROR: {str(e)}")
        import traceback
        traceback.print_exc()

    return results


def search_duckduckgo_multi(email: str = None, name: str = None, username: str = None) -> List[Dict]:
    """
    Enhanced DuckDuckGo search with multiple query formats.
    Tries various combinations to find the most relevant results.
    """
    all_results = []
    queries = []

    # Generate multiple query formats
    if email:
        # Email queries
        queries.append(email)  # Without quotes
        queries.append(f'"{email}"')  # With quotes
        queries.append(f'{email} linkedin')
        queries.append(f'{email} github')

        # Extract and search name from email
        extracted_name = extract_name_from_email(email)
        if extracted_name and len(extracted_name) > 3:
            queries.append(f'"{extracted_name}"')
            queries.append(f'{extracted_name} linkedin')

    if name:
        queries.append(f'"{name}"')
        queries.append(f'{name} linkedin')
        queries.append(f'{name} github')
        queries.append(f'"{name}" filetype:pdf')

    if username:
        queries.append(f'{username} linkedin')
        queries.append(f'{username} github')
        queries.append(f'"{username}"')

    print(f"[DUCKDUCKGO MULTI] Running {len(queries)} search queries")

    # Execute queries in parallel
    seen_urls = set()
    for query in queries[:5]:  # Limit to 5 queries
        results = search_duckduckgo(query, max_results=3)
        for result in results:
            # Deduplicate by URL
            if result['url'] not in seen_urls:
                seen_urls.add(result['url'])
                all_results.append(result)

    print(f"[DUCKDUCKGO MULTI] Total unique results: {len(all_results)}")
    return all_results


def search_google_custom(query: str, max_results: int = 5) -> List[Dict]:
    """
    Use Google Custom Search API for news and social media.
    Searches LinkedIn, Twitter, Instagram, and news sites.
    """
    results = []

    try:
        if not GOOGLE_API_KEY or not GOOGLE_CSE_ID:
            print("[GOOGLE] API key or CSE ID not configured")
            return results

        print(f"[GOOGLE] Searching for: {query}")

        url = 'https://www.googleapis.com/customsearch/v1'
        params = {
            'key': GOOGLE_API_KEY,
            'cx': GOOGLE_CSE_ID,
            'q': query,
            'num': min(max_results, 10)  # Google API max is 10
        }

        response = requests.get(url, params=params, timeout=10)
        print(f"[GOOGLE] Response status: {response.status_code}")

        if response.status_code == 200:
            data = response.json()
            print(f"[GOOGLE] Response: {json.dumps(data, indent=2)[:500]}")

            for item in data.get('items', []):
                results.append({
                    'title': item.get('title', ''),
                    'url': item.get('link', ''),
                    'snippet': item.get('snippet', ''),
                    'source': 'Google Custom Search'
                })

            print(f"[GOOGLE] Found {len(results)} results")
        elif response.status_code == 429:
            print("[GOOGLE] Rate limit exceeded")
        else:
            print(f"[GOOGLE] Error response: {response.text[:200]}")

    except Exception as e:
        print(f"[GOOGLE] ERROR: {str(e)}")
        import traceback
        traceback.print_exc()

    return results


def search_google_multi(email: str = None, name: str = None, username: str = None) -> List[Dict]:
    """
    Enhanced Google Custom Search with multiple targeted queries.
    Searches LinkedIn, GitHub, news, and social media.
    """
    all_results = []
    queries = []

    # Generate targeted queries
    if email:
        queries.append(f'"{email}"')
        queries.append(f'site:linkedin.com "{email}"')
        queries.append(f'site:github.com "{email}"')

        # Extract name from email
        extracted_name = extract_name_from_email(email)
        if extracted_name and len(extracted_name) > 3:
            queries.append(f'site:linkedin.com "{extracted_name}"')

    if name:
        queries.append(f'site:linkedin.com "{name}"')
        queries.append(f'"{name}" news')
        queries.append(f'site:github.com "{name}"')

    if username:
        queries.append(f'site:linkedin.com "{username}"')
        queries.append(f'site:github.com "{username}"')
        queries.append(f'site:twitter.com "{username}"')

    print(f"[GOOGLE MULTI] Running {len(queries)} search queries")

    # Execute queries
    seen_urls = set()
    for query in queries[:3]:  # Limit to 3 queries to avoid rate limiting
        results = search_google_custom(query, max_results=5)
        for result in results:
            # Deduplicate by URL
            if result['url'] not in seen_urls:
                seen_urls.add(result['url'])
                all_results.append(result)

    print(f"[GOOGLE MULTI] Total unique results: {len(all_results)}")
    return all_results


def discover_documents(name: str = None, email: str = None) -> List[Dict]:
    """
    Discover documents (PDFs, DOCX) using search engines.
    Extracts metadata from PDFs when possible.
    """
    documents = []

    if not name and not email:
        return documents

    print(f"\n[DOCUMENT DISCOVERY] Starting")

    queries = []
    if name:
        queries.append(f'"{name}" filetype:pdf')
        queries.append(f'"{name}" filetype:docx')
        queries.append(f'"{name}" resume OR CV')

    if email:
        queries.append(f'"{email}" filetype:pdf')

    # Search using DuckDuckGo
    for query in queries[:4]:  # Limit to 4 document queries
        results = search_duckduckgo(query, max_results=3)
        for result in results:
            if result['url'] not in [d['url'] for d in documents]:
                documents.append({
                    'url': result['url'],
                    'title': result['title'],
                    'type': 'PDF' if 'pdf' in result['url'].lower() else 'Document',
                    'source': 'DuckDuckGo Document Search'
                })

    print(f"[DOCUMENT DISCOVERY] Found {len(documents)} documents")
    return documents


def scrape_whitepages(name: str) -> Dict:
    """
    Scrape Whitepages for relatives, addresses, phone numbers.
    Legal - publicly available data.
    """
    result = {
        'age': None,
        'relatives': [],
        'addresses': [],
        'phones': [],
        'found': False
    }

    try:
        if not name or len(name) < 5:
            return result

        print(f"[WHITEPAGES] Searching for: {name}")

        # Format name for URL
        name_parts = name.strip().split()
        if len(name_parts) < 2:
            return result

        first_name = name_parts[0]
        last_name = name_parts[-1]

        url = f'https://www.whitepages.com/name/{first_name}-{last_name}'
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }

        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            # Basic HTML parsing to extract data
            html = response.text

            # Extract age (pattern: "Age: XX" or "XX years old")
            age_match = re.search(r'Age[:\s]+(\d{2,3})|(\d{2,3})\s+years\s+old', html, re.IGNORECASE)
            if age_match:
                result['age'] = age_match.group(1) or age_match.group(2)

            # Extract phone numbers
            phone_pattern = r'\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}'
            phones = re.findall(phone_pattern, html)
            result['phones'] = list(set(phones))[:5]  # Limit to 5

            # Extract addresses (simple pattern)
            address_pattern = r'\d{1,5}\s+\w+\s+(?:street|st|avenue|ave|road|rd|drive|dr|lane|ln|court|ct|boulevard|blvd)\.?(?:,?\s+\w+,?\s+[A-Z]{2}\s+\d{5})?'
            addresses = re.findall(address_pattern, html, re.IGNORECASE)
            result['addresses'] = list(set(addresses))[:3]  # Limit to 3

            # Extract relatives (pattern: common relative listings)
            # Note: This is basic pattern matching, real implementation would need better parsing
            relative_pattern = r'Relative[s]?[:]\s*((?:[A-Z][a-z]+\s+[A-Z][a-z]+(?:,\s*)?)+)'
            relatives_match = re.search(relative_pattern, html, re.IGNORECASE)
            if relatives_match:
                relatives_text = relatives_match.group(1)
                relatives = [r.strip() for r in relatives_text.split(',')]
                result['relatives'] = relatives[:10]  # Limit to 10

            if result['age'] or result['phones'] or result['addresses'] or result['relatives']:
                result['found'] = True
                print(f"[WHITEPAGES] ✓ Found data for {name}")
                print(f"[WHITEPAGES] Age: {result['age']}, Phones: {len(result['phones'])}, Addresses: {len(result['addresses'])}, Relatives: {len(result['relatives'])}")
            else:
                print(f"[WHITEPAGES] No data found for {name}")

    except Exception as e:
        print(f"[WHITEPAGES] ERROR: {str(e)}")
        import traceback
        traceback.print_exc()

    return result


def lookup_phone_from_breaches(email: str = None, name: str = None) -> List[str]:
    """
    Search Ghost breaches for associated phone numbers.
    Cross-references with breach data.
    """
    phones = []

    try:
        db = SessionLocal()

        print(f"[PHONE LOOKUP] Searching breaches for phone numbers")

        # Search credentials for phone patterns in additional_data
        search_terms = []
        if email:
            search_terms.append(email)
        if name:
            search_terms.extend(name.split())

        for term in search_terms:
            if len(term) > 3:
                creds = db.query(UploadedCredential).filter(
                    UploadedCredential.email.ilike(f'%{term}%')
                ).limit(20).all()

                for cred in creds:
                    # Extract phone from additional_data
                    if cred.additional_data:
                        phone_pattern = r'\b(?:\+?1)?[\s.-]?\(?(\d{3})\)?[\s.-]?(\d{3})[\s.-]?(\d{4})\b'
                        phone_matches = re.findall(phone_pattern, cred.additional_data)
                        for match in phone_matches:
                            phone = '-'.join(match)
                            if phone not in phones:
                                phones.append(phone)

        db.close()

        print(f"[PHONE LOOKUP] Found {len(phones)} phone numbers in breaches")

    except Exception as e:
        print(f"[PHONE LOOKUP] ERROR: {str(e)}")

    return phones[:10]  # Limit to 10


def calculate_risk_score(professional: Dict, breaches: Dict, mentions: List, social: List) -> int:
    """
    Calculate overall risk score (0-100) based on all collected data.

    Scoring breakdown:
    - Breaches: 40 points max (critical exposure)
    - Professional info: 25 points max (company/position known)
    - Social mentions: 20 points max (public visibility)
    - Social media: 15 points max (social footprint)
    """
    score = 0

    # Breaches score (40 points max)
    if breaches['risk_level'] == 'critical':
        score += 40
    elif breaches['risk_level'] == 'high':
        score += 30
    elif breaches['risk_level'] == 'medium':
        score += 20
    elif breaches['risk_level'] == 'low' and breaches['total_breaches'] > 0:
        score += 10

    # Professional info score (25 points max)
    if professional.get('company'):
        score += 10
    if professional.get('position'):
        score += 8
    if professional.get('linkedin') or professional.get('twitter'):
        score += 7

    # Social mentions score (20 points max)
    mention_count = len(mentions)
    if mention_count >= 10:
        score += 20
    elif mention_count >= 5:
        score += 15
    elif mention_count >= 2:
        score += 10
    elif mention_count >= 1:
        score += 5

    # Social media score (15 points max)
    social_count = len(social)
    if social_count >= 5:
        score += 15
    elif social_count >= 3:
        score += 10
    elif social_count >= 1:
        score += 5

    return min(score, 100)


def calculate_confidence_score(professional: Dict, breaches: Dict, mentions: List, social: List) -> int:
    """
    Calculate confidence score (0-100) based on data quality and sources.
    """
    confidence = 0

    # Professional data confidence
    if professional.get('confidence', 0) > 0:
        confidence += professional['confidence'] * 0.3  # 30% weight

    # Breach data confidence (high confidence if found in database)
    if breaches['total_breaches'] > 0:
        confidence += 35  # 35% weight

    # Mentions confidence
    if len(mentions) > 0:
        confidence += min(len(mentions) * 5, 20)  # 20% weight max

    # Social media confidence
    if len(social) > 0:
        confidence += min(len(social) * 3, 15)  # 15% weight max

    return min(int(confidence), 100)


def analyze_exposure(email: str = None, name: str = None, username: str = None, company: str = None,
                    phone: str = None, location: str = None, age: str = None, context: str = None) -> Dict:
    """
    Main exposure analysis function with OPSYCH Intelligence Inference Engine.

    Args:
        email: Email address to analyze
        name: Full name
        username: Username/handle
        company: Company name
        phone: Phone number
        location: City/state/location
        age: Age or age range
        context: Additional context to help narrow search

    Returns:
        Comprehensive exposure analysis with risk score and intelligence inference
    """
    print(f"\n{'='*80}")
    print(f"[EXPOSURE ANALYSIS] Starting OPSYCH Intelligence Inference")
    print(f"Email: {email}, Name: {name}, Username: {username}, Company: {company}")
    print(f"Phone: {phone}, Location: {location}, Age: {age}, Context: {context}")
    print(f"{'='*80}\n")

    # === PHASE 1: Build Query Plan ===
    from .query_builder import build_advanced_queries, get_query_description

    query_params = {
        'name': name,
        'email': email,
        'phone': phone,
        'username': username,
        'company': company,
        'location': location,
        'age': age,
        'context': context
    }

    query_plan = build_advanced_queries(**query_params)
    query_desc = get_query_description(query_plan)

    print(f"\n[QUERY PLAN] Data sources: {', '.join(query_plan['sources'][:5])}")
    print(f"[QUERY PLAN] False positive risk: {query_plan['false_positive_risk']}")
    if query_plan.get('warning'):
        print(f"[QUERY PLAN] ⚠️ WARNING: {query_plan['warning']}")
    print()

    result = {
        'professional': {},
        'breaches': {},
        'mentions': [],
        'social': [],
        'accounts': [],  # NEW: Username enumeration results
        'family': {},  # NEW: Whitepages relatives/addresses
        'documents': [],  # NEW: Found PDFs/documents
        'phones': [],  # NEW: Phone numbers from breaches
        'risk_score': 0,
        'confidence': 0,
        'analyzed_at': datetime.now(timezone.utc).isoformat()
    }

    # === PHASE 2: Execute Data Collection ===
    raw_data = {}  # Store all raw data for inference engine

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {}

        # Reverse lookups (based on query plan)
        if 'reverse_email' in query_plan['sources'] and email:
            from .scrapers.reverse_lookup import reverse_email_lookup
            futures['reverse_email'] = executor.submit(reverse_email_lookup, email)

        if 'reverse_phone' in query_plan['sources'] and phone:
            from .scrapers.reverse_lookup import reverse_phone_lookup
            futures['reverse_phone'] = executor.submit(reverse_phone_lookup, phone)

        # Professional enrichment (Hunter.io)
        if email and 'hunter' in query_plan['sources']:
            futures['professional'] = executor.submit(search_hunter_email, email)

        # Ghost database breach check
        if 'ghost_breaches' in query_plan['sources']:
            futures['breaches'] = executor.submit(search_ghost_breaches, email, username, name)

        # Whitepages lookups (based on query plan)
        if any(s in query_plan['sources'] for s in ['whitepages_filtered', 'whitepages_name', 'whitepages_phone', 'whitepages_age_filter']):
            from .scrapers.whitepages_scraper import scrape_whitepages
            futures['whitepages'] = executor.submit(scrape_whitepages, name, phone, location, age)

        # Enhanced DuckDuckGo searches
        if 'google_dork' in query_plan['sources']:
            futures['ddg_multi'] = executor.submit(search_duckduckgo_multi, email, name, username)

        # Enhanced Google Custom Search
        if GOOGLE_API_KEY and GOOGLE_CSE_ID and 'google_dork' in query_plan['sources']:
            futures['google_multi'] = executor.submit(search_google_multi, email, name, username)

        # Username enumeration (Sherlock-style)
        if 'sherlock' in query_plan['sources']:
            futures['accounts'] = executor.submit(enumerate_social_accounts, email, name, username)

        # Document discovery
        if name or email:
            futures['documents'] = executor.submit(discover_documents, name, email)

        # Phone lookup from breaches
        if email or name:
            futures['phones'] = executor.submit(lookup_phone_from_breaches, email, name)

        # Collect results into raw_data for inference engine
        for key, future in futures.items():
            try:
                data = future.result()
                raw_data[key] = data

                # Also populate legacy result structure
                if key == 'professional':
                    result['professional'] = data
                elif key == 'breaches':
                    result['breaches'] = data
                elif key == 'ddg_multi' or key == 'google_multi':
                    result['mentions'].extend(data)
                elif key == 'accounts':
                    result['accounts'] = data
                elif key == 'documents':
                    result['documents'] = data
                elif key == 'whitepages':
                    # Convert whitepages format to family format
                    if data.get('found'):
                        result['family'] = data
                elif key == 'phones':
                    result['phones'] = data

            except Exception as e:
                print(f"[EXPOSURE ANALYSIS] ERROR in {key}: {str(e)}")
                import traceback
                traceback.print_exc()

    # === PHASE 3: Intelligence Inference ===
    from .inference_engine import infer_intelligence, handle_ambiguity

    print("\n[INFERENCE ENGINE] Building intelligence profiles...")
    inference_result = infer_intelligence(raw_data, query_params)
    inference_result = handle_ambiguity(inference_result, query_params)

    # Add inference results to output
    result['inference'] = {
        'profiles': inference_result.get('profiles', []),
        'confidence_level': inference_result.get('confidence_level', 'low'),
        'ambiguity_detected': inference_result.get('ambiguity_detected', False),
        'recommendation': inference_result.get('recommendation'),
        'total_sources_checked': inference_result.get('total_sources_checked', 0),
        'sources_with_hits': inference_result.get('sources_with_hits', 0),
        'cross_reference_strength': inference_result.get('cross_reference_strength', 0)
    }

    if inference_result.get('ambiguity_status'):
        result['inference']['ambiguity_status'] = inference_result['ambiguity_status']

    print(f"[INFERENCE ENGINE] Found {len(result['inference']['profiles'])} potential profile(s)")
    print(f"[INFERENCE ENGINE] Confidence level: {result['inference']['confidence_level']}")
    if result['inference']['ambiguity_detected']:
        print(f"[INFERENCE ENGINE] ⚠️ Multiple matches detected")
        print(f"[INFERENCE ENGINE] Recommendation: {result['inference']['recommendation']}")

    # Calculate risk and confidence scores
    result['risk_score'] = calculate_risk_score(
        result['professional'],
        result['breaches'],
        result['mentions'],
        result['social']
    )

    result['confidence'] = calculate_confidence_score(
        result['professional'],
        result['breaches'],
        result['mentions'],
        result['social']
    )

    print(f"\n{'='*80}")
    print(f"[EXPOSURE ANALYSIS] COMPLETE")
    print(f"Risk Score: {result['risk_score']}/100")
    print(f"Confidence: {result['confidence']}/100")
    print(f"Breaches: {result['breaches']['total_breaches']}")
    print(f"Mentions: {len(result['mentions'])}")
    print(f"{'='*80}\n")

    return result


if __name__ == "__main__":
    # Test the exposure analysis
    import sys

    if len(sys.argv) > 1:
        email = sys.argv[1] if '@' in sys.argv[1] else None
        name = ' '.join(sys.argv[1:]) if not email else None

        results = analyze_exposure(email=email, name=name)
        print(json.dumps(results, indent=2, default=str))
    else:
        print("Usage: python exposure_analysis.py <email or name>")
        print("\nExamples:")
        print("  python exposure_analysis.py john@company.com")
        print("  python exposure_analysis.py John Doe")
