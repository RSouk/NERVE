import time
from typing import Dict, List
from modules.ghost.search_engine import analyze_query
from modules.ghost.hudson_rock import (
    search_by_email,
    search_by_domain,
    search_by_password,
    search_by_username,
    search_by_ip,
    search_by_keyword
)
from modules.ghost.api_breaches import check_leakcheck_api, check_breachdirectory_api
from modules.ghost.breach_checker import check_local_breaches
from modules.ghost.intelligence_x import search_email_intelx, search_domain_intelx, search_keyword_intelx
from modules.ghost.hibp_passwords import check_password_pwned
from datetime import datetime
from database import get_db, GitHubFinding, PasteBinFinding

class UnifiedSearch:
    """
    Orchestrates searches across all available data sources
    """
    
    def __init__(self):
        self.search_id = None
        self.query = None
        self.query_type = None
        self.start_time = None
        self.results = {
            'sources': {},
            'total_findings': 0,
            'errors': []
        }
    
    def search(self, query: str) -> Dict:
        """
        Main search entry point
        Analyzes query, routes to appropriate sources, aggregates results
        """
        self.start_time = time.time()
        self.query = query
        self.search_id = f"search_{int(time.time())}_{hash(query) % 10000}"
        
        print(f"\n{'='*60}")
        print(f"GHOST Unified Search")
        print(f"Query: {query}")
        print(f"Search ID: {self.search_id}")
        print(f"{'='*60}\n")
        
        # Analyze query to determine type and applicable sources
        analysis = analyze_query(query)
        
        if not analysis['valid']:
            return {
                'success': False,
                'error': analysis['error'],
                'query': query
            }
        
        self.query_type = analysis['type']
        print(f"Detected type: {self.query_type}")
        print(f"Applicable sources: {', '.join(analysis['sources'])}\n")
        
        # Route to appropriate search method based on type
        if self.query_type == 'email':
            self._search_email(query)
        elif self.query_type == 'domain':
            self._search_domain(query)
        elif self.query_type == 'password':
            self._search_password(query)
        elif self.query_type == 'username':
            self._search_username(query)
        elif self.query_type == 'ip' or self.query_type == 'cidr':
            self._search_ip(query)
        elif self.query_type == 'keyword':
            self._search_keyword(query)
        else:
            self._search_generic(query)
        
        # Calculate summary
        elapsed = time.time() - self.start_time
        
        return {
            'success': True,
            'search_id': self.search_id,
            'query': query,
            'query_type': self.query_type,
            'sources_queried': list(self.results['sources'].keys()),
            'total_findings': self.results['total_findings'],
            'results': self.results['sources'],
            'errors': self.results['errors'],
            'elapsed_seconds': round(elapsed, 2)
        }
    
    def _search_email(self, email: str):
        """Search all email-capable sources"""
        print("🔍 Searching email across sources...\n")
        # Query ALL sources
        self._query_source('hudson_rock', lambda: self._hudson_rock_email(email))
        self._query_source('leakcheck', lambda: self._leakcheck_search(email))
        self._query_source('breachdirectory', lambda: self._breachdirectory_search(email))
        self._query_source('intelligence_x', lambda: self._intelx_email_search(email))
        self._query_source('local_files', lambda: self._local_search(email))
        self._query_source('github', lambda: self._search_github_data(email, 'email'))
        self._query_source('pastebin', lambda: self._search_pastebin_data(email, 'email'))
    
    def _search_domain(self, domain: str):
        """Search all domain-capable sources"""
        print("🔍 Searching domain across sources...\n")

        # Hudson Rock domain search
        self._query_source('hudson_rock', lambda: self._hudson_rock_domain(domain))

        # BreachDirectory can also search domains
        self._query_source('breachdirectory', lambda: self._breachdirectory_search(domain))

        # GitHub and PasteBin domain search
        self._query_source('github', lambda: self._search_github_data(domain, 'domain'))
        self._query_source('pastebin', lambda: self._search_pastebin_data(domain, 'domain'))
    
    def _search_password(self, password: str):
        """Search password across sources"""
        print("🔍 Searching password across sources...\n")

        # Hudson Rock password search
        self._query_source('hudson_rock', lambda: self._hudson_rock_password(password))

        # Have I Been Pwned Passwords API check
        self._query_source('pwned_passwords', lambda: self._check_pwned_password(password))

        # GitHub and PasteBin password search
        self._query_source('github', lambda: self._search_github_data(password, 'password'))
        self._query_source('pastebin', lambda: self._search_pastebin_data(password, 'password'))

        # Local files (if implemented)
        # self._query_source('local_files', lambda: self._local_password_search(password))
    
    def _search_username(self, username: str):
        """Search username across sources"""
        print("🔍 Searching username across sources...\n")

        # Hudson Rock username search
        self._query_source('hudson_rock', lambda: self._hudson_rock_username(username))

        # GitHub and PasteBin username search
        self._query_source('github', lambda: self._search_github_data(username, 'username'))
        self._query_source('pastebin', lambda: self._search_pastebin_data(username, 'username'))

        # Local files
        # self._query_source('local_files', lambda: self._local_username_search(username))
    
    def _search_ip(self, ip: str):
        """Search IP address across sources"""
        print("🔍 Searching IP across sources...\n")
        
        # Hudson Rock IP search
        self._query_source('hudson_rock', lambda: self._hudson_rock_ip(ip))
    
    def _search_keyword(self, keyword: str):
        """Search keyword across sources"""
        print("🔍 Searching keyword across sources...\n")

        # Hudson Rock keyword search
        self._query_source('hudson_rock', lambda: self._hudson_rock_keyword(keyword))

        # GitHub and PasteBin keyword search
        self._query_source('github', lambda: self._search_github_data(keyword, 'keyword'))
        self._query_source('pastebin', lambda: self._search_pastebin_data(keyword, 'keyword'))
    
    def _search_generic(self, query: str):
        """Generic search when type is unclear"""
        print("🔍 Generic search...\n")
        # Try multiple types
        pass
    
    # Source-specific query methods
    
    def _hudson_rock_email(self, email: str):
        """Query Hudson Rock for email - WITH PROPER PASSWORD EXTRACTION"""
        data, count = search_by_email(email)
        
        if count and count > 0:
            # Extract and structure the credentials properly
            structured_data = self._structure_hudson_rock_data(data)
            
            return {
                'found': True,
                'count': count,
                'data': structured_data,
                'type': 'infostealer_logs'
            }
        return {'found': False, 'count': 0}
    
    def _hudson_rock_domain(self, domain: str):
        """Query Hudson Rock for domain"""
        data, count = search_by_domain(domain)
    
        if count and count > 0:
            structured_data = self._structure_hudson_rock_data(data)
            return {
                'found': True,
                'count': count,
                'data': structured_data,
                'type': 'infostealer_logs'  # Changed from 'domain_exposure'
            }
        return {'found': False, 'count': 0}
    
    def _hudson_rock_password(self, password: str):
        """Query Hudson Rock for password"""
        data, count = search_by_password(password)
        
        if count and count > 0:
            structured_data = self._structure_hudson_rock_data(data)
            return {
                'found': True,
                'count': count,
                'data': structured_data,
                'type': 'password_reuse'
            }
        return {'found': False, 'count': 0}
    
    def _hudson_rock_username(self, username: str):
        """Query Hudson Rock for username"""
        data, count = search_by_username(username)
        
        if count and count > 0:
            structured_data = self._structure_hudson_rock_data(data)
            return {
                'found': True,
                'count': count,
                'data': structured_data,
                'type': 'username_exposure'
            }
        return {'found': False, 'count': 0}
    
    def _hudson_rock_ip(self, ip: str):
        """Query Hudson Rock for IP"""
        data, count = search_by_ip(ip)
    
        if count and count > 0:
            structured_data = self._structure_hudson_rock_data(data)
            print(f"DEBUG: Structured IP data: {structured_data}")
            return {
                'found': True,
                'count': count,
                'data': structured_data,
                'type': 'infostealer_logs'  # Changed from 'ip_exposure'
            }
        return {'found': False, 'count': 0}
    
    def _hudson_rock_keyword(self, keyword: str):
        """Query Hudson Rock for keyword"""
        data, count = search_by_keyword(keyword)
        
        if count and count > 0:
            structured_data = self._structure_hudson_rock_data(data)
            return {
                'found': True,
                'count': count,
                'data': structured_data,
                'type': 'keyword_match'
            }
        return {'found': False, 'count': 0}
    
    def _structure_hudson_rock_data(self, raw_data):
        """
        Properly structure Hudson Rock data to extract passwords
        Hudson Rock returns: {"data": [...], "nextCursor": "..."}
        Each item has: credentials array with url, domain, username, password
        """
        if not raw_data:
            return []
        
        # Handle both list and dict responses
        if isinstance(raw_data, dict):
            items = raw_data.get('data', [])
        elif isinstance(raw_data, list):
            items = raw_data
        else:
            return []
        
        structured = []
        
        for item in items:
            # Extract credentials properly
            credentials = []
            raw_creds = item.get('credentials', [])
            
            for cred in raw_creds:
                credentials.append({
                    'url': cred.get('url', ''),
                    'domain': cred.get('domain', ''),
                    'username': cred.get('username', ''),
                    'password': cred.get('password', '[Encrypted]'),  # This is the actual password
                    'type': cred.get('type', 'login')
                })
            
            structured.append({
                'stealer_family': item.get('malware_path', 'Unknown Stealer'),
                'computer_name': item.get('computer_name', 'Unknown'),
                'operating_system': item.get('operating_system', 'Unknown'),
                'ip': item.get('ip', 'Unknown'),
                'date_compromised': item.get('date_compromised', 'Unknown'),
                'credentials': credentials,  # Now properly structured with passwords
                'antiviruses': item.get('antiviruses', []),
                'top_logins': item.get('top_logins', []),
                'top_sites': item.get('top_sites', []),
                'employee_of': item.get('employee_of', []),
                'client_of': item.get('client_of', [])
            })
        
        return structured
    
    def _leakcheck_search(self, email: str):
        """Query LeakCheck"""
        breaches, count = check_leakcheck_api(email)
        
        if count > 0:
            return {
                'found': True,
                'count': count,
                'data': breaches,
                'type': 'breach_data'
            }
        return {'found': False, 'count': 0}
    
    def _breachdirectory_search(self, query: str):
        """Query BreachDirectory - works for email and domain"""
        breaches, count = check_breachdirectory_api(query)
        
        if count > 0:
            return {
                'found': True,
                'count': count,
                'data': breaches,
                'type': 'breach_data'
            }
        return {'found': False, 'count': 0}
    
    def _local_search(self, email: str):
        """Query local breach files"""
        breaches = check_local_breaches(email)
        
        if breaches:
            return {
                'found': True,
                'count': len(breaches),
                'data': breaches,
                'type': 'local_breach_data'
            }
        return {'found': False, 'count': 0}
    
    def _intelx_email_search(self, email: str):
        """Query Intelligence X for email"""
        results, count = search_email_intelx(email)
        
        if count and count > 0:
            return {
                'found': True,
                'count': count,
                'data': results,
                'type': 'intelx_records'
            }
        return {'found': False, 'count': 0}
    
    def _intelx_domain_search(self, domain: str):
        """Query Intelligence X for domain"""
        results, count = search_domain_intelx(domain)
        
        if count and count > 0:
            return {
                'found': True,
                'count': count,
                'data': results,
                'type': 'intelx_records'
            }
        return {'found': False, 'count': 0}
    
    def _intelx_keyword_search(self, keyword: str):
        """Query Intelligence X for keyword"""
        results, count = search_keyword_intelx(keyword)

        if count and count > 0:
            return {
                'found': True,
                'count': count,
                'data': results,
                'type': 'intelx_records'
            }
        return {'found': False, 'count': 0}

    def _check_pwned_password(self, password: str):
        """Query Have I Been Pwned Passwords API"""
        breach_count = check_password_pwned(password)

        # Handle API failure (None returned)
        if breach_count is None:
            return {
                'found': False,
                'count': 0,
                'error': 'API unavailable',
                'type': 'breach_count'
            }

        # Password found in breaches
        if breach_count > 0:
            return {
                'found': True,
                'count': breach_count,
                'data': {
                    'breach_count': breach_count,
                    'severity': self._assess_password_severity(breach_count)
                },
                'type': 'breach_count'
            }

        # Password not found (safe)
        return {
            'found': True,
            'count': 0,
            'data': {
                'breach_count': 0,
                'severity': 'safe'
            },
            'type': 'breach_count'
        }

    def _assess_password_severity(self, count: int) -> str:
        """Assess password breach severity based on count"""
        if count == 0:
            return 'safe'
        elif count < 10:
            return 'low'
        elif count < 100:
            return 'medium'
        elif count < 1000:
            return 'high'
        elif count < 10000:
            return 'very_high'
        else:
            return 'critical'

    def _search_github_data(self, query: str, query_type: str):
        """Query GitHub findings database"""
        db = get_db()

        try:
            # Query based on query_term and query_type
            findings = db.query(GitHubFinding).filter(
                GitHubFinding.query_term.like(f'%{query}%'),
                GitHubFinding.query_type == query_type
            ).all()

            if findings:
                # Structure data to match expected format
                structured_data = []
                for finding in findings:
                    structured_data.append({
                        'source': 'GitHub',
                        'url': finding.gist_url,
                        'filename': finding.filename,
                        'credential_type': finding.credential_type,
                        'credential_value': finding.credential_value,
                        'date': finding.created_at.isoformat() if finding.created_at else 'Unknown',
                        'context': finding.context[:500] if finding.context else '',
                        'discovered_at': finding.discovered_at.isoformat() if finding.discovered_at else 'Unknown'
                    })

                db.close()
                return {
                    'found': True,
                    'count': len(findings),
                    'data': structured_data,
                    'type': 'github_exposure'
                }

            db.close()
            return {'found': False, 'count': 0}

        except Exception as e:
            print(f"[ERROR] GitHub search failed: {e}")
            db.close()
            return {'found': False, 'count': 0, 'error': str(e)}

    def _search_pastebin_data(self, query: str, query_type: str):
        """Query PasteBin findings database"""
        db = get_db()

        try:
            # Query based on query_term and query_type
            findings = db.query(PasteBinFinding).filter(
                PasteBinFinding.query_term.like(f'%{query}%'),
                PasteBinFinding.query_type == query_type
            ).all()

            if findings:
                # Structure data to match expected format
                structured_data = []
                for finding in findings:
                    structured_data.append({
                        'source': 'PasteBin',
                        'url': finding.paste_url,
                        'title': finding.paste_title,
                        'credential_value': finding.credential_password if finding.credential_password else '',
                        'date': finding.posted_date if finding.posted_date else 'Unknown',
                        'context': finding.context[:500] if finding.context else '',
                        'discovered_at': finding.discovered_at.isoformat() if finding.discovered_at else 'Unknown'
                    })

                db.close()
                return {
                    'found': True,
                    'count': len(findings),
                    'data': structured_data,
                    'type': 'paste_exposure'
                }

            db.close()
            return {'found': False, 'count': 0}

        except Exception as e:
            print(f"[ERROR] PasteBin search failed: {e}")
            db.close()
            return {'found': False, 'count': 0, 'error': str(e)}

    def _query_source(self, source_name: str, query_func):
        """
        Execute query against a source with error handling
        """
        print(f"Querying {source_name}...", end=' ')
        
        try:
            result = query_func()
            
            if result and result.get('found'):
                print(f"✓ Found {result['count']} results")
                self.results['sources'][source_name] = result
                self.results['total_findings'] += result['count']
            else:
                print("✗ No results")
                self.results['sources'][source_name] = {'found': False, 'count': 0}
        
        except Exception as e:
            print(f"✗ Error: {str(e)}")
            self.results['errors'].append({
                'source': source_name,
                'error': str(e)
            })
            self.results['sources'][source_name] = {'found': False, 'error': str(e)}


# Test the unified search
if __name__ == "__main__":
    searcher = UnifiedSearch()
    
    test_queries = [
        "test@adobe.com",  # Email
        "example.com",     # Domain
        "john_doe123",     # Username
        "192.168.1.1",     # IP
    ]
    
    for query in test_queries:
        result = searcher.search(query)
        
        print(f"\n{'='*60}")
        print(f"RESULTS SUMMARY")
        print(f"{'='*60}")
        print(f"Query: {result['query']}")
        print(f"Type: {result['query_type']}")
        print(f"Total findings: {result['total_findings']}")
        print(f"Sources queried: {len(result['sources_queried'])}")
        print(f"Time: {result['elapsed_seconds']}s")
        
        if result['total_findings'] > 0:
            print(f"\nFindings by source:")
            for source, data in result['results'].items():
                if data.get('found'):
                    print(f"  - {source}: {data['count']} results")
        
        if result['errors']:
            print(f"\nErrors:")
            for error in result['errors']:
                print(f"  - {error['source']}: {error['error']}")
        
        print("\n")