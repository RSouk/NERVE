import time
from typing import Dict, List
from search_engine import analyze_query
from hudson_rock import search_by_email, search_by_domain, search_by_password
from api_breaches import check_leakcheck_api, check_breachdirectory_api
from breach_checker import check_local_breaches
from datetime import datetime

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
        elif self.query_type == 'ip':
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
        
        # Hudson Rock
        self._query_source('hudson_rock', lambda: self._hudson_rock_email(email))
        
        # LeakCheck
        self._query_source('leakcheck', lambda: self._leakcheck_search(email))
        
        # BreachDirectory
        self._query_source('breachdirectory', lambda: self._breachdirectory_search(email))
        
        # Local files
        self._query_source('local_files', lambda: self._local_search(email))
        
        # TODO: Intelligence X
        # self._query_source('intelligence_x', lambda: self._intelx_search(email))
    
    def _search_domain(self, domain: str):
        """Search all domain-capable sources"""
        print("🔍 Searching domain across sources...\n")
        
        # Hudson Rock domain search
        self._query_source('hudson_rock', lambda: self._hudson_rock_domain(domain))
        
        # TODO: Intelligence X, URLScan, etc.
    
    def _search_password(self, password: str):
        """Search password across sources"""
        print("🔍 Searching password across sources...\n")
        
        # Hudson Rock password search
        self._query_source('hudson_rock', lambda: self._hudson_rock_password(password))
        
        # Local files
        # TODO: Implement password search in local files
    
    def _search_username(self, username: str):
        """Search username across sources"""
        print("🔍 Searching username across sources...\n")
        
        # Hudson Rock
        # TODO: Hudson Rock username search
        
        # Local files
        # TODO: Username search in local files
    
    def _search_ip(self, ip: str):
        """Search IP address across sources"""
        print("🔍 Searching IP across sources...\n")
        
        # Hudson Rock
        # TODO: Hudson Rock IP search
        
        # Feodo Tracker
        # TODO: Botnet C2 check
    
    def _search_keyword(self, keyword: str):
        """Search keyword across sources"""
        print("🔍 Searching keyword across sources...\n")
        
        # Hudson Rock
        # TODO: Hudson Rock keyword search
        
        # Intelligence X
        # TODO: Intelligence X search
    
    def _search_generic(self, query: str):
        """Generic search when type is unclear"""
        print("🔍 Generic search...\n")
        # Try multiple types
        pass
    
    # Source-specific query methods
    
    def _hudson_rock_email(self, email: str):
        """Query Hudson Rock for email"""
        data, count = search_by_email(email)
        
        if count > 0:
            return {
                'found': True,
                'count': count,
                'data': data,
                'type': 'infostealer_logs'
            }
        return {'found': False, 'count': 0}
    
    def _hudson_rock_domain(self, domain: str):
        """Query Hudson Rock for domain"""
        data = search_by_domain(domain)
        
        if data:
            return {
                'found': True,
                'count': len(data) if isinstance(data, list) else 1,
                'data': data,
                'type': 'domain_exposure'
            }
        return {'found': False, 'count': 0}
    
    def _hudson_rock_password(self, password: str):
        """Query Hudson Rock for password"""
        data = search_by_password(password)
        
        if data:
            return {
                'found': True,
                'count': len(data) if isinstance(data, list) else 1,
                'data': data,
                'type': 'password_reuse'
            }
        return {'found': False, 'count': 0}
    
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
    
    def _breachdirectory_search(self, email: str):
        """Query BreachDirectory"""
        breaches, count = check_breachdirectory_api(email)
        
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
        "test@adobe.com",
        "example.com",
        # "Password123!",  # Uncomment if you want to test password search
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