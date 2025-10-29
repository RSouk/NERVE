import re
import ipaddress
from typing import Dict, List, Tuple

def detect_search_type(query: str) -> str:
    """
    Detect what type of search query this is
    Returns: 'email', 'domain', 'ip', 'cidr', 'username', 'password', 'keyword'
    """
    query = query.strip()
    
    # Email detection (has @ and valid domain)
    if '@' in query:
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if re.match(email_pattern, query):
            return 'email'
    
    # IP address detection
    try:
        ipaddress.ip_address(query)
        return 'ip'
    except ValueError:
        pass
    
    # CIDR notation detection
    try:
        ipaddress.ip_network(query, strict=False)
        return 'cidr'
    except ValueError:
        pass
    
    # Domain detection (has dot, no @, looks like domain)
    if '.' in query and '@' not in query:
        domain_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}$'
        if re.match(domain_pattern, query):
            return 'domain'
    
    # Password detection (common password patterns, length checks)
    # If it has special chars, numbers, and is 6-30 chars, likely password
    if 6 <= len(query) <= 30:
        has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', query))
        has_number = bool(re.search(r'\d', query))
        if has_special or has_number:
            return 'password'
    
    # Username detection (alphanumeric, underscores, dashes, 3-30 chars)
    if 3 <= len(query) <= 30:
        username_pattern = r'^[a-zA-Z0-9_-]+$'
        if re.match(username_pattern, query):
            return 'username'
    
    # Default to keyword search
    return 'keyword'

def get_applicable_sources(search_type: str) -> List[str]:
    """
    Return list of data sources that support this search type
    """
    source_capabilities = {
        'email': [
            'hudson_rock',
            'leakcheck',
            'breachdirectory',
            'intelligence_x',
            'local_files',
            'github',
            'pastebin'
        ],
        'domain': [
            'hudson_rock',
            'breachdirectory',
            'intelligence_x',
            'urlscan',
            'certificate_transparency',
            'github',
            'pastebin'
        ],
        'ip': [
            'hudson_rock',
            'feodo_tracker',
            'criminalip',
            'shodan'
        ],
        'cidr': [
            'hudson_rock',
            'shodan'
        ],
        'username': [
            'hudson_rock',
            'intelligence_x',
            'local_files',
            'sherlock',
            'github',
            'pastebin'
        ],
        'password': [
            'hudson_rock',
            'local_files',
            'github',
            'pastebin'
        ],
        'keyword': [
            'hudson_rock',
            'intelligence_x',
            'pastebin',
            'github'
        ]
    }
    
    return source_capabilities.get(search_type, [])

def validate_query(query: str, search_type: str) -> Tuple[bool, str]:
    """
    Validate if query is acceptable for the detected type
    Returns: (is_valid, error_message)
    """
    if not query or len(query.strip()) == 0:
        return False, "Query cannot be empty"
    
    if len(query) > 500:
        return False, "Query too long (max 500 characters)"
    
    # Type-specific validation
    if search_type == 'email':
        if '@' not in query:
            return False, "Invalid email format"
        parts = query.split('@')
        if len(parts) != 2 or not parts[0] or not parts[1]:
            return False, "Invalid email format"
    
    elif search_type == 'domain':
        if not '.' in query:
            return False, "Invalid domain format"
        if query.startswith('.') or query.endswith('.'):
            return False, "Invalid domain format"
    
    elif search_type == 'ip':
        try:
            ipaddress.ip_address(query)
        except ValueError:
            return False, "Invalid IP address"
    
    elif search_type == 'password':
        if len(query) < 4:
            return False, "Password too short to search (min 4 characters)"
    
    elif search_type == 'username':
        if len(query) < 3:
            return False, "Username too short (min 3 characters)"
    
    return True, ""

def analyze_query(query: str) -> Dict:
    """
    Complete analysis of search query
    Returns dict with type, sources, validation, etc.
    """
    search_type = detect_search_type(query)
    applicable_sources = get_applicable_sources(search_type)
    is_valid, error = validate_query(query, search_type)
    
    return {
        'query': query,
        'type': search_type,
        'sources': applicable_sources,
        'valid': is_valid,
        'error': error if not is_valid else None,
        'source_count': len(applicable_sources)
    }

# Test function
if __name__ == "__main__":
    test_queries = [
        "test@example.com",
        "example.com",
        "192.168.1.1",
        "john_doe123",
        "Password123!",
        "malware analysis",
        "192.168.1.0/24"
    ]
    
    print("Search Type Detection Test\n" + "="*60)
    
    for query in test_queries:
        analysis = analyze_query(query)
        print(f"\nQuery: {query}")
        print(f"Type: {analysis['type']}")
        print(f"Valid: {analysis['valid']}")
        print(f"Sources: {', '.join(analysis['sources'][:3])}{'...' if len(analysis['sources']) > 3 else ''}")
        if analysis['error']:
            print(f"Error: {analysis['error']}")