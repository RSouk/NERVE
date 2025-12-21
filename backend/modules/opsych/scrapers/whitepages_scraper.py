"""
Whitepages Scraper - Extract public directory information
Handles reverse phone lookup, name search, and filtered searches
"""

import requests
from bs4 import BeautifulSoup
import re
import time
from urllib.parse import quote_plus


def scrape_whitepages(name=None, phone=None, location=None, age=None):
    """
    Scrape Whitepages for person information
    Returns all matches with confidence scores

    Args:
        name: Full name to search
        phone: Phone number (reverse lookup)
        location: City, State or Zip code
        age: Age or age range (e.g., "35" or "30-40")

    Returns:
        {
            'matches': [list of potential matches],
            'total_matches': int,
            'query_type': str,
            'confidence_method': str
        }
    """

    results = {
        'matches': [],
        'total_matches': 0,
        'query_type': '',
        'confidence_method': '',
        'source': 'whitepages'
    }

    try:
        # === REVERSE PHONE LOOKUP ===
        if phone:
            results['query_type'] = 'reverse_phone'
            matches = _reverse_phone_lookup(phone)

            for match in matches:
                match['confidence_score'] = 70  # Base score for phone match
                if location and location.lower() in match.get('location', '').lower():
                    match['confidence_score'] += 20
                if age and _age_matches(age, match.get('age')):
                    match['confidence_score'] += 10

                results['matches'].append(match)

            results['total_matches'] = len(results['matches'])
            return results

        # === NAME SEARCH ===
        if name:
            results['query_type'] = 'name_search'

            # If we have location, do filtered search
            if location:
                results['query_type'] = 'name_location_search'
                matches = _name_location_search(name, location)
            else:
                matches = _name_search(name)

            # Apply filters and confidence scoring
            for match in matches:
                base_score = 20  # Low base for name only

                # Location match bonus
                if location and location.lower() in match.get('location', '').lower():
                    base_score += 50

                # Age match bonus
                if age and _age_matches(age, match.get('age')):
                    base_score += 30

                # Phone match bonus (if we're given a phone to verify)
                if phone and phone in match.get('phones', []):
                    base_score += 70

                match['confidence_score'] = min(base_score, 100)
                results['matches'].append(match)

            # Sort by confidence
            results['matches'] = sorted(results['matches'],
                                       key=lambda x: x['confidence_score'],
                                       reverse=True)

            results['total_matches'] = len(results['matches'])
            return results

    except Exception as e:
        results['error'] = str(e)
        return results

    return results


def _reverse_phone_lookup(phone):
    """
    Reverse phone lookup - find person by phone number
    NOTE: This is a placeholder implementation
    Real implementation would use Whitepages API or web scraping
    """

    # Clean phone number
    clean_phone = re.sub(r'[^0-9]', '', phone)

    # Placeholder data structure
    # In production, this would scrape or API call Whitepages
    matches = []

    # Example structure of what real data would look like
    """
    match = {
        'name': 'John Doe',
        'age': '35',
        'location': 'New York, NY',
        'phones': [clean_phone],
        'addresses': ['123 Main St, New York, NY 10001'],
        'relatives': [
            {'name': 'Jane Doe', 'relationship': 'Possible Relative'},
            {'name': 'Bob Doe', 'relationship': 'Possible Relative'}
        ],
        'carrier': 'Verizon Wireless',
        'line_type': 'Mobile'
    }
    matches.append(match)
    """

    # For demo purposes, return empty (would be populated by real scraper)
    return matches


def _name_search(name):
    """
    Search Whitepages by name only
    Returns multiple potential matches
    """

    matches = []

    # Placeholder for actual scraping implementation
    # Real implementation would:
    # 1. Query Whitepages search
    # 2. Parse result pages
    # 3. Extract person records
    # 4. Return structured data

    return matches


def _name_location_search(name, location):
    """
    Search Whitepages by name with location filter
    More accurate than name-only search
    """

    matches = []

    # Placeholder for actual scraping implementation
    # Real implementation would:
    # 1. Build filtered query URL
    # 2. Query Whitepages with location filter
    # 3. Parse results
    # 4. Extract and structure data

    # Example of what a real match would look like:
    """
    match = {
        'name': name,
        'age': '35',
        'location': location,
        'phones': ['+1-555-123-4567'],
        'addresses': ['123 Main St, New York, NY 10001'],
        'relatives': [
            {'name': 'Jane Doe', 'age': '33', 'relationship': 'Possible Relative'},
            {'name': 'Bob Doe', 'age': '65', 'relationship': 'Possible Relative'}
        ],
        'associates': [
            {'name': 'Alice Smith', 'relationship': 'Neighbor/Associate'}
        ]
    }
    matches.append(match)
    """

    return matches


def _age_matches(search_age, actual_age):
    """
    Check if age matches search criteria
    Handles single age or range (e.g., "35" or "30-40")
    """

    if not actual_age:
        return False

    try:
        # Extract numeric age from string
        actual_age_num = int(re.search(r'\d+', str(actual_age)).group())

        # Check if search_age is a range
        if '-' in str(search_age):
            min_age, max_age = map(int, search_age.split('-'))
            return min_age <= actual_age_num <= max_age
        else:
            # Single age with tolerance of +/- 2 years
            target_age = int(search_age)
            return abs(actual_age_num - target_age) <= 2

    except:
        return False


def get_property_records(name, location):
    """
    Search public property records
    Returns property ownership information
    """

    records = {
        'properties': [],
        'total_found': 0,
        'source': 'property_records'
    }

    # Placeholder for property record scraping
    # Real implementation would query:
    # - County assessor databases
    # - Property deed records
    # - Tax records

    return records


def get_voter_records(name, location, age=None):
    """
    Search public voter registration records
    Returns voter registration information
    """

    records = {
        'registrations': [],
        'total_found': 0,
        'source': 'voter_records'
    }

    # Placeholder for voter record lookup
    # Real implementation would query:
    # - State voter registration databases
    # - Public voter file data
    # - Cross-reference with age/location

    return records


# Example helper function for building Whitepages URLs
def _build_whitepages_url(name=None, location=None, phone=None):
    """Build Whitepages search URL based on parameters"""

    base_url = "https://www.whitepages.com"

    if phone:
        clean_phone = re.sub(r'[^0-9]', '', phone)
        return f"{base_url}/phone/{clean_phone}"

    if name and location:
        encoded_name = quote_plus(name)
        encoded_location = quote_plus(location)
        return f"{base_url}/name/{encoded_name}/{encoded_location}"

    if name:
        encoded_name = quote_plus(name)
        return f"{base_url}/name/{encoded_name}"

    return None
