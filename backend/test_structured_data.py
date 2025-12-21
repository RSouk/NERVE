#!/usr/bin/env python3
"""Test Hudson Rock structured data flow"""

import sys
sys.path.insert(0, '.')

from modules.ghost.hudson_rock import search_by_email
from modules.ghost.unified_search import UnifiedSearch

print("=" * 60)
print("Testing Hudson Rock FREE API Data Flow")
print("=" * 60)

# Test 1: Raw API response
print("\n[TEST 1] Raw API Response")
print("-" * 60)
result, count = search_by_email("danieljohnwild@gmail.com")

if count > 0 and isinstance(result, dict):
    stealer = result['stealers'][0]
    print(f"Stealer data from API:")
    print(f"  - malware_path: {stealer.get('malware_path', 'N/A')}")
    print(f"  - total_user_services: {stealer.get('total_user_services', 0)}")
    print(f"  - top_passwords count: {len(stealer.get('top_passwords', []))}")
    print(f"  - top_logins count: {len(stealer.get('top_logins', []))}")
    print(f"  - credentials array: {len(stealer.get('credentials', []))}")

    # Test 2: Structured data
    print("\n[TEST 2] Structured Data (after processing)")
    print("-" * 60)

    searcher = UnifiedSearch()
    structured = searcher._structure_hudson_rock_data(result)

    if structured:
        item = structured[0]
        print(f"Structured item:")
        print(f"  - stealer_family: {item.get('stealer_family', 'N/A')}")
        print(f"  - computer_name: {item.get('computer_name', 'N/A')}")
        print(f"  - total_credentials: {item.get('total_credentials', 0)}")
        print(f"  - sample credentials: {len(item.get('credentials', []))}")

        if item.get('credentials'):
            print(f"\n  First sample credential:")
            cred = item['credentials'][0]
            print(f"    - username: {cred.get('username', 'N/A')}")
            print(f"    - password: {cred.get('password', 'N/A')}")
            print(f"    - domain: {cred.get('domain', 'N/A')}")

print("\n" + "=" * 60)
print("Test completed!")
print("=" * 60)
