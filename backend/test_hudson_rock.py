#!/usr/bin/env python3
"""
Test Hudson Rock Cavalier API (FREE)
Test email: danieljohnwild@gmail.com
"""

import sys
sys.path.insert(0, '.')

from modules.ghost.hudson_rock import search_by_email, search_by_domain

print("=" * 60)
print("Testing Hudson Rock FREE Cavalier API")
print("=" * 60)

# Test 1: Email Search
print("\n[TEST 1] Searching email: danieljohnwild@gmail.com")
print("-" * 60)
result, count = search_by_email("danieljohnwild@gmail.com")

if count and count > 0:
    print(f"\n[SUCCESS] Found {count} stealer logs")
    print(f"\nResponse structure:")
    if isinstance(result, dict):
        print(f"  - Message: {result.get('message', 'N/A')[:100]}...")
        print(f"  - Total Corporate Services: {result.get('total_corporate_services', 0)}")
        print(f"  - Total User Services: {result.get('total_user_services', 0)}")
        print(f"  - Stealers count: {len(result.get('stealers', []))}")

        if result.get('stealers'):
            first = result['stealers'][0]
            print(f"\n  First stealer log sample:")
            print(f"    - Malware Path: {first.get('malware_path', 'N/A')}")
            print(f"    - Computer: {first.get('computer_name', 'N/A')}")
            print(f"    - OS: {first.get('operating_system', 'N/A')}")
            print(f"    - IP: {first.get('ip', 'N/A')}")
            print(f"    - Date: {first.get('date_compromised', 'N/A')}")
            print(f"    - Credentials: {len(first.get('credentials', []))} found")

            if first.get('credentials'):
                cred = first['credentials'][0]
                print(f"\n  First credential sample:")
                print(f"    - Domain: {cred.get('domain', 'N/A')}")
                print(f"    - URL: {cred.get('url', 'N/A')}")
                print(f"    - Username: {cred.get('username', 'N/A')}")
                print(f"    - Password: {'*' * len(cred.get('password', ''))}")
elif count == 0:
    print("\n[INFO] API responded but no results found")
else:
    print(f"\n[FAILED] Error code {count}")

# Test 2: Domain Search
print("\n\n[TEST 2] Searching domain: gmail.com")
print("-" * 60)
result2, count2 = search_by_domain("gmail.com")

if count2 and count2 > 0:
    print(f"\n[SUCCESS] Found {count2} domain exposures")
elif count2 == 0:
    print("\n[INFO] API responded but no results found")
else:
    print(f"\n[FAILED] Error code {count2}")

print("\n" + "=" * 60)
print("Tests completed!")
print("=" * 60)
