import requests
import os

# FREE Cavalier API - No API key needed!
HUDSON_ROCK_BASE = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"

def search_by_email(email):
    """Search Hudson Rock by email using FREE Cavalier API"""
    url = f"{HUDSON_ROCK_BASE}/search-by-email?email={email}"
    headers = {
        "accept": "application/json"
    }

    try:
        print(f"Hudson Rock (Cavalier): Searching email {email}...")
        response = requests.get(url, headers=headers, timeout=30)

        print(f"Hudson Rock: Status {response.status_code}")

        if response.status_code == 200:
            data = response.json()

            # Cavalier API uses 'stealers' array instead of 'data'
            if isinstance(data, dict):
                message = data.get('message', '')
                stealers = data.get('stealers', [])
                count = len(stealers)

                print(f"Hudson Rock: {message}")
                print(f"Hudson Rock: Found {count} stealer logs")

                # Return in compatible format
                return {
                    'stealers': stealers,
                    'message': message,
                    'total_corporate_services': data.get('total_corporate_services', 0),
                    'total_user_services': data.get('total_user_services', 0)
                }, count
            else:
                print("Hudson Rock: No results")
                return [], 0

        elif response.status_code == 404:
            print("Hudson Rock: No results found (404)")
            return [], 0

        elif response.status_code == 429:
            print("Hudson Rock: Rate limited")
            return None, -1

        else:
            print(f"Hudson Rock: Error {response.status_code}")
            print(f"Response: {response.text[:300]}")
            return None, -2

    except Exception as e:
        print(f"Hudson Rock error: {e}")
        return None, -3

def search_by_domain(domain):
    """Search Hudson Rock by domain using FREE Cavalier API"""
    url = f"{HUDSON_ROCK_BASE}/search-by-domain?domain={domain}"
    headers = {
        "accept": "application/json"
    }

    try:
        print(f"Hudson Rock (Cavalier): Searching domain {domain}...")
        response = requests.get(url, headers=headers, timeout=20)

        print(f"Hudson Rock: Status {response.status_code}")

        if response.status_code == 200:
            data = response.json()

            # Cavalier API uses 'stealers' array instead of 'data'
            if isinstance(data, dict):
                message = data.get('message', '')
                stealers = data.get('stealers', [])
                count = len(stealers)

                print(f"Hudson Rock: {message}")
                print(f"Hudson Rock: Found {count} domain exposures")

                # Return in compatible format
                return {
                    'stealers': stealers,
                    'message': message,
                    'total_corporate_services': data.get('total_corporate_services', 0),
                    'total_user_services': data.get('total_user_services', 0)
                }, count

            print("Hudson Rock: No domain results")
            return [], 0

        elif response.status_code == 404:
            print("Hudson Rock: Domain not found")
            return [], 0

        else:
            print(f"Hudson Rock: Error {response.status_code}")
            print(f"Response: {response.text[:300]}")
            return None, -2

    except Exception as e:
        print(f"Hudson Rock domain search error: {e}")
        return None, -3

def search_by_password(password):
    """Search Hudson Rock by password - NOT AVAILABLE IN FREE API"""
    print(f"Hudson Rock: Password search not available in free Cavalier API")
    return [], 0

def search_by_username(username):
    """Search Hudson Rock by username - NOT AVAILABLE IN FREE API"""
    print(f"Hudson Rock: Username search not available in free Cavalier API")
    print(f"Hudson Rock: Use email search instead")
    return [], 0

def search_by_ip(ip):
    """Search Hudson Rock by IP address - NOT AVAILABLE IN FREE API"""
    print(f"Hudson Rock: IP search not available in free Cavalier API")
    return [], 0

def search_by_keyword(keyword):
    """Search Hudson Rock by keyword - NOT AVAILABLE IN FREE API"""
    print(f"Hudson Rock: Keyword search not available in free Cavalier API")
    print(f"Hudson Rock: Use email or domain search instead")
    return [], 0