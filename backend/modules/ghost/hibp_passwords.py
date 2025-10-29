"""
Have I Been Pwned Passwords API Integration
Uses k-anonymity model to check if passwords have been breached
"""

import hashlib
import requests
from typing import Optional

# Simple in-memory cache to avoid repeat lookups
_password_cache = {}

def check_password_pwned(password: str) -> Optional[int]:
    """
    Check if a password has been pwned using the HIBP Passwords API

    Uses k-anonymity model:
    1. Hash password with SHA-1
    2. Send first 5 chars to API
    3. Search for full hash in response
    4. Return breach count

    Args:
        password: Plaintext password to check

    Returns:
        int: Number of times password appears in breaches (0 if not found)
        None: If API call fails or error occurs

    Example:
        >>> check_password_pwned("password123")
        2851877
        >>> check_password_pwned("super_unique_pass_12345")
        0
    """

    # Handle empty password
    if not password or not password.strip():
        print("HIBP: Empty password provided")
        return 0

    # Check cache first
    if password in _password_cache:
        print(f"HIBP: Cache hit for password")
        return _password_cache[password]

    try:
        # Step 1: Hash password with SHA-1
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()

        # Step 2: Extract first 5 chars and suffix
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        print(f"HIBP: Checking password (hash prefix: {prefix})")

        # Step 3: Call HIBP API with k-anonymity model
        url = f"https://api.pwnedpasswords.com/range/{prefix}"

        response = requests.get(
            url,
            timeout=2,
            headers={'User-Agent': 'NERVE-GHOST-Security-Tool'}
        )

        # Check if request was successful
        if response.status_code != 200:
            print(f"HIBP: API returned status {response.status_code}")
            return None

        # Step 4: Parse response and find matching hash
        # Response format: SUFFIX:COUNT\r\n for each hash
        response_text = response.text

        for line in response_text.splitlines():
            if ':' not in line:
                continue

            hash_suffix, count_str = line.split(':', 1)

            # Case-insensitive comparison
            if hash_suffix.upper() == suffix:
                breach_count = int(count_str)
                print(f"HIBP: [FOUND] Password found in {breach_count} breaches")

                # Cache the result
                _password_cache[password] = breach_count

                return breach_count

        # Password not found in breaches
        print(f"HIBP: [SAFE] Password not found in breaches")
        _password_cache[password] = 0
        return 0

    except requests.exceptions.Timeout:
        print("HIBP: [ERROR] API timeout (2 seconds)")
        return None

    except requests.exceptions.RequestException as e:
        print(f"HIBP: [ERROR] API request failed: {str(e)}")
        return None

    except ValueError as e:
        print(f"HIBP: [ERROR] Failed to parse breach count: {str(e)}")
        return None

    except Exception as e:
        print(f"HIBP: [ERROR] Unexpected error: {str(e)}")
        return None


def clear_cache():
    """Clear the password cache (useful for testing)"""
    global _password_cache
    _password_cache = {}
    print("HIBP: Cache cleared")


# Test the module
if __name__ == "__main__":
    test_passwords = [
        "password",      # Very common
        "test",          # Common
        "Password123!",  # Common pattern
        "super_unique_password_that_probably_doesnt_exist_98765"  # Should be safe
    ]

    print("Testing Have I Been Pwned Passwords API\n")
    print("=" * 60)

    for pwd in test_passwords:
        print(f"\nChecking: '{pwd}'")
        count = check_password_pwned(pwd)

        if count is None:
            print("[X] API check failed")
        elif count == 0:
            print("[OK] Password is safe (not found in breaches)")
        else:
            print(f"[WARNING] Password has been pwned {count:,} times")

    print("\n" + "=" * 60)
