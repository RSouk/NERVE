import requests
import os
from dotenv import load_dotenv

load_dotenv()

HUDSON_ROCK_API_KEY = os.getenv('HUDSON_ROCK_API_KEY', 'MdBmjE4lF1_2YHD3PZL2W0XXhn.VtNTYQfJ3wClmCxx9cChelzXBJaP1JkfxmRQA')
HUDSON_ROCK_BASE = "https://api.hudsonrock.com/json/v3"

def search_by_email(email):
    """Search Hudson Rock by email"""
    url = f"{HUDSON_ROCK_BASE}/search-by-login/emails"
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "api-key": HUDSON_ROCK_API_KEY
    }
    
    # Hudson Rock expects an array of emails in "logins" field
    payload = {
        "logins": [email],
        "sort_by": "date_compromised",
        "sort_direction": "desc",
        "filter_credentials": True
    }
    
    try:
        print(f"Hudson Rock: Searching email {email}...")
        response = requests.post(url, headers=headers, json=payload, timeout=30)
        
        print(f"Hudson Rock: Status {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"Hudson Rock: Response received: {str(data)[:200]}")
            
            # Response format: {"data": [...], "nextCursor": "..."}
            if isinstance(data, dict) and 'data' in data:
                stealers = data['data']
                count = len(stealers)
                print(f"Hudson Rock: Found {count} stealer logs")
                return stealers, count
            elif isinstance(data, list):
                count = len(data)
                print(f"Hudson Rock: Found {count} stealer logs")
                return data, count
            else:
                print("Hudson Rock: No results")
                return [], 0
        
        elif response.status_code == 404:
            print("Hudson Rock: No results found (404)")
            return [], 0
        
        elif response.status_code == 401:
            print("Hudson Rock: Invalid API key")
            return None, -4
        
        elif response.status_code == 403:
            print("Hudson Rock: Forbidden - insufficient permissions")
            return None, -4
        
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
    """Search Hudson Rock by domain"""
    url = f"{HUDSON_ROCK_BASE}/search-by-domain"
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "api-key": HUDSON_ROCK_API_KEY
    }
    
    payload = {"domain": domain}
    
    try:
        print(f"Hudson Rock: Searching domain {domain}...")
        response = requests.post(url, headers=headers, json=payload, timeout=20)
        
        print(f"Hudson Rock: Status {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            
            if isinstance(data, dict):
                results = data.get('stealers', data.get('results', []))
                if isinstance(results, list):
                    count = len(results)
                    print(f"Hudson Rock: Found {count} domain exposures")
                    return results, count
            elif isinstance(data, list):
                count = len(data)
                print(f"Hudson Rock: Found {count} domain exposures")
                return data, count
            
            print("Hudson Rock: No domain results")
            return [], 0
        
        elif response.status_code == 404:
            print("Hudson Rock: Domain not found")
            return [], 0
        
        else:
            print(f"Hudson Rock: Error {response.status_code}")
            return None, -2
            
    except Exception as e:
        print(f"Hudson Rock domain search error: {e}")
        return None, -3

def search_by_password(password):
    """Search Hudson Rock by password"""
    url = f"{HUDSON_ROCK_BASE}/search-by-password"
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "api-key": HUDSON_ROCK_API_KEY
    }
    
    payload = {"password": password}
    
    try:
        print(f"Hudson Rock: Searching password...")
        response = requests.post(url, headers=headers, json=payload, timeout=20)
        
        print(f"Hudson Rock: Status {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            
            if isinstance(data, dict):
                results = data.get('stealers', data.get('results', []))
                if isinstance(results, list):
                    count = len(results)
                    print(f"Hudson Rock: Password found in {count} stealer logs")
                    return results, count
            elif isinstance(data, list):
                count = len(data)
                print(f"Hudson Rock: Password found in {count} stealer logs")
                return data, count
            
            print("Hudson Rock: Password not found")
            return [], 0
        
        elif response.status_code == 404:
            print("Hudson Rock: Password not found")
            return [], 0
        
        else:
            print(f"Hudson Rock: Error {response.status_code}")
            return None, -2
            
    except Exception as e:
        print(f"Hudson Rock password search error: {e}")
        return None, -3