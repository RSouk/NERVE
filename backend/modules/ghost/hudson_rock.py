import requests
import os
from dotenv import load_dotenv

load_dotenv()

HUDSON_ROCK_API_KEY = os.getenv('HUDSON_ROCK_API_KEY')
HUDSON_ROCK_BASE = "https://api.hudsonrock.com/json/v3"

def search_by_email(email):
    """Search Hudson Rock by email"""
    url = f"{HUDSON_ROCK_BASE}/search-by-login/emails"
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "api-key": HUDSON_ROCK_API_KEY
    }
    
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
            
            if isinstance(data, dict) and 'data' in data:
                stealers = data['data']
                count = len(stealers)
                print(f"Hudson Rock: Found {count} stealer logs")
                return data, count
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
    """Search Hudson Rock by domain - FIXED FORMAT"""
    url = f"{HUDSON_ROCK_BASE}/search-by-domain"
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "api-key": HUDSON_ROCK_API_KEY
    }
    
    # FIXED: API expects "domains" array, not "domain" string
    payload = {
        "domains": [domain],
        "sort_by": "date_compromised",
        "sort_direction": "desc"
    }
    
    try:
        print(f"Hudson Rock: Searching domain {domain}...")
        response = requests.post(url, headers=headers, json=payload, timeout=20)
        
        print(f"Hudson Rock: Status {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            
            if isinstance(data, dict) and 'data' in data:
                results = data['data']
                count = len(results)
                print(f"Hudson Rock: Found {count} domain exposures")
                return data, count
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
            print(f"Response: {response.text[:300]}")
            return None, -2
            
    except Exception as e:
        print(f"Hudson Rock domain search error: {e}")
        return None, -3

def search_by_password(password):
    """Search Hudson Rock by password - REQUIRES PAID TIER"""
    print(f"Hudson Rock: Password search requires paid API tier")
    return [], 0  # Skip this search type for now

def search_by_username(username):
    """Search Hudson Rock by username"""
    url = f"{HUDSON_ROCK_BASE}/search-by-login/usernames"
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "api-key": HUDSON_ROCK_API_KEY
    }
    
    payload = {
        "logins": [username],
        "sort_by": "date_compromised",
        "sort_direction": "desc",
        "filter_credentials": True
    }
    
    try:
        print(f"Hudson Rock: Searching username {username}...")
        response = requests.post(url, headers=headers, json=payload, timeout=20)
        
        print(f"Hudson Rock: Status {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            
            if isinstance(data, dict) and 'data' in data:
                results = data['data']
                count = len(results)
                print(f"Hudson Rock: Found {count} results for username")
                return data, count
            elif isinstance(data, list):
                count = len(data)
                print(f"Hudson Rock: Found {count} results for username")
                return data, count
            
            print("Hudson Rock: Username not found")
            return [], 0
        
        elif response.status_code == 404:
            print("Hudson Rock: Username not found")
            return [], 0
        
        else:
            print(f"Hudson Rock: Error {response.status_code}")
            return None, -2
            
    except Exception as e:
        print(f"Hudson Rock username search error: {e}")
        return None, -3

def search_by_ip(ip):
    """Search Hudson Rock by IP address - FIXED FORMAT"""
    url = f"{HUDSON_ROCK_BASE}/search-by-ip"
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "api-key": HUDSON_ROCK_API_KEY
    }
    
    # FIXED: API expects "ips" array
    payload = {
        "ips": [ip],
        "sort_by": "date_compromised",
        "sort_direction": "desc",
        "filter_credentials": True
    }
    
    try:
        print(f"Hudson Rock: Searching IP {ip}...")
        response = requests.post(url, headers=headers, json=payload, timeout=20)
        
        print(f"Hudson Rock: Status {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            
            if isinstance(data, dict) and 'data' in data:
                results = data['data']
                count = len(results)
                print(f"Hudson Rock: Found {count} machines on IP")
                return data, count
            elif isinstance(data, list):
                count = len(data)
                print(f"Hudson Rock: Found {count} machines on IP")
                return data, count
            
            print("Hudson Rock: No machines found on IP")
            return [], 0
        
        elif response.status_code == 404:
            print("Hudson Rock: IP not found")
            return [], 0
        
        else:
            print(f"Hudson Rock: Error {response.status_code}")
            print(f"Response: {response.text[:300]}")
            return None, -2
            
    except Exception as e:
        print(f"Hudson Rock IP search error: {e}")
        return None, -3

def search_by_keyword(keyword):
    """Search Hudson Rock by keyword"""
    url = f"{HUDSON_ROCK_BASE}/search"
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "api-key": HUDSON_ROCK_API_KEY
    }
    
    payload = {
        "query": keyword,
        "sort_by": "date_compromised",
        "sort_direction": "desc"
    }
    
    try:
        print(f"Hudson Rock: Searching keyword '{keyword}'...")
        response = requests.post(url, headers=headers, json=payload, timeout=20)
        
        print(f"Hudson Rock: Status {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            
            if isinstance(data, dict) and 'data' in data:
                results = data['data']
                count = len(results)
                print(f"Hudson Rock: Found {count} results for keyword")
                return data, count
            elif isinstance(data, list):
                count = len(data)
                print(f"Hudson Rock: Found {count} results for keyword")
                return data, count
            
            print("Hudson Rock: No results for keyword")
            return [], 0
        
        elif response.status_code == 404:
            print("Hudson Rock: No results for keyword")
            return [], 0
        
        else:
            print(f"Hudson Rock: Error {response.status_code}")
            return None, -2
            
    except Exception as e:
        print(f"Hudson Rock keyword search error: {e}")
        return None, -3