import requests
import os
import time
from dotenv import load_dotenv

load_dotenv()

INTELX_API_KEY = os.getenv('INTELX_API_KEY')
print(f"DEBUG: IntelX API Key loaded: {INTELX_API_KEY}")
INTELX_BASE = "https://2.intelx.io"

def search_intelx(query, search_type='email'):
    """
    Search Intelligence X for email, domain, IP, etc.
    Returns: (results, count)
    
    Note: Intelligence X requires a 2-step process:
    1. Initiate search (get search ID)
    2. Poll for results
    """
    
    if not INTELX_API_KEY or INTELX_API_KEY == '':
        print("Intelligence X: No API key configured")
        return None, -4
    
    # Step 1: Initiate search
    search_url = f"{INTELX_BASE}/intelligent/search"
    headers = {
        "x-key": INTELX_API_KEY,
        "Content-Type": "application/json"
    }
    
    payload = {
        "term": query,
        "buckets": [],  # Empty = search all buckets
        "lookuplevel": 0,  # 0 = quick, 1 = deep
        "maxresults": 100,
        "timeout": 5,
        "datefrom": "",
        "dateto": "",
        "sort": 4,  # Sort by date
        "media": 0,  # 0 = no media
        "terminate": []
    }
    
    try:
        print(f"Intelligence X: Initiating search for {query}...")
        response = requests.post(search_url, headers=headers, json=payload, timeout=10)
        
        if response.status_code != 200:
            print(f"Intelligence X: Error {response.status_code}")
            return None, -2
        
        search_data = response.json()
        search_id = search_data.get('id')
        
        if not search_id:
            print("Intelligence X: Failed to get search ID")
            return None, -2
        
        # Step 2: Poll for results
        results_url = f"{INTELX_BASE}/intelligent/search/result"
        results_payload = {
            "id": search_id,
            "limit": 100
        }
        
        # Wait a bit for results to populate
        time.sleep(2)
        
        print(f"Intelligence X: Fetching results...")
        results_response = requests.post(results_url, headers=headers, json=results_payload, timeout=10)
        
        if results_response.status_code != 200:
            print(f"Intelligence X: Error fetching results {results_response.status_code}")
            return None, -2
        
        results_data = results_response.json()
        records = results_data.get('records', [])
        
        count = len(records)
        print(f"Intelligence X: Found {count} records")
        
        # Structure the results
        structured_results = []
        for record in records:
            structured_results.append({
                'name': record.get('name', 'Unknown'),
                'bucket': record.get('bucket', 'Unknown'),
                'date': record.get('date', 'Unknown'),
                'size': record.get('size', 0),
                'media': record.get('media', 0),
                'systemid': record.get('systemid', ''),
                'type': record.get('type', 0)
            })
        
        return structured_results, count
        
    except Exception as e:
        print(f"Intelligence X error: {e}")
        return None, -3

def search_email_intelx(email):
    """Search Intelligence X for email"""
    return search_intelx(email, 'email')

def search_domain_intelx(domain):
    """Search Intelligence X for domain"""
    return search_intelx(domain, 'domain')

def search_ip_intelx(ip):
    """Search Intelligence X for IP"""
    return search_intelx(ip, 'ip')

def search_keyword_intelx(keyword):
    """Search Intelligence X for keyword"""
    return search_intelx(keyword, 'keyword')

# Test function
if __name__ == "__main__":
    print("Testing Intelligence X API...\n")
    
    test_email = "test@example.com"
    print(f"Searching for: {test_email}")
    
    results, count = search_email_intelx(test_email)
    
    if count > 0:
        print(f"\nFound {count} results:")
        for i, result in enumerate(results[:5], 1):
            print(f"\n{i}. {result['name']}")
            print(f"   Bucket: {result['bucket']}")
            print(f"   Date: {result['date']}")
    elif count == 0:
        print("\nNo results found")
    else:
        print(f"\nError: {count}")