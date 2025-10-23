import requests
import time
import os
from dotenv import load_dotenv

load_dotenv()

def check_dehashed_api(email):
    """
    Check DeHashed API for breaches
    Free tier: 100 searches/day (requires free account)
    API: https://dehashed.com/
    """
    api_key = os.getenv('DEHASHED_API_KEY')
    api_user = os.getenv('DEHASHED_USERNAME')
    
    if not api_key or not api_user:
        return None, -4  # No API key
    
    url = f"https://api.dehashed.com/search?query=email:{email}"
    
    try:
        response = requests.get(
            url,
            auth=(api_user, api_key),
            headers={'Accept': 'application/json'},
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            entries = data.get('entries', [])
            
            # Group by database/breach name
            breaches = {}
            for entry in entries:
                db_name = entry.get('database_name', 'Unknown')
                if db_name not in breaches:
                    breaches[db_name] = {
                        'name': db_name,
                        'date': 'Unknown',
                        'data_types': set()
                    }
                
                # Track what data was exposed
                if entry.get('password'):
                    breaches[db_name]['data_types'].add('Passwords')
                if entry.get('hashed_password'):
                    breaches[db_name]['data_types'].add('Password Hashes')
                if entry.get('username'):
                    breaches[db_name]['data_types'].add('Usernames')
                if entry.get('name'):
                    breaches[db_name]['data_types'].add('Names')
                if entry.get('address'):
                    breaches[db_name]['data_types'].add('Addresses')
                if entry.get('phone'):
                    breaches[db_name]['data_types'].add('Phone Numbers')
            
            breach_list = []
            for breach in breaches.values():
                breach['data_types'] = list(breach['data_types'])
                breach_list.append(breach)
            
            return breach_list, len(breach_list)
        
        elif response.status_code == 401:
            return None, -4  # Invalid API key
        elif response.status_code == 429:
            return None, -1  # Rate limited
        else:
            return None, -2  # API error
            
    except Exception as e:
        print(f"DeHashed API error: {e}")
        return None, -3  # Network error

def check_leakcheck_api(email):
    """
    Check LeakCheck.io PUBLIC API (no key required!)
    Free public API with no authentication
    """
    url = f"https://leakcheck.io/api/public?check={email}"
    
    try:
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            if not data.get('success') or data.get('found', 0) == 0:
                return [], 0
            
            sources = data.get('sources', [])
            breach_list = []
            
            for source in sources:
                breach_list.append({
                    'name': source.get('name', 'Unknown'),
                    'date': source.get('date', 'Unknown'),
                    'data_types': data.get('fields', ['Email'])
                })
            
            return breach_list, len(breach_list)
        
        elif response.status_code == 429:
            return None, -1
        else:
            return None, -2
            
    except Exception as e:
        print(f"LeakCheck API error: {e}")
        return None, -3

def check_breachdirectory_api(email):
    """
    Check BreachDirectory API (free, no auth required)
    Public service for breach checking
    Note: Rate limited but no API key needed
    """
    url = "https://breachdirectory.p.rapidapi.com/"
    
    # This requires RapidAPI key (free tier available)
    api_key = os.getenv('RAPIDAPI_KEY')
    
    if not api_key or api_key == '':
        print("BreachDirectory: No RapidAPI key found")
        return None, -4
    
    if not api_key:
        return None, -4
    
    try:
        response = requests.get(
            url,
            params={'func': 'auto', 'term': email},
            headers={
                'X-RapidAPI-Key': api_key,
                'X-RapidAPI-Host': 'breachdirectory.p.rapidapi.com'
            },
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            
            if not data.get('found'):
                return [], 0
            
            sources = data.get('sources', [])
            breach_list = []
            
            for source in sources:
                breach_list.append({
                    'name': source,
                    'date': 'Unknown',
                    'data_types': ['Email']
                })
            
            return breach_list, len(breach_list)
        
        elif response.status_code == 429:
            return None, -1
        else:
            return None, -2
            
    except Exception as e:
        print(f"BreachDirectory API error: {e}")
        return None, -3

def check_snusbase_api(email):
    """
    Check Snusbase API
    Paid service but has free trial
    API: https://snusbase.com/
    """
    api_key = os.getenv('SNUSBASE_API_KEY')
    
    if not api_key:
        return None, -4
    
    url = "https://api.snusbase.com/v1/search"
    
    try:
        response = requests.post(
            url,
            json={
                'type': 'email',
                'term': email
            },
            headers={
                'Authorization': f'Bearer {api_key}',
                'Content-Type': 'application/json'
            },
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            
            if not data.get('results'):
                return [], 0
            
            # Snusbase returns results grouped by database
            databases = data.get('results', {})
            breach_list = []
            
            for db_name, entries in databases.items():
                if entries:  # Only add if there are actual entries
                    breach_list.append({
                        'name': db_name,
                        'date': 'Unknown',
                        'data_types': ['Email', 'Various']
                    })
            
            return breach_list, len(breach_list)
        
        elif response.status_code == 401:
            return None, -4
        elif response.status_code == 429:
            return None, -1
        else:
            return None, -2
            
    except Exception as e:
        print(f"Snusbase API error: {e}")
        return None, -3

def check_all_apis(email):
    """
    Check all available breach APIs and combine results
    Returns: (combined_breach_list, total_count, sources_used)
    """
    all_breaches = []
    sources_used = []
    
    # Try each API in order of preference (free first!)
    apis = [
        ('LeakCheck', check_leakcheck_api),
        ('BreachDirectory', check_breachdirectory_api),
        ('DeHashed', check_dehashed_api),
        ('Snusbase', check_snusbase_api)
    ]
    
    at_least_one_worked = False
    
    for api_name, api_func in apis:
        try:
            print(f"Trying {api_name}...")
            breaches, count = api_func(email)
            
            if count == -4:  # No API key
                print(f"{api_name}: No API key configured (skipping)")
                continue
            elif count == -1:  # Rate limited
                print(f"{api_name}: Rate limited (skipping)")
                continue
            elif count in [-2, -3]:  # Error
                print(f"{api_name}: Error occurred (skipping)")
                continue
            elif count >= 0:  # Success (even if 0 results)
                at_least_one_worked = True
                print(f"{api_name}: Returned {count} breaches")
                if count > 0:
                    all_breaches.extend(breaches)
                    sources_used.append(api_name)
                    break  # Found results, stop here
                # If count == 0, continue to next API
        except Exception as e:
            print(f"{api_name}: Exception - {e}")
            continue
    
    # If no API worked at all, return error code
    if not at_least_one_worked:
        print("No APIs were successful")
        return None, -4, []
    
    # Deduplicate breaches by name
    unique_breaches = {}
    for breach in all_breaches:
        name = breach['name']
        if name not in unique_breaches:
            unique_breaches[name] = breach
    
    final_breaches = list(unique_breaches.values())
    
    return final_breaches, len(final_breaches), sources_used

def get_api_setup_instructions():
    """
    Return instructions for setting up API keys
    """
    return """
    ========================================
    BREACH API SETUP INSTRUCTIONS
    ========================================
    
    Add these to your .env file:
    
    # DeHashed (Free tier: 100/day)
    DEHASHED_USERNAME=your_username
    DEHASHED_API_KEY=your_api_key
    Sign up: https://dehashed.com/register
    
    # RapidAPI for BreachDirectory (Free tier)
    RAPIDAPI_KEY=your_rapid_api_key
    Sign up: https://rapidapi.com/rohan-patra/api/breachdirectory/
    
    # LeakCheck (Limited free tier)
    LEAKCHECK_API_KEY=your_api_key
    Sign up: https://leakcheck.io/
    
    # Snusbase (Paid, optional)
    SNUSBASE_API_KEY=your_api_key
    Info: https://snusbase.com/
    
    ========================================
    PRIORITY: Start with DeHashed (best free option)
    ========================================
    """

if __name__ == "__main__":
    print(get_api_setup_instructions())
    
    # Test with sample email
    test_email = "test@example.com"
    print(f"\nTesting breach APIs with: {test_email}")
    breaches, count, sources = check_all_apis(test_email)
    
    print(f"\nResults: {count} breaches found")
    print(f"Sources used: {', '.join(sources) if sources else 'None (no API keys configured)'}")
    
    if count > 0:
        for breach in breaches:
            print(f"  - {breach['name']} ({breach.get('date', 'Unknown')})")