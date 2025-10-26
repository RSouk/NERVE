import requests
import time
import os
from dotenv import load_dotenv
from database import get_db, Profile, Breach
from modules.ghost.breach_checker import get_breach_summary, check_local_breaches
from modules.ghost.api_breaches import check_all_apis

load_dotenv()

def check_hibp_breaches(email):
    """
    Check Have I Been Pwned for breaches
    Returns list of breaches and total count
    """
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    
    # Check if we have an API key
    api_key = os.getenv('HIBP_API_KEY')
    
    headers = {
        'User-Agent': 'Ghost-OSINT-Platform',
        'Accept': 'application/json'
    }
    
    if api_key and api_key != 'your_key_here_when_you_get_it':
        headers['hibp-api-key'] = api_key
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        print(f"HIBP Response Status: {response.status_code}")
        
        # 404 means no breaches found
        if response.status_code == 404:
            return [], 0
        
        # 200 means breaches found
        if response.status_code == 200:
            breaches = response.json()
            return breaches, len(breaches)
        
        # 429 means rate limited
        if response.status_code == 429:
            return None, -1
        
        # 401 means unauthorized (need API key)
        if response.status_code == 401:
            print("HIBP requires API key. Get one at https://haveibeenpwned.com/API/Key")
            return None, -4
        
        print(f"Unexpected status code: {response.status_code}")
        return None, -2
        
    except Exception as e:
        print(f"Error checking HIBP: {e}")
        return None, -3

def scan_profile_breaches(profile_id):
    """
    Scan a profile for breaches and update database
    Returns dict with results
    """
    db = get_db()
    profile = db.query(Profile).filter(Profile.id == profile_id).first()
    
    if not profile or not profile.email:
        db.close()
        return {'error': 'Profile not found or no email'}
    
    print(f"Scanning {profile.email} for breaches...")
    
    # Priority 1: Check local breach files
    breach_count, local_breaches = get_breach_summary(profile.email)
    
    if breach_count > 0:
        print(f"Found {breach_count} breaches in local database")
        breaches_to_store = local_breaches
        data_source = "local"
    else:
        # Priority 2: Check breach APIs (DeHashed, LeakCheck, etc.)
        print("No local breaches found, checking APIs...")
        api_breaches, api_count, sources_used = check_all_apis(profile.email)
        
        # Check if APIs actually worked (not just returned 0 results)
        if api_count is not None and api_count != -4:
            # APIs worked, use their results (even if 0)
            if api_count > 0:
                print(f"Found {api_count} breaches via APIs: {', '.join(sources_used)}")
                breaches_to_store = api_breaches
                breach_count = api_count
                data_source = f"api ({', '.join(sources_used)})"
            else:
                print("APIs returned 0 breaches (email is clean)")
                breach_count = 0
                breaches_to_store = []
                data_source = "api (clean)"
        else:
            # All APIs failed, try HIBP as last resort
            print("All APIs failed, trying HIBP...")
            hibp_breaches, hibp_count = check_hibp_breaches(profile.email)
        
            if hibp_count == -1:
                db.close()
                return {'error': 'Rate limited on all sources. Wait and try again.'}
            
            if hibp_count == -4:
                db.close()
                return {'error': 'No breach data sources available. Add API keys to .env or breach files to data/breach_databases/'}
            
            if hibp_count == -2:
                db.close()
                return {'error': 'API error occurred'}
            
            if hibp_count == -3:
                db.close()
                return {'error': 'Network error'}
            
            if hibp_breaches is None:
                db.close()
                return {'error': 'No breach sources configured or all failed'}
            
            breach_count = hibp_count
            breaches_to_store = hibp_breaches if hibp_breaches else []
            data_source = "hibp"
    
    # Clear old breach data for this profile
    db.query(Breach).filter(Breach.profile_id == profile_id).delete()
    
    # Add new breach data
    if breach_count > 0:
        for breach in breaches_to_store:
            if data_source == "local":
                # Local breach format
                new_breach = Breach(
                    profile_id=profile_id,
                    breach_name=breach.get('name', 'Unknown'),
                    breach_date='Unknown',
                    data_classes='Email, Passwords (likely)'
                )
            elif data_source.startswith("api"):
                # API format (DeHashed, LeakCheck, etc.)
                data_types = breach.get('data_types', ['Email'])
                new_breach = Breach(
                    profile_id=profile_id,
                    breach_name=breach.get('name', 'Unknown'),
                    breach_date=breach.get('date', 'Unknown'),
                    data_classes=', '.join(data_types) if isinstance(data_types, list) else str(data_types)
                )
            else:
                # HIBP format
                new_breach = Breach(
                    profile_id=profile_id,
                    breach_name=breach.get('Name'),
                    breach_date=breach.get('BreachDate'),
                    data_classes=', '.join(breach.get('DataClasses', []))
                )
            db.add(new_breach)
    
    # Update profile breach count and risk score
    profile.breach_count = breach_count
    
    # Calculate risk score based on breaches
    breach_score = min(breach_count * 10, 60)
    
    # Add points for sensitive data types
    sensitive_score = 0
    if data_source == "hibp" and breach_count > 0:
        for breach in breaches_to_store:
            data_classes = breach.get('DataClasses', [])
            if 'Passwords' in data_classes:
                sensitive_score += 15
            if 'Credit cards' in data_classes or 'Bank account numbers' in data_classes:
                sensitive_score += 20
            if 'Social security numbers' in data_classes:
                sensitive_score += 25
    elif data_source.startswith("api") and breach_count > 0:
        # API sources provide detailed data types
        for breach in breaches_to_store:
            data_types = breach.get('data_types', [])
            if 'Passwords' in data_types or 'Password Hashes' in data_types:
                sensitive_score += 15
            if 'Credit cards' in data_types or 'Bank' in str(data_types):
                sensitive_score += 20
    elif data_source == "local" and breach_count > 0:
        # Assume passwords exposed in local breaches
        sensitive_score = 15
    
    profile.risk_score = min(breach_score + sensitive_score, 100)
    
    db.commit()
    
    result = {
        'profile_id': profile_id,
        'email': profile.email,
        'breaches_found': breach_count,
        'risk_score': profile.risk_score,
        'data_source': data_source,
        'breaches': [{
            'name': b.get('name') if data_source in ["local"] or data_source.startswith("api") else b.get('Name'),
            'date': b.get('date', 'Unknown') if data_source.startswith("api") else (b.get('BreachDate', 'Unknown') if data_source == "hibp" else 'Unknown'),
            'data_types': b.get('data_types', ['Email', 'Passwords']) if data_source.startswith("api") else (b.get('DataClasses', ['Email']) if data_source == "hibp" else ['Email', 'Passwords (likely)'])
        } for b in breaches_to_store] if breaches_to_store else []
    }
    
    db.close()
    print(f"Scan complete: {breach_count} breaches found via {data_source}")
    return result

def calculate_risk_score(profile_id):
    """
    Calculate overall risk score for a profile
    Based on multiple factors
    """
    db = get_db()
    profile = db.query(Profile).filter(Profile.id == profile_id).first()
    
    if not profile:
        db.close()
        return 0
    
    score = 0
    
    # Breach score (0-60 points)
    score += min(profile.breach_count * 10, 60)
    
    # Social media exposure (0-20 points) - TODO: implement when we add social media scanning
    # Device exposure (0-20 points) - TODO: implement when we add device scanning
    
    profile.risk_score = min(score, 100)
    db.commit()
    db.close()
    
    return profile.risk_score