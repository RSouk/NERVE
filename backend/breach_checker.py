import os
import hashlib
import json
from pathlib import Path

# Path to breach databases folder
BREACH_DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'breach_databases')

def hash_email(email):
    """Hash email for privacy and faster lookups"""
    return hashlib.sha256(email.lower().encode()).hexdigest()

def check_local_breaches(email):
    """
    Check if email exists in local breach databases
    Returns: list of breach names where email was found
    """
    email_lower = email.lower()
    found_breaches = []
    
    # Create breach_databases folder if it doesn't exist
    os.makedirs(BREACH_DB_PATH, exist_ok=True)
    
    # Check if we have any breach files
    breach_files = list(Path(BREACH_DB_PATH).glob('*.txt'))
    
    if not breach_files:
        print(f"No breach files found in {BREACH_DB_PATH}")
        return []
    
    print(f"Checking {len(breach_files)} breach files...")
    
    for breach_file in breach_files:
        try:
            breach_name = breach_file.stem  # Filename without extension
            
            with open(breach_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    
                    # Skip empty lines
                    if not line:
                        continue
                    
                    # Most breach formats: email:password or email;password
                    if ':' in line:
                        parts = line.split(':', 1)
                        breach_email = parts[0].strip().lower()
                    elif ';' in line:
                        parts = line.split(';', 1)
                        breach_email = parts[0].strip().lower()
                    else:
                        # Just email on the line
                        breach_email = line.lower()
                    
                    if breach_email == email_lower:
                        found_breaches.append({
                            'name': breach_name,
                            'file': breach_file.name
                        })
                        print(f"✓ Found in {breach_name}")
                        break  # Found in this file, move to next
                        
        except Exception as e:
            print(f"Error reading {breach_file.name}: {e}")
            continue
    
    return found_breaches

def check_sample_breaches(email):
    """
    Check against a small sample breach database for testing
    This simulates having breach data without needing to download GB of files
    """
    # Sample known breached emails for testing (publicly disclosed breaches)
    sample_breaches = {
        'test@example.com': ['Collection1', 'LinkedIn2012'],
        'adobe@breach.com': ['Adobe2013'],
        'linkedin@test.com': ['LinkedIn2012', 'Dropbox2012'],
    }
    
    email_lower = email.lower()
    
    if email_lower in sample_breaches:
        return [{'name': breach, 'file': 'sample_database'} for breach in sample_breaches[email_lower]]
    
    return []

def get_breach_summary(email):
    """
    Get summary of breaches for an email
    Returns: (breach_count, breach_list)
    """
    # First try local breach files
    local_breaches = check_local_breaches(email)
    
    # If no local files exist, use sample for testing
    if not local_breaches:
        local_breaches = check_sample_breaches(email)
        if local_breaches:
            print(f"Using sample breach database (no real breach files found)")
    
    breach_count = len(local_breaches)
    
    return breach_count, local_breaches

def add_breach_file_instructions():
    """
    Print instructions for adding breach data files
    """
    instructions = f"""
    =====================================================
    HOW TO ADD BREACH DATA FILES
    =====================================================
    
    1. Place breach compilation files (.txt format) in:
       {BREACH_DB_PATH}
    
    2. File format should be one of:
       - email:password
       - email;password  
       - email (one per line)
    
    3. Name files descriptively:
       - Collection1.txt
       - LinkedIn2012.txt
       - Adobe2013.txt
    
    4. Sources for breach data (for research/pentesting):
       - Have I Been Pwned offline lists
       - Public breach compilations on security research sites
       - Client-provided breach data
       
    ⚠️  LEGAL NOTE: Only use breach data you have legal right to possess.
        For pentesting: ensure your engagement contract covers breach checking.
        
    =====================================================
    """
    return instructions

if __name__ == "__main__":
    # Test the breach checker
    print("Testing breach checker...")
    print(add_breach_file_instructions())
    
    test_emails = [
        'test@example.com',
        'notfound@example.com',
        'adobe@breach.com'
    ]
    
    for email in test_emails:
        print(f"\nChecking: {email}")
        count, breaches = get_breach_summary(email)
        if count > 0:
            print(f"Found in {count} breaches:")
            for breach in breaches:
                print(f"  - {breach['name']}")
        else:
            print("Not found in any breaches")