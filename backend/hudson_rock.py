import requests
import os
from dotenv import load_dotenv

load_dotenv()

HUDSON_ROCK_API_KEY = "MdBmjE4lF1_2YHD3PZL2W0XXhn.VtNTYQfJ3wClmCxx9cChelzXBJaP1JkfxmRQA"
HUDSON_ROCK_BASE = "https://api.hudsonrock.com/json/v3"

def search_by_email(email):
    """Search Hudson Rock by email"""
    url = f"{HUDSON_ROCK_BASE}/search-by-email"
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "api-key": HUDSON_ROCK_API_KEY
    }
    
    try:
        response = requests.post(url, headers=headers, json={"email": email}, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            # Parse Hudson Rock response
            return data, len(data) if isinstance(data, list) else 1
        else:
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
    
    try:
        response = requests.post(url, headers=headers, json={"domain": domain}, timeout=15)
        
        if response.status_code == 200:
            return response.json()
        else:
            return None
            
    except Exception as e:
        print(f"Hudson Rock domain search error: {e}")
        return None

def search_by_password(password):
    """Search Hudson Rock by password"""
    url = f"{HUDSON_ROCK_BASE}/search-by-password"
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "api-key": HUDSON_ROCK_API_KEY
    }
    
    try:
        response = requests.post(url, headers=headers, json={"password": password}, timeout=15)
        
        if response.status_code == 200:
            return response.json()
        else:
            return None
            
    except Exception as e:
        print(f"Hudson Rock password search error: {e}")
        return None