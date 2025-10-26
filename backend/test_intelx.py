import requests
import os
from dotenv import load_dotenv

load_dotenv()

api_key = os.getenv('INTELX_API_KEY')
print(f"API Key from .env: {api_key}")

# Test the API
url = "https://2.intelx.io/authenticate/info"
headers = {"x-key": api_key}

response = requests.post(url, headers=headers)
print(f"Status Code: {response.status_code}")
print(f"Response: {response.text}")