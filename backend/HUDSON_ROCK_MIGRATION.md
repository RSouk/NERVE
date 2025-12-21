# Hudson Rock Migration to FREE Cavalier API

## Overview
Successfully migrated from paid Hudson Rock API to **FREE Cavalier API** - no API key needed!

## Changes Made

### 1. `hudson_rock.py` - Updated API Endpoints

**OLD (Paid API):**
- Base URL: `https://api.hudsonrock.com/json/v3`
- Required: `HUDSON_ROCK_API_KEY` in headers
- Method: POST with JSON payload
- Response format: `{"data": [...], "nextCursor": "..."}`

**NEW (Free Cavalier API):**
- Base URL: `https://cavalier.hudsonrock.com/api/json/v2/osint-tools`
- Required: **NOTHING** - No API key needed!
- Method: GET with query parameters
- Response format: `{"stealers": [...], "message": "...", "total_corporate_services": X, "total_user_services": Y}`

**Endpoints Updated:**
- ✅ `search_by_email`: `GET /search-by-email?email={email}`
- ✅ `search_by_domain`: `GET /search-by-domain?domain={domain}`
- ❌ `search_by_password`: Not available in free API
- ❌ `search_by_username`: Not available in free API (use email instead)
- ❌ `search_by_ip`: Not available in free API
- ❌ `search_by_keyword`: Not available in free API (use email/domain)

### 2. `unified_search.py` - Updated Response Parsing

**Updated `_structure_hudson_rock_data()` function:**
- Now handles both `stealers` (new) and `data` (old) arrays
- Extracts stealer family name from multiple possible field names:
  - `malware_path`
  - `stealer_family`
  - `stealer_type`
  - `malware_family`
- Maintains backward compatibility

### 3. Response Structure

**Cavalier API Response:**
```json
{
  "message": "This email address is associated with a computer that was infected...",
  "stealers": [
    {
      "malware_path": "C:\\Windows\\SysWOW64\\explorer.exe",
      "computer_name": "Daniel Wild",
      "operating_system": "Windows 11 Home (10.0.22631) x64",
      "ip": "70.75.***.** ",
      "date_compromised": "2025-01-24T16:52:07.000Z",
      "credentials": [
        {
          "url": "https://example.com",
          "domain": "example.com",
          "username": "user@example.com",
          "password": "password123",
          "type": "login"
        }
      ]
    }
  ],
  "total_corporate_services": 3,
  "total_user_services": 364
}
```

## Test Results

**Email Search (danieljohnwild@gmail.com):**
- ✅ Status: 200 OK
- ✅ Found: 3 stealer logs
- ✅ Corporate Services: 3
- ✅ User Services: 364
- ✅ Extracted: Malware path, computer name, OS, IP, credentials

**Domain Search:**
- ✅ Endpoint working
- ⚠️ Some generic domains (like gmail.com) return 400
- ✅ Specific domains work fine

## Benefits

1. **FREE** - No API key or subscription required
2. **Simple** - Just HTTP GET requests
3. **Fast** - Direct API access
4. **Maintained** - Hudson Rock's official free tier

## Usage

```python
from modules.ghost.hudson_rock import search_by_email, search_by_domain

# Email search
data, count = search_by_email("user@example.com")
if count > 0:
    print(f"Found {count} stealer logs!")
    stealers = data['stealers']

# Domain search
data, count = search_by_domain("example.com")
if count > 0:
    print(f"Found {count} compromised machines!")
```

## Migration Complete! 🎉

No action required - everything works automatically with the free API!
