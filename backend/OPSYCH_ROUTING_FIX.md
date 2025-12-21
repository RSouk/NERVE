# OPSYCH Routing Fix - Using exposure_analysis.py

## Problem
The `/api/opsych/search` endpoint was calling the old `social_search.py` module which skipped NAME inputs and only supported Hunter.io and Twitter searches.

## Solution
Refactored the endpoint to use the new `exposure_analysis.py` module which provides comprehensive person intelligence with:
- DuckDuckGo OSINT searches
- Google Custom Search
- Ghost database breach checking
- Hunter.io professional enrichment

## Changes Made

### 1. Import Update (backend/app.py:5)
```python
# OLD
from modules.opsych.social_search import fast_search

# NEW
from modules.opsych.exposure_analysis import analyze_exposure
```

### 2. Endpoint Refactor (backend/app.py:1173-1389)
Complete rewrite of `/api/opsych/search` endpoint to:

**Input Detection:**
- EMAIL: Detects `@` symbol → passes to `email` parameter
- NAME: Detects spaces without commas → passes to `name` parameter
- USERNAME: Detects single word → passes to `username` parameter
- PHONE: Detects numeric input → returns "not implemented" message

**Analysis Pipeline:**
```python
results = analyze_exposure(
    email=email,
    name=name,
    username=username,
    company=company
)
```

**Result Conversion:**
Converts exposure analysis results into profile format:
- Professional data → Hunter.io profiles
- Breach credentials → Ghost Breach profiles
- GitHub leaks → GitHub profiles
- PasteBin leaks → PasteBin profiles
- Web mentions → Web Mention profiles (DuckDuckGo/Google)
- Social profiles → Social Media profiles

**Enhanced Response:**
```json
{
  "success": true,
  "search_id": "search_1731327932_abc123",
  "query": "Reece Soukoroff",
  "query_type": "name",
  "profiles": [...],
  "emails": [...],
  "phones": [...],
  "aliases": [...],
  "total_found": 5,
  "risk_score": 15,
  "confidence": 20,
  "breach_count": 0
}
```

## NAME Input Handling - FIXED

### Before:
```python
# social_search.py skipped NAME inputs
elif query_type == 'name':
    print(f"[FAST_SEARCH] NAME route: SKIPPED - No working name search APIs available")
```

### After:
```python
# exposure_analysis.py processes NAME inputs
if name:
    futures['ddg_name'] = executor.submit(
        search_duckduckgo, f'"{name}"'
    )
    futures['ddg_documents'] = executor.submit(
        search_duckduckgo, f'"{name}" filetype:pdf'
    )
```

## Test Results

### Input: "Reece Soukoroff"

**Detected Type:** NAME ✅

**Results Found:**
- 5 web mentions (DuckDuckGo)
- Elite Prospects hockey profile
- HockeyDB stats
- News articles
- Company website mentions

**Scoring:**
- Risk Score: 15/100
- Confidence: 20/100
- Breach Count: 0

## API Usage

### Search by Name
```bash
curl -X POST http://localhost:5000/api/opsych/search \
  -H "Content-Type: application/json" \
  -d '{"query": "Reece Soukoroff"}'
```

### Search by Email
```bash
curl -X POST http://localhost:5000/api/opsych/search \
  -H "Content-Type: application/json" \
  -d '{"query": "john@company.com"}'
```

### Search by Username
```bash
curl -X POST http://localhost:5000/api/opsych/search \
  -H "Content-Type: application/json" \
  -d '{"query": "johndoe"}'
```

## Benefits

1. **No More Skipping**: NAME inputs are now fully processed
2. **Comprehensive Analysis**: DuckDuckGo + Google + Ghost + Hunter.io
3. **Risk Scoring**: Every search returns a risk score (0-100)
4. **Breach Detection**: Automatic Ghost database checks
5. **Unified Results**: All data sources consolidated into profiles

## Backward Compatibility

The endpoint maintains the same response structure as before, so existing frontend code (social-search.html) continues to work without modifications:

- `profiles`: Array of profile objects
- `emails`: Array of found emails
- `phones`: Array of found phones
- `aliases`: Array of found aliases
- `total_found`: Count of profiles

**New fields added:**
- `risk_score`: 0-100 risk assessment
- `confidence`: 0-100 confidence score
- `breach_count`: Number of breaches found

## Files Modified

1. `backend/app.py` (lines 5, 1173-1389)
   - Changed import
   - Refactored `/api/opsych/search` endpoint

## Files No Longer Used

- `backend/modules/opsych/social_search.py` (kept for reference, not called)

## Next Steps

Consider deprecating `social_search.py` entirely once exposure_analysis.py is proven stable in production.
