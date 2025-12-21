# OPSYCH Exposure Analysis - Component 1

## Overview
Comprehensive person intelligence module that calculates human exposure and risk scores using multiple intelligence sources.

## Features Implemented

### 1. Backend Module (`exposure_analysis.py`)
- **Hunter.io Integration**: Work email/company enrichment
- **Ghost Database Queries**: Searches across:
  - Uploaded credentials
  - GitHub findings
  - PasteBin findings
  - Breach data with passwords, SSN, credit cards
- **DuckDuckGo OSINT**: Searches for:
  - Documents (filetype:pdf)
  - Email mentions
  - Name + company mentions
- **Google Custom Search API**:
  - LinkedIn profiles
  - News articles
  - Social media (Twitter, Instagram)

### 2. Risk Scoring Algorithm
Calculates a 0-100 risk score based on:
- **Breaches (40 points max)**: Critical exposure from leaked credentials
- **Professional Info (25 points max)**: Known company/position data
- **Social Mentions (20 points max)**: Public visibility
- **Social Media (15 points max)**: Social footprint

### 3. Confidence Scoring
Calculates a 0-100 confidence score based on:
- Professional data quality (30% weight)
- Breach data presence (35% weight)
- Mentions found (20% weight)
- Social media profiles (15% weight)

### 4. Frontend UI (`exposure-analysis.html`)
- **Sage Green Theme** (#8FBC8F)
- **Human Risk Score Dashboard**: Large, color-coded risk display
- **Four Category Cards**:
  - Professional: Company, position, LinkedIn, Twitter
  - Breaches: Credentials, GitHub leaks, PasteBin leaks
  - Social: Social media profiles
  - Mentions: Web mentions and documents
- **Real-time Analysis**: Loading states and responsive UI

### 5. API Endpoint (`/api/opsych/exposure`)
- **POST** endpoint accepting:
  - `email`: Email address (optional)
  - `name`: Full name (optional)
  - `username`: Username/handle (optional)
  - `company`: Company name (optional)
- Returns comprehensive exposure analysis with risk scores

## Data Structure

```json
{
  "professional": {
    "email": "john@company.com",
    "name": "John Doe",
    "position": "Software Engineer",
    "company": "TechCorp",
    "linkedin": "https://linkedin.com/in/johndoe",
    "twitter": "https://twitter.com/johndoe",
    "confidence": 80
  },
  "breaches": {
    "total_breaches": 5,
    "passwords": ["password123", "welcome1"],
    "credentials": [
      {
        "email": "john@company.com",
        "password": "password123",
        "source": "Uploaded Credentials"
      }
    ],
    "github_leaks": [
      {
        "url": "https://gist.github.com/...",
        "credential_type": "api_key",
        "credential_value": "sk_live_...",
        "context": "..."
      }
    ],
    "pastebin_leaks": [...],
    "sensitive_data": [
      {
        "type": "SSN",
        "value": "123-45-6789"
      }
    ],
    "risk_level": "high"
  },
  "mentions": [
    {
      "title": "Article Title",
      "url": "https://...",
      "snippet": "...",
      "source": "DuckDuckGo"
    }
  ],
  "social": [],
  "risk_score": 65,
  "confidence": 75,
  "analyzed_at": "2025-11-11T11:18:52Z"
}
```

## Usage

### Command Line
```bash
python backend/modules/opsych/exposure_analysis.py john@company.com
python backend/modules/opsych/exposure_analysis.py "John Doe"
```

### API
```bash
curl -X POST http://localhost:5000/api/opsych/exposure \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@company.com",
    "name": "John Doe",
    "username": "johndoe",
    "company": "TechCorp"
  }'
```

### Web UI
Navigate to: `http://localhost:5000/modules/opsych/exposure-analysis.html`

## Environment Variables Required

```env
# Required for professional enrichment
HUNTER_API_KEY=your_hunter_api_key

# Optional for enhanced search
GOOGLE_CSE_ID=your_google_cse_id
GOOGLE_API_KEY=your_google_api_key
```

## Testing

The module was tested with:
- Email lookups (Hunter.io integration)
- Ghost database queries (breach detection)
- DuckDuckGo searches (OSINT data)
- Risk score calculation (0-100 scale)
- Confidence scoring (data quality assessment)

Results show proper integration across all data sources with appropriate error handling.

## SpiderFoot Removal

All SpiderFoot code has been removed from the OPSYCH module as requested:
- Removed `search_spiderfoot()` function from `social_search.py`
- Removed SpiderFoot API endpoint configuration
- Updated routing logic to skip SpiderFoot for name searches
- Cleaned up documentation references

## Next Steps

1. Add more OSINT sources (Shodan, Censys, etc.)
2. Implement caching for repeated queries
3. Add export functionality (PDF reports)
4. Implement historical tracking of risk scores
5. Add alerting for high-risk individuals
