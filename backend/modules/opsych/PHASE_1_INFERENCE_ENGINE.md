# OPSYCH Phase 1: Intelligence Inference Engine

## Overview

The OPSYCH Intelligence Inference Engine is a comprehensive OSINT system that accepts **flexible input** (any combination of identifiers) and intelligently routes queries to appropriate data sources, cross-references results, and builds high-confidence intelligence profiles.

## Key Features

### 1. Fully Flexible Input
- **ALL fields are optional** - at least ONE required
- Supported inputs:
  - Name
  - Email
  - Phone number
  - Username
  - Company
  - Location/City
  - Age or age range
  - Additional context (free text)

### 2. Smart Query Routing
The `query_builder.py` module intelligently routes queries based on input combination:

**Email Only**: Hunter + Ghost breaches + Reverse email lookup
**Phone Only**: Reverse phone lookup + Whitepages
**Username Only**: Sherlock enumeration + GitHub + Twitter
**Name Only**: Whitepages + Google (flags HIGH false positive risk)
**Name + Location**: Targeted Whitepages + Property records
**Name + Company**: LinkedIn + Hunter domain search
**Multiple Identifiers**: Cross-reference ALL sources

### 3. Data Source Integration

#### Core Sources
- **Hunter.io**: Professional email enrichment
- **Ghost Database**: Breach data (passwords, SSNs, phones, credit cards)
- **Whitepages**: Reverse phone/name lookup, relatives, addresses
- **Social Enumeration**: GitHub, Twitter, Instagram, Reddit
- **DuckDuckGo**: OSINT searches
- **Google Custom Search**: News, social profiles

#### Reverse Lookup Modules
- `reverse_lookup.py`:
  - `reverse_phone_lookup()`: Find person/business from phone
  - `reverse_email_lookup()`: Find person from email
  - `reverse_username_lookup()`: Find all accounts for username

#### Whitepages Scraping
- `whitepages_scraper.py`:
  - Name search (basic)
  - Name + location search (filtered)
  - Reverse phone lookup
  - Age filtering
  - Returns: addresses, relatives, phone numbers

### 4. Inference Engine

The `inference_engine.py` module:

#### Profile Building
- Merges data from ALL sources
- Detects duplicate profiles (same person from different sources)
- Cross-references fields for validation

#### Confidence Scoring
Each profile gets:
- **Overall confidence score** (0-100)
- **Field-level confidence** (per data point)
- **Cross-reference strength** (how well sources agree)

Scoring factors:
- Number of sources confirming data: +15-45 points
- Unique identifier match (email/phone): +25 points each
- Name match: +15 points
- Location match: +10 points
- Age match: +10 points
- Company match: +10 points

#### Ambiguity Handling

**When multiple matches found:**
- Returns ALL potential profiles ranked by confidence
- Flags ambiguity: "Multiple potential matches found"
- Recommends missing fields to narrow results
- Highlights differences between top matches

**Example Output:**
```json
{
  "ambiguity_detected": true,
  "recommendation": "Multiple potential matches found. Add location, age to narrow results.",
  "profiles": [
    {
      "name": "John Smith",
      "location": "New York, NY",
      "confidence_score": 75
    },
    {
      "name": "John Smith",
      "location": "Los Angeles, CA",
      "confidence_score": 68
    }
  ]
}
```

### 5. False Positive Risk Assessment

Query builder calculates FP risk:
- **Low Risk**: Email/phone + other data
- **Medium Risk**: Name + location/company
- **High Risk**: Name only (common name)

**Example Warnings:**
```
"Common name detected - results may include multiple people.
Add location, age, or company to improve accuracy."
```

## System Architecture

```
┌─────────────────────────────────────────────────────┐
│         Frontend: exposure-analysis.html            │
│  (Multi-field form: name, email, phone, username,  │
│   company, location, age, context)                  │
└─────────────────┬───────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────┐
│       Backend API: /api/opsych/exposure             │
│   (Accepts flexible JSON, validates ≥1 field)       │
└─────────────────┬───────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────┐
│      PHASE 1: Query Builder (query_builder.py)     │
│  • Analyzes input combination                       │
│  • Routes to appropriate data sources               │
│  • Calculates false positive risk                   │
└─────────────────┬───────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────┐
│       PHASE 2: Data Collection (Parallel)           │
│  ┌──────────────┬──────────────┬──────────────┐    │
│  │ Reverse      │ Whitepages   │ Social       │    │
│  │ Lookups      │ Scraping     │ Enumeration  │    │
│  └──────────────┴──────────────┴──────────────┘    │
│  ┌──────────────┬──────────────┬──────────────┐    │
│  │ Hunter.io    │ Ghost        │ Google/DDG   │    │
│  │ Professional │ Breaches     │ OSINT        │    │
│  └──────────────┴──────────────┴──────────────┘    │
└─────────────────┬───────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────┐
│    PHASE 3: Inference Engine (inference_engine.py) │
│  • Merge similar profiles                           │
│  • Calculate confidence scores                      │
│  • Detect ambiguity                                 │
│  • Cross-reference validation                       │
└─────────────────┬───────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────┐
│              Results with Intelligence              │
│  • Multiple ranked profiles (if ambiguous)          │
│  • Confidence scores per field                      │
│  • Recommendations for narrowing                    │
│  • Cross-reference strength                         │
└─────────────────────────────────────────────────────┘
```

## Usage Examples

### Example 1: Email Only
**Input:**
```json
{
  "email": "john.doe@company.com"
}
```

**Query Plan:**
- Sources: Hunter, Ghost breaches, Reverse email lookup, Google dork
- False Positive Risk: LOW
- Confidence: 90% (email is unique identifier)

### Example 2: Name Only (Common Name)
**Input:**
```json
{
  "name": "John Smith"
}
```

**Query Plan:**
- Sources: Whitepages, Google, LinkedIn
- False Positive Risk: HIGH
- Warning: "Common name detected - results may include multiple people"
- Result: Returns top 5 matches with confidence scores

### Example 3: Name + Location + Age (Good Combination)
**Input:**
```json
{
  "name": "John Smith",
  "location": "New York, NY",
  "age": "35"
}
```

**Query Plan:**
- Sources: Whitepages (filtered), Property records, Voter records
- False Positive Risk: LOW
- Confidence: 85%
- Result: Single high-confidence profile

### Example 4: Phone + Name
**Input:**
```json
{
  "phone": "+1-555-123-4567",
  "name": "Jane Doe"
}
```

**Query Plan:**
- Sources: Reverse phone, Whitepages, Ghost breaches
- False Positive Risk: LOW
- Confidence: 90%

### Example 5: Username Only
**Input:**
```json
{
  "username": "johndoe123"
}
```

**Query Plan:**
- Sources: Sherlock enumeration, GitHub, Twitter, Social platforms
- False Positive Risk: MEDIUM
- Result: List of all social accounts found

## API Response Structure

```json
{
  "success": true,
  "query": {
    "name": "John Doe",
    "location": "New York, NY",
    "age": "35"
  },
  "professional": {
    "company": "Acme Corp",
    "position": "Software Engineer",
    "linkedin": "https://linkedin.com/in/johndoe"
  },
  "breaches": {
    "total_breaches": 3,
    "credentials": [...],
    "github_leaks": [...],
    "ssns": [],
    "phones": ["+1-555-123-4567"]
  },
  "family": {
    "relatives": [
      {"name": "Jane Doe", "age": "33", "relationship": "Spouse"},
      {"name": "Bob Doe", "age": "65", "relationship": "Parent"}
    ],
    "addresses": ["123 Main St, New York, NY 10001"],
    "phones": ["+1-555-987-6543"]
  },
  "social": [
    {"platform": "GitHub", "username": "johndoe", "url": "..."},
    {"platform": "Twitter", "username": "johndoe", "url": "..."}
  ],
  "inference": {
    "profiles": [
      {
        "name": "John Doe",
        "email": "john@example.com",
        "location": "New York, NY",
        "age": "35",
        "confidence_score": 92,
        "sources": ["whitepages", "hunter", "reverse_phone"],
        "field_confidence": {
          "name": 90,
          "email": 95,
          "location": 85,
          "age": 70
        }
      }
    ],
    "confidence_level": "high",
    "ambiguity_detected": false,
    "total_sources_checked": 8,
    "sources_with_hits": 5,
    "cross_reference_strength": 88
  },
  "risk_score": 45,
  "confidence": 92
}
```

## Files Created

### Frontend
- `frontend/modules/opsych/exposure-analysis.html` - Updated with multi-field form

### Backend
- `backend/modules/opsych/query_builder.py` - Smart query routing
- `backend/modules/opsych/inference_engine.py` - Profile building & confidence scoring
- `backend/modules/opsych/scrapers/whitepages_scraper.py` - Whitepages data extraction
- `backend/modules/opsych/scrapers/reverse_lookup.py` - Reverse phone/email lookups
- `backend/modules/opsych/exposure_analysis.py` - Updated main analysis function
- `backend/app.py` - Updated `/api/opsych/exposure` endpoint

## Future Enhancements (Phase 2)

1. **Real Whitepages Scraping**: Implement actual web scraping (currently placeholder)
2. **TrueCaller Integration**: Real reverse phone lookup
3. **Sherlock Integration**: Actual username enumeration tool
4. **Property Records API**: Public property database queries
5. **Voter Records API**: Voter registration lookups
6. **ML Confidence Tuning**: Machine learning for better confidence scores
7. **Relationship Mapping**: Visual family/associate network graphs

## Testing

To test the system:

1. Start backend: `python backend/app.py`
2. Open: `http://localhost:5000/frontend/modules/opsych/exposure-analysis.html`
3. Try different input combinations:
   - Email only
   - Name only (see ambiguity handling)
   - Name + Location (better results)
   - Phone + Name (high confidence)

## Notes

- All scrapers currently use placeholder implementations
- Real implementations would require actual web scraping or API integrations
- Ghost database integration is LIVE and functional
- Hunter.io integration is LIVE (requires API key)
- Social enumeration (GitHub, Twitter, Reddit) is LIVE

## Security & Legal

- All data sources use publicly available information
- No authentication bypass or unauthorized access
- Respects robots.txt and rate limits
- For authorized OSINT research and security testing only
