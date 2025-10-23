# NERVE Intelligence Platform

**The Unified Intelligence Platform for Security Professionals**

---

## Platform Overview

NERVE is a modular intelligence platform designed for penetration testers, security researchers, and threat intelligence analysts. It aggregates data from multiple sources to provide comprehensive attack surface analysis.

### The Five Modules

**Current Development:**
1. **GHOST** - Credential & Breach Intelligence *(In Development - Phase 1)*

**Planned Modules:**
2. **OPSYCH** - Social Engineering Intelligence *(Phase 2)*
3. **WATCHTOWER** - Physical & IoT Security *(Phase 3)*
4. **ORACLE** - Predictive Attack Intelligence *(Phase 4)*
5. **TBD** - Fifth module to be determined based on market needs

---

## Module 1: GHOST - Credential Intelligence

**Version:** 0.3.0  
**Status:** Active Development - Phase 1  
**Started:** October 22, 2025

### What is GHOST?

GHOST is a credential and breach intelligence module that aggregates data from breached databases, stolen credential repositories, and data leak sources. It provides security teams with visibility into compromised credentials that could be used against their organization or clients.

**Core Purpose:** Answer the question "Has this person/organization been compromised in a data breach?"

**Think:** Hudson Rock Cavalier + Resecurity breach intelligence

### GHOST Capabilities

**Current Features:**
- ✅ Multi-source breach checking (local files, LeakCheck, BreachDirectory)
- ✅ Automated risk scoring based on breach exposure
- ✅ Profile management (create, search, delete)
- ✅ Persistent SQLite database
- ✅ Web-based interface
- ✅ Data classification by sensitivity (passwords, financial, PII)

**Planned Features:**
- 🔄 Detailed profile view with breach timeline
- 🔄 Export to PDF/JSON
- 🔄 Bulk profile import (CSV)
- 🔄 Google dorking for exposed credentials
- 🔄 Automated daily rescans
- 🔄 Email notifications for new findings
- 🔄 Breach data correlation across profiles

### Data Sources

**Active (Free):**
- LeakCheck.io - Public API, no authentication
- BreachDirectory via RapidAPI - 500 requests/month free
- Local breach compilation files

**Documented (Requires API Key):**
- Have I Been Pwned - $3.50/month
- DeHashed - Paid credits required
- Snusbase - Paid service

**Planned:**
- Telegram bot monitoring for fresh breach releases
- Custom breach database with monthly updates
- Integration with botnet/stealer log sources

---

## Future Modules (Not Yet Started)

### Module 2: OPSYCH - Social Engineering Intelligence

**Purpose:** Human-centric threat intelligence - profile psychological vulnerabilities and social engineering attack surface

**Capabilities:**
- Email-based social media discovery (not just username)
- Phone number reverse lookup to social profiles
- Behavioral analysis and psychological profiling
- "Attacker View" digital twin simulation
- Social engineering scenario generation
- Engagement pattern analysis
- Face recognition social media discovery (PimEyes-style)

**Design Philosophy:** Replicate how an attacker profiles a human target, but for defensive purposes

**UI:** Black/gold aesthetic, radar scanner risk visualizations, attacker simulation dashboard

### Module 3: WATCHTOWER - Physical & IoT Security

**Purpose:** Map physical attack surface through exposed devices and network infrastructure

**Capabilities:**
- Shodan/Censys integration for exposed devices
- Camera feed discovery and location mapping
- IoT vulnerability identification
- Network device enumeration
- Physical security exposure scoring
- Corporate infrastructure mapping

### Module 4: ORACLE - Predictive Intelligence

**Purpose:** AI-powered prediction and automation layer across all modules

**Capabilities:**
- Attack scenario prediction ("What will attacker do next?")
- Pattern recognition across GHOST, OPSYCH, WATCHTOWER
- Automated playbook generation
- Risk trend analysis
- Proactive threat hunting suggestions
- Integration into all other modules as predictive layer

### Module 5: TBD

**Options Under Consideration:**
- **DOCKET** - Court records and legal intelligence
- **FININT** - Financial transaction intelligence
- **GEOINT** - Physical location tracking and movement patterns
- **SIGINT** - Communication intercepts (enterprise/gov only)

Decision based on market research and customer needs.

---

## Current Status: GHOST Module (Phase 1)

### What's Working (Oct 23, 2025)

✅ **Profile Management**
- Create profiles with name, email, username, phone, notes
- Search profiles by name or email
- Delete profiles with confirmation
- Data persists across server restarts

✅ **Breach Intelligence**
- Multi-source breach checking (3 working sources)
- Risk scoring algorithm (0-100 scale)
- Breach data storage with timeline
- Data classification by type

✅ **Infrastructure**
- Flask REST API
- SQLite database with proper schema
- CORS-enabled for frontend
- Error handling and logging

### What's Next for GHOST

**Phase 1 Completion (Current Focus):**
1. ✅ Breach scanning infrastructure - DONE
2. 🔄 Detailed profile view page - IN PROGRESS
3. ⬜ Export functionality (PDF, JSON)
4. ⬜ Google dorking integration
5. ⬜ Bulk profile import (CSV)
6. ⬜ Enhanced error handling and UI feedback

**Phase 1.5 - Polish & Testing:**
- Comprehensive testing (50+ profiles)
- Performance optimization
- Bug fixes and edge cases
- Documentation completion
- Demo video and screenshots

**Phase 2 - UI Overhaul:**
- Modern dark theme (black/gold)
- Better notifications (no browser alerts)
- Loading states and progress indicators
- Responsive design
- Dashboard with statistics

---

## Technical Architecture

### GHOST Module Structure

```
Ghost/
├── backend/
│   ├── app.py                    # Flask API server
│   ├── database.py               # SQLAlchemy models
│   ├── osint.py                  # Breach scanning orchestration
│   ├── breach_checker.py         # Local breach file handler
│   ├── api_breaches.py           # External API integrations
│   └── config.py                 # Configuration
├── frontend/
│   └── index.html                # Web interface
├── data/
│   ├── ghost.db                  # SQLite database
│   └── breach_databases/         # Local breach files
├── docs/                         # Documentation
├── .env                          # Environment variables
├── .gitignore                    # Git ignore rules
├── README.md                     # This file
├── DEVLOG.md                     # Development journal
└── requirements.txt              # Python dependencies
```

### Database Schema (GHOST)

**Profiles Table**
- id, name, email, username, phone
- notes, risk_score, breach_count
- created_at, updated_at

**Breaches Table**
- profile_id (FK), breach_name, breach_date
- data_classes (what data was exposed)
- discovered_at

**Future Tables (for other modules)**
- SocialMedia (OPSYCH module)
- Devices (WATCHTOWER module)
- CourtRecords (potential 5th module)

### Tech Stack

**Backend:**
- Python 3.11+
- Flask (REST API)
- SQLAlchemy (ORM)
- SQLite (database)
- Requests (HTTP client)

**Frontend:**
- Vanilla JavaScript
- HTML5/CSS3
- No frameworks (for now)

**Why These Choices:**
- Fast iteration and prototyping
- No build process needed
- Easy to understand and modify
- Can scale to React/PostgreSQL later

---

## Installation & Setup

### Prerequisites
- Python 3.11+
- Git
- VS Code (recommended)

### Quick Start

1. **Clone repository**
```bash
git clone https://github.com/RSouk/Ghost.git
cd Ghost
```

2. **Create virtual environment**
```bash
python -m venv venv
```

3. **Activate virtual environment**
```bash
# Windows PowerShell
.\venv\Scripts\Activate

# Windows CMD
venv\Scripts\activate.bat

# Mac/Linux
source venv/bin/activate
```

4. **Install dependencies**
```bash
pip install -r requirements.txt
```

5. **Configure environment variables**

Create `.env` file:
```bash
# Breach API Keys (optional but recommended)
RAPIDAPI_KEY=your_rapidapi_key_here

# Other APIs (optional)
HIBP_API_KEY=
DEHASHED_USERNAME=
DEHASHED_API_KEY=
LEAKCHECK_API_KEY=
SNUSBASE_API_KEY=
```

6. **Run GHOST**
```bash
cd backend
python app.py
```

7. **Open interface**

Open `frontend/index.html` in your browser or navigate to `http://localhost:5000` (API only)

### Getting API Keys

**RapidAPI (BreachDirectory) - FREE**
1. Sign up at https://rapidapi.com
2. Subscribe to BreachDirectory API
3. Select FREE tier (500 requests/month)
4. Copy API key to `.env`

**LeakCheck - FREE (No Key Needed)**
- Works out of the box
- Public API with no authentication

---

## Usage Guide

### Creating a Profile
1. Enter target information in left panel
2. Email is required for breach checking
3. Click "Create Profile"

### Checking for Breaches
1. Click "🔍 Scan Breaches" on any profile
2. System checks multiple sources automatically
3. Risk score updates based on findings
4. View breach details in profile

### Understanding Risk Scores

**0-30: Low Risk** (Green)
- Few or no breaches
- Limited data exposure

**31-70: Medium Risk** (Yellow)
- Multiple breaches found
- Passwords likely compromised
- Moderate exposure

**71-100: High Risk** (Red)
- Extensive breach history
- Sensitive data exposed (SSN, financial)
- Critical security concern

### Managing Profiles
- **Search:** Type in search box to filter
- **Delete:** Click trash icon with confirmation
- **View Details:** Coming soon (detailed breach timeline)

---

## API Documentation

### Endpoints

**Profile Management**
- `POST /api/create` - Create new profile
- `GET /api/profiles` - List all profiles
- `GET /api/profile/<id>` - Get profile details
- `DELETE /api/profile/<id>` - Delete profile
- `GET /api/search?q=<query>` - Search profiles

**Intelligence Gathering**
- `POST /api/scan/breaches/<id>` - Scan for breaches

**System**
- `GET /` - API status and version

### Request Examples

**Create Profile:**
```bash
curl -X POST http://localhost:5000/api/create \
  -H "Content-Type: application/json" \
  -d '{
    "name": "John Doe",
    "email": "john@example.com",
    "username": "johndoe",
    "phone": "+1234567890",
    "notes": "Test profile"
  }'
```

**Scan Breaches:**
```bash
curl -X POST http://localhost:5000/api/scan/breaches/target_1_20251022
```

---

## Development Roadmap

### Phase 1: GHOST Foundation (Current)
**Timeline:** Oct 22 - Nov 15, 2025
- [x] Backend infrastructure
- [x] Database schema
- [x] Breach data sources (3 working)
- [x] Basic UI
- [x] Profile CRUD operations
- [ ] Detailed profile views
- [ ] Export functionality
- [ ] Testing & bug fixes

### Phase 2: GHOST Polish
**Timeline:** Nov 16 - Dec 15, 2025
- [ ] UI overhaul (modern dark theme)
- [ ] Better notifications
- [ ] Dashboard with statistics
- [ ] Performance optimization
- [ ] Documentation completion

### Phase 3: OPSYCH Module
**Timeline:** Jan 2026+
- [ ] Email-based social media discovery
- [ ] Psychological profiling
- [ ] Attacker view simulation
- [ ] Social engineering scenarios

### Phase 4: WATCHTOWER Module
**Timeline:** TBD
- [ ] Shodan integration
- [ ] IoT device mapping
- [ ] Physical security intel

### Phase 5: ORACLE Module
**Timeline:** TBD
- [ ] AI prediction layer
- [ ] Attack scenario generation
- [ ] Cross-module intelligence

### Phase 6: Module 5
**Timeline:** TBD
- [ ] Market research
- [ ] Capability selection
- [ ] Development

---

## Contributing

Currently a personal project. Open to collaboration once Phase 1 is complete.

---

## Security & Legal

### Use Responsibly

⚠️ **NERVE Platform handles sensitive data. Use ethically and legally.**

**Authorized Use Only:**
- Penetration testing with signed contracts
- Security research on your own data
- Authorized threat intelligence gathering
- Compliance with local laws

**Do NOT Use For:**
- Unauthorized access attempts
- Stalking or harassment
- Identity theft
- Any illegal activity

### Data Handling

- Breach data should be obtained legally
- Encrypt sensitive databases
- Secure your `.env` file
- Follow data protection regulations
- Document authorization in engagement contracts

---

## License

TBD - Currently private development

---

## Contact & Support

**Developer:** Reece Soukoroff  
**GitHub:** https://github.com/RSouk/Ghost  
**Purpose:** Security research and penetration testing

---

## Version History

**v0.3.0** - October 23, 2025
- Added multi-source breach checking
- Integrated LeakCheck and BreachDirectory APIs
- Local breach file support
- Delete profile functionality

**v0.2.0** - October 22, 2025
- Database persistence with SQLite
- Risk scoring algorithm
- Basic breach scanning infrastructure

**v0.1.0** - October 22, 2025
- Initial release
- Basic profile management
- Flask API framework
- Frontend interface

---

**Last Updated:** October 23, 2025  
**Current Module:** GHOST (Breach Intelligence)  
**Status:** Phase 1 Development - 65% Complete  
**Next Milestone:** Detailed profile views + export functionality

**Last Updated:** October 22, 2025  
**Status:** Active Development  
**Next Milestone:** Free breach data sources + Sherlock integration
