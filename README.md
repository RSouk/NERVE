# Ghost
Project Ghost
# GHOST - Person Intelligence Platform

**Version:** 0.2.0  
**Started:** October 22, 2025

## What is Ghost?

Ghost is a person intelligence and attack surface analysis platform designed for penetration testers and security researchers. It aggregates OSINT data, breach information, IoT exposure, and social engineering attack vectors into a unified intelligence platform.

**Think:** Hudson Rock's Cavalier + physical security mapping + social engineering automation

## Current Status (Oct 22, 2025)

### ✅ What's Working
- **Backend API** - Flask-based REST API running on localhost:5000
- **Database** - SQLite with persistent storage for profiles, breaches, social media, devices
- **Frontend UI** - Clean web interface for creating and managing target profiles
- **Profile Management** - Create, search, view, and delete profiles
- **Breach Scanning Infrastructure** - Ready to integrate breach data sources

### 🚧 In Progress
- **HIBP Integration** - Infrastructure built, needs API key ($3.50/month) or free alternative
- **Risk Scoring** - Basic algorithm in place, needs refinement
- **Data Collection** - Need to add free OSINT sources

### 📋 Planned Features
- **Watchtower Module** - IoT/camera/device exposure tracking (Shodan/Censys integration)
- **Shadow Module** - Network and device intelligence
- **Oracle Module** - Predictive AI for attack scenario generation
- **Social Media Scanning** - Automated discovery across 300+ platforms
- **Detailed Profile Views** - Comprehensive intelligence dashboards
- **Export Capabilities** - PDF reports, JSON exports

## Project Structure

```
Ghost/
├── backend/
│   ├── app.py           # Main Flask API server
│   ├── database.py      # SQLAlchemy models and DB setup
│   ├── osint.py         # OSINT data collection functions
│   └── config.py        # Configuration (unused currently)
├── frontend/
│   └── index.html       # Web UI
├── data/
│   └── ghost.db         # SQLite database (auto-generated)
├── docs/                # Documentation (future)
├── venv/                # Python virtual environment
├── .env                 # Environment variables (API keys)
├── .gitignore           # Git ignore rules
└── README.md            # This file
```

## Setup Instructions

### Prerequisites
- Python 3.11+ installed
- Git installed
- VS Code (recommended)

### Installation

1. **Clone the repository**
```bash
git clone <your-repo-url>
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
pip install flask flask-cors sqlalchemy requests beautifulsoup4 python-dotenv
```

5. **Set up environment variables**
Create a `.env` file in the Ghost folder:
```
HIBP_API_KEY=your_key_here
```

6. **Run the backend**
```bash
cd backend
python app.py
```

7. **Open the frontend**
Open `frontend/index.html` in your web browser

## Usage

### Creating a Profile
1. Fill in target information in the left panel
2. Click "Create Profile"
3. Profile appears in the right panel

### Scanning for Breaches
1. Click "🔍 Scan Breaches" on any profile
2. System checks Have I Been Pwned for breach data
3. Risk score updates automatically based on findings

**Note:** Currently requires HIBP API key. Free alternatives coming soon.

## API Endpoints

- `GET /` - API status and version info
- `GET /api/profiles` - List all profiles
- `GET /api/profile/<id>` - Get detailed profile
- `POST /api/create` - Create new profile
- `POST /api/scan/breaches/<id>` - Scan profile for breaches
- `GET /api/search?q=<query>` - Search profiles
- `DELETE /api/profile/<id>` - Delete profile

## Database Schema

### Profiles Table
- id (String, primary key)
- name, email, username, phone
- notes (Text)
- risk_score (Float, 0-100)
- breach_count (Integer)
- created_at, updated_at (DateTime)

### Breaches Table
- profile_id (Foreign key)
- breach_name, breach_date
- data_classes (Text)

### Social Media Table (ready for future use)
- profile_id (Foreign key)
- platform, username, url
- followers, posts_count

### Devices Table (ready for Watchtower module)
- profile_id (Foreign key)
- ip_address, hostname, device_type
- ports_open, vulnerabilities
- location

## Development Notes

### Why This Approach?
- **Modular Design** - Each intelligence type (person, device, social) is separate
- **Free First** - Prioritizing free data sources before paid APIs
- **Pentesting Focus** - Built for recon phases of security assessments
- **Incremental Build** - Start simple, add complexity as needed

### Tech Stack Decisions
- **Flask** - Lightweight, easy to extend
- **SQLite** - No server needed, portable database
- **Vanilla JS** - No framework overhead, fast iteration
- **SQLAlchemy** - Future-proof for PostgreSQL if needed

### Next Session Priorities
1. Add free breach data sources (public breach compilations, Google dorking)
2. Build Sherlock integration for social media discovery
3. Create detailed profile view page
4. Start Watchtower module (Shodan integration)

## Known Issues

- HIBP requires paid API key ($3.50/month)
- No authentication/authorization (local use only)
- Frontend needs use UI/UX improvements
- Risk scoring algorithm is basic

## Security Considerations

⚠️ **This tool handles sensitive data. Use responsibly.**

- Only use on authorized targets (pentesting contracts, your own data)
- Keep `.env` file secure (never commit to GitHub)
- Database contains PII - encrypt if storing long-term
- Follow local laws regarding data collection

## Long-Term Vision

**Public Platform (Ghost Core)**
- Corporate security teams
- Penetration testers
- Security researchers
- Law enforcement (vetted)

**Government Platform (Nerve)**
- Military/intelligence only
- Full capabilities (location tracking, intercepts, etc.)
- Heavily vetted customers

## Contributing

This is a personal project but open to collaboration. If you want to contribute:
- Fork the repo
- Create feature branch
- Submit PR with clear description

## License

TBD - Currently private/personal use

## Contact

Built by: [Your Name]
For: Penetration testing and security research

---

**Last Updated:** October 22, 2025  
**Status:** Active Development  
**Next Milestone:** Free breach data sources + Sherlock integration
