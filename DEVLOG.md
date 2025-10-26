# Ghost Platform - Development Log

## October 22, 2025 - Day 1: Foundation & Infrastructure

### Session Overview
First day of building Ghost - Person Intelligence Platform. Focus was on establishing core infrastructure, database architecture, and basic functionality.

### What We Built

#### 1. Project Structure
```
Ghost/
├── backend/
│   ├── app.py          # Flask REST API (172 lines)
│   ├── database.py     # SQLAlchemy models (88 lines)
│   ├── osint.py        # OSINT collection functions (150 lines)
│   └── config.py       # (placeholder)
├── frontend/
│   └── index.html      # Web UI (400+ lines)
├── data/
│   └── ghost.db        # SQLite database (auto-generated)
├── .env                # Environment variables
├── .gitignore          # Git ignore rules
├── README.md           # Project documentation
└── requirements.txt    # Python dependencies
```

#### 2. Backend API (Flask)
**Endpoints Created:**
- `GET /` - API status and version
- `GET /api/profiles` - List all profiles
- `GET /api/profile/<id>` - Get detailed profile
- `POST /api/create` - Create new profile
- `POST /api/scan/breaches/<id>` - Scan for breaches
- `GET /api/search?q=<query>` - Search profiles
- `DELETE /api/profile/<id>` - Delete profile

**Key Features:**
- Flask-CORS enabled for frontend communication
- JSON API responses
- Error handling for 404s
- Debug mode for development

#### 3. Database Schema (SQLAlchemy + SQLite)
**Tables Created:**

**Profiles**
- id (String, primary key) - Format: `target_N_YYYYMMDD`
- name, email, username, phone (String)
- notes (Text)
- risk_score (Float, 0-100)
- breach_count (Integer)
- created_at, updated_at (DateTime)
- Social media JSON, exposed passwords, data leaks (Text fields)

**Breaches**
- profile_id (Foreign key)
- breach_name, breach_date (String)
- data_classes (Text) - Types of data leaked
- discovered_at (DateTime)

**Social Media** (ready for future use)
- profile_id, platform, username, url
- followers, posts_count
- discovered_at

**Devices** (ready for Watchtower module)
- profile_id, ip_address, hostname, device_type
- ports_open, vulnerabilities, location
- discovered_at

#### 4. OSINT Module (osint.py)
**Functions Implemented:**
- `check_hibp_breaches(email)` - Check Have I Been Pwned API
- `scan_profile_breaches(profile_id)` - Full breach scan workflow
- `calculate_risk_score(profile_id)` - Risk scoring algorithm

**Risk Scoring Logic:**
- Base: 10 points per breach (max 60)
- +15 points if passwords exposed
- +20 points if financial data exposed
- +25 points if SSN exposed
- Capped at 100

#### 5. Frontend UI (index.html)
**Features Built:**
- Dark theme interface (purple/blue gradient)
- Two-panel layout: Create Profile | View Profiles
- Profile cards with risk badges (green/yellow/red)
- Search functionality (live filtering)
- "Scan Breaches" button per profile
- "View Details" button (placeholder)
- Success/error notifications
- Responsive grid layout

**UI Components:**
- Form inputs for profile creation
- Real-time search box
- Profile cards with actions
- Status messages
- Empty states

### Technical Decisions Made

#### Why Flask?
- Lightweight, easy to extend
- Perfect for MVP/prototyping
- Can scale to production with gunicorn
- Extensive library ecosystem

#### Why SQLite?
- No server setup required
- Portable database file
- Good enough for 1000s of profiles
- Easy to backup/transfer
- Can migrate to PostgreSQL later if needed

#### Why Vanilla JavaScript?
- No build process or framework overhead
- Fast iteration during development
- Easy to understand for future maintainers
- Can refactor to React later if needed

#### Why SQLAlchemy ORM?
- Database abstraction (easy to switch DB later)
- Built-in migrations support
- Type safety and validation
- Relationship management

### Issues Encountered & Resolved

#### Issue 1: PowerShell Script Execution
**Problem:** `.\venv\Scripts\Activate` failed with security error
**Solution:** `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`

#### Issue 2: Emoji Characters in Terminal
**Problem:** 🚀 and 📍 emojis caused Flask to exit silently
**Solution:** Removed emojis from print statements in `app.py`

#### Issue 3: Flask-CORS Not Installed
**Problem:** `ModuleNotFoundError: No module named 'flask_cors'`
**Solution:** `pip install flask-cors`

#### Issue 4: SQLAlchemy Not Installed
**Problem:** `ModuleNotFoundError: No module named 'sqlalchemy'`
**Solution:** `pip install sqlalchemy`

#### Issue 5: Frontend Updates Not Showing
**Problem:** Browser cached old HTML
**Solution:** Hard refresh (Ctrl+Shift+R) and full artifact rewrite

#### Issue 6: Breach Scan Endpoint 404
**Problem:** `/api/scan/breaches/<id>` endpoint missing from app.py
**Solution:** Added endpoint manually (artifact update didn't apply)

#### Issue 7: HIBP API Requires Key
**Problem:** Have I Been Pwned returns 401 Unauthorized
**Status:** Known limitation - HIBP now requires $3.50/month API key
**Next Step:** Add free alternative breach sources

#### Issue 8: Git Not Initialized
**Problem:** `fatal: not a git repository`
**Solution:** `git init` then connect to GitHub repo

### What's Working

✅ **Profile Management**
- Create profiles with name, email, username, phone, notes
- Profiles persist across server restarts
- Search profiles by name or email
- View all profiles in clean UI
- Delete profiles (backend ready, UI pending)

✅ **Database**
- SQLite file generated in `/data/ghost.db`
- All tables created automatically
- Relationships properly defined
- DateTime fields auto-populate

✅ **API Server**
- Flask running on localhost:5000
- All endpoints responding
- CORS enabled for local frontend
- Debug mode shows request logs

✅ **UI/UX**
- Forms work correctly
- Real-time search filters profiles
- Profile cards display properly
- Risk scores show with color coding
- Buttons trigger API calls

### What's NOT Working

❌ **Breach Scanning**
- HIBP API requires paid key ($3.50/month)
- Infrastructure built but no free data source yet
- Returns "HIBP API key required" error
- Risk scores stuck at 0 until breach data available

❌ **Profile Details View**
- "View Details" button just shows alert
- Need to build detailed profile page
- Should show all OSINT data, breaches, social media, devices

❌ **Social Media Discovery**
- Table exists but no collection mechanism
- Need to integrate Sherlock or similar
- No UI for displaying social accounts yet

❌ **Device/IoT Scanning**
- Watchtower module not started
- No Shodan/Censys integration yet
- Table ready but unused

❌ **Export Functionality**
- Can't export profiles to PDF/JSON
- No reporting features yet

### Dependencies Installed
```
flask==3.1.2
flask-cors==6.0.1
sqlalchemy==2.0.x
requests==2.31.0
beautifulsoup4==4.12.x
python-dotenv==1.0.x
```

### Configuration Files Created

**.env**
```
HIBP_API_KEY=your_key_here_when_you_get_it
```

**.gitignore**
- Ignores venv/, .env, *.db, __pycache__, IDE files

### Git Repository
- **Repo:** https://github.com/RSouk/Ghost
- **Initial Commit:** "Initial Ghost platform - Profile management and breach scanning infrastructure"
- **Status:** Public repository
- **Commits:** 2 (initial + merge)

### Lessons Learned

1. **Artifact updates can fail silently** - Always verify code changes actually applied to files
2. **Browser caching is aggressive** - Use hard refresh during dev
3. **Free APIs aren't always free** - HIBP changed to paid, need backup sources
4. **PowerShell security can block scripts** - Document workarounds
5. **Emojis break terminals** - Stick to ASCII for console output
6. **Start with .gitignore immediately** - Prevents committing sensitive files

### Phase 1 - TODO (Foundation Completion)

Before moving to Phase 2 (UI redesign), we must complete:

#### Critical Path Items
1. **Add free breach data sources**
   - Public breach compilation databases
   - Leaked password lists (processed securely)
   - Google dorking for exposed credentials
   - Alternative APIs (DeHashed free tier, etc.)

2. **Social media discovery**
   - Integrate Sherlock for username enumeration
   - Add social media account table population
   - Display findings in profile view

3. **Build detailed profile view page**
   - Show all collected data
   - Display breach details
   - Social media accounts list
   - Timeline of discoveries
   - Export button

4. **Robust error handling**
   - API timeouts
   - Invalid input validation
   - Database connection errors
   - Rate limiting handling

5. **Testing & validation**
   - Test with 50+ profiles
   - Verify database integrity
   - Check all API endpoints
   - Browser compatibility

#### Nice-to-Have Items
- Batch profile import (CSV)
- Profile notes with timestamps
- Risk score history tracking
- Automated daily rescans
- Email notifications for new findings

### Next Session Priorities

**Tomorrow (Oct 23):**
1. Add free breach data sources (priority #1)
2. Integrate basic social media discovery
3. Build detailed profile view page
4. Add better error messages to UI
5. Test everything thoroughly

**Do NOT start yet:**
- UI redesign (that's Phase 2)
- Opsych aesthetic integration
- IoT/device scanning (Watchtower)
- AI/prediction features (Oracle)

### Notes for Future Sessions

**When Chat Limits Hit:**
Share this devlog + README.md to resume context. Key files to reference:
- `backend/app.py` (API endpoints)
- `backend/database.py` (schema)
- `backend/osint.py` (data collection)
- `frontend/index.html` (UI)

**GitHub Workflow:**
```bash
git pull origin main          # Get latest
# make changes
git add .
git commit -m "Description"
git push origin main
```

**Running the Platform:**
```bash
cd C:\Projects\Ghost
.\venv\Scripts\Activate
cd backend
python app.py
# Open frontend/index.html in browser
```

### Vision Alignment Check

Today confirmed Ghost is:
- ✅ Offensive intelligence tool (not defensive monitoring like Opsych)
- ✅ For pentesters/researchers analyzing targets
- ✅ Modular architecture (can add capabilities incrementally)
- ✅ Free-first approach (paid APIs only when necessary)

Will incorporate Opsych concepts in Phase 2:
- Black/gold aesthetic
- Attacker View digital twin
- Psychological vulnerability profiling
- Inference engine for attack scenarios
- Beautiful risk visualization

### Stats
- **Time invested:** ~4 hours
- **Lines of code:** ~800+
- **API endpoints:** 7
- **Database tables:** 4
- **Features working:** 5
- **Known issues:** 5
- **Git commits:** 2

### End of Day 1

**Status:** Foundation infrastructure complete, Phase 1 ~40% done
**Next milestone:** Free data sources + functional breach scanning
**Blocker:** Need alternatives to paid HIBP API

---## October 23, 2025 - Evening: Architecture Pivot

### Major Decision: Search-First Architecture

**Changed from:**
- Profile-based system (create profile → scan → view)

**Changed to:**
- Search-first system (search anything → auto-detect → query all sources → results)

**Reason:** Industry standard for CTI platforms (Hudson Rock, Intelligence X model)

### New Files Created

**backend/search_engine.py** - Query type detection
- Auto-detects: email, domain, IP, CIDR, username, password, keyword
- Returns applicable data sources for each type
- Validates queries before searching

**backend/unified_search.py** - Search orchestrator
- Routes searches to all applicable sources
- Aggregates results from multiple APIs
- Error handling per source
- Returns unified results

**backend/hudson_rock.py** - Hudson Rock API integration
- Email search
- Domain search
- Password search
- Free infostealer API access

### Architecture Changes

**Search Type Support:**
- Email → Hudson Rock, LeakCheck, BreachDirectory, Local files
- Domain → Hudson Rock, Intelligence X, URLScan
- Password → Hudson Rock, Local files
- Username → Hudson Rock, Local files
- IP/CIDR → Hudson Rock, Feodo Tracker, Criminal IP
- Keyword → Hudson Rock, Intelligence X, Pastebin

**Unified Search Flow:**
1. User enters any query
2. System auto-detects type
3. Queries all applicable sources in parallel
4. Aggregates results
5. Returns unified response

### API Keys Added

- Hudson Rock: MdBmjE4lF1_2YHD3PZL2W0XXhn.VtNTYQfJ3wClmCxx9cChelzXBJaP1JkfxmRQA
- Intelligence X: 463eb54d-bf1f-4346-b085-409e98e77212

### Testing Results

**Email Search (test@adobe.com):**
- LeakCheck: 4 breaches found
- Hudson Rock: 0 results (not in stealer logs)
- BreachDirectory: 0 results
- Time: 7.24s

**Domain Search (example.com):**
- Hudson Rock: 0 results
- Time: 0.6s

### Next Steps (Sprint 1 Continued)

1. ✅ Unified search architecture - DONE
2. 🔄 Add Intelligence X integration
3. ⬜ Build search results API endpoint
4. ⬜ Rebuild frontend for search-first UI
5. ⬜ Add investigation save/history
6. ⬜ Add Telegram monitoring
7. ⬜ Add botnet data sources

---

**Status:** Sprint 1 - 40% complete (architecture foundation done)
**Next Session:** Build search API endpoint, start on new UI

------

## October 25, 2025 - Hudson Rock Integration Success

### Breakthrough: Real Stealer Data

**Fixed Hudson Rock API integration:**
- Correct endpoint: `/search-by-login/emails` (not `/search-by-email`)
- Correct payload: `{"logins": [email]}` array format
- Proper response parsing: `data.data` structure

**Results:**
- Successfully querying stealer logs
- Returning detailed infection data:
  - Stealer family (Lumma, Raccoon, etc.)
  - Date compromised
  - Computer name, OS, IP
  - Credentials count (354+ in test case)
  - Exposed URLs/domains
  - Employee/client associations

### UI Improvements

**Frontend now displays:**
- Hudson Rock stealer details with formatting
- Credential counts in red
- Computer information
- Company associations (employeeAt)
- Scrollable cards for long results

**Known issue:** Cards overflow with long data - needs CSS fix

### Hudson Rock Capabilities Available

**Implemented:**
- ✅ Email search (working)
- ✅ Domain search (endpoint ready)
- ✅ Password search (endpoint ready)

**Available but not yet implemented:**
- Username search
- IP/CIDR search
- Stealer-specific search
- Keyword search
- File search
- Advanced search with filters

### Test Results

**Email:** danieljohnwild@gmail.com
- Hudson Rock: 3 stealer logs found
  - Lumma (2025-01-24): 354 credentials
  - Raccoon (2023-05-18): 160 credentials
  - Additional infections with company data
- LeakCheck: 4 breaches (Coinmama, Twitter, LuminPDF, Stealer Logs)
- Total: 7 findings across 2 sources
- Search time: 2.67s

### Next Steps for Module 1 (GHOST)

**Sprint 1 Remaining:**
1. ⬜ Fix UI overflow (CSS updates)
2. ⬜ Add remaining Hudson Rock endpoints (username, IP, keyword)
3. ⬜ Intelligence X integration
4. ⬜ Telegram breach monitoring setup
5. ⬜ Local file optimization

**Sprint 2: Data Enhancement**
1. Show actual passwords (when available)
2. Credential detail view
3. Timeline visualization
4. Export functionality
5. Investigation save/history

**Sprint 3: Dashboard & Navigation**
1. Main dashboard with statistics
2. Custom RSS news feed
3. Left sidebar navigation for modules
4. Module switcher (GHOST ↔ OPSYCH ↔ WATCHTOWER)

### Platform Vision Update

**NERVE Platform Structure:**

**Main Dashboard (Landing Page):**
- Platform statistics
- Recent searches/investigations
- Threat intel news feed (custom RSS)
- Quick search bar

**Left Sidebar Navigation:**
- 🔍 GHOST - Credential Intelligence
- 🧠 OPSYCH - Social Engineering Intel (Phase 2)
- 📡 WATCHTOWER - IoT/Physical Security (Phase 3)
- 🔮 ORACLE - Predictive Intelligence (Phase 4)
- [Module 5] - TBD

**Each module gets its own interface, all accessible from main nav.**

---

**Status:** Module 1 (GHOST) ~50% complete
**Next Session:** Fix UI, add remaining Hudson Rock endpoints, start dashboard design
**Blocker:** None - all core systems working

## October 26, 2025 - All Search Types Implemented (50% Complete)

### 🎯 GHOST Module Progress: 25% → 50%

**Session Focus:** Add missing search capabilities and fix API integrations

### ✅ Completed Features:

**Search Types (All Working):**
- Email search (Hudson Rock + LeakCheck)
- Domain search (Hudson Rock)
- Username search (Hudson Rock)
- IP address search (Hudson Rock)
- Keyword search (Hudson Rock)
- Password search (disabled - paid tier required)

**Data Sources:**
- Hudson Rock: 5/6 endpoints working
- LeakCheck: Active
- BreachDirectory: Active (rate limited)
- Intelligence X: API issues (deferred)

**Frontend:**
- GHOST logo integrated
- 6 search type examples
- Filters by type and source
- Professional UI maintained

### 🐛 Bugs Fixed:
1. Hudson Rock domain search payload (domains → array)
2. Hudson Rock IP search payload (ips → array) + endpoint
3. Data type categorization (domain_exposure/ip_exposure → infostealer_logs)
4. Indentation bug causing type mismatch in returns
5. Search routing (removed conditional - all sources query)

### 📊 Current Capabilities:
- 5 active search types
- 3 working data sources
- ~18,000+ credentials searchable
- Real-time stealer log analysis
- Multi-source breach aggregation

### 🚀 Next Phase: Adversary Intelligence (WOW Factor)
**Goal:** Build personalized threat actor matching
- Input: Industry, tech stack, location
- Output: Specific APT groups that will target you
- Show: TTPs, attack chains, recent campaigns
- **Differentiator:** Nobody else does personalized threat matching

**Target:** 60-70% completion after adversary module

## October 26, 2025 - Adversary Intelligence System Built (60% Complete)

### 🎯 GHOST Module Progress: 50% → 60%

**Session Focus:** Build the WOW factor - Personalized threat actor matching

### ✅ Completed Features:

**Adversary Intelligence Module:**
- Scraped 863 threat actors from MISP Galaxy
- Built intelligent matching algorithm with 10-factor analysis
- Personalized risk explanations per organization profile
- Real-time TTP extraction from threat descriptions
- Attack scenario generation based on user's attack surface

**Matching Factors (100 points total):**
- Industry targeting (35 points) - 12 sectors mapped
- Geographic targeting (25 points) - 6 regions mapped
- Tech stack preferences (20 points)
- Attack surface exploitation (10 points)
- Data value assessment (10 points)

**UI Features:**
- Color-coded threat levels with pulsing animations
- Multi-select checkboxes for critical assets
- Detailed threat cards showing origin, sophistication, TTPs
- Match confidence scoring with explanations
- Warning icons (⚠️ critical, 🔴 high, 🟡 moderate)

### 📊 Data Quality:
- 863 total threat actors loaded
- 128 actors with industry targeting data (15%)
- 146 actors with geographic targeting data (17%)
- 402 actors with origin attribution (47%)
- Sophistication levels inferred from state sponsorship

### 💡 Key Insights:
- Users need 4+ matching factors to reach 80%+ threat scores
- Financial sector + Windows infrastructure = highest match rates
- State-sponsored groups (China, Russia, Iran, NK) get "Advanced" rating
- Match threshold set at 30% to reduce false positives

### 🎨 Design Decisions:
- Checkbox UI for multi-select (better than Ctrl+Click dropdowns)
- Pulsing red borders for critical threats (80%+)
- Bottom note explaining scoring methodology
- Risk explanations personalized to user's specific profile

### 🚀 Next Phase: Data Enhancement
**Goals:**
- Add Telegram breach channel scrapers
- Integrate more real-time threat feeds
- Add export/report functionality
- Enhance MISP data with manual curation of top 50 APTs
- Add threat trend analysis over time

**Target:** 70% completion after Telegram integration
---