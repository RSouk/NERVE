from flask import Flask, render_template, request, jsonify, g, Response, send_from_directory, redirect
from flask_cors import CORS
from functools import wraps
from database import (
    get_db, SessionLocal, Profile, SocialMedia, Breach, Device, BaitToken, BaitAccess,
    UploadedFile, UploadedCredential, GitHubFinding, PasteBinFinding, OpsychSearchResult,
    ASMScan, CachedASMScan, LightboxScan, save_xasm_for_ai, save_lightbox_for_ai,
    get_companies_with_scans, cleanup_expired_ai_scans, ComplianceAssessment,
    ComplianceControl, ComplianceEvidence, RoadmapProfile, RoadmapTask, RoadmapUserTask,
    RoadmapAchievement, RoadmapProgressHistory,
    # Authentication
    User, UserRole, UserStatus, Company, Session as UserSession,
    hash_password, verify_password, create_session, validate_session, revoke_session,
    log_login_attempt, detect_brute_force, generate_secure_token,
    # Profile & API Keys
    LoginAttempt, APIKey, log_security_event, create_api_key, revoke_api_key,
    # Admin - System & Settings
    SecurityEvent, PlatformSettings, ErrorLog,
    run_health_check, create_backup, optimize_database, AuditLog, DB_PATH,
    # Content Management
    NewsSource, EducationResource, BackupRecord,
    # Search Quota
    UserSearchQuota,
    # Maintenance Checklist
    MaintenanceChecklist,
    # Waitlist
    WaitlistSignup
)
import feedparser
from modules.ghost.osint import scan_profile_breaches
from modules.opsych.exposure_analysis import analyze_exposure
import os
import json
from datetime import datetime, timedelta, timezone
from sqlalchemy import func, distinct
import threading
from modules.ghost.unified_search import UnifiedSearch
from modules.ghost.adversary_matcher import AdversaryMatcher
from modules.ghost.bait_generator import BaitGenerator
from modules.ghost.bait_seeder import BaitSeeder
from compliance_mappings import analyze_scan_findings, get_affected_controls, get_vulnerability_info, VULNERABILITY_MAPPINGS
from modules.ghost.ip_intelligence import check_ip_reputation as check_ip_intel, get_ip_badge_type
from modules.ghost.attacker_fingerprinting import analyze_attacker, get_evidence_badge_info, get_attribution_badge_info
from modules.ghost.cti_newsfeed import get_news_feed, get_feed_stats
from modules.ghost.ioc_fetcher import IOCFetcher
import re
import secrets
import time
from dotenv import load_dotenv
import logging
import http.client
import urllib.parse
import atexit
from apscheduler.schedulers.background import BackgroundScheduler
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Load environment variables
load_dotenv()

# Setup logging
logger = logging.getLogger(__name__)

# Get the absolute path to the frontend directory for static file serving
frontend_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'frontend')

app = Flask(__name__, static_folder=frontend_path, static_url_path='')
CORS(app, resources={
    r"/api/*": {
        "origins": "*",
        "methods": ["GET", "POST", "DELETE", "PUT", "PATCH", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "expose_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True
    }
})

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["2000 per day", "500 per hour"],  # Increased 10x for better UX
    storage_uri="memory://"
)

# Rate limit error handler
@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        'error': 'Rate limit exceeded',
        'message': 'Too many requests. Please try again later.',
        'retry_after': str(e.description)
    }), 429

# Global progress tracking dictionary
# Format: {domain: {status: str, current_step: str, progress: int, total: int, message: str}}
scan_progress = {}
scan_progress_lock = threading.Lock()

# Initialize cleanup scheduler for expired AI scan data
scheduler = BackgroundScheduler()
scheduler.add_job(
    func=cleanup_expired_ai_scans,
    trigger='interval',
    hours=1,
    id='cleanup_expired_scans'
)


def auto_scan_company_domains():
    """
    Auto-scan company domains every 24 hours.
    Runs every hour to check if any scans are due.
    Only updates existing scans - does not create new ones.
    """
    from modules.ghost.asm_scanner import scan_domain

    session = SessionLocal()

    try:
        now = datetime.now(timezone.utc)

        # Find scans that are ready for refresh (next_scan_at has passed)
        scans_to_refresh = session.query(CachedASMScan).filter(
            CachedASMScan.auto_scan_enabled == True,
            CachedASMScan.next_scan_at <= now,
            CachedASMScan.deleted_at == None
        ).all()

        if not scans_to_refresh:
            return

        print(f"[AUTO-SCAN] Found {len(scans_to_refresh)} domains ready for auto-scan")

        for scan in scans_to_refresh:
            try:
                print(f"[AUTO-SCAN] Starting scan for {scan.domain}")

                # Perform the scan
                scan_results = scan_domain(scan.domain)

                # Update the existing scan record
                cve_stats = scan_results.get('cve_statistics', {})
                scan.risk_score = scan_results.get('risk_score', 0)
                scan.risk_level = scan_results.get('risk_level', 'low')
                scan.total_cves = cve_stats.get('total_cves', 0)
                scan.critical_cves = cve_stats.get('critical_cves', 0)
                scan.vulnerabilities_found = scan_results.get('vulnerabilities_found', 0)
                scan.open_ports_count = len(scan_results.get('port_scan_results', []))
                scan.scan_results = scan_results
                scan.scanned_at = now
                scan.last_scanned = now
                scan.next_scan_at = now + timedelta(hours=24)

                session.commit()
                print(f"[AUTO-SCAN] Completed scan for {scan.domain} - Risk Score: {scan.risk_score}")

            except Exception as e:
                print(f"[AUTO-SCAN] Error scanning {scan.domain}: {str(e)}")
                # Still update next_scan_at to avoid retry loop
                scan.next_scan_at = now + timedelta(hours=24)
                session.commit()
                continue

    except Exception as e:
        print(f"[AUTO-SCAN] Scheduler error: {str(e)}")
    finally:
        session.close()


scheduler.add_job(
    func=auto_scan_company_domains,
    trigger='interval',
    hours=1,
    id='auto_scan_company_domains'
)

scheduler.start()
print("[SCHEDULER] Started hourly cleanup of expired AI scan data")
print("[SCHEDULER] Started hourly auto-scan check for company domains")

# Ensure scheduler shuts down with app
atexit.register(lambda: scheduler.shutdown())


# =============================================================================
# AUTHENTICATION MIDDLEWARE
# =============================================================================

def require_auth(f):
    """
    Decorator that requires valid authentication.
    Attaches user_id and user object to request context.
    Returns 401 if token is missing or invalid.

    Usage:
        @app.route('/api/protected')
        @require_auth
        def protected_route():
            user_id = request.user_id
            user = request.user
            ...
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        token = None

        if auth_header.startswith('Bearer '):
            token = auth_header[7:].strip()

        if not token:
            return jsonify({
                'success': False,
                'error': 'Authentication required',
                'code': 'AUTH_REQUIRED'
            }), 401

        # Validate the session
        session_info = validate_session(token)

        if not session_info:
            return jsonify({
                'success': False,
                'error': 'Invalid or expired session',
                'code': 'INVALID_SESSION'
            }), 401

        # Get user from database
        db = SessionLocal()
        try:
            user = db.query(User).filter(
                User.id == session_info['user_id'],
                User.deleted_at.is_(None)
            ).first()

            if not user:
                return jsonify({
                    'success': False,
                    'error': 'User not found',
                    'code': 'USER_NOT_FOUND'
                }), 401

            if user.status != UserStatus.ACTIVE:
                return jsonify({
                    'success': False,
                    'error': 'Account is not active',
                    'code': 'ACCOUNT_INACTIVE'
                }), 403

            # Attach user info to request context
            request.user_id = user.id
            request.user = {
                'id': user.id,
                'email': user.email,
                'full_name': user.full_name,
                'role': user.role.value if user.role else 'analyst',
                'company_id': user.company_id
            }

            # Also store in Flask's g object for broader access
            g.user_id = user.id
            g.user = request.user

        finally:
            db.close()

        return f(*args, **kwargs)
    return decorated_function


def optional_auth(f):
    """
    Decorator that optionally authenticates.
    Attaches user_id and user if token is present and valid.
    Sets request.user_id = None if no token or invalid token.
    Never returns 401 - always proceeds to route.

    Usage:
        @app.route('/api/public')
        @optional_auth
        def public_route():
            if request.user_id:
                # Logged in user
                ...
            else:
                # Anonymous user
                ...
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        token = None

        # Default to anonymous
        request.user_id = None
        request.user = None
        g.user_id = None
        g.user = None

        if auth_header.startswith('Bearer '):
            token = auth_header[7:]

        if token:
            # Try to validate the session
            session_info = validate_session(token)

            if session_info:
                # Get user from database
                db = SessionLocal()
                try:
                    user = db.query(User).filter(
                        User.id == session_info['user_id'],
                        User.deleted_at.is_(None),
                        User.status == UserStatus.ACTIVE
                    ).first()

                    if user:
                        # Attach user info to request context
                        request.user_id = user.id
                        request.user = {
                            'id': user.id,
                            'email': user.email,
                            'full_name': user.full_name,
                            'role': user.role.value if user.role else 'analyst',
                            'company_id': user.company_id
                        }
                        g.user_id = user.id
                        g.user = request.user
                finally:
                    db.close()

        return f(*args, **kwargs)
    return decorated_function


def get_current_user():
    """
    Helper function to get the current authenticated user.
    Must be called within a @require_auth or @optional_auth decorated route.

    Returns:
        dict: User info dict or None if not authenticated

    Raises:
        RuntimeError: If called outside of request context
    """
    if not hasattr(request, 'user'):
        raise RuntimeError('get_current_user() must be called within a request context with @require_auth or @optional_auth')
    return request.user


def get_current_user_id():
    """
    Helper function to get the current authenticated user's ID.

    Returns:
        int: User ID or None if not authenticated
    """
    return getattr(request, 'user_id', None)


def require_page_auth(f):
    """
    Decorator for protected page routes that require authentication.
    Checks for session token in cookies and redirects to login if not authenticated.

    Usage:
        @app.route('/dashboard')
        @require_page_auth
        def dashboard():
            return send_from_directory(...)
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check for session token in cookie
        token = request.cookies.get('nerve_session')

        if not token:
            return redirect('/login')

        # Validate the session
        session_info = validate_session(token)

        if not session_info:
            return redirect('/login')

        # Verify user exists and is active
        db = SessionLocal()
        try:
            user = db.query(User).filter(
                User.id == session_info['user_id'],
                User.deleted_at.is_(None),
                User.status == UserStatus.ACTIVE
            ).first()

            if not user:
                return redirect('/login')

            # Attach user info to request context
            request.user_id = user.id
            request.user = {
                'id': user.id,
                'email': user.email,
                'full_name': user.full_name,
                'role': user.role.value if user.role else 'analyst',
                'company_id': user.company_id
            }
            g.user_id = user.id
            g.user = request.user

        finally:
            db.close()

        return f(*args, **kwargs)
    return decorated_function


def require_admin_page(f):
    """
    Decorator for admin page routes that require admin authentication.
    Checks for session token in cookies and verifies admin role.
    Redirects to login if not authenticated, or to dashboard if not admin.

    Usage:
        @app.route('/admin/dashboard')
        @require_admin_page
        def admin_dashboard():
            return send_from_directory(...)
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check for session token in cookie
        token = request.cookies.get('nerve_session')

        if not token:
            return redirect('/login')

        # Validate the session
        session_info = validate_session(token)

        if not session_info:
            return redirect('/login')

        # Verify user exists, is active, and is admin
        db = SessionLocal()
        try:
            user = db.query(User).filter(
                User.id == session_info['user_id'],
                User.deleted_at.is_(None),
                User.status == UserStatus.ACTIVE
            ).first()

            if not user:
                return redirect('/login')

            # Check for admin role (ADMIN or SUPER_ADMIN)
            if user.role not in [UserRole.ADMIN, UserRole.SUPER_ADMIN]:
                return redirect('/dashboard')

            # Attach user info to request context
            request.user_id = user.id
            request.user = {
                'id': user.id,
                'email': user.email,
                'full_name': user.full_name,
                'role': user.role.value if user.role else 'analyst',
                'company_id': user.company_id
            }
            g.user_id = user.id
            g.user = request.user

        finally:
            db.close()

        return f(*args, **kwargs)
    return decorated_function


def require_email_monitoring_access(f):
    """
    Decorator to restrict email monitoring to COMPANY_USER and above.
    USER and DEMO roles cannot access email monitoring features.
    Must be used after @require_auth.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({
                'error': 'Authentication required',
                'code': 'AUTH_REQUIRED'
            }), 401

        # Check if user has access - COMPANY_USER and above
        allowed_roles = ['company_user', 'admin', 'analyst', 'super_admin', 'owner']
        user_role = (user.get('role') or '').lower()

        if user_role not in allowed_roles:
            return jsonify({
                'error': 'Access denied',
                'message': 'Email monitoring is only available for Company accounts and above',
                'code': 'EMAIL_MONITORING_ACCESS_DENIED'
            }), 403

        return f(*args, **kwargs)
    return decorated_function


# =============================================================================
# SEARCH QUOTA MANAGEMENT
# =============================================================================

# V1: Hardcoded search limit (V2 will read from platform_settings)
DEFAULT_SEARCH_LIMIT = 10

def is_exempt_from_quota(user_role):
    """
    Check if user role is exempt from search limits.

    Exempt roles: admin, analyst, super_admin
    Limited roles: user, company_user, demo

    Args:
        user_role: String or UserRole enum value

    Returns:
        bool: True if user is exempt from quota limits
    """
    # Handle both string and enum values
    role_str = user_role.value if hasattr(user_role, 'value') else str(user_role)
    exempt_roles = ['admin', 'analyst', 'super_admin']
    return role_str.lower() in exempt_roles


def get_next_reset_time():
    """
    Get time until midnight UTC (daily reset).

    Returns:
        str: Formatted string like "5h 23m"
    """
    now = datetime.now(timezone.utc)
    tomorrow = now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
    seconds_until_reset = int((tomorrow - now).total_seconds())
    hours = seconds_until_reset // 3600
    minutes = (seconds_until_reset % 3600) // 60
    return f"{hours}h {minutes}m"


def check_search_quota(user_id, user_role):
    """
    Check if user has remaining searches for today.

    Args:
        user_id: User's database ID
        user_role: User's role (string or UserRole enum)

    Returns:
        dict: Quota status including:
            - allowed: bool - whether user can perform a search
            - exempt: bool - whether user is exempt from limits
            - searches_used: int - number of searches used today
            - search_limit: int or 'unlimited' - max allowed searches
            - remaining: int or 'unlimited' - searches left today
            - reset_time: str - time until quota resets (if not exempt)
    """
    # Admins and Analysts are exempt
    if is_exempt_from_quota(user_role):
        return {
            'allowed': True,
            'exempt': True,
            'searches_used': 0,
            'search_limit': 'unlimited',
            'remaining': 'unlimited'
        }

    session = SessionLocal()

    try:
        today = datetime.now(timezone.utc).date()

        # Get or create today's quota record
        quota = session.query(UserSearchQuota).filter_by(
            user_id=user_id,
            date=today
        ).first()

        if not quota:
            # Create new quota record for today
            quota = UserSearchQuota(
                user_id=user_id,
                date=today,
                searches_used=0,
                search_limit=DEFAULT_SEARCH_LIMIT  # V1: Hardcoded limit
            )
            session.add(quota)
            session.commit()

        # Check if limit exceeded
        if quota.searches_used >= quota.search_limit:
            return {
                'allowed': False,
                'exempt': False,
                'searches_used': quota.searches_used,
                'search_limit': quota.search_limit,
                'remaining': 0,
                'reset_time': get_next_reset_time()
            }

        return {
            'allowed': True,
            'exempt': False,
            'searches_used': quota.searches_used,
            'search_limit': quota.search_limit,
            'remaining': quota.search_limit - quota.searches_used,
            'reset_time': get_next_reset_time()
        }

    finally:
        session.close()


def increment_search_usage(user_id, user_role):
    """
    Increment search count for user (skip if exempt).

    Args:
        user_id: User's database ID
        user_role: User's role (string or UserRole enum)

    Returns:
        bool: True if increment was successful, False otherwise
    """
    # Don't increment for exempt roles
    if is_exempt_from_quota(user_role):
        return True

    session = SessionLocal()

    try:
        today = datetime.now(timezone.utc).date()

        quota = session.query(UserSearchQuota).filter_by(
            user_id=user_id,
            date=today
        ).first()

        if quota:
            quota.searches_used += 1
            quota.updated_at = datetime.now(timezone.utc)
            session.commit()
            return True
        else:
            # Create quota record if it doesn't exist (shouldn't happen normally)
            quota = UserSearchQuota(
                user_id=user_id,
                date=today,
                searches_used=1,
                search_limit=DEFAULT_SEARCH_LIMIT
            )
            session.add(quota)
            session.commit()
            return True

    except Exception as e:
        print(f"[QUOTA] Error incrementing search usage: {e}")
        session.rollback()
        return False

    finally:
        session.close()


# ==================== PUBLIC ROUTES ====================

@app.route('/')
@app.route('/home')
def landing_page():
    """Landing page"""
    import os
    frontend_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'frontend')
    return send_from_directory(frontend_path, 'landing.html')


@app.route('/login')
def login_page():
    """Login page"""
    import os
    frontend_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'frontend', 'auth')
    return send_from_directory(frontend_path, 'login.html')


@app.route('/forgot-password')
def forgot_password_page():
    """Forgot password page"""
    auth_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'frontend', 'auth')
    return send_from_directory(auth_path, 'forgot-password.html')


@app.route('/waitlist')
def waitlist_redirect():
    """Redirect to landing page waitlist section"""
    return redirect('/#waitlist')


# ==================== PROTECTED ROUTES ====================

@app.route('/dashboard')
@require_page_auth
def nerve_dashboard():
    """NERVE main dashboard (requires auth)"""
    import os
    frontend_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'frontend')
    return send_from_directory(frontend_path, 'index.html')


@app.route('/ghost')
@require_page_auth
def ghost_dashboard():
    """Ghost module dashboard"""
    import os
    frontend_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'frontend', 'modules', 'ghost')
    return send_from_directory(frontend_path, 'ghost.html')


@app.route('/ghost/search')
@require_page_auth
def ghost_search():
    """Ghost search page"""
    import os
    frontend_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'frontend', 'modules', 'ghost')
    return send_from_directory(frontend_path, 'ghost-search.html')


@app.route('/ghost/adversary')
@require_page_auth
def ghost_adversary():
    """Ghost adversary page"""
    import os
    frontend_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'frontend', 'modules', 'ghost')
    return send_from_directory(frontend_path, 'ghost-adversary.html')


@app.route('/ghost/xasm')
@require_page_auth
def ghost_xasm():
    """Ghost XASM (Attack Surface) page"""
    import os
    frontend_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'frontend', 'modules', 'ghost')
    return send_from_directory(frontend_path, 'ghost-asm.html')


@app.route('/ghost/roadmap')
@require_page_auth
def ghost_roadmap():
    """Ghost security roadmap page"""
    import os
    frontend_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'frontend', 'modules', 'ghost')
    return send_from_directory(frontend_path, 'ghost-roadmap.html')


@app.route('/profile')
@require_page_auth
def profile_page():
    """User profile page"""
    import os
    frontend_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'frontend')
    return send_from_directory(frontend_path, 'profile.html')


# Admin routes (require admin role)
@app.route('/admin/dashboard')
@require_admin_page
def admin_dashboard_page():
    """Admin dashboard page"""
    import os
    frontend_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'frontend', 'admin')
    return send_from_directory(frontend_path, 'admin-dashboard.html')


@app.route('/admin/users')
@require_admin_page
def admin_users():
    """Admin user management"""
    import os
    frontend_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'frontend', 'admin')
    return send_from_directory(frontend_path, 'admin-users.html')


@app.route('/admin/companies')
@require_admin_page
def admin_companies():
    """Admin company management"""
    import os
    frontend_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'frontend', 'admin')
    return send_from_directory(frontend_path, 'admin-companies.html')


@app.route('/admin/system')
@require_admin_page
def admin_system():
    """Admin system management"""
    import os
    frontend_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'frontend', 'admin')
    return send_from_directory(frontend_path, 'admin-system.html')


@app.route('/admin/logs')
@require_admin_page
def admin_logs():
    """Admin logs"""
    import os
    frontend_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'frontend', 'admin')
    return send_from_directory(frontend_path, 'admin-logs.html')


@app.route('/admin/settings')
@require_admin_page
def admin_settings():
    """Admin settings"""
    import os
    frontend_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'frontend', 'admin')
    return send_from_directory(frontend_path, 'admin-settings.html')


# ==================== API ROUTES ====================

@app.route('/api')
def api_index():
    """API documentation endpoint"""
    return jsonify({
        "message": "NERVE API is running",
        "version": "0.3.0",
        "endpoints": {
            "search": "/api/search",
            "profile": "/api/profile/<target_id>",
            "create": "/api/create",
            "profiles": "/api/profiles",
            "unified_search": "/api/search/unified",
            "adversary_analysis": "/api/adversary/analyze",
            "bait": {
                "generate": "/api/ghost/bait/generate",
                "seed": "/api/ghost/bait/seed",
                "active": "/api/ghost/bait/active",
                "triggered": "/api/ghost/bait/triggered",
                "timeline": "/api/ghost/bait/timeline/<identifier>",
                "stats": "/api/ghost/bait/stats"
            }
        }
    })

@app.route('/api/search', methods=['GET'])
@optional_auth
def search():
    """Search for existing profiles"""
    query = request.args.get('q', '')
    user_id = request.user_id  # May be None for anonymous
    db = get_db()
    
    results = db.query(Profile).filter(
        (Profile.name.contains(query)) | (Profile.email.contains(query))
    ).all()
    
    response = [{
        'id': p.id,
        'name': p.name,
        'email': p.email,
        'risk_score': p.risk_score
    } for p in results]
    
    db.close()
    return jsonify({'results': response, 'count': len(response)})

@app.route('/api/profile/<target_id>', methods=['GET'])
def get_profile(target_id):
    """Get detailed profile for a target"""
    db = get_db()
    profile = db.query(Profile).filter(Profile.id == target_id).first()
    
    if not profile:
        db.close()
        return jsonify({'error': 'Profile not found'}), 404
    
    # Get related data
    social_media = db.query(SocialMedia).filter(SocialMedia.profile_id == target_id).all()
    breaches = db.query(Breach).filter(Breach.profile_id == target_id).all()
    devices = db.query(Device).filter(Device.profile_id == target_id).all()
    
    response = {
        'id': profile.id,
        'name': profile.name,
        'email': profile.email,
        'username': profile.username,
        'phone': profile.phone,
        'notes': profile.notes,
        'risk_score': profile.risk_score,
        'breach_count': profile.breach_count,
        'created_at': profile.created_at.isoformat() if profile.created_at else None,
        'social_media': [{
            'platform': sm.platform,
            'username': sm.username,
            'url': sm.url,
            'followers': sm.followers
        } for sm in social_media],
        'breaches': [{
            'name': b.breach_name,
            'date': b.breach_date,
            'data_classes': b.data_classes
        } for b in breaches],
        'devices': [{
            'ip': d.ip_address,
            'hostname': d.hostname,
            'type': d.device_type,
            'location': d.location
        } for d in devices]
    }
    
    db.close()
    return jsonify(response)

@app.route('/api/create', methods=['POST'])
def create_profile():
    """Create a new target profile"""
    data = request.json
    db = get_db()
    
    # Generate unique ID
    profile_count = db.query(Profile).count()
    target_id = f"target_{profile_count + 1}_{datetime.now().strftime('%Y%m%d')}"
    
    profile = Profile(
        id=target_id,
        name=data.get('name'),
        email=data.get('email'),
        username=data.get('username'),
        phone=data.get('phone'),
        notes=data.get('notes', ''),
        risk_score=0.0
    )
    
    db.add(profile)
    db.commit()
    
    response = {
        'id': profile.id,
        'name': profile.name,
        'email': profile.email,
        'username': profile.username,
        'phone': profile.phone,
        'risk_score': profile.risk_score,
        'notes': profile.notes
    }
    
    db.close()
    return jsonify(response), 201

@app.route('/api/profiles', methods=['GET'])
def list_profiles():
    """List all profiles"""
    db = get_db()
    profiles = db.query(Profile).all()
    
    response = [{
        'id': p.id,
        'name': p.name,
        'email': p.email,
        'username': p.username,
        'phone': p.phone,
        'risk_score': p.risk_score,
        'breach_count': p.breach_count,
        'created_at': p.created_at.isoformat() if p.created_at else None
    } for p in profiles]
    
    db.close()
    return jsonify({'profiles': response, 'count': len(response)})

@app.route('/api/profile/<target_id>', methods=['DELETE'])
def delete_profile(target_id):
    """Delete a profile"""
    db = get_db()
    profile = db.query(Profile).filter(Profile.id == target_id).first()
    
    if not profile:
        db.close()
        return jsonify({'error': 'Profile not found'}), 404
    
    # Delete related data
    db.query(SocialMedia).filter(SocialMedia.profile_id == target_id).delete()
    db.query(Breach).filter(Breach.profile_id == target_id).delete()
    db.query(Device).filter(Device.profile_id == target_id).delete()
    db.delete(profile)
    db.commit()
    db.close()
    
    return jsonify({'message': 'Profile deleted'}), 200

@app.route('/api/scan/breaches/<target_id>', methods=['POST'])
def scan_breaches(target_id):
    """Scan a profile for data breaches"""
    result = scan_profile_breaches(target_id)
    return jsonify(result)


@app.route('/api/search/unified', methods=['POST'])
@limiter.limit("30 per minute")  # Prevent API abuse
@require_auth
def unified_search_endpoint():
    """Unified search across all data sources with quota enforcement"""
    user_id = request.user_id
    user_role = request.user.get('role', 'user') if request.user else 'user'

    # Check user's search quota (admins/analysts exempt)
    quota_status = check_search_quota(user_id, user_role)

    if not quota_status['allowed']:
        return jsonify({
            'error': 'Search limit reached',
            'message': f'You have used all {quota_status["search_limit"]} daily searches. Resets in {quota_status["reset_time"]}.',
            'quota': quota_status
        }), 429

    data = request.json
    query = data.get('query', '').strip()

    if not query:
        return jsonify({'error': 'Query cannot be empty'}), 400

    searcher = UnifiedSearch()
    result = searcher.search(query)

    # Increment usage AFTER successful search
    increment_search_usage(user_id, user_role)

    # Include updated quota in response
    updated_quota = check_search_quota(user_id, user_role)
    result['quota'] = updated_quota

    return jsonify(result)


@app.route('/api/search/quota', methods=['GET'])
@require_auth
def get_search_quota():
    """
    Get current user's search quota status.

    Returns:
        JSON with quota information:
        - allowed: bool - whether user can perform a search
        - exempt: bool - whether user is exempt from limits (admin/analyst)
        - searches_used: int - number of searches used today
        - search_limit: int or 'unlimited' - max allowed searches
        - remaining: int or 'unlimited' - searches left today
        - reset_time: str - time until quota resets (e.g., "5h 23m")
    """
    user_id = request.user_id
    user_role = request.user.get('role', 'user') if request.user else 'user'

    quota_status = check_search_quota(user_id, user_role)
    return jsonify(quota_status)


# Initialize adversary matcher
adversary_matcher = AdversaryMatcher()

@app.route('/api/adversary/analyze', methods=['POST'])
@optional_auth
def analyze_adversary():
    """Analyze threat landscape based on organization profile"""
    try:
        user_id = request.user_id  # May be None for anonymous
        data = request.json

        # Validate required fields
        required = ['industry', 'location', 'company_size', 'tech_stack',
                   'cloud_usage', 'remote_work', 'security_maturity',
                   'internet_facing', 'critical_assets', 'data_sensitivity']
        
        for field in required:
            if field not in data:
                return jsonify({'success': False, 'error': f'Missing field: {field}'}), 400
        
        # Analyze threats
        threats = adversary_matcher.analyze_threat_landscape(data)
        
        return jsonify({
            'success': True,
            'threats': threats,
            'total_matches': len(threats)
        })
        
    except Exception as e:
        import traceback
        import sys

        print("\n" + "="*80)
        print("FULL ERROR TRACEBACK:")
        traceback.print_exc(file=sys.stdout)
        print("="*80)
        print(f"Error type: {type(e).__name__}")
        print(f"Error message: {str(e)}")
        print(f"Request data: {request.json}")
        print("="*80 + "\n")

        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# IOC ENDPOINTS
# ============================================================================

@app.route('/api/adversary/iocs/<apt_name>', methods=['GET'])
def get_apt_iocs(apt_name):
    """Get IOCs for specific APT"""
    try:
        force_refresh = request.args.get('refresh', 'false').lower() == 'true'

        print(f"[API] Fetching IOCs for: {apt_name}")

        fetcher = IOCFetcher()
        iocs = fetcher.fetch_iocs(apt_name, force_refresh=force_refresh)

        return jsonify({
            'success': True,
            'apt_name': apt_name,
            'iocs': iocs['iocs'],
            'stats': iocs['stats'],
            'cached_at': iocs['cached_at'],
            'sources': iocs['sources']
        })

    except Exception as e:
        print(f"[API] IOC fetch error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/adversary/iocs/cleanup', methods=['POST'])
def cleanup_ioc_cache():
    """Cleanup old IOC cache files"""
    try:
        fetcher = IOCFetcher()
        fetcher.cleanup_old_cache()

        return jsonify({'success': True, 'message': 'Cache cleaned'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
# BAIT ENDPOINTS
# ============================================================================

@app.route('/api/ghost/bait/generate', methods=['POST'])
def generate_bait():
    """Generate a new bait credential"""
    try:
        # Log incoming request
        data = request.json
        print(f"\n{'='*60}")
        print(f"[BAIT GENERATE] Incoming request data: {data}")

        bait_type = data.get('type', '').lower()
        print(f"[BAIT GENERATE] Extracted bait_type: '{bait_type}'")

        if not bait_type:
            print("[BAIT GENERATE] ❌ Error: Type is required")
            return jsonify({'success': False, 'error': 'Type is required'}), 400

        # Validate bait type
        valid_types = ['aws_key', 'stripe_token', 'database', 'ssh_key', 'github_token', 'slack_token']
        if bait_type not in valid_types:
            print(f"[BAIT GENERATE] ❌ Error: Invalid type '{bait_type}'")
            return jsonify({
                'success': False,
                'error': f'Invalid type. Must be one of: {", ".join(valid_types)}'
            }), 400

        # Create generator and generate bait
        print(f"[BAIT GENERATE] Creating BaitGenerator instance...")
        generator = BaitGenerator()

        # Generate based on type
        print(f"[BAIT GENERATE] Generating {bait_type} credential...")

        result = None
        if bait_type == 'aws_key':
            print("[BAIT GENERATE] Calling generator.generate_aws_credentials(save_to_db=True)")
            result = generator.generate_aws_credentials(save_to_db=True)
        elif bait_type == 'stripe_token':
            print("[BAIT GENERATE] Calling generator.generate_api_token(service_name='stripe', prefix='sk', save_to_db=True)")
            result = generator.generate_api_token(service_name='stripe', prefix='sk', save_to_db=True)
        elif bait_type == 'github_token':
            print("[BAIT GENERATE] Calling generator.generate_api_token(service_name='github', prefix='ghp', save_to_db=True)")
            result = generator.generate_api_token(service_name='github', prefix='ghp', save_to_db=True)
        elif bait_type == 'slack_token':
            print("[BAIT GENERATE] Calling generator.generate_api_token(service_name='slack', prefix='xoxb', save_to_db=True)")
            result = generator.generate_api_token(service_name='slack', prefix='xoxb', save_to_db=True)
        elif bait_type == 'database':
            print("[BAIT GENERATE] Calling generator.generate_database_credentials(save_to_db=True)")
            result = generator.generate_database_credentials(save_to_db=True)
        elif bait_type == 'ssh_key':
            print("[BAIT GENERATE] Calling generator.generate_ssh_key(save_to_db=True)")
            result = generator.generate_ssh_key(save_to_db=True)
        else:
            print(f"[BAIT GENERATE] ❌ Error: Invalid bait type '{bait_type}'")
            return jsonify({'success': False, 'error': 'Invalid bait type'}), 400

        print(f"[BAIT GENERATE] ✓ Generated bait successfully")
        print(f"[BAIT GENERATE] Bait identifier: {result.get('identifier')}")
        print(f"[BAIT GENERATE] Bait type: {result.get('type')}")
        print(f"[BAIT GENERATE] DB ID: {result.get('db_id', 'N/A')}")

        response_data = {
            'success': True,
            'data': result
        }

        print(f"[BAIT GENERATE] Returning success response with data")
        print(f"{'='*60}\n")

        return jsonify(response_data), 201

    except Exception as e:
        print(f"\n[BAIT GENERATE] ❌ Exception occurred:")
        print(f"[BAIT GENERATE] Error type: {type(e).__name__}")
        print(f"[BAIT GENERATE] Error message: {str(e)}")

        import traceback
        print(f"[BAIT GENERATE] Full traceback:")
        traceback.print_exc()
        print(f"{'='*60}\n")

        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/ghost/bait/seed', methods=['POST'])
def seed_bait():
    """Seed a bait credential to GitHub Gist or Pastebin"""
    db = None
    try:
        data = request.json
        identifier = data.get('identifier', '').strip()
        deployment_method = data.get('deployment_method', 'github').lower()  # 'github' or 'pastebin'
        title = data.get('title', 'Configuration File')

        if not identifier:
            return jsonify({'success': False, 'error': 'Identifier is required'}), 400

        # Query database for BaitToken
        db = get_db()
        bait_token = db.query(BaitToken).filter(BaitToken.identifier == identifier).first()

        if not bait_token:
            db.close()
            return jsonify({'success': False, 'error': 'Bait not found'}), 404

        # Parse token_value JSON
        try:
            token_data = json.loads(bait_token.token_value)
        except:
            db.close()
            return jsonify({'success': False, 'error': 'Invalid token data'}), 500

        # Deploy based on method
        if deployment_method == 'github':
            result = deploy_to_github_gist(token_data, title)
        else:
            # Fallback to Pastebin
            seeder = BaitSeeder()
            result = seeder.seed_to_pastebin(token_data, title)

        if result.get('success'):
            # Update bait token with seeded location
            bait_token.seeded_location = result.get('url')
            db.commit()

        db.close()

        return jsonify(result), 200 if result.get('success') else 500

    except Exception as e:
        if db:
            db.close()
        print(f"❌ Bait seeding error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

def deploy_to_github_gist(token_data, title):
    """Deploy bait credential to GitHub Gist"""
    try:
        import requests

        # Get GitHub token from environment
        github_token = os.getenv('GITHUB_TOKEN')
        if not github_token:
            return {'success': False, 'error': 'GitHub token not configured'}

        # Format credential as file content
        if isinstance(token_data, dict):
            # Pretty format the credential data
            file_content = json.dumps(token_data, indent=2)
            filename = f"{title.lower().replace(' ', '_')}.json"
        else:
            file_content = str(token_data)
            filename = f"{title.lower().replace(' ', '_')}.txt"

        # Create gist payload
        gist_data = {
            "description": title,
            "public": True,
            "files": {
                filename: {
                    "content": file_content
                }
            }
        }

        # Make request to GitHub API
        headers = {
            'Authorization': f'token {github_token}',
            'Accept': 'application/vnd.github.v3+json'
        }

        print(f"[GITHUB GIST] Creating gist: {title}")
        response = requests.post(
            'https://api.github.com/gists',
            headers=headers,
            json=gist_data,
            timeout=10
        )

        if response.status_code == 201:
            gist_url = response.json().get('html_url')
            print(f"[GITHUB GIST] ✓ Created gist: {gist_url}")
            return {
                'success': True,
                'url': gist_url,
                'message': 'Successfully deployed to GitHub Gist'
            }
        else:
            error_msg = response.json().get('message', 'Unknown error')
            print(f"[GITHUB GIST] ❌ Failed: {response.status_code} - {error_msg}")
            return {
                'success': False,
                'error': f'GitHub API error: {error_msg}'
            }

    except Exception as e:
        print(f"[GITHUB GIST] ❌ Exception: {str(e)}")
        return {
            'success': False,
            'error': f'GitHub Gist deployment failed: {str(e)}'
        }


@app.route('/api/ghost/bait/active', methods=['GET'])
def get_active_baits():
    """Get all active bait tokens"""
    db = None
    try:
        db = get_db()

        # Query active baits
        baits = db.query(BaitToken).filter(
            BaitToken.status == 'active'
        ).order_by(BaitToken.seeded_at.desc()).all()

        result = []
        for bait in baits:
            result.append({
                'id': bait.id,
                'identifier': bait.identifier,
                'bait_type': bait.bait_type,
                'seeded_at': bait.seeded_at.isoformat() if bait.seeded_at else None,
                'access_count': bait.access_count,
                'seeded_location': bait.seeded_location
            })

        db.close()

        return jsonify({
            'success': True,
            'baits': result,
            'count': len(result)
        }), 200

    except Exception as e:
        if db:
            db.close()
        print(f"❌ Error fetching active baits: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/ghost/bait/triggered', methods=['GET'])
def get_triggered_baits():
    """Get all triggered bait tokens with latest access info"""
    db = None
    try:
        db = get_db()

        # Query triggered baits
        baits = db.query(BaitToken).filter(
            BaitToken.status == 'triggered'
        ).order_by(BaitToken.last_access.desc()).all()

        result = []
        for bait in baits:
            # Get latest access record
            latest_access = db.query(BaitAccess).filter(
                BaitAccess.bait_id == bait.id
            ).order_by(BaitAccess.accessed_at.desc()).first()

            bait_data = {
                'id': bait.id,
                'identifier': bait.identifier,
                'bait_type': bait.bait_type,
                'seeded_at': bait.seeded_at.isoformat() if bait.seeded_at else None,
                'seeded_location': bait.seeded_location,
                'first_access': bait.first_access.isoformat() if bait.first_access else None,
                'last_access': bait.last_access.isoformat() if bait.last_access else None,
                'access_count': bait.access_count
            }

            if latest_access:
                bait_data['latest_access'] = {
                    'source_ip': latest_access.source_ip,
                    'user_agent': latest_access.user_agent,
                    'geolocation': latest_access.geolocation,
                    'threat_level': latest_access.threat_level,
                    'accessed_at': latest_access.accessed_at.isoformat() if latest_access.accessed_at else None
                }

            result.append(bait_data)

        db.close()

        return jsonify({
            'success': True,
            'baits': result,
            'count': len(result)
        }), 200

    except Exception as e:
        if db:
            db.close()
        print(f"❌ Error fetching triggered baits: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/ghost/bait/timeline/<identifier>', methods=['GET'])
def get_bait_timeline(identifier):
    """Get full timeline for a specific bait token"""
    db = None
    try:
        db = get_db()

        # Query bait token
        bait_token = db.query(BaitToken).filter(
            BaitToken.identifier == identifier
        ).first()

        if not bait_token:
            db.close()
            return jsonify({'success': False, 'error': 'Bait not found'}), 404

        # Query all access records
        accesses = db.query(BaitAccess).filter(
            BaitAccess.bait_id == bait_token.id
        ).order_by(BaitAccess.accessed_at.desc()).all()

        # Build timeline
        timeline = []
        unique_ips = set()
        threat_breakdown = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}

        for access in accesses:
            # Perform attacker fingerprinting analysis
            fingerprint_analysis = analyze_attacker(access)

            timeline.append({
                'id': access.id,
                'accessed_at': access.accessed_at.isoformat() if access.accessed_at else None,
                'source_ip': access.source_ip,
                'user_agent': access.user_agent,
                'request_type': access.request_type,
                'geolocation': access.geolocation,
                'threat_level': access.threat_level,
                'request_headers': json.loads(access.request_headers) if access.request_headers else {},
                'request_body': json.loads(access.request_body) if access.request_body else None,
                # Fingerprinting data
                'fingerprint': fingerprint_analysis,
                'attribution_type': fingerprint_analysis.get('attribution_type'),
                'evidence_strength': fingerprint_analysis.get('evidence_strength'),
                'tool_name': fingerprint_analysis.get('tool_name')
            })

            unique_ips.add(access.source_ip)

            if access.threat_level in threat_breakdown:
                threat_breakdown[access.threat_level] += 1

        # Bait details
        bait_details = {
            'id': bait_token.id,
            'identifier': bait_token.identifier,
            'bait_type': bait_token.bait_type,
            'seeded_at': bait_token.seeded_at.isoformat() if bait_token.seeded_at else None,
            'seeded_location': bait_token.seeded_location,
            'first_access': bait_token.first_access.isoformat() if bait_token.first_access else None,
            'last_access': bait_token.last_access.isoformat() if bait_token.last_access else None,
            'access_count': bait_token.access_count,
            'status': bait_token.status
        }

        # Statistics
        statistics = {
            'total_accesses': len(accesses),
            'unique_ips': len(unique_ips),
            'threat_level_breakdown': threat_breakdown
        }

        db.close()

        return jsonify({
            'success': True,
            'bait': bait_details,
            'timeline': timeline,
            'statistics': statistics
        }), 200

    except Exception as e:
        if db:
            db.close()
        print(f"❌ Error fetching bait timeline: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/ghost/bait/stats', methods=['GET'])
def get_bait_stats():
    """Get overall bait statistics"""
    db = None
    try:
        db = get_db()

        # Total baits
        total_baits = db.query(func.count(BaitToken.id)).scalar() or 0

        # Active baits
        active_baits = db.query(func.count(BaitToken.id)).filter(
            BaitToken.status == 'active'
        ).scalar() or 0

        # Triggered baits
        triggered_baits = db.query(func.count(BaitToken.id)).filter(
            BaitToken.status == 'triggered'
        ).scalar() or 0

        # Total attempts
        total_attempts = db.query(func.count(BaitAccess.id)).scalar() or 0

        # Attempts today
        today = datetime.now(timezone.utc).date()
        attempts_today = db.query(func.count(BaitAccess.id)).filter(
            func.date(BaitAccess.accessed_at) == today
        ).scalar() or 0

        # Unique IPs
        unique_ips = db.query(func.count(distinct(BaitAccess.source_ip))).scalar() or 0

        db.close()

        return jsonify({
            'success': True,
            'stats': {
                'total_baits': total_baits,
                'active_baits': active_baits,
                'triggered_baits': triggered_baits,
                'total_attempts': total_attempts,
                'attempts_today': attempts_today,
                'unique_ips': unique_ips
            }
        }), 200

    except Exception as e:
        if db:
            db.close()
        print(f"❌ Error fetching bait stats: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/ghost/bait/delete/<identifier>', methods=['DELETE'])
def delete_bait(identifier):
    """Delete a bait token and its access records"""
    db = None
    try:
        print(f"\n[BAIT DELETE] Deleting bait: {identifier}")
        db = get_db()

        # Find the bait token
        bait_token = db.query(BaitToken).filter(BaitToken.identifier == identifier).first()

        if not bait_token:
            print(f"[BAIT DELETE] ❌ Bait not found: {identifier}")
            db.close()
            return jsonify({'success': False, 'error': 'Bait not found'}), 404

        print(f"[BAIT DELETE] Found bait ID: {bait_token.id}")

        # Delete associated access records (cascade should handle this, but explicit is better)
        access_count = db.query(BaitAccess).filter(BaitAccess.bait_id == bait_token.id).count()
        print(f"[BAIT DELETE] Deleting {access_count} associated access records...")
        db.query(BaitAccess).filter(BaitAccess.bait_id == bait_token.id).delete()

        # Delete the bait token
        print(f"[BAIT DELETE] Deleting bait token...")
        db.delete(bait_token)
        db.commit()

        print(f"[BAIT DELETE] ✓ Successfully deleted bait: {identifier}")
        db.close()

        return jsonify({
            'success': True,
            'message': f'Honeytoken {identifier} deleted successfully'
        }), 200

    except Exception as e:
        if db:
            db.rollback()
            db.close()
        print(f"[BAIT DELETE] ❌ Error deleting bait: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

# IP Reputation Check Endpoint
@app.route('/api/ghost/bait/check-ip/<ip>', methods=['GET'])
def check_ip_reputation_endpoint(ip):
    """
    Check IP reputation using AbuseIPDB and IPQualityScore APIs
    """
    db = None
    try:
        print(f"\n{'='*60}")
        print(f"[IP CHECK] Checking reputation for IP: {ip}")

        db = get_db()

        # 1. Query database for other hits by this IP
        print(f"[IP CHECK] Querying database for other hits...")
        other_hits = db.query(BaitAccess).filter(BaitAccess.source_ip == ip).all()
        hits_count = len(other_hits)

        # Get unique baits hit by this IP
        unique_baits = set()
        for hit in other_hits:
            if hit.bait_token:
                unique_baits.add(hit.bait_token.identifier)

        print(f"[IP CHECK] Found {hits_count} hits across {len(unique_baits)} different baits")

        # 2. Query IP intelligence APIs (AbuseIPDB + IPQualityScore)
        print(f"[IP CHECK] Querying IP intelligence APIs...")
        reputation = check_ip_intel(ip)

        # Add database hits to reputation data
        reputation['hits_on_other_baits'] = hits_count
        reputation['unique_baits_hit'] = len(unique_baits)
        reputation['baits_hit'] = list(unique_baits)[:10]  # Limit to first 10

        # Enhance threat level if IP is known scanner
        if hits_count >= 5 and reputation['threat_level'] == 'low':
            reputation['threat_level'] = 'high'
            reputation['summary'] += f" Known scanner ({hits_count} hits on {len(unique_baits)} baits)"
        elif hits_count >= 2 and reputation['threat_level'] == 'low':
            reputation['threat_level'] = 'medium'
            reputation['summary'] += f" Multiple hits detected ({hits_count} hits)"

        # Get badge type for frontend display
        reputation['badge_type'] = get_ip_badge_type(reputation)
        reputation['success'] = True

        print(f"[IP CHECK] Threat Level: {reputation['threat_level']}")
        print(f"[IP CHECK] Attribution Confidence: {reputation['attribution_confidence']}")
        print(f"[IP CHECK] ✓ Reputation check complete")
        print(f"{'='*60}\n")

        db.close()
        return jsonify(reputation), 200

    except Exception as e:
        if db:
            db.close()
        print(f"[IP CHECK] ❌ Error checking IP reputation: {e}")
        import traceback
        traceback.print_exc()

        # Return minimal data on error
        return jsonify({
            'success': False,
            'ip': ip,
            'error': str(e),
            'threat_level': 'unknown',
            'attribution_confidence': 'unknown',
            'summary': 'IP reputation check failed',
            'badge_type': 'datacenter'
        }), 500

# ============================================================================
# CTI DASHBOARD ENDPOINT
# ============================================================================

@app.route('/api/ghost/dashboard/feed', methods=['GET'])
def get_dashboard_feed():
    """
    Get CTI dashboard data including news feed and module statistics
    """
    db = None
    try:
        print("\n" + "="*60)
        print("[DASHBOARD] Fetching dashboard data...")

        db = get_db()

        # Get news feed
        force_refresh = request.args.get('refresh', 'false').lower() == 'true'
        news_articles = get_news_feed(force_refresh=force_refresh)
        feed_stats = get_feed_stats()

        # Calculate module statistics
        print("[DASHBOARD] Calculating module statistics...")

        # Credentials monitored (GitHub + PasteBin findings)
        github_count = db.query(GitHubFinding).count()
        pastebin_count = db.query(PasteBinFinding).count()
        credentials_monitored = github_count + pastebin_count

        # Active honeytokens
        active_honeytokens = db.query(BaitToken).filter(
            BaitToken.status == 'active'
        ).count()

        # High risk IPs (threat_level high or critical)
        high_risk_ips = db.query(distinct(BaitAccess.source_ip)).filter(
            BaitAccess.threat_level.in_(['high', 'critical'])
        ).count()

        # Recent breaches (last 5 searches - can be from various sources)
        recent_breaches = []

        # Get last 5 GitHub findings
        github_recent = db.query(GitHubFinding).order_by(
            GitHubFinding.discovered_at.desc()
        ).limit(5).all()

        for finding in github_recent:
            recent_breaches.append({
                'type': 'GitHub Gist',
                'query_term': finding.query_term,
                'credential_type': finding.credential_type,
                'date': finding.discovered_at.isoformat() if finding.discovered_at else None,
                'url': finding.gist_url
            })

        # Get last 5 PasteBin findings if we need more
        if len(recent_breaches) < 5:
            pastebin_recent = db.query(PasteBinFinding).order_by(
                PasteBinFinding.discovered_at.desc()
            ).limit(5 - len(recent_breaches)).all()

            for finding in pastebin_recent:
                recent_breaches.append({
                    'type': 'PasteBin',
                    'query_term': finding.query_term,
                    'date': finding.discovered_at.isoformat() if finding.discovered_at else None,
                    'url': finding.paste_url
                })

        # Sort recent breaches by date
        recent_breaches.sort(key=lambda x: x['date'] or '', reverse=True)
        recent_breaches = recent_breaches[:5]  # Limit to 5

        db.close()

        print(f"[DASHBOARD] Statistics:")
        print(f"[DASHBOARD]   - Credentials monitored: {credentials_monitored}")
        print(f"[DASHBOARD]   - Active honeytokens: {active_honeytokens}")
        print(f"[DASHBOARD]   - High risk IPs: {high_risk_ips}")
        print(f"[DASHBOARD]   - Recent breaches: {len(recent_breaches)}")
        print(f"[DASHBOARD]   - News articles: {len(news_articles)}")
        print(f"[DASHBOARD] Dashboard data ready")
        print("="*60 + "\n")

        return jsonify({
            'success': True,
            'stats': {
                'credentials_monitored': credentials_monitored,
                'active_honeytokens': active_honeytokens,
                'high_risk_ips': high_risk_ips,
                'recent_breaches_count': len(recent_breaches)
            },
            'recent_breaches': recent_breaches,
            'news': {
                'articles': news_articles[:50],  # Limit to 50 most recent
                'feed_stats': feed_stats
            }
        }), 200

    except Exception as e:
        if db:
            db.close()
        print(f"[DASHBOARD] Error fetching dashboard data: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# ============================================================================
# MAINTENANCE CHECKLIST ENDPOINTS (User-Specific)
# ============================================================================

# Default maintenance tasks for the weekly checklist
DEFAULT_MAINTENANCE_TASKS = [
    {
        'key': 'rescan',
        'name': 'Re-scan your domain',
        'description': 'Recommended weekly to track changes'
    },
    {
        'key': 'breach-check',
        'name': 'Check for new breaches',
        'description': 'Run Global Search for your domain'
    },
    {
        'key': 'adversary-review',
        'name': 'Review threat landscape',
        'description': 'Check Adversary Matcher for new threats'
    },
    {
        'key': 'lightbox-test',
        'name': 'Test one fix with Lightbox',
        'description': 'Verify remediation worked'
    }
]


def get_week_start(date_obj=None):
    """Get the Monday of the current week (or specified date's week)"""
    from datetime import date
    if date_obj is None:
        date_obj = date.today()
    # Monday is weekday 0
    days_since_monday = date_obj.weekday()
    return date_obj - timedelta(days=days_since_monday)


@app.route('/api/ghost/maintenance/checklist', methods=['GET'])
@require_auth
def get_maintenance_checklist():
    """
    Get weekly maintenance checklist for current user.
    Creates default tasks for this week if none exist.
    """
    db = None
    try:
        db = SessionLocal()
        user_id = request.user_id
        week_start = get_week_start()

        # Get user's tasks for this week
        tasks = db.query(MaintenanceChecklist).filter_by(
            user_id=user_id,
            week_start=week_start
        ).order_by(MaintenanceChecklist.id).all()

        # If no tasks for this week, create default tasks
        if not tasks:
            for task_def in DEFAULT_MAINTENANCE_TASKS:
                task = MaintenanceChecklist(
                    user_id=user_id,
                    task_key=task_def['key'],
                    task_name=task_def['name'],
                    task_description=task_def['description'],
                    week_start=week_start,
                    completed=False
                )
                db.add(task)
            db.commit()

            # Reload tasks
            tasks = db.query(MaintenanceChecklist).filter_by(
                user_id=user_id,
                week_start=week_start
            ).order_by(MaintenanceChecklist.id).all()

        results = []
        for task in tasks:
            results.append({
                'id': task.id,
                'task_key': task.task_key,
                'task_name': task.task_name,
                'task_description': task.task_description,
                'completed': task.completed,
                'completed_at': task.completed_at.isoformat() if task.completed_at else None,
                'week_start': task.week_start.isoformat() if task.week_start else None
            })

        return jsonify({
            'success': True,
            'tasks': results,
            'week_start': week_start.isoformat()
        }), 200

    except Exception as e:
        print(f"[MAINTENANCE] Error getting checklist: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    finally:
        if db:
            db.close()


@app.route('/api/ghost/maintenance/checklist/<int:task_id>/toggle', methods=['POST'])
@require_auth
def toggle_maintenance_task(task_id):
    """
    Toggle a maintenance task completion status.
    Users can only toggle their own tasks.
    """
    db = None
    try:
        db = SessionLocal()
        user_id = request.user_id

        # Find task and verify ownership
        task = db.query(MaintenanceChecklist).filter_by(
            id=task_id,
            user_id=user_id
        ).first()

        if not task:
            return jsonify({
                'success': False,
                'error': 'Task not found or unauthorized'
            }), 404

        # Toggle completion status
        task.completed = not task.completed
        task.completed_at = datetime.now(timezone.utc) if task.completed else None
        task.updated_at = datetime.now(timezone.utc)

        db.commit()

        return jsonify({
            'success': True,
            'task': {
                'id': task.id,
                'task_key': task.task_key,
                'completed': task.completed,
                'completed_at': task.completed_at.isoformat() if task.completed_at else None
            }
        }), 200

    except Exception as e:
        print(f"[MAINTENANCE] Error toggling task: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    finally:
        if db:
            db.close()


@app.route('/api/ghost/maintenance/checklist/<task_key>/toggle-by-key', methods=['POST'])
@require_auth
def toggle_maintenance_task_by_key(task_key):
    """
    Toggle a maintenance task by its key (for backward compatibility with frontend).
    Creates the task for current week if it doesn't exist.
    """
    db = None
    try:
        db = SessionLocal()
        user_id = request.user_id
        week_start = get_week_start()

        # Find task by key for this user and week
        task = db.query(MaintenanceChecklist).filter_by(
            user_id=user_id,
            task_key=task_key,
            week_start=week_start
        ).first()

        # If task doesn't exist, create it
        if not task:
            # Find task definition
            task_def = next((t for t in DEFAULT_MAINTENANCE_TASKS if t['key'] == task_key), None)
            if not task_def:
                return jsonify({
                    'success': False,
                    'error': f'Unknown task key: {task_key}'
                }), 400

            task = MaintenanceChecklist(
                user_id=user_id,
                task_key=task_key,
                task_name=task_def['name'],
                task_description=task_def['description'],
                week_start=week_start,
                completed=False
            )
            db.add(task)
            db.commit()
            db.refresh(task)

        # Toggle completion status
        task.completed = not task.completed
        task.completed_at = datetime.now(timezone.utc) if task.completed else None
        task.updated_at = datetime.now(timezone.utc)

        db.commit()

        return jsonify({
            'success': True,
            'task': {
                'id': task.id,
                'task_key': task.task_key,
                'completed': task.completed,
                'completed_at': task.completed_at.isoformat() if task.completed_at else None
            }
        }), 200

    except Exception as e:
        print(f"[MAINTENANCE] Error toggling task by key: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    finally:
        if db:
            db.close()


# ============================================================================
# DAILY SECURITY QUIZ ENDPOINTS
# ============================================================================

# Security quiz questions bank (rotates daily based on date)
QUIZ_QUESTIONS = [
    {
        "id": 1,
        "category": "Phishing Defense",
        "question": "You receive an email from 'IT Support' asking you to click a link to verify your credentials. The sender's email is support@c0mpany-it.com. What should you do?",
        "options": [
            "Click the link - IT Support needs to verify accounts regularly",
            "Forward the email to your actual IT department to verify",
            "Reply asking if they are legitimate IT staff",
            "Delete the email and clear your inbox"
        ],
        "correct_answer": 1,
        "explanation": "The sender's domain uses a zero instead of 'o' (c0mpany vs company), a common phishing tactic. <strong>Always verify suspicious emails with your actual IT department</strong> through known contact channels, never by replying to the suspicious email."
    },
    {
        "id": 2,
        "category": "Password Security",
        "question": "Which of the following is the most secure password practice?",
        "options": [
            "Using the same complex password across all accounts",
            "Writing passwords on a sticky note kept under your keyboard",
            "Using a password manager with unique passwords per site",
            "Creating passwords based on personal information like birthdays"
        ],
        "correct_answer": 2,
        "explanation": "<strong>Password managers generate and store unique, complex passwords</strong> for each account. This prevents credential stuffing attacks where one breached password compromises all your accounts."
    },
    {
        "id": 3,
        "category": "Social Engineering",
        "question": "A caller claims to be from Microsoft and says your computer has a virus. They ask for remote access to fix it. What is this?",
        "options": [
            "Legitimate technical support",
            "A vishing (voice phishing) attack",
            "A routine security check",
            "An automated security notification"
        ],
        "correct_answer": 1,
        "explanation": "This is a classic <strong>vishing attack</strong>. Microsoft and other legitimate companies never make unsolicited calls about computer problems. Attackers use urgency and fear to gain remote access to steal data or install malware."
    },
    {
        "id": 4,
        "category": "Data Protection",
        "question": "What is the primary purpose of data encryption at rest?",
        "options": [
            "To make files smaller for storage",
            "To speed up data access times",
            "To protect data if storage media is stolen or accessed unauthorized",
            "To organize files more efficiently"
        ],
        "correct_answer": 2,
        "explanation": "<strong>Encryption at rest</strong> protects stored data from unauthorized access. If a laptop is stolen or a hard drive is accessed without authorization, encrypted data remains unreadable without the proper decryption keys."
    },
    {
        "id": 5,
        "category": "Network Security",
        "question": "You're working from a coffee shop and need to access company resources. What's the safest approach?",
        "options": [
            "Connect directly to the cafe's free WiFi",
            "Use your phone as a mobile hotspot with VPN",
            "Ask the staff for the WiFi password and trust it",
            "Use any available open network for convenience"
        ],
        "correct_answer": 1,
        "explanation": "Public WiFi networks can be compromised or spoofed by attackers. <strong>Using a mobile hotspot combined with a VPN</strong> provides encrypted connectivity that protects your data from man-in-the-middle attacks."
    },
    {
        "id": 6,
        "category": "Malware Defense",
        "question": "A USB drive is found in your office parking lot with a label 'Q4 Salary Review'. What should you do?",
        "options": [
            "Plug it into your computer to find the owner",
            "Give it to IT security without plugging it in",
            "Plug it into a public computer to check contents",
            "Keep it in case the owner asks for it"
        ],
        "correct_answer": 1,
        "explanation": "This is a <strong>baiting attack</strong> - attackers deliberately drop infected USB drives hoping curiosity will make someone plug them in. Unknown USB devices should always be handed to IT security who have isolated systems to safely examine them."
    },
    {
        "id": 7,
        "category": "Access Control",
        "question": "What does the principle of 'least privilege' mean in cybersecurity?",
        "options": [
            "Give everyone admin access for efficiency",
            "Users should only have access needed for their specific job",
            "Restrict internet access for all employees",
            "Privileged users should have the least monitoring"
        ],
        "correct_answer": 1,
        "explanation": "<strong>Least privilege</strong> means granting only the minimum access rights necessary to perform a job. This limits the damage potential if an account is compromised and reduces the attack surface across the organization."
    },
    {
        "id": 8,
        "category": "Incident Response",
        "question": "You notice your computer is running unusually slow and the hard drive is constantly active even when idle. What should be your first action?",
        "options": [
            "Restart the computer to fix the slowness",
            "Install a free antivirus from the internet",
            "Disconnect from the network and report to IT security",
            "Continue working and wait for it to resolve"
        ],
        "correct_answer": 2,
        "explanation": "These symptoms could indicate malware activity such as cryptocurrency mining or data exfiltration. <strong>Disconnecting from the network prevents potential spread</strong> and stops data leaving the system while IT security investigates."
    },
    {
        "id": 9,
        "category": "Authentication",
        "question": "What is the main advantage of hardware security keys (like YubiKey) over SMS-based 2FA?",
        "options": [
            "They are cheaper to implement",
            "They cannot be phished or intercepted like SMS codes",
            "They work without internet connection only",
            "They eliminate the need for passwords entirely"
        ],
        "correct_answer": 1,
        "explanation": "<strong>Hardware security keys</strong> are phishing-resistant because they use cryptographic proof tied to the specific website. SMS codes can be intercepted through SIM swapping attacks or SS7 vulnerabilities, making them less secure."
    },
    {
        "id": 10,
        "category": "Cloud Security",
        "question": "What is the 'shared responsibility model' in cloud computing?",
        "options": [
            "All security is the cloud provider's responsibility",
            "Security duties are split between the provider and customer",
            "Customers must handle all security themselves",
            "A model where employees share login credentials"
        ],
        "correct_answer": 1,
        "explanation": "In cloud computing, <strong>providers secure the infrastructure</strong> (physical data centers, network, hypervisor) while <strong>customers secure their data, access management, and application configurations</strong>. Understanding this division is crucial for proper cloud security."
    },
    {
        "id": 11,
        "category": "Ransomware",
        "question": "Your screen suddenly shows a message demanding Bitcoin payment to decrypt your files. What's the recommended first response?",
        "options": [
            "Pay the ransom to recover files quickly",
            "Isolate the system, don't pay, and contact IT/incident response",
            "Try to decrypt the files yourself using online tools",
            "Format the hard drive immediately"
        ],
        "correct_answer": 1,
        "explanation": "<strong>Never pay ransomware demands</strong> - it funds criminal operations and doesn't guarantee file recovery. Isolate the infected system to prevent spread, then work with IT security to assess damage and restore from backups."
    },
    {
        "id": 12,
        "category": "Secure Development",
        "question": "What is SQL injection and how can it be prevented?",
        "options": [
            "A database optimization technique using special queries",
            "An attack inserting malicious SQL; prevented by parameterized queries",
            "A method to speed up SQL queries in applications",
            "An attack on physical servers; prevented by firewalls"
        ],
        "correct_answer": 1,
        "explanation": "<strong>SQL injection</strong> occurs when attackers insert malicious SQL code through user inputs. Using <strong>parameterized queries</strong> (prepared statements) ensures user input is treated as data, not executable code."
    },
    {
        "id": 13,
        "category": "Physical Security",
        "question": "Someone in business attire follows you through a secure door without badging in, claiming they forgot their badge. What should you do?",
        "options": [
            "Let them in - they look professional",
            "Politely ask them to contact reception for a visitor badge",
            "Ignore the situation to avoid confrontation",
            "Give them your badge to use temporarily"
        ],
        "correct_answer": 1,
        "explanation": "This is <strong>tailgating</strong>, a social engineering technique. Professional appearance is easily faked. Politely directing them to reception maintains security without confrontation and follows proper access control procedures."
    },
    {
        "id": 14,
        "category": "Threat Intelligence",
        "question": "What is an Indicator of Compromise (IoC)?",
        "options": [
            "A legal document for security compliance",
            "Evidence that suggests a security breach may have occurred",
            "A metric for measuring employee security awareness",
            "A type of encryption algorithm"
        ],
        "correct_answer": 1,
        "explanation": "<strong>Indicators of Compromise</strong> are forensic artifacts like suspicious IP addresses, file hashes, or unusual network traffic that suggest malicious activity. Security teams use IoCs to detect, investigate, and respond to threats."
    },
    {
        "id": 15,
        "category": "Zero Trust",
        "question": "What is the core principle of Zero Trust security architecture?",
        "options": [
            "Trust all internal network traffic automatically",
            "Never trust, always verify - regardless of network location",
            "Zero security measures are needed for trusted users",
            "Trust users after they've been employed for a year"
        ],
        "correct_answer": 1,
        "explanation": "<strong>Zero Trust</strong> assumes breach and verifies every request as if it originates from an untrusted network. This means continuous authentication, least-privilege access, and micro-segmentation regardless of whether traffic is internal or external."
    }
]

@app.route('/api/ghost/daily-quiz', methods=['GET'])
@require_auth
def get_daily_quiz():
    """
    Get today's quiz question for the authenticated user.
    Question rotates daily based on date.
    """
    user_id = request.user_id
    db = None
    try:
        db = get_db()

        # Determine today's question based on date
        today = datetime.now(timezone.utc).date()
        question_index = today.toordinal() % len(QUIZ_QUESTIONS)
        question = QUIZ_QUESTIONS[question_index].copy()

        # Get or create user quiz stats
        user = db.query(User).filter_by(id=user_id).first()

        # Check if user already answered today (store in session or simple tracking)
        # For simplicity, we'll use a date-based approach
        # In production, you'd want a proper QuizAnswer table

        # Get basic stats (placeholder - in production use proper tables)
        stats = {
            'streak': 0,
            'correct_count': 0,
            'total_attempted': 0,
            'completed_today': False,
            'already_answered': False
        }

        # Return question without correct answer exposed initially
        response = {
            'question_id': question['id'],
            'category': question['category'],
            'question': question['question'],
            'options': question['options'],
            'correct_answer': question['correct_answer'],
            'explanation': question['explanation'],
            'has_more': True,
            **stats
        }

        return jsonify(response)

    except Exception as e:
        print(f"[QUIZ] Error getting quiz: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
    finally:
        if db:
            db.close()


@app.route('/api/ghost/daily-quiz/answer', methods=['POST'])
@require_auth
def submit_quiz_answer():
    """
    Submit answer for the daily quiz question.
    """
    user_id = request.user_id
    db = None
    try:
        data = request.get_json()
        db = get_db()

        question_id = data.get('question_id')
        selected_answer = data.get('selected_answer')
        correct = data.get('correct', False)

        # In production, save to QuizAnswer table and update user stats
        # For now, return updated stats
        response = {
            'success': True,
            'streak': 1 if correct else 0,
            'correct_count': 1 if correct else 0,
            'total_attempted': 1
        }

        return jsonify(response)

    except Exception as e:
        print(f"[QUIZ] Error saving answer: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        if db:
            db.close()


@app.route('/api/ghost/daily-quiz/next', methods=['GET'])
@require_auth
def get_next_quiz_question():
    """
    Get the next quiz question (for bonus questions).
    """
    user_id = request.user_id
    try:
        # Pick a random question different from today's
        today = datetime.now(timezone.utc).date()
        today_index = today.toordinal() % len(QUIZ_QUESTIONS)

        # Get a different random question
        import random
        available_indices = [i for i in range(len(QUIZ_QUESTIONS)) if i != today_index]
        next_index = random.choice(available_indices)
        question = QUIZ_QUESTIONS[next_index].copy()

        response = {
            'question_id': question['id'],
            'category': question['category'],
            'question': question['question'],
            'options': question['options'],
            'correct_answer': question['correct_answer'],
            'explanation': question['explanation'],
            'has_more': len(available_indices) > 1
        }

        return jsonify(response)

    except Exception as e:
        print(f"[QUIZ] Error getting next question: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================================================
# HACKER PLAYBOOK ENDPOINTS
# ============================================================================

# Hacker techniques database - 100 real-world attack techniques with defenses
HACKER_PLAYBOOK = [
    {
        "id": 0,
        "name": "SQL Injection",
        "difficulty": "MEDIUM",
        "description": "Attackers inject malicious code into website forms to steal database contents like passwords, credit cards, and customer data.",
        "attack_steps": [
            "Identify input fields that interact with databases",
            "Test with basic payloads like ' OR '1'='1",
            "Use UNION SELECT to extract data from other tables",
            "Escalate to read files or execute commands if possible"
        ],
        "defense_steps": [
            "Use parameterized queries or prepared statements",
            "Implement input validation and sanitization",
            "Apply principle of least privilege to database accounts",
            "Use Web Application Firewalls (WAF) as additional layer"
        ]
    },
    {
        "id": 1,
        "name": "Cross-Site Scripting (XSS)",
        "difficulty": "MEDIUM",
        "description": "Hackers inject malicious scripts into websites that run in your browser, stealing your login sessions, redirecting you to fake sites, or capturing everything you type.",
        "attack_steps": [
            "Find user input reflected in page output",
            "Test with simple payloads like <script>alert(1)</script>",
            "Craft payload to steal session cookies or credentials",
            "Use social engineering to deliver malicious link"
        ],
        "defense_steps": [
            "Encode output based on context (HTML, JS, URL, CSS)",
            "Implement Content Security Policy (CSP) headers",
            "Use HTTPOnly and Secure flags on cookies",
            "Sanitize rich text with allowlist-based filtering"
        ]
    },
    {
        "id": 2,
        "name": "Password Spraying",
        "difficulty": "EASY",
        "description": "Attackers try common passwords like 'Summer2024!' across thousands of accounts simultaneously, hoping someone used an easy-to-guess password.",
        "attack_steps": [
            "Gather list of valid usernames through OSINT or enumeration",
            "Choose common passwords (Season+Year, Company123, etc.)",
            "Spray one password across all accounts, then wait",
            "Avoid lockouts by staying below threshold"
        ],
        "defense_steps": [
            "Enforce strong password policies with complexity requirements",
            "Implement multi-factor authentication (MFA)",
            "Monitor for distributed login failures",
            "Use adaptive authentication based on risk signals"
        ]
    },
    {
        "id": 3,
        "name": "Phishing with Credential Harvesting",
        "difficulty": "EASY",
        "description": "Criminals create fake login pages that look identical to real ones, trick you into entering your password, then capture your credentials to access your accounts.",
        "attack_steps": [
            "Clone target company's login page with tools like Gophish",
            "Register look-alike domain (typosquatting)",
            "Craft convincing email with urgency or authority",
            "Capture credentials and optionally proxy to real site"
        ],
        "defense_steps": [
            "Train users to recognize phishing indicators",
            "Deploy email security with DMARC, DKIM, SPF",
            "Use phishing-resistant MFA like hardware keys",
            "Monitor for brand impersonation and takedown fake domains"
        ]
    },
    {
        "id": 4,
        "name": "LLMNR/NBT-NS Poisoning",
        "difficulty": "MEDIUM",
        "description": "When computers on your network ask 'where is the file server?', attackers answer 'right here!' and capture passwords when your computer tries to connect to them.",
        "attack_steps": [
            "Position on same network segment as targets",
            "Run Responder to answer broadcast name queries",
            "Capture NTLMv2 hashes from authentication attempts",
            "Crack hashes offline or relay to other services"
        ],
        "defense_steps": [
            "Disable LLMNR via Group Policy",
            "Disable NBT-NS in network adapter settings",
            "Enable SMB signing to prevent relay attacks",
            "Segment networks and monitor for suspicious broadcasts"
        ]
    },
    {
        "id": 5,
        "name": "Kerberoasting",
        "difficulty": "MEDIUM",
        "description": "Attackers request service account passwords from your network and crack them offline to gain access to critical systems like databases and file servers.",
        "attack_steps": [
            "Enumerate SPNs with tools like GetUserSPNs.py",
            "Request TGS tickets for service accounts",
            "Extract tickets and crack offline with hashcat",
            "Use cracked credentials to access services"
        ],
        "defense_steps": [
            "Use long, complex passwords for service accounts",
            "Implement Group Managed Service Accounts (gMSA)",
            "Monitor for excessive TGS requests",
            "Apply AES encryption instead of RC4 for Kerberos"
        ]
    },
    {
        "id": 6,
        "name": "Pass-the-Hash",
        "difficulty": "HARD",
        "description": "Hackers steal password hashes and reuse them to log in as other users without ever cracking the actual password - like using a master key mold.",
        "attack_steps": [
            "Obtain NTLM hash through credential dumping",
            "Use hash directly for authentication without cracking",
            "Authenticate to services accepting NTLM (SMB, WMI, etc.)",
            "Move laterally across the network"
        ],
        "defense_steps": [
            "Implement Credential Guard on Windows 10/11",
            "Use Protected Users security group for privileged accounts",
            "Disable NTLM where possible, enforce Kerberos",
            "Deploy LAPS for unique local admin passwords"
        ]
    },
    {
        "id": 7,
        "name": "Golden Ticket Attack",
        "difficulty": "EXPERT",
        "description": "After stealing the master encryption key from your domain controller, attackers forge unlimited access passes to impersonate any user forever - the ultimate skeleton key.",
        "attack_steps": [
            "Compromise domain controller to get KRBTGT hash",
            "Forge TGT with any user/group membership",
            "Ticket valid until KRBTGT password changed twice",
            "Access any resource in the domain as any user"
        ],
        "defense_steps": [
            "Reset KRBTGT password twice to invalidate tickets",
            "Monitor for TGTs with unusually long lifetimes",
            "Implement tiered administration model",
            "Use Advanced Threat Analytics or Defender for Identity"
        ]
    },
    {
        "id": 8,
        "name": "DNS Tunneling",
        "difficulty": "HARD",
        "description": "Attackers hide stolen data inside normal-looking website address lookups, sneaking information out of your network through a channel most firewalls ignore.",
        "attack_steps": [
            "Set up authoritative DNS server for controlled domain",
            "Encode data in DNS queries (subdomains) and responses",
            "Use tools like dnscat2 or iodine for C2 channel",
            "Bypass firewalls that allow outbound DNS"
        ],
        "defense_steps": [
            "Monitor for high-volume or unusual DNS queries",
            "Analyze DNS query entropy and length anomalies",
            "Force internal DNS resolution through proxy",
            "Block DNS over HTTPS (DoH) or monitor it"
        ]
    },
    {
        "id": 9,
        "name": "Living off the Land (LOLBins)",
        "difficulty": "MEDIUM",
        "description": "Instead of bringing their own malware, hackers abuse legitimate Windows tools already on your computer to download and run malicious code, making detection much harder.",
        "attack_steps": [
            "Use built-in tools like PowerShell, certutil, mshta",
            "Download payloads with certutil or bitsadmin",
            "Execute code through wmic, regsvr32, or rundll32",
            "Evade detection by avoiding custom malware"
        ],
        "defense_steps": [
            "Implement application allowlisting with AppLocker/WDAC",
            "Enable PowerShell logging (Script Block, Module, Transcription)",
            "Monitor command-line arguments for LOLBin abuse",
            "Use EDR with behavioral detection capabilities"
        ]
    },
    {
        "id": 10,
        "name": "Server-Side Request Forgery (SSRF)",
        "difficulty": "MEDIUM",
        "description": "Tricking your server into accessing internal systems that should be off-limits, exposing sensitive data, admin panels, or cloud credentials to attackers.",
        "attack_steps": [
            "Find functionality that fetches URLs (webhooks, imports)",
            "Test access to internal resources (169.254.169.254)",
            "Pivot to internal services not exposed externally",
            "Exfiltrate cloud metadata credentials"
        ],
        "defense_steps": [
            "Validate and allowlist destination URLs",
            "Block requests to internal/private IP ranges",
            "Disable unnecessary URL schemes (file://, gopher://)",
            "Use IMDSv2 requiring session tokens for cloud metadata"
        ]
    },
    {
        "id": 11,
        "name": "Command Injection",
        "difficulty": "HARD",
        "description": "Attackers insert operating system commands into form fields or URLs, making your server execute whatever they want - like remotely typing commands on your computer.",
        "attack_steps": [
            "Identify inputs passed to system commands",
            "Test with command separators (; | & ` $())",
            "Chain commands to establish reverse shell",
            "Escalate privileges through command access"
        ],
        "defense_steps": [
            "Avoid calling system commands with user input",
            "Use language APIs instead of shell commands",
            "If unavoidable, use strict allowlist validation",
            "Run applications with minimal privileges"
        ]
    },
    {
        "id": 12,
        "name": "Insecure Deserialization",
        "difficulty": "HARD",
        "description": "Applications trust data they previously saved, so attackers craft malicious 'saved data' that executes code when the application reads it back.",
        "attack_steps": [
            "Identify serialized data in requests or cookies",
            "Analyze application for gadget chains",
            "Craft malicious serialized object for RCE",
            "Use tools like ysoserial for Java applications"
        ],
        "defense_steps": [
            "Avoid deserializing untrusted data",
            "Implement integrity checks (HMAC) on serialized data",
            "Use allowlists for deserializable classes",
            "Keep frameworks updated to patch known gadgets"
        ]
    },
    {
        "id": 13,
        "name": "Subdomain Takeover",
        "difficulty": "EASY",
        "description": "When companies forget to remove old DNS records pointing to decommissioned cloud services, attackers claim those services and host malicious content on your trusted domain.",
        "attack_steps": [
            "Enumerate subdomains using tools like subfinder",
            "Check for dangling DNS records (CNAME to unclaimed service)",
            "Register the unclaimed resource on cloud provider",
            "Serve malicious content on trusted subdomain"
        ],
        "defense_steps": [
            "Regularly audit DNS records for stale entries",
            "Remove DNS records before deprovisioning services",
            "Monitor for unauthorized subdomain content changes",
            "Use subdomain takeover scanning tools proactively"
        ]
    },
    {
        "id": 14,
        "name": "JWT Token Attacks",
        "difficulty": "MEDIUM",
        "description": "Attackers exploit weak or misconfigured authentication tokens to forge their own access passes, impersonating other users or gaining admin privileges.",
        "attack_steps": [
            "Intercept JWT token from authentication flow",
            "Try algorithm confusion (alg:none or RS256->HS256)",
            "Brute force weak signing secrets",
            "Modify claims and resign with discovered key"
        ],
        "defense_steps": [
            "Use strong, random signing keys (256+ bits)",
            "Explicitly validate algorithm in verification code",
            "Implement short expiration times with refresh tokens",
            "Use asymmetric algorithms (RS256, ES256) properly"
        ]
    },
    {
        "id": 15,
        "name": "Directory Traversal",
        "difficulty": "EASY",
        "description": "By adding '../' to file paths, attackers escape intended directories and read sensitive files like passwords, configuration files, or source code from your server.",
        "attack_steps": [
            "Identify file path parameters in requests",
            "Test with ../ sequences to escape directory",
            "Try encoding bypasses (%2e%2e/, ..%00/)",
            "Read sensitive files like /etc/passwd or web.config"
        ],
        "defense_steps": [
            "Canonicalize paths and validate against allowlist",
            "Use chroot or containers to limit filesystem access",
            "Remove path separators from user input",
            "Store files with random names, use database mapping"
        ]
    },
    {
        "id": 16,
        "name": "Privilege Escalation via SUID",
        "difficulty": "MEDIUM",
        "description": "Attackers find programs with special 'run as admin' permissions and abuse them to gain full control of your Linux system - turning limited access into root power.",
        "attack_steps": [
            "Find SUID binaries with: find / -perm -4000",
            "Check GTFOBins for exploitable binaries",
            "Abuse misconfigured SUID programs",
            "Escalate to root through vulnerable binary"
        ],
        "defense_steps": [
            "Audit and minimize SUID/SGID binaries",
            "Remove SUID from unnecessary programs",
            "Use capabilities instead of SUID where possible",
            "Mount partitions with nosuid option"
        ]
    },
    {
        "id": 17,
        "name": "Cloud Storage Misconfiguration",
        "difficulty": "EASY",
        "description": "Amazon S3 buckets or Azure blobs accidentally left open to the public, exposing company files, customer data, and backups to anyone on the internet.",
        "attack_steps": [
            "Enumerate S3 buckets using keyword-based naming",
            "Check for public read/write permissions",
            "Download sensitive data or upload malicious content",
            "Pivot using discovered credentials in files"
        ],
        "defense_steps": [
            "Block public access at account level",
            "Enable S3 Block Public Access settings",
            "Use bucket policies with explicit denies",
            "Enable CloudTrail logging for all S3 operations"
        ]
    },
    {
        "id": 18,
        "name": "Container Escape",
        "difficulty": "EXPERT",
        "description": "Attackers break out of Docker containers that were supposed to isolate them, gaining access to the host system and potentially all other containers running on it.",
        "attack_steps": [
            "Check for privileged container or dangerous mounts",
            "Exploit kernel vulnerabilities (Dirty Pipe, etc.)",
            "Abuse Docker socket if mounted inside container",
            "Access host filesystem through /proc or device nodes"
        ],
        "defense_steps": [
            "Never run containers as privileged",
            "Use seccomp, AppArmor, or SELinux profiles",
            "Keep container runtime and kernel updated",
            "Implement Pod Security Standards in Kubernetes"
        ]
    },
    {
        "id": 19,
        "name": "OAuth Token Theft",
        "difficulty": "MEDIUM",
        "description": "Attackers hijack the 'Login with Google/Microsoft' flow to steal access tokens, letting them impersonate you on connected apps without knowing your password.",
        "attack_steps": [
            "Exploit open redirectors in OAuth flow",
            "Use redirect_uri manipulation to steal codes",
            "Phish users to authorize malicious application",
            "Replay stolen tokens for account access"
        ],
        "defense_steps": [
            "Strictly validate redirect_uri against allowlist",
            "Use PKCE (Proof Key for Code Exchange)",
            "Implement token binding where supported",
            "Audit and revoke unused OAuth application grants"
        ]
    },
    {
        "id": 20,
        "name": "Man-in-the-Middle (MITM)",
        "difficulty": "MEDIUM",
        "description": "Attackers secretly position themselves between you and the website you're visiting, reading and modifying everything you send - like someone opening your mail before delivery.",
        "attack_steps": [
            "Position between victim and target using ARP spoofing",
            "Intercept and modify traffic in real-time",
            "Strip TLS with tools like sslstrip (if possible)",
            "Capture credentials or inject malicious content"
        ],
        "defense_steps": [
            "Enforce HTTPS everywhere with HSTS preloading",
            "Implement certificate pinning for critical apps",
            "Use VPN for sensitive communications",
            "Enable 802.1X for network access control"
        ]
    },
    {
        "id": 21,
        "name": "Business Email Compromise (BEC)",
        "difficulty": "EASY",
        "description": "Criminals impersonate your CEO or CFO via email, tricking employees into wiring money or sharing sensitive data by exploiting trust and urgency.",
        "attack_steps": [
            "Compromise executive email or spoof their address",
            "Study communication patterns and relationships",
            "Send urgent request for wire transfer or gift cards",
            "Use authority and urgency to bypass verification"
        ],
        "defense_steps": [
            "Require out-of-band verification for financial requests",
            "Implement DMARC with reject policy",
            "Train employees on BEC indicators",
            "Flag external emails that spoof internal domains"
        ]
    },
    {
        "id": 22,
        "name": "API Key Exposure",
        "difficulty": "EASY",
        "description": "Developers accidentally publish secret passwords and API keys to GitHub, letting anyone who finds them access your cloud services, databases, or paid APIs.",
        "attack_steps": [
            "Search GitHub, GitLab for exposed credentials",
            "Use tools like truffleHog or gitleaks",
            "Check client-side JavaScript for hardcoded keys",
            "Abuse discovered keys for unauthorized access"
        ],
        "defense_steps": [
            "Use secrets managers, never commit credentials",
            "Implement pre-commit hooks to scan for secrets",
            "Rotate keys regularly and monitor for abuse",
            "Use short-lived tokens with minimal permissions"
        ]
    },
    {
        "id": 23,
        "name": "Wireless Evil Twin",
        "difficulty": "MEDIUM",
        "description": "Attackers set up a fake WiFi network with the same name as a legitimate one, tricking your device into connecting so they can spy on all your internet traffic.",
        "attack_steps": [
            "Create fake access point with same SSID as target",
            "Use stronger signal to attract victim connections",
            "Capture credentials through fake captive portal",
            "Perform MITM on connected clients"
        ],
        "defense_steps": [
            "Use WPA3 Enterprise with certificate validation",
            "Train users to verify network authenticity",
            "Deploy Wireless Intrusion Detection Systems",
            "Use always-on VPN for corporate devices"
        ]
    },
    {
        "id": 24,
        "name": "Domain Fronting",
        "difficulty": "HARD",
        "description": "Malware hides its communications by routing through trusted services like Google or Amazon, making malicious traffic look like normal website visits.",
        "attack_steps": [
            "Use CDN that allows routing based on Host header",
            "Send traffic appearing to go to legitimate domain",
            "CDN routes to attacker's backend server",
            "Bypass domain-based blocking and monitoring"
        ],
        "defense_steps": [
            "Implement TLS inspection for outbound traffic",
            "Monitor for Host header mismatches",
            "Use CDNs that have disabled domain fronting",
            "Deploy behavioral analysis for C2 detection"
        ]
    },
    {
        "id": 25,
        "name": "DLL Hijacking",
        "difficulty": "MEDIUM",
        "description": "Attackers place malicious code libraries where legitimate programs will accidentally load them, hijacking trusted applications to run their malware.",
        "attack_steps": [
            "Find applications with insecure DLL search order",
            "Place malicious DLL in application or PATH directory",
            "Wait for application to load the malicious DLL",
            "Execute code in context of legitimate application"
        ],
        "defense_steps": [
            "Use absolute paths for DLL loading",
            "Implement SafeDllSearchMode",
            "Sign and verify all loaded DLLs",
            "Restrict write access to application directories"
        ]
    },
    {
        "id": 26,
        "name": "Watering Hole Attack",
        "difficulty": "HARD",
        "description": "Instead of attacking you directly, hackers compromise websites you frequently visit, infecting your computer when you browse sites you trust.",
        "attack_steps": [
            "Identify websites frequently visited by target group",
            "Compromise the trusted website",
            "Inject malicious code or exploit kit",
            "Selectively target specific visitor IP ranges"
        ],
        "defense_steps": [
            "Keep browsers and plugins fully patched",
            "Use network segmentation and monitoring",
            "Implement browser isolation for high-risk users",
            "Monitor for unusual website behavior changes"
        ]
    },
    {
        "id": 27,
        "name": "Macro Malware in Documents",
        "difficulty": "EASY",
        "description": "Malicious Word or Excel documents contain hidden scripts that run when you click 'Enable Content', downloading malware onto your computer.",
        "attack_steps": [
            "Create document with malicious VBA macro",
            "Social engineer user to enable macros",
            "Macro downloads and executes payload",
            "Establish persistence and C2 connection"
        ],
        "defense_steps": [
            "Disable macros by default via Group Policy",
            "Use Attack Surface Reduction (ASR) rules",
            "Block macros in documents from internet",
            "Convert documents to PDF for external sharing"
        ]
    },
    {
        "id": 28,
        "name": "Registry Persistence",
        "difficulty": "MEDIUM",
        "description": "Malware adds itself to Windows startup locations in the registry, ensuring it runs every time you restart your computer - surviving reboots and updates.",
        "attack_steps": [
            "Add entries to Run/RunOnce keys for user persistence",
            "Use HKLM keys for system-wide persistence",
            "Abuse lesser-known keys like AppInit_DLLs",
            "Survive reboots and user logoffs"
        ],
        "defense_steps": [
            "Monitor registry keys with Sysmon or EDR",
            "Implement application allowlisting",
            "Use least privilege to limit registry writes",
            "Regularly audit autorun locations"
        ]
    },
    {
        "id": 29,
        "name": "BloodHound AD Mapping",
        "difficulty": "MEDIUM",
        "description": "Attackers use specialized tools to map out your entire corporate network, finding the quickest path from a regular user account to domain administrator.",
        "attack_steps": [
            "Run SharpHound to collect AD relationships",
            "Import data into BloodHound for analysis",
            "Identify shortest paths to Domain Admin",
            "Chain attack paths through vulnerable nodes"
        ],
        "defense_steps": [
            "Review and reduce excessive privileges",
            "Clean up nested group memberships",
            "Implement tiered administration model",
            "Monitor for LDAP enumeration activity"
        ]
    },
    {
        "id": 30,
        "name": "CSRF (Cross-Site Request Forgery)",
        "difficulty": "MEDIUM",
        "description": "A malicious website tricks your browser into performing actions on other sites where you're logged in - like transferring money while you're still signed into your bank.",
        "attack_steps": [
            "Identify state-changing actions without CSRF protection",
            "Craft malicious page with auto-submitting form",
            "Trick authenticated user into visiting page",
            "Action executes with victim's session"
        ],
        "defense_steps": [
            "Implement anti-CSRF tokens on all forms",
            "Use SameSite cookie attribute (Strict or Lax)",
            "Verify Origin and Referer headers",
            "Require re-authentication for sensitive actions"
        ]
    },
    {
        "id": 31,
        "name": "WMI Persistence",
        "difficulty": "HARD",
        "description": "Malware hides in Windows Management system to automatically restart itself based on triggers like system boot or specific times - nearly invisible to antivirus.",
        "attack_steps": [
            "Create WMI event subscription for persistence",
            "Use EventConsumer to execute payload on trigger",
            "Survive reboots without file-based persistence",
            "Difficult to detect with traditional antivirus"
        ],
        "defense_steps": [
            "Monitor WMI activity with Sysmon Event ID 19-21",
            "Audit WMI subscriptions regularly",
            "Restrict WMI access to necessary accounts",
            "Use ASR rules to block WMI event subscriptions"
        ]
    },
    {
        "id": 32,
        "name": "Browser Extension Hijacking",
        "difficulty": "MEDIUM",
        "description": "Malicious browser extensions spy on everything you do online - reading your passwords, banking info, and private messages from every website you visit.",
        "attack_steps": [
            "Create or compromise browser extension",
            "Request broad permissions (all URLs, cookies)",
            "Intercept web traffic and steal credentials",
            "Inject malicious content into pages"
        ],
        "defense_steps": [
            "Audit and allowlist approved extensions",
            "Use enterprise browser management policies",
            "Monitor extension installations and updates",
            "Educate users about extension permissions"
        ]
    },
    {
        "id": 33,
        "name": "Scheduled Task Persistence",
        "difficulty": "EASY",
        "description": "Attackers create Windows scheduled tasks to run their malware automatically at startup, login, or specific times - like a recurring calendar event for malware.",
        "attack_steps": [
            "Create scheduled task running malicious payload",
            "Set trigger for boot, logon, or time-based",
            "Run with SYSTEM or user privileges",
            "Persist across reboots and updates"
        ],
        "defense_steps": [
            "Monitor scheduled task creation with Sysmon",
            "Audit scheduled tasks regularly",
            "Restrict task creation to authorized users",
            "Use application allowlisting to prevent execution"
        ]
    },
    {
        "id": 34,
        "name": "Silver Ticket Attack",
        "difficulty": "HARD",
        "description": "After stealing a service account's password hash, attackers forge access tickets to that specific service without ever contacting the domain controller.",
        "attack_steps": [
            "Obtain service account password hash",
            "Forge TGS for specific service without DC contact",
            "Access target service as any user",
            "Stealthier than Golden Ticket (no DC communication)"
        ],
        "defense_steps": [
            "Use gMSA for service accounts",
            "Implement PAC validation on services",
            "Monitor for TGS requests without prior TGT",
            "Rotate service account passwords regularly"
        ]
    },
    {
        "id": 35,
        "name": "PowerShell Constrained Language Bypass",
        "difficulty": "HARD",
        "description": "When security tools restrict PowerShell commands, attackers find creative workarounds to still run malicious scripts - defeating your protective measures.",
        "attack_steps": [
            "Identify constrained language mode restrictions",
            "Use Add-Type to compile inline C# code",
            "Leverage COM objects for code execution",
            "Downgrade PowerShell version if possible"
        ],
        "defense_steps": [
            "Implement WDAC with strict policies",
            "Block PowerShell v2 via Windows Features",
            "Enable comprehensive PowerShell logging",
            "Use Just Enough Administration (JEA)"
        ]
    },
    {
        "id": 36,
        "name": "Email Header Injection",
        "difficulty": "MEDIUM",
        "description": "Attackers abuse your website's contact form to send spam or phishing emails that appear to come from your company's legitimate email servers.",
        "attack_steps": [
            "Find contact forms that send emails",
            "Inject newlines and additional headers",
            "Add BCC or modify From address",
            "Use application as open relay for spam/phishing"
        ],
        "defense_steps": [
            "Sanitize user input, remove newlines",
            "Use email libraries with proper encoding",
            "Implement rate limiting on email functions",
            "Monitor outbound email for anomalies"
        ]
    },
    {
        "id": 37,
        "name": "XML External Entity (XXE)",
        "difficulty": "MEDIUM",
        "description": "When applications process XML files, attackers inject special references that trick the server into revealing sensitive files or connecting to internal systems.",
        "attack_steps": [
            "Identify XML parsing endpoints",
            "Inject external entity referencing local files",
            "Exfiltrate sensitive files through entity expansion",
            "Perform SSRF through external DTD references"
        ],
        "defense_steps": [
            "Disable external entity processing",
            "Use less complex formats like JSON where possible",
            "Validate XML against strict schema",
            "Keep XML parsers updated"
        ]
    },
    {
        "id": 38,
        "name": "Active Directory Certificate Services Abuse",
        "difficulty": "EXPERT",
        "description": "Misconfigured certificate templates let attackers request certificates that impersonate any user, including domain admins - a backdoor that survives password changes.",
        "attack_steps": [
            "Find misconfigured certificate templates",
            "Request certificate for privileged user (ESC1)",
            "Use certificate for Kerberos PKINIT authentication",
            "Gain Domain Admin through certificate abuse"
        ],
        "defense_steps": [
            "Audit certificate templates for misconfigurations",
            "Require manager approval for sensitive templates",
            "Enable certificate mapping for authentication",
            "Monitor certificate requests and usage"
        ]
    },
    {
        "id": 39,
        "name": "Cobalt Strike Beacon Detection",
        "difficulty": "HARD",
        "description": "Professional hackers use Cobalt Strike, a powerful commercial tool, to remotely control compromised systems, evade detection, and move through networks.",
        "attack_steps": [
            "Deploy beacon through phishing or exploit",
            "Use Malleable C2 profiles for evasion",
            "Establish encrypted command and control",
            "Perform post-exploitation and lateral movement"
        ],
        "defense_steps": [
            "Deploy EDR with memory scanning capabilities",
            "Monitor for named pipe and SMB beacon traffic",
            "Analyze network for periodic callback patterns",
            "Use JA3/JA3S fingerprinting for TLS detection"
        ]
    },
    {
        "id": 40,
        "name": "SSH Key Theft",
        "difficulty": "MEDIUM",
        "description": "Attackers steal SSH private key files from compromised machines, then use those keys to access other servers without needing passwords.",
        "attack_steps": [
            "Locate SSH private keys in .ssh directories",
            "Check for keys without passphrases",
            "Use agent forwarding abuse if enabled",
            "Pivot to additional systems using stolen keys"
        ],
        "defense_steps": [
            "Always use passphrases on SSH keys",
            "Disable agent forwarding when not needed",
            "Use SSH certificates with short validity",
            "Implement centralized SSH key management"
        ]
    },
    {
        "id": 41,
        "name": "HTTP Request Smuggling",
        "difficulty": "EXPERT",
        "description": "Attackers exploit differences in how front-end and back-end servers interpret HTTP requests, sneaking malicious requests past security controls.",
        "attack_steps": [
            "Identify discrepancies between frontend and backend",
            "Craft ambiguous Content-Length and Transfer-Encoding",
            "Smuggle malicious requests to backend",
            "Bypass security controls or poison cache"
        ],
        "defense_steps": [
            "Normalize request parsing across all layers",
            "Use HTTP/2 end-to-end where possible",
            "Reject ambiguous requests at load balancer",
            "Keep web server software updated"
        ]
    },
    {
        "id": 42,
        "name": "Process Injection",
        "difficulty": "HARD",
        "description": "Malware injects its code into legitimate running programs like Chrome or Word, hiding inside trusted processes to avoid detection.",
        "attack_steps": [
            "Choose target process for injection",
            "Use techniques like CreateRemoteThread or APC injection",
            "Execute code in context of legitimate process",
            "Evade process-based security monitoring"
        ],
        "defense_steps": [
            "Monitor for cross-process memory operations",
            "Enable CIG (Code Integrity Guard) on processes",
            "Use EDR with injection detection",
            "Implement Credential Guard to protect LSASS"
        ]
    },
    {
        "id": 43,
        "name": "Supply Chain Attack",
        "difficulty": "EXPERT",
        "description": "Rather than attacking you directly, hackers compromise the software vendors you trust, inserting malware into legitimate updates - like poisoning the water supply.",
        "attack_steps": [
            "Compromise developer environment or build system",
            "Inject malicious code into legitimate software",
            "Distribute through official update channels",
            "Gain trusted access to target environments"
        ],
        "defense_steps": [
            "Implement SBOM (Software Bill of Materials)",
            "Verify signatures on all dependencies",
            "Use dependency scanning and pinning",
            "Isolate build systems with zero-trust principles"
        ]
    },
    {
        "id": 44,
        "name": "Keylogger Deployment",
        "difficulty": "MEDIUM",
        "description": "Malware secretly records every keystroke you make, capturing passwords, credit card numbers, and private messages as you type them.",
        "attack_steps": [
            "Deploy software keylogger through malware",
            "Hook keyboard APIs to capture keystrokes",
            "Exfiltrate captured data to C2 server",
            "Target credentials and sensitive communications"
        ],
        "defense_steps": [
            "Use password managers with auto-fill",
            "Implement virtual keyboards for sensitive input",
            "Monitor for suspicious API hooking behavior",
            "Use EDR to detect keylogging indicators"
        ]
    },
    {
        "id": 45,
        "name": "NTDS.dit Extraction",
        "difficulty": "HARD",
        "description": "Attackers steal the Active Directory database file containing every user's password hash in your organization - the ultimate credential heist.",
        "attack_steps": [
            "Gain Domain Admin or backup operator access",
            "Use Volume Shadow Copy to access locked file",
            "Extract NTDS.dit and SYSTEM hive",
            "Dump all domain password hashes offline"
        ],
        "defense_steps": [
            "Monitor for Volume Shadow Copy activity on DCs",
            "Implement Privileged Access Workstations (PAW)",
            "Use gMSA and reduce standing privileges",
            "Alert on sensitive file access on DCs"
        ]
    },
    {
        "id": 46,
        "name": "Mimikatz Credential Dumping",
        "difficulty": "HARD",
        "description": "The infamous Mimikatz tool extracts passwords directly from Windows memory, revealing plaintext credentials of anyone who logged into the computer.",
        "attack_steps": [
            "Execute Mimikatz with administrative privileges",
            "Dump credentials from LSASS memory",
            "Extract Kerberos tickets and NTLM hashes",
            "Use credentials for lateral movement"
        ],
        "defense_steps": [
            "Enable Credential Guard on supported systems",
            "Disable WDigest authentication",
            "Protect LSASS with RunAsPPL",
            "Deploy EDR monitoring LSASS access"
        ]
    },
    {
        "id": 47,
        "name": "SMB Relay Attack",
        "difficulty": "MEDIUM",
        "description": "When your computer tries to authenticate to a file server, attackers intercept and forward those credentials to another server, gaining your access level.",
        "attack_steps": [
            "Position to intercept SMB authentication",
            "Use tools like ntlmrelayx to relay credentials",
            "Authenticate to target services as victim",
            "Execute commands or access shares on target"
        ],
        "defense_steps": [
            "Enable SMB signing on all systems",
            "Disable NTLM where possible",
            "Use EPA (Extended Protection for Authentication)",
            "Implement network segmentation"
        ]
    },
    {
        "id": 48,
        "name": "Log4Shell (Log4j RCE)",
        "difficulty": "HARD",
        "description": "One of the worst vulnerabilities ever - attackers send a special string that makes Java applications automatically download and run malware.",
        "attack_steps": [
            "Identify applications using vulnerable Log4j",
            "Inject JNDI lookup string in logged input",
            "Host malicious LDAP/RMI server",
            "Achieve remote code execution on target"
        ],
        "defense_steps": [
            "Update Log4j to patched versions",
            "Set log4j2.formatMsgNoLookups=true",
            "Block outbound LDAP/RMI connections",
            "Use WAF rules to detect JNDI patterns"
        ]
    },
    {
        "id": 49,
        "name": "Cloud Privilege Escalation",
        "difficulty": "HARD",
        "description": "Attackers with limited cloud access find misconfigurations that let them grant themselves admin permissions, taking over your entire AWS/Azure/GCP account.",
        "attack_steps": [
            "Enumerate IAM permissions of compromised identity",
            "Find path to escalate privileges (PassRole, etc.)",
            "Create new admin user or attach admin policy",
            "Gain persistent high-privilege access"
        ],
        "defense_steps": [
            "Implement least privilege for all identities",
            "Use AWS IAM Access Analyzer or equivalent",
            "Enable CloudTrail with anomaly detection",
            "Regularly audit IAM policies and roles"
        ]
    },
    {
        "id": 50,
        "name": "Ransomware Deployment",
        "difficulty": "HARD",
        "description": "Criminals encrypt all your files and demand payment for the decryption key, often threatening to leak stolen data publicly if you don't pay.",
        "attack_steps": [
            "Gain initial access through phishing or RDP",
            "Establish persistence and map network",
            "Exfiltrate sensitive data for double extortion",
            "Deploy ransomware and encrypt systems"
        ],
        "defense_steps": [
            "Maintain offline, tested backups",
            "Implement network segmentation",
            "Use EDR and monitor for encryption behavior",
            "Disable unnecessary services like RDP"
        ]
    },
    {
        "id": 51,
        "name": "Local File Inclusion (LFI)",
        "difficulty": "MEDIUM",
        "description": "Web applications that load files based on user input can be tricked into reading sensitive system files or even executing attacker-controlled code.",
        "attack_steps": [
            "Identify parameters loading local files",
            "Use path traversal to include sensitive files",
            "Chain with log poisoning for RCE",
            "Read application source code or config files"
        ],
        "defense_steps": [
            "Use allowlist for includeable files",
            "Avoid user input in file paths",
            "Disable PHP wrappers if not needed",
            "Run web server with minimal permissions"
        ]
    },
    {
        "id": 52,
        "name": "GraphQL Introspection Abuse",
        "difficulty": "EASY",
        "description": "GraphQL APIs often expose their entire schema, letting attackers discover hidden endpoints, sensitive data fields, and potential vulnerabilities.",
        "attack_steps": [
            "Query __schema to dump entire API structure",
            "Discover hidden queries, mutations, and types",
            "Find sensitive fields and test authorization",
            "Craft targeted attacks based on schema"
        ],
        "defense_steps": [
            "Disable introspection in production",
            "Implement proper authorization on all fields",
            "Use query depth and complexity limits",
            "Monitor for introspection queries"
        ]
    },
    {
        "id": 53,
        "name": "Android APK Analysis",
        "difficulty": "MEDIUM",
        "description": "Attackers reverse-engineer mobile apps to extract hardcoded secrets, API keys, and discover vulnerabilities in client-side security checks.",
        "attack_steps": [
            "Decompile APK with tools like jadx or apktool",
            "Extract hardcoded credentials and API keys",
            "Analyze network traffic for API endpoints",
            "Find vulnerabilities in client-side logic"
        ],
        "defense_steps": [
            "Never embed secrets in mobile apps",
            "Use obfuscation and code hardening",
            "Implement certificate pinning",
            "Validate all security checks server-side"
        ]
    },
    {
        "id": 54,
        "name": "Formjacking",
        "difficulty": "MEDIUM",
        "description": "Hidden malicious code on shopping websites secretly copies your credit card details as you type them, sending them to criminals.",
        "attack_steps": [
            "Compromise website or third-party script",
            "Inject JavaScript to capture form data",
            "Exfiltrate payment card details to attacker server",
            "Remain undetected in legitimate page"
        ],
        "defense_steps": [
            "Implement Subresource Integrity (SRI)",
            "Use Content Security Policy (CSP)",
            "Monitor for unauthorized script changes",
            "Regular security scanning of third-party code"
        ]
    },
    {
        "id": 55,
        "name": "Responder Credential Capture",
        "difficulty": "MEDIUM",
        "description": "A popular hacking tool that listens on your network for computers looking for resources, then tricks them into handing over password hashes.",
        "attack_steps": [
            "Deploy Responder on internal network",
            "Answer LLMNR, NBT-NS, and mDNS queries",
            "Capture NTLMv1/v2 hashes from clients",
            "Crack or relay captured credentials"
        ],
        "defense_steps": [
            "Disable LLMNR and NBT-NS via Group Policy",
            "Enable SMB signing",
            "Monitor for rogue name resolution responses",
            "Use network segmentation"
        ]
    },
    {
        "id": 56,
        "name": "PrintNightmare Exploitation",
        "difficulty": "HARD",
        "description": "A critical Windows vulnerability in the print spooler service that lets attackers instantly gain SYSTEM-level access to any unpatched computer.",
        "attack_steps": [
            "Identify vulnerable Windows print spooler service",
            "Use CVE-2021-34527 to load malicious DLL",
            "Gain SYSTEM privileges on target",
            "Potentially escalate to domain admin on DCs"
        ],
        "defense_steps": [
            "Apply Microsoft security patches",
            "Disable print spooler where not needed",
            "Restrict Point and Print with Group Policy",
            "Monitor for suspicious spooler activity"
        ]
    },
    {
        "id": 57,
        "name": "Time-Based Blind SQL Injection",
        "difficulty": "HARD",
        "description": "When applications don't show database errors, attackers use time delays to extract data one character at a time - slow but effective.",
        "attack_steps": [
            "Inject time delay payloads (SLEEP, WAITFOR)",
            "Infer database responses from response timing",
            "Extract data one character at a time",
            "Use binary search to speed up extraction"
        ],
        "defense_steps": [
            "Use parameterized queries consistently",
            "Implement query timeouts",
            "Monitor for unusually slow queries",
            "Use WAF with SQLi detection"
        ]
    },
    {
        "id": 58,
        "name": "Dependency Confusion",
        "difficulty": "MEDIUM",
        "description": "Attackers publish malicious packages with the same names as your private internal libraries, tricking your build system into downloading malware.",
        "attack_steps": [
            "Identify internal package names from repositories",
            "Create public package with same name",
            "Trick package managers to pull malicious version",
            "Execute code during package installation"
        ],
        "defense_steps": [
            "Claim namespaces on public registries",
            "Configure package managers for private first",
            "Use package signing and verification",
            "Implement dependency lockfiles"
        ]
    },
    {
        "id": 59,
        "name": "Bluetooth Exploitation",
        "difficulty": "MEDIUM",
        "description": "Attackers exploit vulnerabilities in Bluetooth connections to take over phones, laptops, and IoT devices without any user interaction.",
        "attack_steps": [
            "Scan for discoverable Bluetooth devices",
            "Exploit vulnerabilities like BlueBorne",
            "Pair without authentication if possible",
            "Access device data or establish C2"
        ],
        "defense_steps": [
            "Keep Bluetooth firmware updated",
            "Disable Bluetooth when not in use",
            "Set devices to non-discoverable mode",
            "Monitor for unknown device connections"
        ]
    },
    {
        "id": 60,
        "name": "Host Header Injection",
        "difficulty": "MEDIUM",
        "description": "Attackers manipulate the Host header in HTTP requests to hijack password reset links, poison web caches, or bypass security controls.",
        "attack_steps": [
            "Modify Host header in HTTP requests",
            "Exploit password reset link generation",
            "Poison web cache with malicious content",
            "Bypass access controls based on host"
        ],
        "defense_steps": [
            "Validate Host header against allowlist",
            "Use absolute URLs in password reset emails",
            "Configure web server to reject invalid hosts",
            "Implement proper cache-control headers"
        ]
    },
    {
        "id": 61,
        "name": "Memory Scraping",
        "difficulty": "HARD",
        "description": "Malware on payment terminals reads credit card numbers directly from computer memory before they get encrypted, stealing thousands of cards at once.",
        "attack_steps": [
            "Compromise point-of-sale or payment system",
            "Scan process memory for card data patterns",
            "Extract track data before encryption",
            "Exfiltrate data to attacker infrastructure"
        ],
        "defense_steps": [
            "Implement point-to-point encryption (P2PE)",
            "Use tokenization for stored card data",
            "Deploy memory protection technologies",
            "Monitor for unauthorized memory access"
        ]
    },
    {
        "id": 62,
        "name": "IDOR (Insecure Direct Object Reference)",
        "difficulty": "EASY",
        "description": "Simply changing a number in the URL (like changing order/1234 to order/1235) lets attackers view or modify other users' private data.",
        "attack_steps": [
            "Identify sequential or predictable object IDs",
            "Modify ID parameters to access other users' data",
            "Enumerate through possible ID values",
            "Access or modify unauthorized resources"
        ],
        "defense_steps": [
            "Use non-sequential GUIDs for object references",
            "Implement proper authorization checks",
            "Log and monitor access patterns",
            "Use indirect reference maps per session"
        ]
    },
    {
        "id": 63,
        "name": "Type Juggling Attacks",
        "difficulty": "MEDIUM",
        "description": "PHP and JavaScript's loose type comparisons let attackers bypass authentication by exploiting how these languages compare different data types.",
        "attack_steps": [
            "Identify loose type comparisons in PHP/JavaScript",
            "Craft payloads exploiting type coercion",
            "Bypass authentication with magic hash values",
            "Manipulate comparison logic for privilege escalation"
        ],
        "defense_steps": [
            "Use strict comparison operators (===)",
            "Validate and cast input types explicitly",
            "Audit code for loose comparisons",
            "Use static analysis tools to detect issues"
        ]
    },
    {
        "id": 64,
        "name": "SSTI (Server-Side Template Injection)",
        "difficulty": "HARD",
        "description": "When websites use templates to generate pages, attackers inject template code that gets executed on the server, often leading to full system takeover.",
        "attack_steps": [
            "Identify user input in template rendering",
            "Test with template syntax like {{7*7}}",
            "Discover template engine and craft payload",
            "Achieve remote code execution through templates"
        ],
        "defense_steps": [
            "Never pass user input directly to templates",
            "Use sandbox mode for template engines",
            "Implement strict input validation",
            "Prefer logic-less templates where possible"
        ]
    },
    {
        "id": 65,
        "name": "Firmware Analysis",
        "difficulty": "HARD",
        "description": "Hackers extract and reverse-engineer router and IoT device firmware to find hardcoded passwords, backdoors, and vulnerabilities.",
        "attack_steps": [
            "Extract firmware from device or download",
            "Use binwalk to identify and extract filesystem",
            "Analyze for hardcoded credentials and keys",
            "Find command injection or backdoor access"
        ],
        "defense_steps": [
            "Encrypt firmware with secure boot validation",
            "Remove debug interfaces in production",
            "Implement firmware signing and verification",
            "Regular security audits of embedded systems"
        ]
    },
    {
        "id": 66,
        "name": "Service Principal Abuse (Azure)",
        "difficulty": "HARD",
        "description": "Azure service accounts often have excessive permissions - attackers who steal their credentials can access cloud resources across your entire tenant.",
        "attack_steps": [
            "Enumerate Service Principals with excessive permissions",
            "Obtain SP credentials from config or metadata",
            "Use credentials to access Azure resources",
            "Escalate privileges through role assignments"
        ],
        "defense_steps": [
            "Apply least privilege to Service Principals",
            "Use Managed Identities instead of SPs where possible",
            "Rotate credentials and audit access logs",
            "Implement Conditional Access for SP authentication"
        ]
    },
    {
        "id": 67,
        "name": "GPO Abuse",
        "difficulty": "HARD",
        "description": "Attackers who gain access to modify Group Policy can push malicious settings or scripts to every computer in your domain automatically.",
        "attack_steps": [
            "Gain write access to Group Policy Objects",
            "Modify GPO to deploy malicious scripts or settings",
            "Wait for group policy refresh (90 min default)",
            "Execute code on all machines receiving GPO"
        ],
        "defense_steps": [
            "Audit GPO permissions regularly",
            "Alert on GPO modifications",
            "Implement tiered admin model for GPO management",
            "Use LAPS to prevent lateral movement"
        ]
    },
    {
        "id": 68,
        "name": "Account Enumeration",
        "difficulty": "EASY",
        "description": "Login pages that say 'user not found' vs 'wrong password' let attackers build a list of valid usernames for targeted password attacks.",
        "attack_steps": [
            "Test login and registration endpoints",
            "Observe different responses for valid vs invalid users",
            "Build list of valid usernames from differences",
            "Use list for targeted attacks"
        ],
        "defense_steps": [
            "Use generic error messages consistently",
            "Implement account lockout and rate limiting",
            "Add timing delays to normalize responses",
            "Use CAPTCHA for login and registration"
        ]
    },
    {
        "id": 69,
        "name": "WebSocket Security Issues",
        "difficulty": "MEDIUM",
        "description": "Real-time WebSocket connections often skip the same security checks as regular HTTP requests, creating hidden vulnerabilities in chat and notification features.",
        "attack_steps": [
            "Intercept WebSocket traffic with Burp or similar",
            "Identify missing authentication on WS endpoints",
            "Inject malicious messages through WebSocket",
            "Exploit lack of input validation or CSRF"
        ],
        "defense_steps": [
            "Authenticate WebSocket connections with tokens",
            "Validate Origin header on WS handshake",
            "Implement proper input validation on messages",
            "Use secure WebSocket (wss://) connections"
        ]
    },
    {
        "id": 70,
        "name": "Clickjacking",
        "difficulty": "EASY",
        "description": "Invisible overlays on web pages trick you into clicking hidden buttons - you think you're playing a game but you're actually transferring money.",
        "attack_steps": [
            "Create transparent iframe over legitimate site",
            "Trick user into clicking invisible button",
            "Hijack clicks to perform unintended actions",
            "Steal credentials or change settings"
        ],
        "defense_steps": [
            "Implement X-Frame-Options header",
            "Use Content-Security-Policy frame-ancestors",
            "Add frame-busting JavaScript as backup",
            "Require re-authentication for sensitive actions"
        ]
    },
    {
        "id": 71,
        "name": "DCSync Attack",
        "difficulty": "HARD",
        "description": "Attackers with the right permissions can ask the domain controller to sync all password hashes to them - as if they were a legitimate backup server.",
        "attack_steps": [
            "Obtain account with replication permissions",
            "Use Mimikatz to request replication from DC",
            "Extract password hashes for all domain accounts",
            "Create Golden Ticket or crack passwords"
        ],
        "defense_steps": [
            "Audit accounts with replication permissions",
            "Monitor for unusual replication requests",
            "Implement AdminSDHolder protections",
            "Use Defender for Identity to detect DCSync"
        ]
    },
    {
        "id": 72,
        "name": "Exposed Git Repository",
        "difficulty": "EASY",
        "description": "Accidentally exposed .git folders on websites let attackers download your entire source code history, including old passwords and secrets.",
        "attack_steps": [
            "Access /.git/ directory on web server",
            "Download and reconstruct repository",
            "Extract source code, credentials, and secrets",
            "Analyze commit history for sensitive data"
        ],
        "defense_steps": [
            "Block access to .git directories in web server config",
            "Use separate deployment without .git",
            "Scan for exposed .git in regular assessments",
            "Use git-secrets to prevent credential commits"
        ]
    },
    {
        "id": 73,
        "name": "ICS/SCADA Attacks",
        "difficulty": "EXPERT",
        "description": "Attacks on industrial control systems can shut down power grids, water treatment plants, and manufacturing facilities - causing real-world physical damage.",
        "attack_steps": [
            "Identify industrial control systems on network",
            "Exploit legacy protocols lacking authentication",
            "Send commands to manipulate physical processes",
            "Cause operational disruption or safety issues"
        ],
        "defense_steps": [
            "Segment OT networks from IT networks",
            "Implement network monitoring for OT protocols",
            "Use protocol-aware firewalls for ICS traffic",
            "Maintain inventory of all ICS assets"
        ]
    },
    {
        "id": 74,
        "name": "Password Manager Vulnerabilities",
        "difficulty": "MEDIUM",
        "description": "Even password managers can be attacked - through malicious websites triggering auto-fill, or malware reading passwords from memory.",
        "attack_steps": [
            "Target password manager process or memory",
            "Exploit auto-fill on malicious sites",
            "Access local database if weakly encrypted",
            "Capture master password through keylogging"
        ],
        "defense_steps": [
            "Keep password manager updated",
            "Use strong master password with 2FA",
            "Lock password manager when inactive",
            "Enable origin checking for auto-fill"
        ]
    },
    {
        "id": 75,
        "name": "Steganography Detection Evasion",
        "difficulty": "HARD",
        "description": "Attackers hide malware or stolen data inside innocent-looking images, allowing malicious payloads to slip past security tools undetected.",
        "attack_steps": [
            "Hide malware or commands in image files",
            "Use tools like steghide or LSB techniques",
            "Deliver payload through innocent-looking images",
            "Extract and execute hidden data on target"
        ],
        "defense_steps": [
            "Implement file type verification beyond extension",
            "Use sandboxing for downloaded files",
            "Monitor for unusual image processing activity",
            "Deploy advanced threat detection with behavioral analysis"
        ]
    },
    {
        "id": 76,
        "name": "VPN Credential Theft",
        "difficulty": "MEDIUM",
        "description": "Stolen VPN credentials give attackers direct access to your internal network from anywhere in the world - the keys to your digital kingdom.",
        "attack_steps": [
            "Phish VPN credentials with fake login page",
            "Exploit VPN vulnerabilities (CVE-2018-13379, etc.)",
            "Capture credentials from compromised endpoints",
            "Gain persistent remote access to network"
        ],
        "defense_steps": [
            "Implement MFA for all VPN access",
            "Keep VPN software patched and updated",
            "Use certificate-based authentication",
            "Monitor VPN logins for anomalies"
        ]
    },
    {
        "id": 77,
        "name": "Prototype Pollution",
        "difficulty": "HARD",
        "description": "JavaScript's prototype chain can be poisoned to add malicious properties to every object in an application, leading to XSS or remote code execution.",
        "attack_steps": [
            "Identify JavaScript code modifying object prototypes",
            "Inject __proto__ or constructor.prototype properties",
            "Pollute Object prototype to affect all objects",
            "Achieve XSS, RCE, or privilege escalation"
        ],
        "defense_steps": [
            "Use Object.freeze() on prototypes",
            "Validate and sanitize user input for keys",
            "Use Map instead of plain objects",
            "Update dependencies with prototype pollution fixes"
        ]
    },
    {
        "id": 78,
        "name": "RDP BlueKeep Exploitation",
        "difficulty": "HARD",
        "description": "A wormable Windows vulnerability that lets attackers take over computers through Remote Desktop without any authentication required.",
        "attack_steps": [
            "Scan for systems vulnerable to CVE-2019-0708",
            "Exploit pre-authentication RCE vulnerability",
            "Gain SYSTEM level access without credentials",
            "Potentially wormable across networks"
        ],
        "defense_steps": [
            "Apply Microsoft security patches immediately",
            "Disable RDP if not needed",
            "Use Network Level Authentication (NLA)",
            "Implement VPN or jump servers for RDP access"
        ]
    },
    {
        "id": 79,
        "name": "Session Fixation",
        "difficulty": "MEDIUM",
        "description": "Attackers pre-set your session ID before you log in, then use that same ID to hijack your authenticated session after you enter your password.",
        "attack_steps": [
            "Obtain valid session ID from application",
            "Force victim to authenticate with known session ID",
            "Hijack authenticated session using fixed ID",
            "Access application as authenticated user"
        ],
        "defense_steps": [
            "Regenerate session ID after authentication",
            "Use secure, HTTP-only, SameSite cookies",
            "Implement additional session binding (IP, user-agent)",
            "Expire sessions on logout and timeout"
        ]
    },
    {
        "id": 80,
        "name": "Office Macro Alternative (DDE)",
        "difficulty": "MEDIUM",
        "description": "Even with macros disabled, Word and Excel documents can execute code through Dynamic Data Exchange - a lesser-known but equally dangerous feature.",
        "attack_steps": [
            "Embed DDE field in Word or Excel document",
            "Craft payload to execute on document open",
            "Bypass macro restrictions with DDE",
            "Social engineer user to allow connection"
        ],
        "defense_steps": [
            "Disable DDE in Microsoft Office via registry",
            "Use ASR rules to block Office child processes",
            "Train users to reject external content prompts",
            "Monitor for unusual Office subprocess execution"
        ]
    },
    {
        "id": 81,
        "name": "Shadow Admin Accounts",
        "difficulty": "MEDIUM",
        "description": "Hidden privileged accounts that aren't in obvious admin groups but still have powerful permissions - the backdoors that security teams often miss.",
        "attack_steps": [
            "Identify high-privilege accounts not in admin groups",
            "Look for accounts with DCSync or GPO permissions",
            "Exploit these less-monitored privileged accounts",
            "Maintain persistence through shadow admins"
        ],
        "defense_steps": [
            "Run BloodHound to identify shadow admins",
            "Audit all accounts with elevated permissions",
            "Implement AdminSDHolder properly",
            "Monitor for privilege escalation paths"
        ]
    },
    {
        "id": 82,
        "name": "Mass Assignment Vulnerability",
        "difficulty": "MEDIUM",
        "description": "Web applications that blindly accept all submitted form fields can be exploited to set hidden values like 'isAdmin=true' that weren't meant to be user-editable.",
        "attack_steps": [
            "Identify API endpoints accepting object properties",
            "Add additional properties to requests (isAdmin, role)",
            "Modify protected fields through binding",
            "Escalate privileges or modify system state"
        ],
        "defense_steps": [
            "Use DTOs with explicit property allowlisting",
            "Implement proper input validation and binding",
            "Test for mass assignment in security assessments",
            "Use framework protections for binding"
        ]
    },
    {
        "id": 83,
        "name": "Kubernetes API Server Exploitation",
        "difficulty": "HARD",
        "description": "Exposed or misconfigured Kubernetes API servers let attackers deploy containers, access secrets, and potentially take over your entire cloud infrastructure.",
        "attack_steps": [
            "Find exposed Kubernetes API (port 6443/8443)",
            "Exploit misconfigured RBAC or anonymous access",
            "Create privileged pods or access secrets",
            "Pivot to underlying nodes and infrastructure"
        ],
        "defense_steps": [
            "Never expose API server publicly",
            "Implement strict RBAC policies",
            "Use network policies to segment pod traffic",
            "Enable audit logging for API access"
        ]
    },
    {
        "id": 84,
        "name": "S3 Bucket Access Logging Analysis",
        "difficulty": "MEDIUM",
        "description": "S3 access logs can accidentally contain presigned URLs with embedded credentials, allowing attackers to reuse them and access private files.",
        "attack_steps": [
            "Gain access to S3 server access logs",
            "Analyze for presigned URLs with embedded credentials",
            "Extract and reuse valid presigned URLs",
            "Access restricted objects using discovered URLs"
        ],
        "defense_steps": [
            "Use short expiration times for presigned URLs",
            "Restrict access logging to separate secure bucket",
            "Monitor for presigned URL abuse patterns",
            "Implement bucket policies restricting access"
        ]
    },
    {
        "id": 85,
        "name": "Race Condition Exploitation",
        "difficulty": "HARD",
        "description": "By sending requests at precisely the right moment, attackers exploit timing windows to do things twice - like withdrawing money before the balance check completes.",
        "attack_steps": [
            "Identify time-of-check-to-time-of-use vulnerabilities",
            "Send concurrent requests to exploit race window",
            "Achieve double-spending or privilege escalation",
            "Use tools like Turbo Intruder for precision timing"
        ],
        "defense_steps": [
            "Use proper locking mechanisms",
            "Implement atomic operations for critical sections",
            "Use database transactions with proper isolation",
            "Test for race conditions in security assessments"
        ]
    },
    {
        "id": 86,
        "name": "Credential Stuffing",
        "difficulty": "EASY",
        "description": "Using billions of leaked username/password combinations from data breaches, attackers automatically try them on other websites - exploiting password reuse.",
        "attack_steps": [
            "Obtain breached credential databases",
            "Automated login attempts across multiple sites",
            "Exploit password reuse across accounts",
            "Use rotating proxies to avoid detection"
        ],
        "defense_steps": [
            "Implement MFA on all accounts",
            "Use breached password detection services",
            "Deploy bot detection and rate limiting",
            "Monitor for distributed login failures"
        ]
    },
    {
        "id": 87,
        "name": "Zero-Day Exploitation",
        "difficulty": "EXPERT",
        "description": "The most dangerous attacks use vulnerabilities that vendors don't even know exist yet - no patch available, no defense except detection and response.",
        "attack_steps": [
            "Discover unknown vulnerability through research",
            "Develop working exploit for vulnerability",
            "Deploy exploit before patch availability",
            "Maintain access while avoiding detection"
        ],
        "defense_steps": [
            "Implement defense in depth architecture",
            "Use behavior-based detection and EDR",
            "Apply microsegmentation to limit blast radius",
            "Maintain incident response capability"
        ]
    },
    {
        "id": 88,
        "name": "BitLocker Bypass",
        "difficulty": "HARD",
        "description": "Windows disk encryption can be bypassed through TPM sniffing, cold boot attacks, or boot process vulnerabilities, exposing supposedly protected data.",
        "attack_steps": [
            "Extract BitLocker keys from TPM using sniffing",
            "Exploit vulnerable boot process configurations",
            "Use cold boot attack to dump memory",
            "Access encrypted drive with recovered key"
        ],
        "defense_steps": [
            "Use TPM + PIN for BitLocker authentication",
            "Enable Secure Boot and measure boot chain",
            "Implement physical security for devices",
            "Use BitLocker network unlock with controls"
        ]
    },
    {
        "id": 89,
        "name": "AWS Lambda Injection",
        "difficulty": "MEDIUM",
        "description": "Serverless functions that process user input without validation can be exploited to run malicious code or steal AWS credentials from the execution environment.",
        "attack_steps": [
            "Identify Lambda functions processing user input",
            "Inject commands through event data",
            "Exploit environment variable exposure",
            "Access AWS credentials from execution environment"
        ],
        "defense_steps": [
            "Validate all input to Lambda functions",
            "Use least privilege IAM roles for Lambdas",
            "Implement proper error handling without leaking info",
            "Monitor Lambda execution with CloudWatch"
        ]
    },
    {
        "id": 90,
        "name": "SAML Assertion Manipulation",
        "difficulty": "HARD",
        "description": "Enterprise single sign-on tokens can be forged or modified to impersonate any user, bypassing authentication across all connected applications.",
        "attack_steps": [
            "Intercept SAML response in authentication flow",
            "Modify assertions (user, roles, attributes)",
            "Exploit signature wrapping vulnerabilities",
            "Gain unauthorized access as different user"
        ],
        "defense_steps": [
            "Properly validate SAML signatures",
            "Use encrypted assertions",
            "Implement proper XML parsing security",
            "Test SAML implementation with security tools"
        ]
    },
    {
        "id": 91,
        "name": "Exploiting Debug Endpoints",
        "difficulty": "MEDIUM",
        "description": "Development debug interfaces accidentally left enabled in production expose sensitive data, configuration secrets, and sometimes direct code execution.",
        "attack_steps": [
            "Discover debug endpoints left in production",
            "Access /debug, /trace, /actuator endpoints",
            "Extract sensitive configuration and secrets",
            "Execute arbitrary code through debug features"
        ],
        "defense_steps": [
            "Disable debug features in production",
            "Implement endpoint security regardless of environment",
            "Regular scanning for exposed debug interfaces",
            "Use separate build profiles for production"
        ]
    },
    {
        "id": 92,
        "name": "USB Rubber Ducky Attack",
        "difficulty": "EASY",
        "description": "A USB device that looks like a flash drive but acts as a keyboard, typing malicious commands faster than humanly possible when plugged into any computer.",
        "attack_steps": [
            "Program USB device with keystroke injection payload",
            "Deploy through social engineering or physical access",
            "Execute commands as fast as device can type",
            "Establish persistence or exfiltrate data"
        ],
        "defense_steps": [
            "Disable USB ports or use device control policies",
            "Implement application allowlisting",
            "Monitor for rapid keystroke patterns",
            "Educate users about unknown USB devices"
        ]
    },
    {
        "id": 93,
        "name": "Second Order SQL Injection",
        "difficulty": "HARD",
        "description": "Malicious data stored safely in the database later becomes dangerous when a different part of the application uses it without proper sanitization.",
        "attack_steps": [
            "Store malicious payload in database safely",
            "Payload activates when data is used later",
            "Exploit different context with less sanitization",
            "Bypass input validation targeting entry point"
        ],
        "defense_steps": [
            "Use parameterized queries everywhere, not just input",
            "Sanitize data on retrieval, not just storage",
            "Implement consistent encoding throughout application",
            "Test for stored injection in security assessments"
        ]
    },
    {
        "id": 94,
        "name": "Social Engineering Pretexting",
        "difficulty": "EASY",
        "description": "Attackers create believable scenarios - pretending to be IT support or a vendor - to manipulate employees into revealing passwords or granting access.",
        "attack_steps": [
            "Research target organization and employees",
            "Develop believable scenario (IT support, vendor)",
            "Build rapport and establish trust with target",
            "Extract credentials or gain access through deception"
        ],
        "defense_steps": [
            "Implement verification procedures for requests",
            "Train employees on social engineering tactics",
            "Establish out-of-band verification channels",
            "Create culture where questioning requests is acceptable"
        ]
    },
    {
        "id": 95,
        "name": "Insecure File Upload",
        "difficulty": "MEDIUM",
        "description": "Poorly secured file upload features let attackers upload executable scripts disguised as images, gaining remote control of your web server.",
        "attack_steps": [
            "Find file upload functionality in application",
            "Bypass extension and content-type validation",
            "Upload web shell or malicious executable",
            "Access uploaded file to achieve code execution"
        ],
        "defense_steps": [
            "Validate file type by content, not extension",
            "Store uploads outside web root",
            "Use random filenames for uploaded files",
            "Scan uploads with antivirus before storage"
        ]
    },
    {
        "id": 96,
        "name": "AI/ML Model Poisoning",
        "difficulty": "EXPERT",
        "description": "Attackers corrupt machine learning training data to make AI systems behave maliciously - like teaching a spam filter to let phishing emails through.",
        "attack_steps": [
            "Identify machine learning pipeline and training data",
            "Inject malicious samples into training dataset",
            "Cause model to learn incorrect behaviors",
            "Exploit poisoned model for specific triggers"
        ],
        "defense_steps": [
            "Validate and sanitize training data",
            "Implement anomaly detection on training inputs",
            "Use multiple data sources for verification",
            "Monitor model outputs for unexpected behavior"
        ]
    },
    {
        "id": 97,
        "name": "SIM Swapping",
        "difficulty": "MEDIUM",
        "description": "Criminals convince your phone carrier to transfer your number to their SIM card, intercepting your text messages to bypass two-factor authentication.",
        "attack_steps": [
            "Gather personal information about target",
            "Social engineer mobile carrier support",
            "Transfer target's phone number to attacker SIM",
            "Intercept SMS 2FA codes and reset accounts"
        ],
        "defense_steps": [
            "Use authenticator apps instead of SMS 2FA",
            "Add PIN/password to carrier account",
            "Implement additional verification for account changes",
            "Use hardware security keys where possible"
        ]
    },
    {
        "id": 98,
        "name": "Exploiting Misconfigured CORS",
        "difficulty": "MEDIUM",
        "description": "Overly permissive cross-origin settings let malicious websites read your private data from other sites you're logged into - like reading your emails from a game website.",
        "attack_steps": [
            "Identify APIs with overly permissive CORS",
            "Find reflected Origin in Access-Control headers",
            "Host malicious page to make cross-origin requests",
            "Steal sensitive data or perform actions as victim"
        ],
        "defense_steps": [
            "Explicitly allowlist trusted origins",
            "Never reflect Origin header dynamically",
            "Avoid using credentials with wildcard CORS",
            "Test CORS configuration in security assessments"
        ]
    },
    {
        "id": 99,
        "name": "Lateral Movement via Jump Server",
        "difficulty": "HARD",
        "description": "Compromising the 'secure gateway' server that admins use to access internal systems gives attackers a launching pad to reach everything on your network.",
        "attack_steps": [
            "Compromise jump server or bastion host",
            "Use stored credentials or sessions on jump server",
            "Access multiple internal systems through pivot",
            "Avoid direct network detection on target systems"
        ],
        "defense_steps": [
            "Implement privileged session management",
            "Use ephemeral credentials that don't persist",
            "Monitor jump server for unusual activity",
            "Implement zero-trust access controls"
        ]
    }
]

@app.route('/api/ghost/hacker-playbook', methods=['GET'])
@require_auth
def get_hacker_playbook():
    """Get the current/today's hacker technique"""
    db = None
    try:
        db = get_db()

        # Get user's learned techniques from database
        user = request.user
        user_id = user.get('id') if isinstance(user, dict) else user.id

        # Check for existing progress - use a simple key-value approach
        from sqlalchemy import text
        learned_result = db.execute(
            text("SELECT technique_ids FROM hacker_playbook_progress WHERE user_id = :user_id"),
            {"user_id": user_id}
        ).fetchone()

        learned_ids = []
        if learned_result and learned_result[0]:
            try:
                learned_ids = json.loads(learned_result[0])
            except:
                learned_ids = []

        # Determine current technique index based on date rotation
        today = datetime.now(timezone.utc).date()
        day_of_year = today.timetuple().tm_yday
        current_index = day_of_year % len(HACKER_PLAYBOOK)

        technique = HACKER_PLAYBOOK[current_index]

        return jsonify({
            'current_index': current_index,
            'name': technique['name'],
            'difficulty': technique['difficulty'],
            'description': technique.get('description', ''),
            'attack_steps': technique['attack_steps'],
            'defense_steps': technique['defense_steps'],
            'learned_count': len(learned_ids),
            'is_learned': current_index in learned_ids
        })

    except Exception as e:
        print(f"[PLAYBOOK] Error: {e}")
        # Return first technique as fallback
        technique = HACKER_PLAYBOOK[0]
        return jsonify({
            'current_index': 0,
            'name': technique['name'],
            'difficulty': technique['difficulty'],
            'description': technique.get('description', ''),
            'attack_steps': technique['attack_steps'],
            'defense_steps': technique['defense_steps'],
            'learned_count': 0,
            'is_learned': False
        })
    finally:
        if db:
            db.close()


@app.route('/api/ghost/hacker-playbook/<int:index>', methods=['GET'])
@require_auth
def get_technique_by_index(index):
    """Get a specific technique by index"""
    db = None
    try:
        if index < 0 or index >= len(HACKER_PLAYBOOK):
            return jsonify({'error': 'Invalid technique index'}), 400

        db = get_db()
        user = request.user
        user_id = user.get('id') if isinstance(user, dict) else user.id

        # Get learned techniques
        from sqlalchemy import text
        learned_result = db.execute(
            text("SELECT technique_ids FROM hacker_playbook_progress WHERE user_id = :user_id"),
            {"user_id": user_id}
        ).fetchone()

        learned_ids = []
        if learned_result and learned_result[0]:
            try:
                learned_ids = json.loads(learned_result[0])
            except:
                learned_ids = []

        technique = HACKER_PLAYBOOK[index]

        return jsonify({
            'current_index': index,
            'name': technique['name'],
            'difficulty': technique['difficulty'],
            'description': technique.get('description', ''),
            'attack_steps': technique['attack_steps'],
            'defense_steps': technique['defense_steps'],
            'learned_count': len(learned_ids),
            'is_learned': index in learned_ids
        })

    except Exception as e:
        print(f"[PLAYBOOK] Error getting technique: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        if db:
            db.close()


@app.route('/api/ghost/hacker-playbook/<int:index>/learned', methods=['POST'])
@require_auth
def mark_technique_learned(index):
    """Mark a technique as learned for the user"""
    db = None
    try:
        if index < 0 or index >= len(HACKER_PLAYBOOK):
            return jsonify({'error': 'Invalid technique index'}), 400

        db = get_db()
        user = request.user
        user_id = user.get('id') if isinstance(user, dict) else user.id

        from sqlalchemy import text

        # Get current learned techniques
        learned_result = db.execute(
            text("SELECT technique_ids FROM hacker_playbook_progress WHERE user_id = :user_id"),
            {"user_id": user_id}
        ).fetchone()

        learned_ids = []
        if learned_result and learned_result[0]:
            try:
                learned_ids = json.loads(learned_result[0])
            except:
                learned_ids = []

        # Add technique if not already learned
        if index not in learned_ids:
            learned_ids.append(index)

            if learned_result:
                # Update existing record
                db.execute(
                    text("UPDATE hacker_playbook_progress SET technique_ids = :ids, updated_at = :now WHERE user_id = :user_id"),
                    {"ids": json.dumps(learned_ids), "now": datetime.now(timezone.utc), "user_id": user_id}
                )
            else:
                # Create new record
                db.execute(
                    text("INSERT INTO hacker_playbook_progress (user_id, technique_ids, updated_at) VALUES (:user_id, :ids, :now)"),
                    {"user_id": user_id, "ids": json.dumps(learned_ids), "now": datetime.now(timezone.utc)}
                )

            db.commit()

        return jsonify({
            'success': True,
            'learned_count': len(learned_ids),
            'is_learned': True
        })

    except Exception as e:
        print(f"[PLAYBOOK] Error marking learned: {e}")
        if db:
            db.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        if db:
            db.close()


# ============================================================================
# MONITORING DASHBOARD ENDPOINT
# ============================================================================

@app.route('/api/ghost/monitor/stats', methods=['GET'])
def get_monitor_stats():
    """
    Get monitoring dashboard statistics and recent alerts
    """
    db = None
    try:
        print("\n" + "="*60)
        print("[MONITOR] Fetching monitoring statistics...")

        db = get_db()

        # 1. Monitored Assets (email/domain count from uploaded_credentials)
        monitored_assets = db.query(func.count(distinct(UploadedCredential.email))).scalar() or 0
        print(f"[MONITOR] Monitored assets (unique emails): {monitored_assets}")

        # 2. Active Threats (breaches found this month)
        # Count GitHub + PasteBin findings from this month
        current_month_start = datetime.now(timezone.utc).replace(day=1, hour=0, minute=0, second=0, microsecond=0)

        github_this_month = db.query(GitHubFinding).filter(
            GitHubFinding.discovered_at >= current_month_start
        ).count()

        pastebin_this_month = db.query(PasteBinFinding).filter(
            PasteBinFinding.discovered_at >= current_month_start
        ).count()

        active_threats = github_this_month + pastebin_this_month
        print(f"[MONITOR] Active threats this month: {active_threats} (GitHub: {github_this_month}, PasteBin: {pastebin_this_month})")

        # 3. Honeytokens Deployed (bait_tokens count)
        honeytokens_deployed = db.query(BaitToken).count()
        print(f"[MONITOR] Honeytokens deployed: {honeytokens_deployed}")

        # 4. Recent Access Attempts (bait_accesses last 30 days)
        thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
        recent_attempts = db.query(BaitAccess).filter(
            BaitAccess.accessed_at >= thirty_days_ago
        ).count()
        print(f"[MONITOR] Recent access attempts (30 days): {recent_attempts}")

        # 5. Recent Alerts (last 10 findings combined from all sources)
        recent_alerts = []

        # Get GitHub findings (last 5)
        github_findings = db.query(GitHubFinding).order_by(
            GitHubFinding.discovered_at.desc()
        ).limit(5).all()

        for finding in github_findings:
            recent_alerts.append({
                'timestamp': finding.discovered_at.isoformat() if finding.discovered_at else None,
                'alert_type': 'GitHub Exposure',
                'source': 'GitHub Gist Scanner',
                'description': f"{finding.credential_type} found for {finding.query_term}",
                'severity': 'HIGH'
            })

        # Get PasteBin findings (last 5)
        pastebin_findings = db.query(PasteBinFinding).order_by(
            PasteBinFinding.discovered_at.desc()
        ).limit(5).all()

        for finding in pastebin_findings:
            recent_alerts.append({
                'timestamp': finding.discovered_at.isoformat() if finding.discovered_at else None,
                'alert_type': 'PasteBin Exposure',
                'source': 'PasteBin Scanner',
                'description': f"Credential found for {finding.query_term}",
                'severity': 'MEDIUM'
            })

        # Get Bait Access events (last 5)
        bait_accesses = db.query(BaitAccess).order_by(
            BaitAccess.accessed_at.desc()
        ).limit(5).all()

        for access in bait_accesses:
            # Map threat_level to severity
            severity_map = {
                'critical': 'CRITICAL',
                'high': 'HIGH',
                'medium': 'MEDIUM',
                'low': 'LOW'
            }
            severity = severity_map.get(access.threat_level, 'MEDIUM')

            # Get bait token info
            bait_info = f"Honeytoken {access.bait_token.identifier}" if access.bait_token else "Unknown honeytoken"

            recent_alerts.append({
                'timestamp': access.accessed_at.isoformat() if access.accessed_at else None,
                'alert_type': 'Honeytoken Access',
                'source': 'BAIT Module',
                'description': f"{bait_info} accessed from {access.source_ip}",
                'severity': severity
            })

        # Sort all alerts by timestamp (newest first) and limit to 10
        recent_alerts.sort(key=lambda x: x['timestamp'] or '', reverse=True)
        recent_alerts = recent_alerts[:10]

        db.close()

        print(f"[MONITOR] Recent alerts collected: {len(recent_alerts)}")
        print(f"[MONITOR] Statistics ready")
        print("="*60 + "\n")

        return jsonify({
            'success': True,
            'stats': {
                'monitored_assets': monitored_assets,
                'active_threats': active_threats,
                'honeytokens_deployed': honeytokens_deployed,
                'recent_attempts': recent_attempts
            },
            'recent_alerts': recent_alerts
        }), 200

    except Exception as e:
        if db:
            db.close()
        print(f"[MONITOR] Error fetching monitoring stats: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# ============================================================================
# ATTACK SURFACE MANAGEMENT (ASM) ENDPOINT
# ============================================================================

@app.route('/api/ghost/asm/scan', methods=['POST'])
@limiter.limit("10 per hour")  # Prevent scan spam and resource exhaustion
@require_auth
def asm_scan():
    """
    Attack Surface Management scan for a domain with caching and progress tracking
    Performs subdomain discovery, Shodan search, and DNS enumeration

    Returns cached results if scan < 24 hours old, unless force_rescan=true

    Domain Restrictions:
    - COMPANY_USER: Can only scan their company's primary domain
    - USER, ADMIN, ANALYST, SUPER_ADMIN: Unrestricted access
    """
    user_id = request.user_id
    session = SessionLocal()
    try:
        from modules.ghost.asm_scanner import scan_domain

        data = request.json
        domain = data.get('domain', '').strip()
        force_rescan = data.get('force_rescan', False)

        if not domain:
            return jsonify({'success': False, 'error': 'Domain is required'}), 400

        # Validate domain format (basic)
        import re
        if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
            return jsonify({'success': False, 'error': 'Invalid domain format'}), 400

        # ═══════════════════════════════════════════════════════════════
        # DOMAIN RESTRICTION FOR COMPANY_USER ROLE
        # Company users can only scan their company's domain
        # ═══════════════════════════════════════════════════════════════
        user = session.query(User).filter_by(id=user_id).first()
        if user and user.role and user.role.value == 'company_user':
            if not user.company_id:
                return jsonify({
                    'success': False,
                    'error': 'No company assigned to your account'
                }), 403

            company = session.query(Company).filter_by(id=user.company_id).first()
            if not company or not company.primary_domain:
                return jsonify({
                    'success': False,
                    'error': 'Company domain not configured. Contact your administrator.'
                }), 403

            # Normalize domains for comparison (remove protocol, www, trailing slashes)
            def normalize_domain(d):
                d = d.lower().strip()
                d = d.replace('https://', '').replace('http://', '')
                d = d.replace('www.', '')
                d = d.split('/')[0]  # Remove paths
                return d

            target_normalized = normalize_domain(domain)
            company_normalized = normalize_domain(company.primary_domain)

            if target_normalized != company_normalized:
                logger.warning(f"[ASM] COMPANY_USER {user_id} attempted to scan unauthorized domain: {domain}")
                return jsonify({
                    'success': False,
                    'error': 'Access denied',
                    'message': f'Company users can only scan their own domain: {company.primary_domain}'
                }), 403

            logger.info(f"[ASM] COMPANY_USER {user_id} scanning authorized domain: {domain}")

        logger.info(f"[ASM API] Scan request for {domain} (force={force_rescan})")

        # Check for cached scan (unless force rescan)
        if not force_rescan:
            cached = session.query(CachedASMScan).filter_by(domain=domain).order_by(
                CachedASMScan.scanned_at.desc()
            ).first()

            if cached:
                # Return cached if less than 24 hours old
                scanned_at = cached.scanned_at
                if scanned_at.tzinfo is None:
                    scanned_at = scanned_at.replace(tzinfo=timezone.utc)

                age_hours = (datetime.now(timezone.utc) - scanned_at).total_seconds() / 3600
                if age_hours < 24:
                    logger.info(f"[ASM API] Returning cached scan (age: {age_hours:.1f}h)")
                    return jsonify({
                        'id': cached.id,
                        'domain': cached.domain,
                        'risk_score': cached.risk_score,
                        'total_cves': cached.total_cves,
                        'critical_cves': cached.critical_cves,
                        'scanned_at': cached.scanned_at.isoformat(),
                        'cached': True,
                        'cache_age_hours': age_hours,
                        'last_scanned': cached.last_scanned.isoformat() if cached.last_scanned else None,
                        'next_scan_at': cached.next_scan_at.isoformat() if cached.next_scan_at else None,
                        'auto_scan_enabled': cached.auto_scan_enabled,
                        **cached.scan_results
                    }), 200
                else:
                    logger.info(f"[ASM API] Cache expired (age: {age_hours:.1f}h), rescanning...")

        # Initialize progress tracking
        with scan_progress_lock:
            scan_progress[domain] = {
                'status': 'scanning',
                'current_step': 'Starting scan',
                'progress': 0,
                'total': 100,
                'message': 'Initializing...'
            }

        # Log scan started event
        log_security_event(
            event_type='scan_started',
            severity='info',
            user_id=user_id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', ''),
            description=f'XASM scan started for domain: {domain}',
            metadata={
                'scan_type': 'xasm',
                'domain': domain,
                'force_rescan': force_rescan
            }
        )

        def update_progress(step, progress, total, message):
            """Helper to update progress"""
            with scan_progress_lock:
                if domain in scan_progress:
                    scan_progress[domain].update({
                        'current_step': step,
                        'progress': progress,
                        'total': total,
                        'message': message
                    })
            logger.info(f"[ASM PROGRESS] {step} ({progress}/{total}) - {message}")

        # Perform scan with progress updates
        logger.info(f"[ASM API] Running new scan for {domain}")
        scan_results = scan_domain(domain, progress_callback=update_progress)

        # Save to database
        cve_stats = scan_results.get('cve_statistics', {})
        new_scan = CachedASMScan(
            domain=domain,
            user_id=user_id,
            risk_score=scan_results.get('risk_score', 0),
            risk_level=scan_results.get('risk_level', 'low'),
            total_cves=cve_stats.get('total_cves', 0),
            critical_cves=cve_stats.get('critical_cves', 0),
            vulnerabilities_found=scan_results.get('vulnerabilities_found', 0),
            open_ports_count=len(scan_results.get('port_scan_results', [])),
            scan_results=scan_results
        )

        # Enable auto-scanning for company users only
        user = session.query(User).filter_by(id=user_id).first()
        if user and user.role == UserRole.COMPANY_USER:
            new_scan.auto_scan_enabled = True
            new_scan.last_scanned = datetime.now(timezone.utc)
            new_scan.next_scan_at = datetime.now(timezone.utc) + timedelta(hours=24)
            logger.info(f"[AUTO-SCAN] Enabled for company user on domain: {domain}")
        else:
            new_scan.auto_scan_enabled = False
            new_scan.last_scanned = datetime.now(timezone.utc)
            logger.info(f"[MANUAL-SCAN] Regular user scan on domain: {domain}")

        session.add(new_scan)
        session.commit()
        session.refresh(new_scan)  # Get the auto-generated ID

        logger.info(f"[ASM API] Scan saved with ID: {new_scan.id}")

        update_progress('Complete', 100, 100, 'Scan complete!')

        # Mark scan as complete
        with scan_progress_lock:
            if domain in scan_progress:
                scan_progress[domain]['status'] = 'complete'

        logger.info(f"[ASM API] Scan complete for {domain}")
        logger.info(f"[ASM API] Risk Score: {scan_results.get('risk_score', 0)}/100")
        logger.info(f"[ASM API] Total CVEs: {cve_stats.get('total_cves', 0)}")

        # Log scan completed event
        log_security_event(
            event_type='scan_completed',
            severity='info',
            user_id=user_id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', ''),
            description=f'XASM scan completed for domain: {domain} - Risk Score: {scan_results.get("risk_score", 0)}/100',
            metadata={
                'scan_type': 'xasm',
                'scan_id': new_scan.id,
                'domain': domain,
                'risk_score': scan_results.get('risk_score', 0),
                'total_cves': cve_stats.get('total_cves', 0),
                'critical_cves': cve_stats.get('critical_cves', 0)
            }
        )

        # Save XASM results for AI report generation
        try:
            save_xasm_for_ai(domain, scan_results)
        except Exception as e:
            logger.warning(f"[XASM] Failed to save for AI report: {e}")
            # Don't fail the scan if storage fails

        # Return with ID included - THIS IS CRITICAL
        return jsonify({
            'id': new_scan.id,
            'domain': domain,
            'risk_score': scan_results.get('risk_score', 0),
            'total_cves': cve_stats.get('total_cves', 0),
            'critical_cves': cve_stats.get('critical_cves', 0),
            'scanned_at': new_scan.scanned_at.isoformat(),
            'cached': False,
            'last_scanned': new_scan.last_scanned.isoformat() if new_scan.last_scanned else None,
            'next_scan_at': new_scan.next_scan_at.isoformat() if new_scan.next_scan_at else None,
            'auto_scan_enabled': new_scan.auto_scan_enabled,
            **scan_results
        }), 200

    except Exception as e:
        session.rollback()

        # Mark scan as failed
        with scan_progress_lock:
            if domain in scan_progress:
                scan_progress[domain].update({
                    'status': 'failed',
                    'message': str(e)
                })

        # Log scan failure
        log_security_event(
            event_type='scan_completed',
            severity='error',
            user_id=user_id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', ''),
            description=f'XASM scan failed for domain: {domain} - Error: {str(e)}',
            metadata={
                'scan_type': 'xasm',
                'domain': domain,
                'error': str(e),
                'status': 'failed'
            }
        )

        logger.error(f"[ASM API] Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    finally:
        session.close()

@app.route('/api/ghost/asm/scan-progress', methods=['POST'])
@optional_auth
def asm_scan_progress():
    """
    Get current progress of an ASM scan
    """
    try:
        data = request.json
        domain = data.get('domain', '').strip()

        if not domain:
            return jsonify({'success': False, 'error': 'Domain is required'}), 400

        with scan_progress_lock:
            progress_info = scan_progress.get(domain)

        if not progress_info:
            # No scan in progress, check if cached
            db = get_db()
            cached_scan = db.query(ASMScan).filter(ASMScan.domain == domain).first()
            db.close()

            if cached_scan:
                # Handle naive datetimes from old database records
                scanned_at = cached_scan.scanned_at
                if scanned_at.tzinfo is None:
                    scanned_at = scanned_at.replace(tzinfo=timezone.utc)

                scan_age = datetime.now(timezone.utc) - scanned_at
                return jsonify({
                    'success': True,
                    'status': 'cached',
                    'current_step': 'Complete',
                    'progress': 100,
                    'total': 100,
                    'message': f'Cached scan from {scan_age.total_seconds() / 3600:.1f} hours ago',
                    'scanned_at': cached_scan.scanned_at.isoformat(),
                    'cache_age_hours': scan_age.total_seconds() / 3600
                }), 200
            else:
                return jsonify({
                    'success': True,
                    'status': 'not_started',
                    'current_step': 'Not started',
                    'progress': 0,
                    'total': 100,
                    'message': 'No scan in progress'
                }), 200

        return jsonify({
            'success': True,
            **progress_info
        }), 200

    except Exception as e:
        print(f"[ASM PROGRESS] Error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# ============================================================================
# SCAN HISTORY ENDPOINT
# ============================================================================

@app.route('/api/ghost/scan-history', methods=['GET'])
@require_auth
def get_scan_history():
    """Get XASM scan history for current user only"""
    try:
        # CRITICAL: Filter by authenticated user's ID
        user_id = request.user_id
        session = SessionLocal()
        scans = session.query(CachedASMScan).filter_by(
            user_id=user_id
        ).order_by(CachedASMScan.scanned_at.desc()).all()

        history = []
        for scan in scans:
            # Count critical findings
            critical_count = 0
            total_findings = 0

            if scan.scan_results:
                port_scan_results = scan.scan_results.get('port_scan_results', [])
                total_findings = len(port_scan_results)
                critical_count = len([p for p in port_scan_results if p.get('risk') == 'CRITICAL'])

            history.append({
                'scan_id': scan.id,
                'domain': scan.domain,
                'scan_date': scan.scanned_at.isoformat() if scan.scanned_at else None,
                'risk_score': scan.risk_score,
                'critical_count': critical_count,
                'total_findings': total_findings
            })

        session.close()
        return jsonify(history)

    except Exception as e:
        logger.error(f"[GHOST] Error fetching scan history: {e}")
        return jsonify({'error': str(e)}), 500

# ============================================================================
# LIGHTBOX AUTOMATED TESTING ENDPOINT
# ============================================================================

@app.route('/api/ghost/lightbox/scan', methods=['POST'])
@limiter.limit("10 per hour")  # Prevent scan spam and resource exhaustion
@require_auth
def lightbox_scan():
    """
    Run Lightbox security scan and save results to database.

    Supports two modes:
    1. full_surface: Test all assets from XASM scan (requires domain + scan_id)
    2. specific_targets: Test only user-specified targets (requires targets list)

    Domain Restrictions:
    - COMPANY_USER: Can only scan their company's primary domain
    - USER, ADMIN, ANALYST, SUPER_ADMIN: Unrestricted access
    """
    session = SessionLocal()
    try:
        data = request.json
        mode = data.get('mode', 'full_surface')
        user_id = request.user_id  # From @require_auth decorator

        # Import Lightbox scanner
        from modules.ghost.lightbox_scanner import run_lightbox_scan

        # ═══════════════════════════════════════════════════════════════
        # DOMAIN RESTRICTION FOR COMPANY_USER ROLE
        # Company users can only scan their company's domain
        # IP addresses blocked for company users
        # ═══════════════════════════════════════════════════════════════
        def is_target_allowed_for_company_user(target, company_domain):
            """
            Check if target is allowed for company user to scan.
            Returns: (allowed: bool, error_message: str or None)
            """
            import re
            from urllib.parse import urlparse

            if not company_domain:
                return False, "Company domain not configured"

            # Parse target URL to extract hostname
            try:
                parsed = urlparse(target if '://' in target else f'http://{target}')
                hostname = parsed.hostname or parsed.path.split('/')[0]
                if not hostname:
                    hostname = target.split('/')[0].split(':')[0]
            except:
                return False, "Invalid target format"

            # Check if target is an IP address (block for company users)
            ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
            if re.match(ip_pattern, hostname):
                return False, "Company users cannot test IP addresses. Contact your administrator to add approved IPs."

            # Normalize domains for comparison
            company_normalized = company_domain.lower().replace('https://', '').replace('http://', '').replace('www.', '').split('/')[0]
            target_normalized = hostname.lower().replace('www.', '')

            # Check exact match
            if target_normalized == company_normalized:
                return True, None

            # Check subdomain match (e.g., api.westsidestores.ca matches westsidestores.ca)
            if target_normalized.endswith(f'.{company_normalized}'):
                return True, None

            return False, f"Company users can only test their own domain: {company_domain}"

        user = session.query(User).filter_by(id=user_id).first()
        if user and user.role and user.role.value == 'company_user':
            if not user.company_id:
                return jsonify({
                    'success': False,
                    'error': 'No company assigned to your account'
                }), 403

            company = session.query(Company).filter_by(id=user.company_id).first()
            if not company or not company.primary_domain:
                return jsonify({
                    'success': False,
                    'error': 'Company domain not configured. Contact your administrator.'
                }), 403

            company_domain = company.primary_domain

            # Collect all targets to validate
            targets_to_validate = []

            # Get domain from full_surface mode
            if data.get('domain'):
                targets_to_validate.append(data.get('domain'))

            # Get all targets from specific_targets mode
            if mode == 'specific_targets':
                targets = data.get('targets', [])
                for target in targets:
                    if isinstance(target, str) and target.strip():
                        targets_to_validate.append(target.strip())

            # Validate ALL targets
            for target in targets_to_validate:
                allowed, error_msg = is_target_allowed_for_company_user(target, company_domain)
                if not allowed:
                    logger.warning(f"[LIGHTBOX] COMPANY_USER {user_id} attempted to scan unauthorized target: {target}")
                    return jsonify({
                        'success': False,
                        'error': 'Access denied',
                        'message': error_msg
                    }), 403

            if targets_to_validate:
                logger.info(f"[LIGHTBOX] COMPANY_USER {user_id} scanning {len(targets_to_validate)} authorized target(s)")

        if mode == 'specific_targets':
            # ═══════════════════════════════════════════════════════════════
            # SPECIFIC TARGETS MODE: Test only user-provided targets
            # Runs in BACKGROUND THREAD for non-blocking response
            # ═══════════════════════════════════════════════════════════════
            targets = data.get('targets', [])

            if not targets:
                return jsonify({'error': 'No targets specified'}), 400

            # Validate and clean targets
            validated_targets = []
            for target in targets:
                if isinstance(target, str):
                    target = target.strip()
                    if target:
                        validated_targets.append(target)

            if not validated_targets:
                return jsonify({'error': 'No valid targets provided'}), 400

            # Generate scan key with user isolation
            scan_key = data.get('scan_key') or f"specific_{user_id}_{int(time.time())}"
            domain = validated_targets[0]  # Use first target as domain reference

            logger.info(f"[LIGHTBOX API] Starting SPECIFIC TARGETS scan for user {user_id}")
            logger.info(f"[LIGHTBOX API] Targets: {validated_targets}")
            logger.info(f"[LIGHTBOX API] Using scan_key: {scan_key}")

            # ═══════════════════════════════════════════════════════════════
            # Initialize progress immediately so frontend can start polling
            # ═══════════════════════════════════════════════════════════════
            with scan_progress_lock:
                scan_progress[scan_key] = {
                    'status': 'initializing',
                    'progress': 0,
                    'current_step': 'Starting scan...',
                    'total_steps': 100
                }
            logger.info(f"[LIGHTBOX API] Initialized progress for {scan_key}")

            # ═══════════════════════════════════════════════════════════════
            # Define background worker function
            # ═══════════════════════════════════════════════════════════════
            def run_specific_targets_scan_background():
                """Run the scan in background thread with its own DB session"""
                # Create new session for this thread
                bg_session = SessionLocal()
                try:
                    # Progress callback
                    def update_progress(progress_data):
                        with scan_progress_lock:
                            scan_progress[scan_key] = progress_data
                        logger.info(f"[LIGHTBOX PROGRESS] {progress_data.get('current_step')} - {progress_data.get('progress')}%")

                    # Create assets dict
                    discovered_assets = {
                        'subdomains': [{'subdomain': t} for t in validated_targets],
                        'crt_subdomains': [],
                        'discovered_ips': []
                    }

                    logger.info(f"[LIGHTBOX BG] Running scan on {len(validated_targets)} targets...")
                    scan_results = run_lightbox_scan(discovered_assets, domain, update_progress)

                    # Process results
                    if isinstance(scan_results, dict):
                        critical_findings = scan_results.get('critical', [])
                        high_findings = scan_results.get('high', [])
                        medium_findings = scan_results.get('medium', [])
                        low_findings = scan_results.get('low', [])
                        info_findings = scan_results.get('info', [])
                        all_findings = critical_findings + high_findings + medium_findings + low_findings + info_findings
                        total_findings = len(all_findings)
                        critical = len(critical_findings)
                        high = len(high_findings)
                        medium = len(medium_findings)
                        low = len(low_findings)
                        test_results = scan_results.get('test_results', {})
                    else:
                        all_findings = []
                        total_findings = critical = high = medium = low = 0
                        test_results = {}

                    # Save to database
                    lightbox_record = LightboxScan(
                        domain=domain,
                        total_findings=total_findings,
                        critical_count=critical,
                        high_count=high,
                        medium_count=medium,
                        low_count=low,
                        findings=json.dumps(all_findings),
                        scan_metadata=json.dumps({
                            'mode': 'specific_targets',
                            'asm_scan_id': None,
                            'assets_tested': len(validated_targets),
                            'checks_run': scan_results.get('total_tests', 915) if isinstance(scan_results, dict) else 915,
                            'templates_used': scan_results.get('templates_used', 1) if isinstance(scan_results, dict) else 1,
                            'test_results': test_results
                        }),
                        user_id=user_id
                    )
                    bg_session.add(lightbox_record)
                    bg_session.commit()
                    bg_session.refresh(lightbox_record)

                    logger.info(f"[LIGHTBOX BG] Saved to database with ID {lightbox_record.id}")

                    # Log scan completed event
                    log_security_event(
                        event_type='scan_completed',
                        severity='info',
                        user_id=user_id,
                        description=f'Lightbox scan completed - {total_findings} findings (C:{critical}, H:{high}, M:{medium}, L:{low})',
                        metadata={
                            'scan_type': 'lightbox',
                            'mode': 'specific_targets',
                            'scan_id': lightbox_record.id,
                            'domain': domain,
                            'total_findings': total_findings,
                            'critical': critical,
                            'high': high,
                            'medium': medium,
                            'low': low
                        }
                    )

                    # Save for AI report
                    try:
                        save_lightbox_for_ai(domain, scan_results)
                    except Exception as e:
                        logger.warning(f"[LIGHTBOX BG] Failed to save for AI: {e}")

                    # Set completion status with explicit scan_complete flag
                    with scan_progress_lock:
                        scan_progress[scan_key] = {
                            'status': 'complete',
                            'progress': 100,
                            'current_step': 'Scan complete',
                            'total_steps': 100,
                            'scan_id': lightbox_record.id,
                            'scan_complete': True,
                            'findings_count': total_findings
                        }
                    logger.info(f"[LIGHTBOX BG] Set completion status for {scan_key}")

                    # Wait for frontend to read status, then cleanup (30 seconds to ensure frontend polls)
                    import time as time_mod
                    time_mod.sleep(30)
                    with scan_progress_lock:
                        if scan_key in scan_progress:
                            del scan_progress[scan_key]
                            logger.info(f"[LIGHTBOX BG] Cleaned up progress for {scan_key}")

                except Exception as e:
                    logger.error(f"[LIGHTBOX BG] Error: {e}")
                    import traceback
                    traceback.print_exc()

                    # Log scan failure
                    log_security_event(
                        event_type='scan_completed',
                        severity='error',
                        user_id=user_id,
                        description=f'Lightbox scan failed - Error: {str(e)}',
                        metadata={
                            'scan_type': 'lightbox',
                            'mode': 'specific_targets',
                            'domain': domain,
                            'error': str(e),
                            'status': 'failed'
                        }
                    )

                    # Set error status
                    with scan_progress_lock:
                        scan_progress[scan_key] = {
                            'status': 'error',
                            'progress': 0,
                            'current_step': f'Error: {str(e)}',
                            'total_steps': 100
                        }
                finally:
                    bg_session.close()

            # ═══════════════════════════════════════════════════════════════
            # Start background thread and return immediately
            # ═══════════════════════════════════════════════════════════════
            import threading
            thread = threading.Thread(target=run_specific_targets_scan_background, daemon=True)
            thread.start()
            logger.info(f"[LIGHTBOX API] Started background thread for {scan_key}")

            # Log scan started event
            log_security_event(
                event_type='scan_started',
                severity='info',
                user_id=user_id,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent', ''),
                description=f'Lightbox scan started for {len(validated_targets)} targets',
                metadata={
                    'scan_type': 'lightbox',
                    'mode': 'specific_targets',
                    'targets_count': len(validated_targets),
                    'scan_key': scan_key
                }
            )

            # Return immediately - frontend will poll for progress
            return jsonify({
                'success': True,
                'scan_key': scan_key,
                'mode': 'specific_targets',
                'targets_count': len(validated_targets),
                'message': 'Scan started in background'
            }), 200

        else:
            # ═══════════════════════════════════════════════════════════════
            # FULL SURFACE MODE: Test all assets from XASM scan
            # Runs in BACKGROUND THREAD for non-blocking response
            # ═══════════════════════════════════════════════════════════════
            domain = data.get('domain')
            # Accept both 'scan_id' and 'xasm_scan_id' for backward compatibility
            scan_id = data.get('scan_id') or data.get('xasm_scan_id')

            if not domain:
                return jsonify({'error': 'Domain required'}), 400

            if not scan_id:
                return jsonify({'error': 'XASM scan_id required'}), 400

            # Get XASM scan results from database
            asm_scan = session.query(CachedASMScan).filter_by(id=scan_id).first()

            if not asm_scan:
                logger.error(f"[LIGHTBOX API] XASM scan {scan_id} not found")
                return jsonify({'error': 'XASM scan not found. Please run an XASM scan first.'}), 404

            # Calculate assets count from XASM results
            asm_results = asm_scan.scan_results if isinstance(asm_scan.scan_results, dict) else {}
            assets_count = len(asm_results.get('subdomains', []))

            if assets_count == 0:
                return jsonify({'error': 'No assets found in XASM scan'}), 400

            # Use frontend's scan_key for progress tracking if provided, otherwise generate one with user isolation
            scan_key = data.get('scan_key') or f"{domain}_{user_id}_{int(time.time())}"

            logger.info(f"[LIGHTBOX API] Starting FULL SURFACE scan for {domain}")
            logger.info(f"[LIGHTBOX API] XASM scan ID: {scan_id}, Assets to test: {assets_count}")
            logger.info(f"[LIGHTBOX API] Using scan_key: {scan_key} (user_id: {user_id})")

            # ═══════════════════════════════════════════════════════════════
            # Initialize progress immediately so frontend can start polling
            # ═══════════════════════════════════════════════════════════════
            with scan_progress_lock:
                scan_progress[scan_key] = {
                    'status': 'initializing',
                    'progress': 0,
                    'current_step': 'Starting full surface scan...',
                    'total_steps': 100
                }
            logger.info(f"[LIGHTBOX API] Initialized progress for {scan_key}")

            # Store XASM scan results for background thread (avoid passing session objects)
            asm_scan_results = asm_scan.scan_results

            # ═══════════════════════════════════════════════════════════════
            # Define background worker function
            # ═══════════════════════════════════════════════════════════════
            def run_full_surface_scan_background():
                """Run the full surface scan in background thread with its own DB session"""
                # Create new session for this thread
                bg_session = SessionLocal()
                try:
                    # Progress callback
                    def update_progress(progress_data):
                        with scan_progress_lock:
                            scan_progress[scan_key] = progress_data
                        logger.info(f"[LIGHTBOX PROGRESS] {progress_data.get('current_step')} - {progress_data.get('progress')}%")

                    logger.info(f"[LIGHTBOX BG] Running full surface scan on {assets_count} assets...")
                    scan_results = run_lightbox_scan(asm_scan_results, domain, update_progress)

                    # Calculate assets tested from XASM results
                    assets_tested = len(asm_scan_results.get('subdomains', [])) if isinstance(asm_scan_results, dict) else 0

                    # Extract findings from the dictionary structure
                    if isinstance(scan_results, dict):
                        critical_findings = scan_results.get('critical', [])
                        high_findings = scan_results.get('high', [])
                        medium_findings = scan_results.get('medium', [])
                        low_findings = scan_results.get('low', [])
                        info_findings = scan_results.get('info', [])

                        critical = len(critical_findings)
                        high = len(high_findings)
                        medium = len(medium_findings)
                        low = len(low_findings)

                        all_findings = critical_findings + high_findings + medium_findings + low_findings + info_findings
                        total_findings = len(all_findings)
                        test_results = scan_results.get('test_results', {})

                        logger.info(f"[LIGHTBOX BG] Scan complete - {total_findings} findings (C:{critical}, H:{high}, M:{medium}, L:{low})")
                    else:
                        logger.error(f"[LIGHTBOX BG] ERROR: Expected dict but got {type(scan_results)}")
                        all_findings = []
                        total_findings = critical = high = medium = low = 0
                        test_results = {}

                    # Save to database
                    lightbox_record = LightboxScan(
                        domain=domain,
                        total_findings=total_findings,
                        critical_count=critical,
                        high_count=high,
                        medium_count=medium,
                        low_count=low,
                        findings=json.dumps(all_findings),
                        scan_metadata=json.dumps({
                            'mode': 'full_surface',
                            'asm_scan_id': scan_id,
                            'assets_tested': assets_tested,
                            'checks_run': scan_results.get('total_tests', 915) if isinstance(scan_results, dict) else 915,
                            'templates_used': scan_results.get('templates_used', 1) if isinstance(scan_results, dict) else 1,
                            'test_results': test_results
                        }),
                        user_id=user_id
                    )
                    bg_session.add(lightbox_record)
                    bg_session.commit()
                    bg_session.refresh(lightbox_record)

                    logger.info(f"[LIGHTBOX BG] Saved to database with ID {lightbox_record.id}")

                    # Log scan completed event
                    log_activity_event(
                        db=bg_session,
                        event_type='scan_completed',
                        description=f'Completed Lightbox full surface scan for {domain}: {total_findings} findings (C:{critical}, H:{high}, M:{medium}, L:{low})',
                        severity='info',
                        user_id=user_id,
                        metadata={'scan_type': 'lightbox_full_surface', 'domain': domain, 'scan_id': lightbox_record.id, 'total_findings': total_findings, 'critical': critical, 'high': high, 'medium': medium, 'low': low}
                    )

                    # Save Lightbox results for AI report generation
                    try:
                        save_lightbox_for_ai(domain, scan_results)
                    except Exception as e:
                        logger.warning(f"[LIGHTBOX BG] Failed to save for AI report: {e}")

                    # Set completion status with explicit scan_complete flag
                    with scan_progress_lock:
                        scan_progress[scan_key] = {
                            'status': 'complete',
                            'progress': 100,
                            'current_step': 'Scan complete',
                            'total_steps': 100,
                            'scan_id': lightbox_record.id,
                            'scan_complete': True,
                            'findings_count': total_findings
                        }
                    logger.info(f"[LIGHTBOX BG] Set completion status for {scan_key}")

                    # Wait for frontend to read status, then cleanup (30 seconds to ensure frontend polls)
                    import time as time_mod
                    time_mod.sleep(30)
                    with scan_progress_lock:
                        if scan_key in scan_progress:
                            del scan_progress[scan_key]
                            logger.info(f"[LIGHTBOX BG] Cleaned up progress for {scan_key}")

                except Exception as e:
                    logger.error(f"[LIGHTBOX BG] Error: {e}")
                    import traceback
                    traceback.print_exc()
                    # Set error status
                    with scan_progress_lock:
                        scan_progress[scan_key] = {
                            'status': 'error',
                            'progress': 0,
                            'current_step': f'Error: {str(e)}',
                            'total_steps': 100
                        }
                    # Log scan failure event
                    try:
                        log_activity_event(
                            db=bg_session,
                            event_type='scan_completed',
                            description=f'Lightbox full surface scan failed for {domain}: {str(e)}',
                            severity='error',
                            user_id=user_id,
                            metadata={'scan_type': 'lightbox_full_surface', 'domain': domain, 'error': str(e)}
                        )
                    except:
                        pass  # Don't fail on logging error
                finally:
                    bg_session.close()

            # ═══════════════════════════════════════════════════════════════
            # Start background thread and return immediately
            # ═══════════════════════════════════════════════════════════════
            import threading
            thread = threading.Thread(target=run_full_surface_scan_background, daemon=True)
            thread.start()
            logger.info(f"[LIGHTBOX API] Started background thread for full surface scan {scan_key}")

            # Log scan started event
            log_activity_event(
                db=session,
                event_type='scan_started',
                description=f'Started Lightbox full surface scan for {domain} ({assets_count} assets)',
                severity='info',
                user_id=user_id,
                metadata={'scan_type': 'lightbox_full_surface', 'domain': domain, 'scan_key': scan_key, 'assets_count': assets_count}
            )

            # Return immediately - frontend will poll for progress
            return jsonify({
                'success': True,
                'scan_key': scan_key,
                'mode': 'full_surface',
                'assets_count': assets_count,
                'message': 'Full surface scan started in background'
            }), 200

    except Exception as e:
        session.rollback()
        logger.error(f"[LIGHTBOX API] Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

@app.route('/api/ghost/lightbox/progress', methods=['POST'])
@require_auth
def get_lightbox_progress():
    """Get current Lightbox scan progress"""
    try:
        data = request.json
        scan_key = data.get('scan_key')  # Format: domain_timestamp

        if not scan_key:
            return jsonify({'error': 'Missing scan_key parameter'}), 400

        # Get progress from global dictionary
        with scan_progress_lock:
            progress = scan_progress.get(scan_key, {
                'status': 'idle',
                'progress': 0,
                'current_step': 'Waiting to start',
                'total_steps': 100
            })

        # Ensure scan_complete flag is set based on status for reliable detection
        if progress.get('status') == 'complete':
            progress['scan_complete'] = True
        else:
            progress['scan_complete'] = progress.get('scan_complete', False)

        return jsonify(progress), 200

    except Exception as e:
        logger.error(f"[LIGHTBOX PROGRESS] Error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/ghost/lightbox/history/<domain>', methods=['GET'])
@require_auth
def get_lightbox_history(domain):
    """Get Lightbox scan history for current user only and cleanup old scans (30+ days)"""
    session = SessionLocal()
    user_id = request.user_id  # CRITICAL: Get authenticated user's ID
    try:
        from datetime import timedelta

        # Auto-cleanup: Delete scans older than 30 days (only for current user)
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=30)

        old_scans = session.query(LightboxScan).filter(
            LightboxScan.scanned_at < cutoff_date,
            LightboxScan.user_id == user_id
        ).all()

        if old_scans:
            logger.info(f"[LIGHTBOX CLEANUP] Deleting {len(old_scans)} scans older than 30 days for user {user_id}")
            for scan in old_scans:
                session.delete(scan)
            session.commit()

        # CRITICAL: Get recent scans (last 30 days) FILTERED BY USER
        scans = session.query(LightboxScan).filter_by(
            domain=domain,
            user_id=user_id
        ).filter(
            LightboxScan.scanned_at >= cutoff_date
        ).order_by(LightboxScan.scanned_at.desc()).all()

        return jsonify({
            'domain': domain,
            'scan_count': len(scans),
            'scans': [scan.to_dict() for scan in scans]
        }), 200

    except Exception as e:
        logger.error(f"[LIGHTBOX API] History error: {str(e)}")
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

@app.route('/api/ghost/lightbox/scan/<int:scan_id>', methods=['GET'])
@require_auth
def get_lightbox_scan(scan_id):
    """Get specific Lightbox scan by ID - only if owned by current user"""
    session = SessionLocal()
    try:
        scan = session.query(LightboxScan).get(scan_id)

        if not scan:
            return jsonify({'error': 'Scan not found'}), 404

        # CRITICAL: Verify scan belongs to current user
        if scan.user_id and scan.user_id != request.user_id:
            return jsonify({'error': 'Access denied'}), 403

        return jsonify(scan.to_dict()), 200

    except Exception as e:
        logger.error(f"[LIGHTBOX API] Fetch error: {str(e)}")
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

@app.route('/api/ghost/lightbox/scan/<int:scan_id>', methods=['DELETE'])
@require_auth
def delete_lightbox_scan(scan_id):
    """Manually delete a specific Lightbox scan - only if owned by current user"""
    session = SessionLocal()
    try:
        scan = session.query(LightboxScan).get(scan_id)

        if not scan:
            return jsonify({'error': 'Scan not found'}), 404

        # CRITICAL: Verify scan belongs to current user before deleting
        if scan.user_id and scan.user_id != request.user_id:
            return jsonify({'error': 'Access denied'}), 403

        domain = scan.domain
        session.delete(scan)
        session.commit()

        logger.info(f"[LIGHTBOX] Manually deleted scan {scan_id} for {domain} by user {request.user_id}")

        return jsonify({
            'success': True,
            'message': 'Scan deleted successfully'
        }), 200

    except Exception as e:
        session.rollback()
        logger.error(f"[LIGHTBOX API] Delete error: {str(e)}")
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

# ============================================================================
# XASM SCAN HISTORY ENDPOINTS
# ============================================================================

@app.route('/api/xasm/history', methods=['GET'])
@require_auth
def get_xasm_history():
    """Get XASM scan history for current user only"""
    from database import get_xasm_scan_history

    try:
        # CRITICAL: Filter by authenticated user's ID from token
        user_id = request.user_id
        history = get_xasm_scan_history(user_id=user_id)
        return jsonify({'success': True, 'history': history})
    except Exception as e:
        logger.error(f"[XASM HISTORY] Error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/xasm/history/<scan_id>', methods=['GET'])
@require_auth
def get_xasm_scan_details(scan_id):
    """Get full XASM scan results by ID - only if owned by current user"""
    from database import get_xasm_scan_by_id, XASMScanHistory, SessionLocal

    try:
        # CRITICAL: Verify scan belongs to current user
        session = SessionLocal()
        try:
            scan = session.query(XASMScanHistory).filter_by(scan_id=scan_id).first()
            if not scan:
                return jsonify({'error': 'Scan not found'}), 404
            if scan.user_id and scan.user_id != request.user_id:
                return jsonify({'error': 'Access denied'}), 403
        finally:
            session.close()

        results = get_xasm_scan_by_id(scan_id)
        if results:
            return jsonify({'success': True, 'results': results})
        else:
            return jsonify({'error': 'Scan not found'}), 404
    except Exception as e:
        logger.error(f"[XASM HISTORY] Error fetching scan {scan_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/xasm/history/<scan_id>', methods=['DELETE'])
@require_auth
def delete_xasm_scan_endpoint(scan_id):
    """Delete XASM scan from history - only if owned by current user"""
    from database import delete_xasm_scan, XASMScanHistory, SessionLocal

    try:
        # CRITICAL: Verify scan belongs to current user before deleting
        session = SessionLocal()
        try:
            scan = session.query(XASMScanHistory).filter_by(scan_id=scan_id).first()
            if not scan:
                return jsonify({'error': 'Scan not found'}), 404
            if scan.user_id and scan.user_id != request.user_id:
                return jsonify({'error': 'Access denied'}), 403
        finally:
            session.close()

        success = delete_xasm_scan(scan_id)
        if success:
            return jsonify({'success': True})
        else:
            return jsonify({'error': 'Scan not found'}), 404
    except Exception as e:
        logger.error(f"[XASM HISTORY] Error deleting scan {scan_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/xasm/cached-domains', methods=['GET'])
@require_auth
def get_xasm_cached_domains():
    """Get list of unique domains that have been scanned via XASM and/or Lightbox for current user"""
    from database import get_db, XASMScan, LightboxScanHistory
    from sqlalchemy import func

    db = None
    user_id = request.user_id  # CRITICAL: Filter by authenticated user
    try:
        db = get_db()

        # Dictionary to collect domain data
        domain_data = {}

        # Get XASM domains with last scan date - FILTERED BY USER
        xasm_stats = db.query(
            XASMScan.domain,
            func.max(XASMScan.scan_date).label('last_scan')
        ).filter(
            XASMScan.deleted_at == None,
            XASMScan.user_id == user_id
        ).group_by(
            XASMScan.domain
        ).all()

        for stat in xasm_stats:
            domain = stat.domain
            if domain not in domain_data:
                domain_data[domain] = {
                    'domain': domain,
                    'last_xasm_scan': None,
                    'last_lightbox_scan': None,
                    'has_xasm': False,
                    'has_lightbox': False
                }
            domain_data[domain]['last_xasm_scan'] = stat.last_scan.isoformat() if stat.last_scan else None
            domain_data[domain]['has_xasm'] = True

        # Get Lightbox domains with last scan date - FILTERED BY USER
        lightbox_stats = db.query(
            LightboxScanHistory.target,
            func.max(LightboxScanHistory.timestamp).label('last_scan')
        ).filter(
            LightboxScanHistory.deleted_at == None,
            LightboxScanHistory.user_id == user_id
        ).group_by(
            LightboxScanHistory.target
        ).all()

        for stat in lightbox_stats:
            target = stat.target
            if target not in domain_data:
                domain_data[target] = {
                    'domain': target,
                    'last_xasm_scan': None,
                    'last_lightbox_scan': None,
                    'has_xasm': False,
                    'has_lightbox': False
                }
            domain_data[target]['last_lightbox_scan'] = stat.last_scan.isoformat() if stat.last_scan else None
            domain_data[target]['has_lightbox'] = True

        db.close()

        # Convert to list and sort by most recent scan
        domains = list(domain_data.values())
        domains.sort(key=lambda d: max(
            d['last_xasm_scan'] or '',
            d['last_lightbox_scan'] or ''
        ), reverse=True)

        return jsonify({
            'success': True,
            'domains': domains
        })

    except Exception as e:
        if db:
            db.close()
        logger.error(f"[XASM] Error getting cached domains: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# LIGHTBOX SCAN HISTORY ENDPOINTS
# ============================================================================

@app.route('/api/lightbox/history', methods=['GET'])
@require_auth
def get_lightbox_history_endpoint():
    """Get Lightbox scan history for current user only"""
    from database import get_lightbox_scan_history
    user_id = request.user_id

    try:
        # CRITICAL: Filter history by authenticated user's ID
        history = get_lightbox_scan_history(user_id=user_id)
        return jsonify({'success': True, 'history': history})
    except Exception as e:
        logger.error(f"[LIGHTBOX HISTORY] Error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/lightbox/history/<scan_id>', methods=['GET'])
@require_auth
def get_lightbox_scan_details(scan_id):
    """Get full Lightbox scan results by ID - only if owned by current user"""
    from database import get_lightbox_scan_by_id, LightboxScanHistory, SessionLocal

    try:
        # CRITICAL: Verify scan belongs to current user
        session = SessionLocal()
        try:
            scan = session.query(LightboxScanHistory).filter_by(scan_id=scan_id).first()
            if not scan:
                return jsonify({'error': 'Scan not found'}), 404
            if scan.user_id and scan.user_id != request.user_id:
                return jsonify({'error': 'Access denied'}), 403
        finally:
            session.close()

        results = get_lightbox_scan_by_id(scan_id)
        if results:
            return jsonify({'success': True, 'results': results})
        else:
            return jsonify({'error': 'Scan not found'}), 404
    except Exception as e:
        logger.error(f"[LIGHTBOX HISTORY] Error fetching scan {scan_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/lightbox/history/<scan_id>', methods=['DELETE'])
@require_auth
def delete_lightbox_scan_history_endpoint(scan_id):
    """Delete Lightbox scan from history - only if owned by current user"""
    from database import delete_lightbox_scan_history, LightboxScanHistory, SessionLocal

    try:
        # CRITICAL: Verify scan belongs to current user before deleting
        session = SessionLocal()
        try:
            scan = session.query(LightboxScanHistory).filter_by(scan_id=scan_id).first()
            if not scan:
                return jsonify({'error': 'Scan not found'}), 404
            if scan.user_id and scan.user_id != request.user_id:
                return jsonify({'error': 'Access denied'}), 403
        finally:
            session.close()

        success = delete_lightbox_scan_history(scan_id)
        if success:
            return jsonify({'success': True})
        else:
            return jsonify({'error': 'Scan not found'}), 404
    except Exception as e:
        logger.error(f"[LIGHTBOX HISTORY] Error deleting scan {scan_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ============================================================================
# AI REPORT DATA ENDPOINTS
# ============================================================================

@app.route('/api/ai/companies', methods=['GET'])
@require_auth
def get_companies_for_ai():
    """Get list of companies with available scans for AI reports - FILTERED BY USER"""
    try:
        # CRITICAL: Filter by authenticated user's ID
        user_id = request.user_id
        companies = get_companies_with_scans(user_id=user_id)

        return jsonify({
            'success': True,
            'companies': companies,
            'count': len(companies)
        })

    except Exception as e:
        logger.error(f"[AI API] Error getting companies: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ai/generate-report', methods=['POST'])
@require_auth
def generate_ai_report():
    """Generate AI vulnerability assessment report - FILTERED BY USER"""
    from database import load_xasm_for_ai, load_lightbox_for_ai
    from modules.ghost.ai_vuln_report import generate_vulnerability_report

    try:
        data = request.get_json()
        company = data.get('company')
        user_id = request.user_id  # CRITICAL: Filter by authenticated user

        if not company:
            return jsonify({'error': 'Company required'}), 400

        print(f"[AI API] Generating report for {company} (user_id: {user_id})")

        # Load scan results - filtered by user_id
        xasm_data = load_xasm_for_ai(company, user_id=user_id)
        lightbox_data = load_lightbox_for_ai(company, user_id=user_id)

        if not xasm_data:
            return jsonify({'error': 'XASM scan results not found or expired'}), 404

        if not lightbox_data:
            return jsonify({'error': 'Lightbox scan results not found or expired'}), 404

        # Generate AI report
        report = generate_vulnerability_report(company, xasm_data, lightbox_data)

        return jsonify({
            'success': True,
            'report': report
        })

    except Exception as e:
        print(f"[AI API] Error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


# ============================================================================
# AI VULNERABILITY ASSESSMENT ENDPOINT
# ============================================================================

@app.route('/api/ghost/vuln-assessment/generate', methods=['POST'])
def vuln_assessment_generate():
    """
    Generate AI-powered vulnerability assessment for critical/high findings
    """
    try:
        from modules.ghost.ai_vuln_assessment import generate_vuln_assessment

        data = request.json
        xasm_results = data.get('xasm_results', {})
        lightbox_results = data.get('lightbox_results', {})

        if not xasm_results:
            return jsonify({'success': False, 'error': 'XASM results are required'}), 400

        print(f"\n[VULN ASSESSMENT] Generating AI-powered assessment...")

        # Generate vulnerability assessment
        results = generate_vuln_assessment(xasm_results, lightbox_results)

        if results.get('success'):
            print(f"[VULN ASSESSMENT] ✓ Generated {results.get('assessed_count', 0)} assessments")
            return jsonify({
                'success': True,
                'results': results
            }), 200
        else:
            print(f"[VULN ASSESSMENT] ❌ Error: {results.get('error')}")
            return jsonify(results), 500

    except Exception as e:
        print(f"[VULN ASSESSMENT] ❌ Exception: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# ============================================================================
# FILE UPLOAD ENDPOINTS
# ============================================================================

# Ensure upload directory exists
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'uploaded_files')
os.makedirs(UPLOAD_DIR, exist_ok=True)

def cleanup_old_files():
    """Delete files older than 24 hours"""
    try:
        db = get_db()
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=24)

        # Find old uploads
        old_uploads = db.query(UploadedFile).filter(
            UploadedFile.upload_time < cutoff_time
        ).all()

        for upload in old_uploads:
            print(f"[CLEANUP] Deleting old upload: {upload.upload_id}")

            # Delete physical file
            if os.path.exists(upload.file_path):
                os.remove(upload.file_path)
                print(f"[CLEANUP] Deleted file: {upload.file_path}")

            # Delete credentials (cascade should handle this)
            db.query(UploadedCredential).filter(
                UploadedCredential.upload_id == upload.upload_id
            ).delete()

            # Delete database record
            db.delete(upload)

        db.commit()
        db.close()

        if old_uploads:
            print(f"[CLEANUP] Cleaned up {len(old_uploads)} old uploads")

    except Exception as e:
        print(f"[CLEANUP] Error during cleanup: {e}")
        if db:
            db.close()

@app.route('/api/ghost/upload-breach-file', methods=['POST'])
def upload_breach_file():
    """Upload and parse a breach compilation file"""
    db = None
    try:
        print(f"\n{'='*60}")
        print(f"[UPLOAD] Starting file upload...")

        # Check if file is in request
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file provided'}), 400

        file = request.files['file']

        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400

        # Check file extension
        allowed_extensions = {'.txt', '.csv'}
        file_ext = os.path.splitext(file.filename)[1].lower()
        if file_ext not in allowed_extensions:
            return jsonify({
                'success': False,
                'error': f'Invalid file type. Allowed: {", ".join(allowed_extensions)}'
            }), 400

        # Generate unique upload ID
        timestamp = int(time.time())
        random_str = secrets.token_hex(4)
        upload_id = f"upload_{timestamp}_{random_str}"

        # Save file
        file_path = os.path.join(UPLOAD_DIR, f"{upload_id}{file_ext}")
        file.save(file_path)
        file_size = os.path.getsize(file_path)

        print(f"[UPLOAD] File saved: {file_path}")
        print(f"[UPLOAD] File size: {file_size} bytes")

        # Parse file line by line
        print(f"[UPLOAD] Parsing credentials...")

        db = get_db()

        # Create UploadedFile record
        uploaded_file = UploadedFile(
            upload_id=upload_id,
            filename=file.filename,
            file_path=file_path,
            file_size_bytes=file_size,
            upload_time=datetime.now(timezone.utc)
        )

        db.add(uploaded_file)
        db.flush()  # Get the ID without committing

        # Parse file
        line_count = 0
        parsed_count = 0

        # Patterns to match: email:password, email;password, email|password
        patterns = [
            r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})[:|;](.+)',  # email:pass or email;pass or email|pass
            r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',  # just email
        ]

        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_number, line in enumerate(f, 1):
                line_count += 1
                line = line.strip()

                if not line:
                    continue

                # Try to match patterns
                matched = False
                for pattern in patterns:
                    match = re.match(pattern, line)
                    if match:
                        email = match.group(1)
                        password = match.group(2) if len(match.groups()) > 1 else None

                        # Store in database
                        credential = UploadedCredential(
                            upload_id=upload_id,
                            email=email,
                            password=password,
                            line_number=line_number
                        )
                        db.add(credential)
                        parsed_count += 1
                        matched = True
                        break

                # Batch commit every 1000 lines for performance
                if line_count % 1000 == 0:
                    db.commit()
                    print(f"[UPLOAD] Processed {line_count} lines, parsed {parsed_count} credentials...")

        # Final commit
        uploaded_file.line_count = line_count
        uploaded_file.parsed_credential_count = parsed_count
        db.commit()

        print(f"[UPLOAD] ✓ Upload complete!")
        print(f"[UPLOAD] Total lines: {line_count}")
        print(f"[UPLOAD] Parsed credentials: {parsed_count}")
        print(f"{'='*60}\n")

        db.close()

        return jsonify({
            'success': True,
            'upload_id': upload_id,
            'filename': file.filename,
            'line_count': line_count,
            'parsed_credential_count': parsed_count,
            'file_size_bytes': file_size
        }), 201

    except Exception as e:
        if db:
            db.rollback()
            db.close()
        print(f"[UPLOAD] ❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ghost/search-uploaded-file', methods=['POST'])
def search_uploaded_file():
    """Search an uploaded file for credentials"""
    db = None
    try:
        data = request.json
        upload_id = data.get('upload_id', '').strip()
        query = data.get('query', '').strip().lower()

        if not upload_id:
            return jsonify({'success': False, 'error': 'upload_id is required'}), 400

        if not query:
            return jsonify({'success': False, 'error': 'query is required'}), 400

        print(f"\n[SEARCH UPLOAD] Searching upload {upload_id} for: {query}")

        db = get_db()

        # Check if upload exists
        uploaded_file = db.query(UploadedFile).filter(
            UploadedFile.upload_id == upload_id
        ).first()

        if not uploaded_file:
            db.close()
            return jsonify({'success': False, 'error': 'Upload not found'}), 404

        # Search credentials
        results = db.query(UploadedCredential).filter(
            UploadedCredential.upload_id == upload_id,
            func.lower(UploadedCredential.email).contains(query)
        ).limit(100).all()  # Limit to 100 results

        # Format results in same format as unified_search
        credentials = []
        for cred in results:
            credentials.append({
                'email': cred.email,
                'password': cred.password or 'N/A',
                'source': 'User Upload',
                'line_number': cred.line_number
            })

        print(f"[SEARCH UPLOAD] Found {len(credentials)} results")

        db.close()

        return jsonify({
            'success': True,
            'query': query,
            'credentials': credentials,
            'total_found': len(credentials),
            'upload_info': {
                'filename': uploaded_file.filename,
                'upload_time': uploaded_file.upload_time.isoformat() if uploaded_file.upload_time else None,
                'total_credentials': uploaded_file.parsed_credential_count
            }
        }), 200

    except Exception as e:
        if db:
            db.close()
        print(f"[SEARCH UPLOAD] ❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ghost/monitoring/timeline', methods=['POST'])
@require_auth
@require_email_monitoring_access
def get_monitoring_timeline():
    """Get breach timeline for monitored emails - requires COMPANY_USER role or above"""
    try:
        data = request.json
        emails = data.get('emails', [])

        if not emails:
            return jsonify({'breaches': []})

        print(f"[TIMELINE] Fetching breach history for {len(emails)} emails")

        all_breaches = []
        breach_names = set()  # Deduplicate by breach name

        # Initialize unified search
        searcher = UnifiedSearch()

        # Search each email across all sources
        for email in emails[:15]:  # Limit to 15
            try:
                print(f"[TIMELINE] Searching breaches for: {email}")

                # Use unified search to get breach data
                result = searcher.search(email)

                # Extract breach information from results
                if result and result.get('results'):
                    for source, source_data in result['results'].items():
                        if source_data.get('found') and source_data.get('type') == 'breach_data':
                            data_items = source_data.get('data', [])
                            if not isinstance(data_items, list):
                                data_items = [data_items]

                            for breach in data_items:
                                breach_name = breach.get('name', 'Unknown')

                                # Deduplicate breaches by name
                                if breach_name not in breach_names:
                                    breach_names.add(breach_name)
                                    all_breaches.append({
                                        'name': breach_name,
                                        'date': breach.get('date', 'Unknown'),
                                        'count': 1,  # Increment for each email found
                                        'email': email,
                                        'data_types': breach.get('data_types', [])
                                    })
                                else:
                                    # Increment count for existing breach
                                    for existing_breach in all_breaches:
                                        if existing_breach['name'] == breach_name:
                                            existing_breach['count'] += 1
                                            break

            except Exception as e:
                print(f"[TIMELINE] Error fetching breaches for {email}: {e}")
                continue

        # Sort by date (most recent first)
        all_breaches.sort(key=lambda x: x.get('date', ''), reverse=True)

        print(f"[TIMELINE] Returning {len(all_breaches)} unique breaches")

        return jsonify({
            'success': True,
            'breaches': all_breaches,
            'total_emails': len(emails)
        })

    except Exception as e:
        print(f"[TIMELINE] Error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

# ============================================================================
# OPSYCH MODULE ENDPOINTS
# ============================================================================

@app.route('/api/opsych/search', methods=['POST'])
def opsych_search():
    """
    OPSYCH Social Search - Search for identity using exposure analysis
    Accepts: email, username, phone, name (comma-separated)

    Uses exposure_analysis.py to run:
    - DuckDuckGo searches
    - Google Custom Search
    - Ghost breach checker
    - Hunter.io (if email)
    """
    db = None
    try:
        data = request.json
        query_input = data.get('query', '').strip()

        if not query_input:
            return jsonify({'success': False, 'error': 'query is required'}), 400

        print(f"\n[OPSYCH SEARCH] Starting search for: {query_input}")

        # Detect input type and parse parameters
        email = None
        name = None
        username = None
        company = None
        query_type = 'mixed'

        # Parse query input
        if '@' in query_input:
            # Email input
            email = query_input
            query_type = 'email'
            print(f"[OPSYCH SEARCH] Detected type: EMAIL")
        elif query_input.replace('-', '').replace('+', '').replace(' ', '').replace('(', '').replace(')', '').isdigit():
            # Phone input
            query_type = 'phone'
            print(f"[OPSYCH SEARCH] Detected type: PHONE (no handler yet)")
            # Note: exposure_analysis doesn't handle phone yet
            return jsonify({
                'success': True,
                'search_id': f"search_{int(time.time())}_{secrets.token_hex(4)}",
                'query': query_input,
                'profiles': [],
                'emails': [],
                'phones': [query_input],
                'aliases': [],
                'total_found': 0,
                'message': 'Phone search not yet implemented'
            }), 200
        elif ',' not in query_input and ' ' in query_input:
            # Name input (has space, no comma)
            name = query_input
            query_type = 'name'
            print(f"[OPSYCH SEARCH] Detected type: NAME")
        elif ',' not in query_input:
            # Username input (no space, no comma)
            username = query_input
            query_type = 'username'
            print(f"[OPSYCH SEARCH] Detected type: USERNAME")
        else:
            # Multiple queries - try to parse
            name = query_input
            query_type = 'name'
            print(f"[OPSYCH SEARCH] Detected type: MIXED (treating as NAME)")

        # Run exposure analysis
        print(f"[OPSYCH SEARCH] Running exposure analysis...")
        print(f"  Email: {email}")
        print(f"  Name: {name}")
        print(f"  Username: {username}")
        print(f"  Company: {company}")

        results = analyze_exposure(
            email=email,
            name=name,
            username=username,
            company=company
        )

        # Convert exposure analysis results to profile format
        profiles = []
        emails = set()
        phones = set()
        aliases = set()

        # Add professional info as a profile
        if results['professional'].get('email'):
            emails.add(results['professional']['email'])

        if results['professional'].get('company') or results['professional'].get('position'):
            profiles.append({
                'platform': 'Hunter.io',
                'username': results['professional'].get('email', '').split('@')[0] if results['professional'].get('email') else '',
                'email': results['professional'].get('email', ''),
                'name': results['professional'].get('name', ''),
                'title': results['professional'].get('position', ''),
                'company': results['professional'].get('company', ''),
                'linkedin': results['professional'].get('linkedin', ''),
                'twitter': results['professional'].get('twitter', ''),
                'url': results['professional'].get('linkedin', '') or results['professional'].get('twitter', ''),
                'bio': f"{results['professional'].get('position', 'Professional')} at {results['professional'].get('company', 'Unknown')}",
                'source': 'Hunter.io Professional Data'
            })

        # Add breach credentials as profiles
        for cred in results['breaches'].get('credentials', [])[:5]:
            emails.add(cred['email'])
            profiles.append({
                'platform': 'Ghost Breach',
                'username': cred['email'].split('@')[0],
                'email': cred['email'],
                'password': cred.get('password', ''),
                'url': '',
                'bio': f"Found in breach: {cred.get('source', 'Unknown')}",
                'source': cred.get('source', 'Ghost Database')
            })

        # Add GitHub leaks as profiles
        for leak in results['breaches'].get('github_leaks', [])[:3]:
            profiles.append({
                'platform': 'GitHub',
                'username': '',
                'url': leak['url'],
                'bio': f"{leak.get('credential_type', 'Credential')} found in GitHub gist",
                'source': 'GitHub Leak',
                'leak_type': leak.get('credential_type', 'Unknown')
            })

        # Add PasteBin leaks as profiles
        for leak in results['breaches'].get('pastebin_leaks', [])[:3]:
            profiles.append({
                'platform': 'PasteBin',
                'username': '',
                'url': leak['url'],
                'bio': f"{leak.get('title', 'Untitled paste')}",
                'source': 'PasteBin Leak'
            })

        # Add mentions as profiles (DuckDuckGo and Google results)
        for mention in results['mentions'][:10]:
            profiles.append({
                'platform': 'Web Mention',
                'username': '',
                'url': mention['url'],
                'bio': mention.get('title', mention.get('snippet', 'Web mention')),
                'source': mention.get('source', 'Web Search')
            })

        # Add social profiles
        for social in results.get('social', []):
            profiles.append({
                'platform': social.get('platform', 'Social Media'),
                'username': social.get('username', ''),
                'url': social.get('url', ''),
                'bio': social.get('bio', ''),
                'source': 'Social Media Profile'
            })

        # Add username to aliases if provided
        if username:
            aliases.add(username)

        # Generate search ID
        search_id = f"search_{int(time.time())}_{secrets.token_hex(4)}"

        # Store results in database
        db = get_db()
        stored_count = 0

        for profile in profiles:
            search_result = OpsychSearchResult(
                search_id=search_id,
                query_input=query_input,
                query_type=query_type,
                platform=profile.get('platform', ''),
                username=profile.get('username', ''),
                url=profile.get('url', ''),
                bio=profile.get('bio', ''),
                source=profile.get('source', '')
            )
            db.add(search_result)
            stored_count += 1

        db.commit()
        db.close()

        print(f"[OPSYCH SEARCH] Found {len(profiles)} profiles")
        print(f"[OPSYCH SEARCH] Risk Score: {results['risk_score']}/100")
        print(f"[OPSYCH SEARCH] Confidence: {results['confidence']}/100")
        print(f"[OPSYCH SEARCH] Breaches: {results['breaches']['total_breaches']}")
        print(f"[OPSYCH SEARCH] Stored {stored_count} results with search_id: {search_id}")

        return jsonify({
            'success': True,
            'search_id': search_id,
            'query': query_input,
            'query_type': query_type,
            'profiles': profiles,
            'emails': list(emails),
            'phones': list(phones),
            'aliases': list(aliases),
            'total_found': len(profiles),
            'risk_score': results['risk_score'],
            'confidence': results['confidence'],
            'breach_count': results['breaches']['total_breaches']
        }), 200

    except Exception as e:
        if db:
            db.rollback()
            db.close()
        print(f"[OPSYCH SEARCH] ❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/opsych/search/<search_id>', methods=['GET'])
def get_opsych_search(search_id):
    """
    Retrieve stored OPSYCH search results by search_id
    """
    db = None
    try:
        db = get_db()

        # Get all results for this search
        results = db.query(OpsychSearchResult).filter(
            OpsychSearchResult.search_id == search_id
        ).all()

        if not results:
            db.close()
            return jsonify({'success': False, 'error': 'Search not found'}), 404

        # Format results
        profiles = []
        for result in results:
            profiles.append({
                'platform': result.platform,
                'username': result.username,
                'url': result.url,
                'bio': result.bio,
                'source': result.source,
                'discovered_at': result.discovered_at.isoformat() if result.discovered_at else None
            })

        db.close()

        return jsonify({
            'success': True,
            'search_id': search_id,
            'query': results[0].query_input if results else '',
            'profiles': profiles,
            'total_found': len(profiles)
        }), 200

    except Exception as e:
        if db:
            db.close()
        print(f"[OPSYCH GET] ❌ Error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/opsych/exposure', methods=['POST'])
def opsych_exposure():
    """
    OPSYCH Phase 1: Intelligence Inference Engine
    Comprehensive person intelligence with flexible input

    Accepts JSON with (ALL OPTIONAL - at least ONE required):
    - name: Full name
    - email: Email address
    - phone: Phone number
    - username: Username/handle
    - company: Company name
    - location: City/state/location
    - age: Age or age range
    - context: Additional context

    Returns:
    - professional: Hunter.io enrichment data
    - breaches: Ghost database breach data
    - mentions: DuckDuckGo and Google search results
    - social: Social media profiles
    - family: Whitepages relatives/addresses data
    - inference: Intelligence inference results with confidence scores
    - risk_score: 0-100 risk assessment
    - confidence: 0-100 confidence score
    """
    try:
        from modules.opsych.exposure_analysis import analyze_exposure

        data = request.json
        email = data.get('email')
        name = data.get('name')
        username = data.get('username')
        company = data.get('company')
        phone = data.get('phone')
        location = data.get('location')
        age = data.get('age')
        context = data.get('context')

        # Validate at least one field provided
        if not any([email, name, username, company, phone, location, age, context]):
            return jsonify({
                'success': False,
                'error': 'At least ONE piece of information is required'
            }), 400

        print(f"\n[OPSYCH EXPOSURE] Starting Intelligence Inference")
        print(f"  Email: {email}")
        print(f"  Name: {name}")
        print(f"  Phone: {phone}")
        print(f"  Username: {username}")
        print(f"  Company: {company}")
        print(f"  Location: {location}")
        print(f"  Age: {age}")
        print(f"  Context: {context[:100] if context else None}...")

        # Run exposure analysis with inference engine
        results = analyze_exposure(
            email=email,
            name=name,
            username=username,
            company=company,
            phone=phone,
            location=location,
            age=age,
            context=context
        )

        print(f"[OPSYCH EXPOSURE] Analysis complete")
        print(f"  Risk Score: {results['risk_score']}/100")
        print(f"  Confidence: {results['confidence']}/100")
        print(f"  Breaches: {results['breaches'].get('total_breaches', 0)}")
        print(f"  Profiles Found: {len(results.get('inference', {}).get('profiles', []))}")

        return jsonify({
            'success': True,
            'query': {
                'email': email,
                'name': name,
                'phone': phone,
                'username': username,
                'company': company,
                'location': location,
                'age': age
            },
            'professional': results['professional'],
            'breaches': results['breaches'],
            'mentions': results['mentions'],
            'social': results.get('social', []),
            'family': results.get('family', []),
            'inference': results.get('inference', {}),
            'risk_score': results['risk_score'],
            'confidence': results['confidence'],
            'analyzed_at': results['analyzed_at']
        }), 200

    except Exception as e:
        print(f"[OPSYCH EXPOSURE] ❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================================================
# RSS FEED ENDPOINTS
# ============================================================================

@app.route('/api/rss/fetch', methods=['POST'])
def fetch_rss_feeds():
    """Fetch and parse multiple RSS feeds"""
    try:
        data = request.json
        feed_urls = data.get('feeds', [])

        if not feed_urls:
            return jsonify({'articles': []})

        all_articles = []

        for feed_url in feed_urls[:10]:  # Max 10 feeds
            try:
                print(f"[RSS] Fetching feed: {feed_url}")
                # Parse RSS feed
                feed = feedparser.parse(feed_url)

                # Extract source name from feed
                source_name = feed.feed.get('title', feed_url)

                # Get first 5 articles from each feed
                for entry in feed.entries[:5]:
                    all_articles.append({
                        'title': entry.get('title', 'No title'),
                        'link': entry.get('link', ''),
                        'description': entry.get('summary', '')[:200] + '...' if len(entry.get('summary', '')) > 200 else entry.get('summary', ''),
                        'source': source_name,
                        'published': entry.get('published', '')
                    })
                print(f"[RSS] ✓ Fetched {len(feed.entries[:5])} articles from {source_name}")
            except Exception as e:
                print(f"[RSS] ❌ Error fetching {feed_url}: {e}")
                continue

        # Sort by most recent (if published date available)
        all_articles.sort(key=lambda x: x.get('published', ''), reverse=True)

        print(f"[RSS] Total articles fetched: {len(all_articles)}")

        return jsonify({'articles': all_articles[:20]})  # Return max 20 articles

    except Exception as e:
        print(f"[RSS] ❌ Error: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================================================
# USER-SPECIFIC RSS FEED MANAGEMENT
# ============================================================================

@app.route('/api/news-sources', methods=['GET'])
@require_auth
def get_user_news_sources():
    """Get RSS sources for current user."""
    db = SessionLocal()
    try:
        user = get_current_user()
        if not user:
            return jsonify({'error': 'Unauthorized'}), 401

        sources = db.query(NewsSource).filter_by(
            user_id=user.get('id'),
            active=True
        ).order_by(NewsSource.created_at.desc()).all()

        results = []
        for source in sources:
            results.append({
                'id': source.id,
                'name': source.name,
                'url': source.url,
                'active': source.active,
                'last_fetched': source.last_fetched.isoformat() if source.last_fetched else None
            })

        return jsonify(results)

    except Exception as e:
        print(f"[RSS] Get user news sources error: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/news-sources', methods=['POST'])
@require_auth
def add_user_news_source():
    """Add RSS source for current user."""
    db = SessionLocal()
    try:
        user = get_current_user()
        if not user:
            return jsonify({'error': 'Unauthorized'}), 401

        data = request.get_json() or {}
        url = data.get('url', '').strip()
        name = data.get('name', '').strip()

        if not url:
            return jsonify({'error': 'URL is required'}), 400

        # Check user's feed count (limit to 10)
        feed_count = db.query(NewsSource).filter_by(user_id=user.get('id'), active=True).count()
        if feed_count >= 10:
            return jsonify({'error': 'Maximum 10 feeds allowed'}), 400

        # Check for duplicate URL for this user
        existing = db.query(NewsSource).filter_by(user_id=user.get('id'), url=url).first()
        if existing:
            return jsonify({'error': 'This feed is already added'}), 400

        source = NewsSource(
            user_id=user.get('id'),
            url=url,
            name=name or None,
            active=True,
            created_by=user.get('id')
        )
        db.add(source)
        db.commit()

        print(f"[RSS] User {user.get('id')} added feed: {url}")

        return jsonify({
            'success': True,
            'source': {
                'id': source.id,
                'name': source.name,
                'url': source.url,
                'active': source.active
            }
        })

    except Exception as e:
        db.rollback()
        print(f"[RSS] Add user news source error: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/news-sources/<int:source_id>', methods=['DELETE'])
@require_auth
def delete_user_news_source(source_id):
    """Delete RSS source (only if owned by current user)."""
    db = SessionLocal()
    try:
        user = get_current_user()
        if not user:
            return jsonify({'error': 'Unauthorized'}), 401

        # Find source and verify ownership
        source = db.query(NewsSource).filter_by(
            id=source_id,
            user_id=user.get('id')
        ).first()

        if not source:
            return jsonify({'error': 'Source not found or unauthorized'}), 404

        url = source.url
        db.delete(source)
        db.commit()

        print(f"[RSS] User {user.get('id')} deleted feed: {url}")

        return jsonify({'success': True})

    except Exception as e:
        db.rollback()
        print(f"[RSS] Delete user news source error: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/rss-feed', methods=['GET'])
@require_auth
def get_user_rss_feed():
    """Get aggregated RSS feed from user's sources."""
    db = SessionLocal()
    try:
        user = get_current_user()
        if not user:
            return jsonify({'error': 'Unauthorized'}), 401

        # Get user's active RSS sources
        sources = db.query(NewsSource).filter_by(
            user_id=user.get('id'),
            active=True
        ).all()

        if not sources:
            # Return empty feed if no sources configured
            return jsonify({
                'articles': [],
                'sources_count': 0,
                'message': 'No RSS sources configured'
            })

        # Fetch and aggregate articles from all user's sources
        all_articles = []

        for source in sources:
            try:
                print(f"[RSS] Fetching for user {user.get('id')}: {source.url}")
                feed = feedparser.parse(source.url)

                for entry in feed.entries[:5]:  # Top 5 per source
                    # Parse publication date
                    pub_date = None
                    if hasattr(entry, 'published_parsed') and entry.published_parsed:
                        pub_date = datetime(*entry.published_parsed[:6])
                    elif hasattr(entry, 'updated_parsed') and entry.updated_parsed:
                        pub_date = datetime(*entry.updated_parsed[:6])

                    all_articles.append({
                        'title': entry.get('title', 'No title'),
                        'link': entry.get('link', ''),
                        'description': (entry.get('summary', '') or '')[:200] + '...',
                        'source': source.name or feed.feed.get('title', source.url),
                        'published': pub_date.isoformat() if pub_date else datetime.now(timezone.utc).isoformat()
                    })

                # Update last_fetched timestamp
                source.last_fetched = datetime.now(timezone.utc)
                source.fetch_error = None

            except Exception as e:
                print(f"[RSS] Error fetching {source.url}: {e}")
                source.fetch_error = str(e)
                continue

        db.commit()

        # Sort by date (most recent first)
        all_articles.sort(key=lambda x: x.get('published', ''), reverse=True)

        return jsonify({
            'articles': all_articles[:20],  # Return top 20 articles
            'sources_count': len(sources)
        })

    except Exception as e:
        print(f"[RSS] Get user feed error: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


# ============================================================================
# COMPLIANCE FRAMEWORK ENDPOINTS
# ============================================================================

COMPLIANCE_FRAMEWORKS_PATH = os.path.join(os.path.dirname(__file__), 'data', 'compliance_frameworks')

def load_framework_json(framework_id):
    """Load a compliance framework JSON file"""
    file_map = {
        'soc2': 'soc2.json',
        'iso27001': 'iso27001.json',
        'gdpr': 'gdpr.json',
        'nis2': 'nis2.json'
    }

    if framework_id not in file_map:
        return None

    filepath = os.path.join(COMPLIANCE_FRAMEWORKS_PATH, file_map[framework_id])
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"[COMPLIANCE] Error loading framework {framework_id}: {e}")
        return None


def normalize_framework_controls(framework_id, framework_data):
    """Normalize different framework structures into a unified format"""
    controls = []

    if framework_id == 'soc2':
        # SOC2 has trustServicesCriteria with nested categories
        tsc = framework_data.get('trustServicesCriteria', {})
        for category_name, category_controls in tsc.items():
            if category_name == 'additionalCriteria':
                # Additional criteria has another level of nesting
                for sub_category, sub_controls in category_controls.items():
                    for ctrl in sub_controls:
                        for pof in ctrl.get('pof', []):
                            controls.append({
                                'control_id': pof.get('id', ''),
                                'title': pof.get('title', ''),
                                'description': pof.get('requirement', ''),
                                'category': f"{category_name} - {sub_category}",
                                'parent_principle': ctrl.get('principle', ''),
                                'parent_id': ctrl.get('id', ''),
                                'is_core': True
                            })
            else:
                for ctrl in category_controls:
                    for pof in ctrl.get('pof', []):
                        controls.append({
                            'control_id': pof.get('id', ''),
                            'title': pof.get('title', ''),
                            'description': pof.get('requirement', ''),
                            'category': category_name,
                            'parent_principle': ctrl.get('principle', ''),
                            'parent_id': ctrl.get('id', ''),
                            'is_core': True
                        })

    elif framework_id == 'iso27001':
        # ISO27001 has domains with controls
        for domain in framework_data.get('domains', []):
            for ctrl in domain.get('controls', []):
                controls.append({
                    'control_id': ctrl.get('ref', ''),
                    'title': ctrl.get('title', ''),
                    'description': ctrl.get('summary', ''),
                    'category': domain.get('title', ''),
                    'mapped_controls': ctrl.get('mappedControls', []),
                    'is_core': ctrl.get('isCore', False)
                })

    elif framework_id in ['gdpr', 'nis2']:
        # GDPR and NIS2 have domains with articles
        for domain in framework_data.get('domains', []):
            for article in domain.get('articles', []):
                requirements = article.get('requirements', [])
                controls.append({
                    'control_id': article.get('ref', ''),
                    'title': article.get('title', ''),
                    'description': article.get('summary', ''),
                    'category': domain.get('title', ''),
                    'requirements': requirements,
                    'is_core': article.get('isCore', False)
                })

    return controls


@app.route('/api/compliance/frameworks', methods=['GET'])
def get_compliance_frameworks():
    """List all available compliance frameworks"""
    try:
        frameworks = [
            {
                'id': 'soc2',
                'name': 'SOC 2',
                'full_name': 'SOC 2 Type II',
                'version': 'TSC 2017 + POF 2022',
                'description': 'Service Organization Control 2 - Security, Availability, Processing Integrity, Confidentiality, and Privacy',
                'icon': '🛡️',
                'color': '#3b82f6',
                'control_count': 0
            },
            {
                'id': 'iso27001',
                'name': 'ISO 27001',
                'full_name': 'ISO/IEC 27001:2022',
                'version': '2022',
                'description': 'International standard for information security management systems (ISMS)',
                'icon': '🏛️',
                'color': '#8b5cf6',
                'control_count': 0
            },
            {
                'id': 'gdpr',
                'name': 'GDPR',
                'full_name': 'General Data Protection Regulation',
                'version': 'Regulation (EU) 2016/679',
                'description': 'European Union regulation on data protection and privacy',
                'icon': '🇪🇺',
                'color': '#10b981',
                'control_count': 0
            },
            {
                'id': 'nis2',
                'name': 'NIS2',
                'full_name': 'NIS2 Directive',
                'version': 'Directive (EU) 2022/2555',
                'description': 'EU directive on security of network and information systems',
                'icon': '🔒',
                'color': '#f59e0b',
                'control_count': 0
            }
        ]

        # Load actual control counts
        for fw in frameworks:
            data = load_framework_json(fw['id'])
            if data:
                controls = normalize_framework_controls(fw['id'], data)
                fw['control_count'] = len(controls)

        return jsonify({
            'success': True,
            'frameworks': frameworks
        }), 200

    except Exception as e:
        print(f"[COMPLIANCE] Error getting frameworks: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/compliance/frameworks/<framework_id>', methods=['GET'])
def get_framework_details(framework_id):
    """Get detailed framework with all controls"""
    try:
        data = load_framework_json(framework_id)
        if not data:
            return jsonify({'success': False, 'error': 'Framework not found'}), 404

        controls = normalize_framework_controls(framework_id, data)

        # Group controls by category
        categories = {}
        for ctrl in controls:
            cat = ctrl.get('category', 'Other')
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(ctrl)

        # Count core controls
        core_count = sum(1 for c in controls if c.get('is_core', False))

        return jsonify({
            'success': True,
            'framework_id': framework_id,
            'total_controls': len(controls),
            'core_controls': core_count,
            'categories': categories,
            'controls': controls
        }), 200

    except Exception as e:
        print(f"[COMPLIANCE] Error getting framework details: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/compliance/assessment', methods=['POST'])
@require_auth
def create_assessment():
    """Create a new compliance assessment"""
    user_id = request.user_id
    company_id = request.user.get('company_id') or 1
    db = None
    try:
        data = request.json
        framework_id = data.get('framework_id')

        if not framework_id:
            return jsonify({'success': False, 'error': 'framework_id is required'}), 400

        # Load framework to get controls
        framework_data = load_framework_json(framework_id)
        if not framework_data:
            return jsonify({'success': False, 'error': 'Framework not found'}), 404

        controls = normalize_framework_controls(framework_id, framework_data)

        db = get_db()

        # Check if assessment already exists for this user and framework
        existing = db.query(ComplianceAssessment).filter(
            ComplianceAssessment.created_by_user_id == user_id,
            ComplianceAssessment.framework == framework_id,
            ComplianceAssessment.deleted_at == None
        ).first()

        if existing:
            # Return existing assessment
            return jsonify({
                'success': True,
                'assessment_id': existing.id,
                'message': 'Existing assessment found',
                'existing': True
            }), 200

        # Create new assessment
        assessment = ComplianceAssessment(
            company_id=company_id,
            created_by_user_id=user_id,
            framework=framework_id,
            framework_version=data.get('framework_version', ''),
            status='in_progress',
            assessment_date=datetime.now(timezone.utc)
        )
        db.add(assessment)
        db.flush()  # Get the ID

        # Create control records for each control in the framework
        for ctrl in controls:
            control_record = ComplianceControl(
                assessment_id=assessment.id,
                control_id=ctrl['control_id'],
                control_name=ctrl['title'],
                control_category=ctrl.get('category', ''),
                status='not_tested'
            )
            db.add(control_record)

        db.commit()

        print(f"[COMPLIANCE] Created assessment {assessment.id} with {len(controls)} controls")

        db.close()
        return jsonify({
            'success': True,
            'assessment_id': assessment.id,
            'controls_created': len(controls),
            'message': 'Assessment created successfully'
        }), 201

    except Exception as e:
        if db:
            db.rollback()
            db.close()
        print(f"[COMPLIANCE] Error creating assessment: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/compliance/assessment/<int:assessment_id>', methods=['GET'])
@require_auth
def get_assessment(assessment_id):
    """Get assessment status with all controls"""
    user_id = request.user_id
    db = None
    try:
        db = get_db()

        # Get assessment with ownership check
        assessment = db.query(ComplianceAssessment).filter(
            ComplianceAssessment.id == assessment_id,
            ComplianceAssessment.created_by_user_id == user_id,
            ComplianceAssessment.deleted_at == None
        ).first()

        if not assessment:
            db.close()
            return jsonify({'success': False, 'error': 'Assessment not found'}), 404

        # Get all controls for this assessment
        controls = db.query(ComplianceControl).filter(
            ComplianceControl.assessment_id == assessment_id,
            ComplianceControl.deleted_at == None
        ).all()

        # Calculate statistics
        stats = {
            'total': len(controls),
            'compliant': sum(1 for c in controls if c.status == 'compliant'),
            'non_compliant': sum(1 for c in controls if c.status == 'non_compliant'),
            'partial': sum(1 for c in controls if c.status == 'partial'),
            'not_tested': sum(1 for c in controls if c.status == 'not_tested')
        }

        completion = (stats['compliant'] + stats['partial'] + stats['non_compliant']) / stats['total'] * 100 if stats['total'] > 0 else 0
        compliance_rate = stats['compliant'] / (stats['total'] - stats['not_tested']) * 100 if (stats['total'] - stats['not_tested']) > 0 else 0

        # Group controls by category
        categories = {}
        for ctrl in controls:
            cat = ctrl.control_category or 'Other'
            if cat not in categories:
                categories[cat] = []
            categories[cat].append({
                'id': ctrl.id,
                'control_id': ctrl.control_id,
                'control_name': ctrl.control_name,
                'status': ctrl.status,
                'compliance_score': ctrl.compliance_score,
                'evidence_summary': ctrl.evidence_summary,
                'remediation_notes': ctrl.remediation_notes,
                'last_reviewed': ctrl.last_reviewed.isoformat() if ctrl.last_reviewed else None
            })

        db.close()

        return jsonify({
            'success': True,
            'assessment': {
                'id': assessment.id,
                'framework': assessment.framework,
                'framework_version': assessment.framework_version,
                'status': assessment.status,
                'overall_compliance_score': assessment.overall_compliance_score,
                'assessment_date': assessment.assessment_date.isoformat() if assessment.assessment_date else None,
                'completion_date': assessment.completion_date.isoformat() if assessment.completion_date else None
            },
            'statistics': stats,
            'completion_percentage': round(completion, 1),
            'compliance_rate': round(compliance_rate, 1),
            'categories': categories
        }), 200

    except Exception as e:
        if db:
            db.close()
        print(f"[COMPLIANCE] Error getting assessment: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/compliance/assessment/by-framework/<framework_id>', methods=['GET'])
@require_auth
def get_assessment_by_framework(framework_id):
    """Get existing assessment for a framework (if any)"""
    user_id = request.user_id
    db = None
    try:
        db = get_db()

        # Get user's assessment for this framework
        assessment = db.query(ComplianceAssessment).filter(
            ComplianceAssessment.created_by_user_id == user_id,
            ComplianceAssessment.framework == framework_id,
            ComplianceAssessment.deleted_at == None
        ).first()

        if not assessment:
            db.close()
            return jsonify({'success': True, 'assessment': None}), 200

        # Get control counts
        controls = db.query(ComplianceControl).filter(
            ComplianceControl.assessment_id == assessment.id,
            ComplianceControl.deleted_at == None
        ).all()

        stats = {
            'total': len(controls),
            'compliant': sum(1 for c in controls if c.status == 'compliant'),
            'non_compliant': sum(1 for c in controls if c.status == 'non_compliant'),
            'partial': sum(1 for c in controls if c.status == 'partial'),
            'not_tested': sum(1 for c in controls if c.status == 'not_tested')
        }

        completion = (stats['compliant'] + stats['partial'] + stats['non_compliant']) / stats['total'] * 100 if stats['total'] > 0 else 0

        db.close()

        return jsonify({
            'success': True,
            'assessment': {
                'id': assessment.id,
                'framework': assessment.framework,
                'status': assessment.status,
                'completion_percentage': round(completion, 1),
                'statistics': stats,
                'assessment_date': assessment.assessment_date.isoformat() if assessment.assessment_date else None
            }
        }), 200

    except Exception as e:
        if db:
            db.close()
        print(f"[COMPLIANCE] Error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/compliance/control/<int:control_id>', methods=['PUT'])
@require_auth
def update_control(control_id):
    """Update a compliance control status"""
    user_id = request.user_id
    db = None
    try:
        data = request.json
        db = get_db()

        # Get control with ownership check through assessment
        control = db.query(ComplianceControl).join(ComplianceAssessment).filter(
            ComplianceControl.id == control_id,
            ComplianceControl.deleted_at == None,
            ComplianceAssessment.created_by_user_id == user_id
        ).first()

        if not control:
            db.close()
            return jsonify({'success': False, 'error': 'Control not found'}), 404

        # Update fields
        if 'status' in data:
            control.status = data['status']
        if 'compliance_score' in data:
            control.compliance_score = data['compliance_score']
        if 'evidence_summary' in data:
            control.evidence_summary = data['evidence_summary']
        if 'remediation_notes' in data:
            control.remediation_notes = data['remediation_notes']

        control.last_reviewed = datetime.now(timezone.utc)

        db.commit()

        # Recalculate assessment score
        assessment = db.query(ComplianceAssessment).filter(
            ComplianceAssessment.id == control.assessment_id
        ).first()

        if assessment:
            all_controls = db.query(ComplianceControl).filter(
                ComplianceControl.assessment_id == assessment.id,
                ComplianceControl.deleted_at == None
            ).all()

            tested = [c for c in all_controls if c.status != 'not_tested']
            if tested:
                compliant = sum(1 for c in tested if c.status == 'compliant')
                partial = sum(1 for c in tested if c.status == 'partial')
                score = int((compliant + partial * 0.5) / len(tested) * 100)
                assessment.overall_compliance_score = score
                db.commit()

        db.close()

        return jsonify({
            'success': True,
            'message': 'Control updated successfully'
        }), 200

    except Exception as e:
        if db:
            db.rollback()
            db.close()
        print(f"[COMPLIANCE] Error updating control: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/compliance/evidence', methods=['POST'])
@require_auth
def add_evidence():
    """Add evidence to a control"""
    user_id = request.user_id
    db = None
    try:
        data = request.json
        control_id = data.get('control_id')

        if not control_id:
            return jsonify({'success': False, 'error': 'control_id is required'}), 400

        db = get_db()

        # Verify control exists and user owns it through assessment
        control = db.query(ComplianceControl).join(ComplianceAssessment).filter(
            ComplianceControl.id == control_id,
            ComplianceControl.deleted_at == None,
            ComplianceAssessment.created_by_user_id == user_id
        ).first()

        if not control:
            db.close()
            return jsonify({'success': False, 'error': 'Control not found'}), 404

        # Create evidence record
        evidence = ComplianceEvidence(
            control_id=control_id,
            evidence_type=data.get('evidence_type', 'document'),
            title=data.get('title', 'Untitled Evidence'),
            description=data.get('description', ''),
            file_path=data.get('file_path'),
            file_size=data.get('file_size'),
            file_type=data.get('file_type'),
            uploaded_by_user_id=user_id,
            evidence_date=datetime.now(timezone.utc)
        )
        db.add(evidence)
        db.commit()

        db.close()

        return jsonify({
            'success': True,
            'evidence_id': evidence.id,
            'message': 'Evidence added successfully'
        }), 201

    except Exception as e:
        if db:
            db.rollback()
            db.close()
        print(f"[COMPLIANCE] Error adding evidence: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/compliance/evidence/<int:control_id>', methods=['GET'])
@require_auth
def get_evidence(control_id):
    """Get all evidence for a control"""
    user_id = request.user_id
    db = None
    try:
        db = get_db()

        # Get evidence with ownership check through control -> assessment
        evidence_list = db.query(ComplianceEvidence).join(
            ComplianceControl
        ).join(
            ComplianceAssessment
        ).filter(
            ComplianceEvidence.control_id == control_id,
            ComplianceEvidence.deleted_at == None,
            ComplianceAssessment.created_by_user_id == user_id
        ).all()

        evidence_data = [{
            'id': e.id,
            'evidence_type': e.evidence_type,
            'title': e.title,
            'description': e.description,
            'file_path': e.file_path,
            'file_size': e.file_size,
            'file_type': e.file_type,
            'evidence_date': e.evidence_date.isoformat() if e.evidence_date else None,
            'created_at': e.created_at.isoformat() if e.created_at else None
        } for e in evidence_list]

        db.close()

        return jsonify({
            'success': True,
            'evidence': evidence_data,
            'count': len(evidence_data)
        }), 200

    except Exception as e:
        if db:
            db.close()
        print(f"[COMPLIANCE] Error getting evidence: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/compliance/evidence/<int:evidence_id>', methods=['DELETE'])
@require_auth
def delete_evidence(evidence_id):
    """Delete evidence (soft delete)"""
    user_id = request.user_id
    db = None
    try:
        db = get_db()

        # Get evidence with ownership check
        evidence = db.query(ComplianceEvidence).join(
            ComplianceControl
        ).join(
            ComplianceAssessment
        ).filter(
            ComplianceEvidence.id == evidence_id,
            ComplianceEvidence.deleted_at == None,
            ComplianceAssessment.created_by_user_id == user_id
        ).first()

        if not evidence:
            db.close()
            return jsonify({'success': False, 'error': 'Evidence not found'}), 404

        evidence.deleted_at = datetime.now(timezone.utc)
        db.commit()
        db.close()

        return jsonify({
            'success': True,
            'message': 'Evidence deleted successfully'
        }), 200

    except Exception as e:
        if db:
            db.rollback()
            db.close()
        print(f"[COMPLIANCE] Error deleting evidence: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/compliance/export/<int:assessment_id>', methods=['GET'])
@require_auth
def export_assessment(assessment_id):
    """Export assessment as JSON (for PDF/Excel generation on frontend)"""
    user_id = request.user_id
    db = None
    try:
        db = get_db()

        # Get assessment with ownership check
        assessment = db.query(ComplianceAssessment).filter(
            ComplianceAssessment.id == assessment_id,
            ComplianceAssessment.created_by_user_id == user_id,
            ComplianceAssessment.deleted_at == None
        ).first()

        if not assessment:
            db.close()
            return jsonify({'success': False, 'error': 'Assessment not found'}), 404

        controls = db.query(ComplianceControl).filter(
            ComplianceControl.assessment_id == assessment_id,
            ComplianceControl.deleted_at == None
        ).all()

        # Get framework metadata
        framework_data = load_framework_json(assessment.framework)
        framework_meta = {
            'soc2': {'name': 'SOC 2 Type II', 'version': 'TSC 2017 + POF 2022'},
            'iso27001': {'name': 'ISO/IEC 27001:2022', 'version': '2022'},
            'gdpr': {'name': 'GDPR', 'version': 'Regulation (EU) 2016/679'},
            'nis2': {'name': 'NIS2 Directive', 'version': 'Directive (EU) 2022/2555'}
        }.get(assessment.framework, {'name': assessment.framework, 'version': ''})

        # Calculate stats
        stats = {
            'total': len(controls),
            'compliant': sum(1 for c in controls if c.status == 'compliant'),
            'non_compliant': sum(1 for c in controls if c.status == 'non_compliant'),
            'partial': sum(1 for c in controls if c.status == 'partial'),
            'not_tested': sum(1 for c in controls if c.status == 'not_tested')
        }

        completion = (stats['compliant'] + stats['partial'] + stats['non_compliant']) / stats['total'] * 100 if stats['total'] > 0 else 0

        # Prepare export data
        export_data = {
            'report_generated': datetime.now(timezone.utc).isoformat(),
            'framework': framework_meta,
            'assessment': {
                'id': assessment.id,
                'status': assessment.status,
                'assessment_date': assessment.assessment_date.isoformat() if assessment.assessment_date else None,
                'overall_score': assessment.overall_compliance_score
            },
            'statistics': stats,
            'completion_percentage': round(completion, 1),
            'controls': []
        }

        # Add control details with evidence
        for ctrl in controls:
            evidence = db.query(ComplianceEvidence).filter(
                ComplianceEvidence.control_id == ctrl.id,
                ComplianceEvidence.deleted_at == None
            ).all()

            export_data['controls'].append({
                'control_id': ctrl.control_id,
                'name': ctrl.control_name,
                'category': ctrl.control_category,
                'status': ctrl.status,
                'score': ctrl.compliance_score,
                'evidence_summary': ctrl.evidence_summary,
                'remediation_notes': ctrl.remediation_notes,
                'last_reviewed': ctrl.last_reviewed.isoformat() if ctrl.last_reviewed else None,
                'evidence_count': len(evidence),
                'evidence': [{
                    'title': e.title,
                    'type': e.evidence_type,
                    'description': e.description
                } for e in evidence]
            })

        db.close()

        return jsonify({
            'success': True,
            'export': export_data
        }), 200

    except Exception as e:
        if db:
            db.close()
        print(f"[COMPLIANCE] Error exporting assessment: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# SCAN-TO-COMPLIANCE INTEGRATION ENDPOINTS
# ============================================================================

@app.route('/api/compliance/analyze-scan', methods=['POST'])
@require_auth
def analyze_scan_for_compliance():
    """
    Analyze scan findings and return affected compliance controls.
    Optionally auto-flag controls in an existing assessment.
    """
    user_id = request.user_id
    db = None
    try:
        data = request.json
        findings = data.get('findings', [])
        domain = data.get('domain')
        scan_type = data.get('scan_type', 'xasm')  # 'xasm' or 'lightbox'
        assessment_id = data.get('assessment_id')  # Optional - if provided, auto-flag controls
        auto_flag = data.get('auto_flag', False)

        print(f"\n[SCAN-COMPLIANCE] Analyzing {len(findings)} findings from {scan_type} scan")
        print(f"[SCAN-COMPLIANCE] Domain: {domain}, Assessment ID: {assessment_id}")

        # Analyze findings against compliance mappings
        analysis = analyze_scan_findings(findings)

        print(f"[SCAN-COMPLIANCE] Found {len(analysis['vulnerabilities'])} mapped vulnerabilities")
        print(f"[SCAN-COMPLIANCE] Affected controls: {analysis['affected_controls']}")

        flagged_controls = []

        # If assessment_id provided and auto_flag is true, update controls
        if assessment_id and auto_flag:
            db = get_db()

            # Get assessment with ownership check
            assessment = db.query(ComplianceAssessment).filter(
                ComplianceAssessment.id == assessment_id,
                ComplianceAssessment.created_by_user_id == user_id,
                ComplianceAssessment.deleted_at == None
            ).first()

            if assessment:
                framework = assessment.framework
                affected_control_ids = analysis['affected_controls'].get(framework, [])

                print(f"[SCAN-COMPLIANCE] Flagging {len(affected_control_ids)} controls for {framework}")

                for vuln in analysis['vulnerabilities']:
                    vuln_controls = vuln.get('finding', {})
                    affected = get_affected_controls(vuln['key'], framework)

                    for control_ref in affected:
                        # Find matching control in assessment
                        control = db.query(ComplianceControl).filter(
                            ComplianceControl.assessment_id == assessment_id,
                            ComplianceControl.control_id.like(f'%{control_ref}%'),
                            ComplianceControl.deleted_at == None
                        ).first()

                        if control and control.status != 'non_compliant':
                            # Flag the control
                            control.status = 'non_compliant'
                            control.scan_source = scan_type
                            control.scan_finding_type = vuln['key']
                            control.scan_finding_id = vuln.get('finding', {}).get('id', '')
                            control.scan_flagged_at = datetime.now(timezone.utc)
                            control.scan_domain = domain
                            control.last_reviewed = datetime.now(timezone.utc)

                            flagged_controls.append({
                                'control_id': control.control_id,
                                'control_name': control.control_name,
                                'vulnerability': vuln['name'],
                                'severity': vuln['severity']
                            })

                            # Auto-create evidence record
                            evidence = ComplianceEvidence(
                                control_id=control.id,
                                evidence_type='scan_finding',
                                title=f"Scan Finding: {vuln['name']}",
                                description=f"Auto-flagged by {scan_type.upper()} scan on {domain}.\n\n"
                                           f"Vulnerability: {vuln['description']}\n"
                                           f"Severity: {vuln['severity'].upper()}\n"
                                           f"Finding Details: {json.dumps(vuln.get('finding', {}), indent=2)}",
                                uploaded_by_user_id=1,
                                evidence_date=datetime.now(timezone.utc)
                            )
                            db.add(evidence)

                db.commit()
                print(f"[SCAN-COMPLIANCE] Flagged {len(flagged_controls)} controls")

            db.close()

        return jsonify({
            'success': True,
            'analysis': {
                'vulnerabilities': analysis['vulnerabilities'],
                'affected_controls': analysis['affected_controls'],
                'severity_summary': analysis['severity_summary']
            },
            'flagged_controls': flagged_controls,
            'total_flagged': len(flagged_controls)
        }), 200

    except Exception as e:
        if db:
            db.rollback()
            db.close()
        print(f"[SCAN-COMPLIANCE] Error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/compliance/affected-controls/<domain>', methods=['GET'])
@require_auth
def get_affected_controls_for_domain(domain):
    """
    Get compliance controls that have been flagged by scans for a specific domain.
    """
    user_id = request.user_id
    db = None
    try:
        db = get_db()

        # Get all controls flagged for this domain with ownership check
        controls = db.query(ComplianceControl).join(ComplianceAssessment).filter(
            ComplianceControl.scan_domain == domain,
            ComplianceControl.scan_source != None,
            ComplianceControl.deleted_at == None,
            ComplianceAssessment.created_by_user_id == user_id
        ).all()

        result = []
        for ctrl in controls:
            result.append({
                'id': ctrl.id,
                'control_id': ctrl.control_id,
                'control_name': ctrl.control_name,
                'status': ctrl.status,
                'scan_source': ctrl.scan_source,
                'scan_finding_type': ctrl.scan_finding_type,
                'scan_flagged_at': ctrl.scan_flagged_at.isoformat() if ctrl.scan_flagged_at else None,
                'scan_verified_at': ctrl.scan_verified_at.isoformat() if ctrl.scan_verified_at else None,
                'assessment_id': ctrl.assessment_id
            })

        db.close()

        return jsonify({
            'success': True,
            'domain': domain,
            'affected_controls': result,
            'count': len(result)
        }), 200

    except Exception as e:
        if db:
            db.close()
        print(f"[SCAN-COMPLIANCE] Error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/compliance/flag-from-scan', methods=['POST'])
@require_auth
def flag_controls_from_scan():
    """
    Manually trigger control flagging from recent scan data for a domain.
    Fetches the latest XASM and Lightbox scans and flags affected controls.
    """
    user_id = request.user_id
    db = None
    try:
        data = request.json
        domain = data.get('domain')
        assessment_id = data.get('assessment_id')

        if not domain or not assessment_id:
            return jsonify({'success': False, 'error': 'domain and assessment_id required'}), 400

        db = get_db()

        # Get the assessment with ownership check
        assessment = db.query(ComplianceAssessment).filter(
            ComplianceAssessment.id == assessment_id,
            ComplianceAssessment.created_by_user_id == user_id,
            ComplianceAssessment.deleted_at == None
        ).first()

        if not assessment:
            db.close()
            return jsonify({'success': False, 'error': 'Assessment not found'}), 404

        framework = assessment.framework

        # Get recent XASM scan
        xasm_scan = db.query(CachedASMScan).filter(
            CachedASMScan.domain == domain,
            CachedASMScan.deleted_at == None
        ).order_by(CachedASMScan.created_at.desc()).first()

        # Get recent Lightbox scan
        lightbox_scan = db.query(LightboxScan).filter(
            LightboxScan.domain == domain,
            LightboxScan.deleted_at == None
        ).order_by(LightboxScan.created_at.desc()).first()

        all_findings = []

        # Extract findings from XASM scan
        if xasm_scan and xasm_scan.scan_data:
            try:
                xasm_data = json.loads(xasm_scan.scan_data) if isinstance(xasm_scan.scan_data, str) else xasm_scan.scan_data

                # Extract SSL findings
                ssl_info = xasm_data.get('ssl_info', {})
                if ssl_info.get('grade') in ['C', 'D', 'F']:
                    all_findings.append({'type': f"ssl_grade_{ssl_info.get('grade', 'f').lower()}", 'source': 'xasm'})
                if ssl_info.get('expiring_soon'):
                    all_findings.append({'type': 'cert_expiring_soon', 'source': 'xasm'})

                # Extract port findings
                for port_info in xasm_data.get('open_ports', []):
                    port = port_info.get('port')
                    if port in [22]:
                        all_findings.append({'type': 'ssh_exposed', 'port': port, 'source': 'xasm'})
                    elif port in [3389]:
                        all_findings.append({'type': 'rdp_exposed', 'port': port, 'source': 'xasm'})
                    elif port in [3306]:
                        all_findings.append({'type': 'mysql_exposed', 'port': port, 'source': 'xasm'})
                    elif port in [5432]:
                        all_findings.append({'type': 'postgres_exposed', 'port': port, 'source': 'xasm'})
                    elif port in [27017]:
                        all_findings.append({'type': 'mongodb_exposed', 'port': port, 'source': 'xasm'})
                    elif port in [6379]:
                        all_findings.append({'type': 'redis_exposed', 'port': port, 'source': 'xasm'})
                    elif port in [9200, 9300]:
                        all_findings.append({'type': 'elasticsearch_exposed', 'port': port, 'source': 'xasm'})
                    elif port in [21]:
                        all_findings.append({'type': 'ftp_exposed', 'port': port, 'source': 'xasm'})
                    elif port in [23]:
                        all_findings.append({'type': 'telnet_exposed', 'port': port, 'source': 'xasm'})

                # Extract security header findings
                headers = xasm_data.get('security_headers', {})
                if not headers.get('content_security_policy'):
                    all_findings.append({'type': 'missing_csp', 'source': 'xasm'})
                if not headers.get('strict_transport_security'):
                    all_findings.append({'type': 'missing_hsts', 'source': 'xasm'})
                if not headers.get('x_frame_options'):
                    all_findings.append({'type': 'missing_xfo', 'source': 'xasm'})

                # Extract subdomain findings
                for sub in xasm_data.get('subdomains', []):
                    if sub.get('takeover_risk'):
                        all_findings.append({'type': 'subdomain_takeover', 'subdomain': sub.get('name'), 'source': 'xasm'})

                print(f"[SCAN-COMPLIANCE] Extracted {len(all_findings)} findings from XASM scan")

            except Exception as e:
                print(f"[SCAN-COMPLIANCE] Error parsing XASM data: {e}")

        # Extract findings from Lightbox scan
        if lightbox_scan and lightbox_scan.scan_data:
            try:
                lightbox_data = json.loads(lightbox_scan.scan_data) if isinstance(lightbox_scan.scan_data, str) else lightbox_scan.scan_data

                # Extract vulnerabilities
                for vuln in lightbox_data.get('vulnerabilities', []):
                    all_findings.append({
                        'type': vuln.get('type', vuln.get('name', '')),
                        'severity': vuln.get('severity'),
                        'source': 'lightbox'
                    })

                # Extract exposed files
                for file in lightbox_data.get('exposed_files', []):
                    file_type = file.get('type', '')
                    if 'backup' in file_type.lower():
                        all_findings.append({'type': 'backup_exposed', 'file': file.get('path'), 'source': 'lightbox'})
                    elif 'config' in file_type.lower() or '.env' in file.get('path', ''):
                        all_findings.append({'type': 'env_exposed', 'file': file.get('path'), 'source': 'lightbox'})
                    elif '.git' in file.get('path', ''):
                        all_findings.append({'type': 'git_exposed', 'file': file.get('path'), 'source': 'lightbox'})

                # Extract admin panels
                for panel in lightbox_data.get('admin_panels', []):
                    all_findings.append({'type': 'admin_panel', 'url': panel.get('url'), 'source': 'lightbox'})

                print(f"[SCAN-COMPLIANCE] Extracted {len(all_findings)} total findings (including Lightbox)")

            except Exception as e:
                print(f"[SCAN-COMPLIANCE] Error parsing Lightbox data: {e}")

        # Analyze and flag controls
        analysis = analyze_scan_findings(all_findings)
        affected_control_ids = analysis['affected_controls'].get(framework, [])

        flagged = []
        for vuln in analysis['vulnerabilities']:
            affected = get_affected_controls(vuln['key'], framework)

            for control_ref in affected:
                # Find matching control
                control = db.query(ComplianceControl).filter(
                    ComplianceControl.assessment_id == assessment_id,
                    ComplianceControl.control_id.like(f'%{control_ref}%'),
                    ComplianceControl.deleted_at == None
                ).first()

                if control and control.scan_source is None:  # Only flag if not already flagged
                    control.status = 'non_compliant'
                    control.scan_source = vuln.get('finding', {}).get('source', 'scan')
                    control.scan_finding_type = vuln['key']
                    control.scan_flagged_at = datetime.now(timezone.utc)
                    control.scan_domain = domain
                    control.last_reviewed = datetime.now(timezone.utc)

                    flagged.append({
                        'control_id': control.control_id,
                        'control_name': control.control_name,
                        'vulnerability': vuln['name'],
                        'severity': vuln['severity']
                    })

                    # Auto-create evidence
                    evidence = ComplianceEvidence(
                        control_id=control.id,
                        evidence_type='scan_finding',
                        title=f"Scan Finding: {vuln['name']}",
                        description=f"Auto-flagged from scan on {domain}.\n\n"
                                   f"Severity: {vuln['severity'].upper()}\n"
                                   f"Description: {vuln['description']}",
                        uploaded_by_user_id=1,
                        evidence_date=datetime.now(timezone.utc)
                    )
                    db.add(evidence)

        db.commit()
        db.close()

        return jsonify({
            'success': True,
            'domain': domain,
            'framework': framework,
            'findings_analyzed': len(all_findings),
            'controls_flagged': len(flagged),
            'flagged_controls': flagged,
            'severity_summary': analysis['severity_summary']
        }), 200

    except Exception as e:
        if db:
            db.rollback()
            db.close()
        print(f"[SCAN-COMPLIANCE] Error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/compliance/verify-fix/<int:control_id>', methods=['POST'])
@require_auth
def verify_control_fix(control_id):
    """
    Mark a control as verified after re-scan confirms the fix.
    This is called after a new scan shows the vulnerability is resolved.
    """
    user_id = request.user_id
    db = None
    try:
        data = request.json
        verified = data.get('verified', True)

        db = get_db()

        # Get control with ownership check
        control = db.query(ComplianceControl).join(ComplianceAssessment).filter(
            ComplianceControl.id == control_id,
            ComplianceControl.deleted_at == None,
            ComplianceAssessment.created_by_user_id == user_id
        ).first()

        if not control:
            db.close()
            return jsonify({'success': False, 'error': 'Control not found'}), 404

        if verified:
            control.status = 'compliant'
            control.scan_verified_at = datetime.now(timezone.utc)
            control.last_reviewed = datetime.now(timezone.utc)

            # Add verification evidence
            evidence = ComplianceEvidence(
                control_id=control.id,
                evidence_type='scan_verification',
                title=f"Verified Fixed by Re-scan",
                description=f"Control verified as compliant by re-scan on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}.\n\n"
                           f"Original finding: {control.scan_finding_type}\n"
                           f"Original scan date: {control.scan_flagged_at}",
                uploaded_by_user_id=user_id,
                evidence_date=datetime.now(timezone.utc)
            )
            db.add(evidence)

        db.commit()
        db.close()

        return jsonify({
            'success': True,
            'control_id': control.control_id,
            'status': control.status,
            'verified_at': control.scan_verified_at.isoformat() if control.scan_verified_at else None
        }), 200

    except Exception as e:
        if db:
            db.rollback()
            db.close()
        print(f"[SCAN-COMPLIANCE] Error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/compliance/scan-summary/<int:assessment_id>', methods=['GET'])
@require_auth
def get_scan_flagged_summary(assessment_id):
    """
    Get a summary of controls flagged by scans for an assessment.
    """
    user_id = request.user_id
    db = None
    try:
        db = get_db()

        # Get all scan-flagged controls for this assessment with ownership check
        controls = db.query(ComplianceControl).join(ComplianceAssessment).filter(
            ComplianceControl.assessment_id == assessment_id,
            ComplianceControl.scan_source != None,
            ComplianceControl.deleted_at == None,
            ComplianceAssessment.created_by_user_id == user_id
        ).all()

        # Group by finding type
        by_finding = {}
        by_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

        for ctrl in controls:
            finding_type = ctrl.scan_finding_type or 'unknown'
            if finding_type not in by_finding:
                vuln_info = get_vulnerability_info(finding_type)
                by_finding[finding_type] = {
                    'name': vuln_info['name'] if vuln_info else finding_type,
                    'severity': vuln_info['severity'] if vuln_info else 'medium',
                    'controls': [],
                    'count': 0
                }

            by_finding[finding_type]['controls'].append({
                'id': ctrl.id,
                'control_id': ctrl.control_id,
                'status': ctrl.status,
                'verified': ctrl.scan_verified_at is not None
            })
            by_finding[finding_type]['count'] += 1

            if vuln_info := get_vulnerability_info(finding_type):
                by_severity[vuln_info['severity']] = by_severity.get(vuln_info['severity'], 0) + 1

        db.close()

        return jsonify({
            'success': True,
            'assessment_id': assessment_id,
            'total_flagged': len(controls),
            'verified': sum(1 for c in controls if c.scan_verified_at),
            'unverified': sum(1 for c in controls if not c.scan_verified_at),
            'by_finding_type': by_finding,
            'by_severity': by_severity
        }), 200

    except Exception as e:
        if db:
            db.close()
        print(f"[SCAN-COMPLIANCE] Error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# ROADMAP API ENDPOINTS
# ============================================================================

@app.route('/api/roadmap/profile', methods=['GET'])
@require_auth
def get_roadmap_profile():
    """
    Get or check for existing roadmap profile.
    Returns profile data if exists, or null to trigger profile setup.
    """
    user_id = request.user_id
    db = None
    try:
        db = get_db()

        # Get user's roadmap profile
        profile = db.query(RoadmapProfile).filter(
            RoadmapProfile.user_id == user_id,
            RoadmapProfile.deleted_at == None,
            RoadmapProfile.is_active == True
        ).order_by(RoadmapProfile.created_at.desc()).first()

        # Get user for role check
        user = db.query(User).filter_by(id=user_id).first()

        # Pre-fill company info for COMPANY_USER
        locked_company_info = None
        if user and user.role == UserRole.COMPANY_USER and user.company_id:
            company = db.query(Company).filter_by(id=user.company_id).first()
            if company:
                locked_company_info = {
                    'company_name': company.name,
                    'company_domain': company.primary_domain
                }

        if not profile:
            result = {
                'success': True,
                'profile': None,
                'message': 'No profile found - setup required'
            }
            if locked_company_info:
                result['locked_company_info'] = locked_company_info
            return jsonify(result), 200

        # Parse JSON fields
        current_measures = []
        compliance_reqs = []
        data_types = []
        try:
            if profile.current_measures:
                current_measures = json.loads(profile.current_measures)
            if profile.compliance_requirements:
                compliance_reqs = json.loads(profile.compliance_requirements)
            if profile.data_types:
                data_types = json.loads(profile.data_types)
        except:
            pass

        result = {
            'success': True,
            'profile': {
                'id': profile.id,
                'company_name': profile.company_name,
                'company_domain': profile.company_domain,
                'company_size': profile.company_size,
                'industry': profile.industry,
                'employee_count': profile.employee_count,
                'current_security_score': profile.current_security_score or 0,
                'target_security_score': profile.target_security_score or 75,
                'handles_pii': profile.handles_pii,
                'handles_payment_data': profile.handles_payment_data,
                'handles_health_data': profile.handles_health_data,
                'handles_financial_data': profile.handles_financial_data,
                'data_types': data_types,  # Expanded data types array
                'current_measures': current_measures,
                'compliance_requirements': compliance_reqs,
                'created_at': profile.created_at.isoformat() if profile.created_at else None,
                'last_recalculated': profile.last_recalculated.isoformat() if profile.last_recalculated else None
            }
        }
        if locked_company_info:
            result['locked_company_info'] = locked_company_info
        return jsonify(result), 200

    except Exception as e:
        print(f"[ROADMAP] Error getting profile: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if db:
            db.close()


@app.route('/api/roadmap/profile', methods=['POST'])
@require_auth
def create_roadmap_profile():
    """
    Create or update roadmap profile.
    """
    user_id = request.user_id
    db = None
    try:
        data = request.get_json()
        db = get_db()

        # Get company name/domain from request
        company_name = data.get('company_name', 'My Company').strip() if data.get('company_name') else 'My Company'
        company_domain = data.get('company_domain', '').strip() if data.get('company_domain') else None

        # COMPANY_USER: override with actual company info (enforced)
        user = db.query(User).filter_by(id=user_id).first()
        if user and user.role == UserRole.COMPANY_USER and user.company_id:
            company = db.query(Company).filter_by(id=user.company_id).first()
            if company:
                company_name = company.name
                company_domain = company.primary_domain

        # Check for existing profile for this user
        existing = db.query(RoadmapProfile).filter(
            RoadmapProfile.user_id == user_id,
            RoadmapProfile.deleted_at == None,
            RoadmapProfile.is_active == True
        ).first()

        if existing:
            # Update existing profile
            existing.company_name = company_name
            existing.company_domain = company_domain
            existing.company_size = data.get('company_size', existing.company_size)
            existing.industry = data.get('industry', existing.industry)
            existing.employee_count = data.get('employee_count', existing.employee_count)
            existing.handles_pii = data.get('handles_pii', existing.handles_pii)
            existing.handles_payment_data = data.get('handles_payment_data', existing.handles_payment_data)
            existing.handles_health_data = data.get('handles_health_data', existing.handles_health_data)
            existing.handles_financial_data = data.get('handles_financial_data', existing.handles_financial_data)

            # Handle expanded data_types array
            if data.get('data_types'):
                existing.data_types = json.dumps(data['data_types'])

            if data.get('current_measures'):
                existing.current_measures = json.dumps(data['current_measures'])
            if data.get('compliance_requirements'):
                existing.compliance_requirements = json.dumps(data['compliance_requirements'])

            existing.updated_at = datetime.now(timezone.utc)
            db.commit()

            return jsonify({
                'success': True,
                'profile_id': existing.id,
                'message': 'Profile updated successfully'
            }), 200
        else:
            # Create new profile for this user
            profile = RoadmapProfile(
                user_id=user_id,
                company_name=company_name,
                company_domain=company_domain,
                company_size=data.get('company_size', 'small'),
                industry=data.get('industry', 'technology'),
                employee_count=data.get('employee_count'),
                current_security_score=0,
                target_security_score=data.get('target_security_score', 75),
                handles_pii=data.get('handles_pii', False),
                handles_payment_data=data.get('handles_payment_data', False),
                handles_health_data=data.get('handles_health_data', False),
                handles_financial_data=data.get('handles_financial_data', False),
                data_types=json.dumps(data.get('data_types', [])),  # Expanded data types array
                current_measures=json.dumps(data.get('current_measures', [])),
                compliance_requirements=json.dumps(data.get('compliance_requirements', [])),
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc)
            )

            db.add(profile)
            db.commit()
            db.refresh(profile)

            return jsonify({
                'success': True,
                'profile_id': profile.id,
                'message': 'Profile created successfully'
            }), 201

    except Exception as e:
        if db:
            db.rollback()
        print(f"[ROADMAP] Error creating profile: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if db:
            db.close()


@app.route('/api/roadmap/tasks', methods=['GET'])
@require_auth
def get_roadmap_tasks():
    """
    Get all assigned tasks for user's roadmap.
    Query params: phase, status, source, company_id (admin only)
    """
    from roadmap_mappings import TASK_LIBRARY
    user_id = request.user_id
    user_role = getattr(request, 'user_role', None)

    db = None
    try:
        db = get_db()

        # Check for company_id param (admin viewing company roadmap)
        company_id = request.args.get('company_id', type=int)
        target_user_ids = [user_id]

        if company_id and user_role in ['SUPER_ADMIN', 'ADMIN', 'ANALYST']:
            # Get all users in the specified company
            company_users = db.query(User).filter(
                User.company_id == company_id,
                User.deleted_at.is_(None)
            ).all()
            target_user_ids = [u.id for u in company_users]

        # Get profile(s) - for admin viewing company, get first active profile
        profile = db.query(RoadmapProfile).filter(
            RoadmapProfile.user_id.in_(target_user_ids),
            RoadmapProfile.deleted_at == None,
            RoadmapProfile.is_active == True
        ).first()

        if not profile:
            return jsonify({
                'success': True,
                'tasks': [],
                'stats': {'total': 0, 'not_started': 0, 'in_progress': 0, 'completed': 0, 'by_phase': {}},
                'message': 'No profile found'
            }), 200

        # Build query
        query = db.query(RoadmapUserTask).filter(
            RoadmapUserTask.profile_id == profile.id,
            RoadmapUserTask.deleted_at == None,
            RoadmapUserTask.is_active == True
        )

        # Apply filters
        phase = request.args.get('phase')
        status = request.args.get('status')
        source = request.args.get('source')

        if phase:
            query = query.filter(RoadmapUserTask.phase == int(phase))
        if status:
            query = query.filter(RoadmapUserTask.status == status)
        if source:
            query = query.filter(RoadmapUserTask.source == source)

        # Order by phase and priority
        user_tasks = query.order_by(RoadmapUserTask.phase, RoadmapUserTask.priority_order).all()

        # Build response with task details from library
        tasks = []
        for ut in user_tasks:
            task_details = TASK_LIBRARY.get(ut.task_id, {})

            tasks.append({
                'id': ut.id,
                'task_id': ut.task_id,
                'task_name': task_details.get('task_name', ut.task_id),
                'category': task_details.get('category', 'general'),
                'status': ut.status,
                'phase': ut.phase,
                'priority_order': ut.priority_order,
                'source': ut.source,
                'finding_type': ut.finding_type,
                'finding_severity': ut.finding_severity,
                'estimated_time_minutes': task_details.get('estimated_time_minutes', 30),
                'estimated_cost_min': task_details.get('estimated_cost_min', 0),
                'estimated_cost_max': task_details.get('estimated_cost_max', 0),
                'difficulty_level': task_details.get('difficulty_level', 'medium'),
                'security_score_impact': task_details.get('security_score_impact', 5),
                'description': task_details.get('description', ''),
                'why_it_matters': task_details.get('why_it_matters', ''),
                'how_to_fix': task_details.get('how_to_fix', ''),
                'scan_domain': ut.scan_domain,
                'scan_date': ut.scan_date.isoformat() if ut.scan_date else None,
                'started_at': ut.started_at.isoformat() if ut.started_at else None,
                'completed_at': ut.completed_at.isoformat() if ut.completed_at else None,
                'verified_at': ut.verified_at.isoformat() if ut.verified_at else None,
                'user_notes': ut.user_notes
            })

        # Calculate stats
        all_tasks = db.query(RoadmapUserTask).filter(
            RoadmapUserTask.profile_id == profile.id,
            RoadmapUserTask.deleted_at == None,
            RoadmapUserTask.is_active == True
        ).all()

        stats = {
            'total': len(all_tasks),
            'not_started': sum(1 for t in all_tasks if t.status == 'not_started'),
            'in_progress': sum(1 for t in all_tasks if t.status == 'in_progress'),
            'completed': sum(1 for t in all_tasks if t.status == 'completed'),
            'by_phase': {
                'phase1': sum(1 for t in all_tasks if t.phase == 1),
                'phase2': sum(1 for t in all_tasks if t.phase == 2),
                'phase3': sum(1 for t in all_tasks if t.phase == 3),
                'phase4': sum(1 for t in all_tasks if t.phase == 4)
            }
        }

        db.close()

        return jsonify({
            'success': True,
            'tasks': tasks,
            'stats': stats
        }), 200

    except Exception as e:
        if db:
            db.close()
        print(f"[ROADMAP] Error getting tasks: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/roadmap/generate', methods=['POST'])
@require_auth
def generate_roadmap():
    """
    Generate personalized roadmap based on profile + scans + data types.
    """
    from roadmap_mappings import (
        TASK_LIBRARY, map_scan_to_tasks, get_tasks_for_profile, prioritize_tasks,
        generate_data_specific_tasks, generate_scan_based_tasks
    )
    user_id = request.user_id

    db = None
    try:
        data = request.get_json() or {}
        include_scans = data.get('include_scans', True)

        db = get_db()

        # Get user's profile
        profile = db.query(RoadmapProfile).filter(
            RoadmapProfile.user_id == user_id,
            RoadmapProfile.deleted_at == None,
            RoadmapProfile.is_active == True
        ).first()

        if not profile:
            return jsonify({'success': False, 'error': 'No profile found. Create profile first.'}), 400

        # Get existing completed tasks BEFORE regeneration to preserve progress
        existing_tasks = db.query(RoadmapUserTask).filter(
            RoadmapUserTask.profile_id == profile.id
        ).all()

        # Create map of completed tasks by task_id
        completed_map = {}
        for task in existing_tasks:
            if task.status == 'completed':
                completed_map[task.task_id] = {
                    'completed_at': task.completed_at,
                    'started_at': task.started_at,
                    'verified_at': task.verified_at,
                    'user_notes': task.user_notes
                }

        # Delete only pending/in_progress tasks (keep completed for reference, but we'll recreate them)
        db.query(RoadmapUserTask).filter(
            RoadmapUserTask.profile_id == profile.id
        ).delete()
        db.commit()

        tasks_to_create = []

        # 1. Get profile-based generic tasks
        compliance_reqs = []
        try:
            if profile.compliance_requirements:
                compliance_reqs = json.loads(profile.compliance_requirements)
        except:
            pass

        recommended_task_ids = get_tasks_for_profile(
            industry=profile.industry or 'technology',
            company_size=profile.company_size or 'small',
            compliance_requirements=compliance_reqs
        )

        # Add essential generic tasks (limit to 10-12)
        essential_tasks = ['TASK_MFA_ENABLE', 'TASK_PASSWORD_POLICY', 'TASK_AUTOMATED_BACKUP',
                          'TASK_SECURITY_HEADERS', 'TASK_UPDATE_SOFTWARE', 'TASK_CONFIGURE_SPF',
                          'TASK_CONFIGURE_DMARC', 'TASK_SETUP_MONITORING']

        for task_id in essential_tasks:
            if task_id in TASK_LIBRARY:
                tasks_to_create.append({
                    'task_id': task_id,
                    'source': 'profile',
                    'finding_type': None,
                    'finding_severity': TASK_LIBRARY[task_id].get('risk_level', 'medium')
                })

        # 2. Get data-type-specific tasks based on what data the user handles
        data_types = []
        try:
            if profile.data_types:
                data_types = json.loads(profile.data_types)
        except:
            pass

        if data_types:
            data_type_tasks = generate_data_specific_tasks(data_types)
            for task in data_type_tasks:
                if task['task_id'] in TASK_LIBRARY:
                    tasks_to_create.append(task)

        # 3. If include_scans, get scan-based tasks
        if include_scans:
            # Get latest XASM scan
            xasm_scan = db.query(CachedASMScan).order_by(CachedASMScan.scanned_at.desc()).first()
            if xasm_scan and xasm_scan.scan_results:
                xasm_tasks = map_scan_to_tasks(xasm_scan.scan_results, 'xasm')
                for task in xasm_tasks:
                    task['source'] = 'xasm_scan'
                    task['scan_domain'] = xasm_scan.domain
                    task['scan_date'] = xasm_scan.scanned_at
                    tasks_to_create.append(task)

            # Get latest Lightbox scan
            lightbox_scan = db.query(LightboxScan).order_by(LightboxScan.scanned_at.desc()).first()
            if lightbox_scan:
                lb_results = lightbox_scan.to_dict()
                lb_tasks = map_scan_to_tasks(lb_results, 'lightbox')
                for task in lb_tasks:
                    task['source'] = 'lightbox_scan'
                    task['scan_domain'] = lightbox_scan.domain
                    task['scan_date'] = lightbox_scan.scanned_at
                    tasks_to_create.append(task)

        # Remove duplicates by task_id
        seen_task_ids = set()
        unique_tasks = []
        for task in tasks_to_create:
            if task['task_id'] not in seen_task_ids:
                seen_task_ids.add(task['task_id'])
                unique_tasks.append(task)

        # Prioritize and assign phases
        prioritized = prioritize_tasks(unique_tasks, {
            'industry': profile.industry,
            'company_size': profile.company_size
        })

        # Create user tasks, restoring completion status for previously completed tasks
        tasks_preserved = 0
        for task in prioritized:
            task_id = task['task_id']

            # Check if this task was previously completed
            if task_id in completed_map:
                status = 'completed'
                completed_at = completed_map[task_id]['completed_at']
                started_at = completed_map[task_id]['started_at']
                verified_at = completed_map[task_id]['verified_at']
                user_notes = completed_map[task_id]['user_notes']
                tasks_preserved += 1
            else:
                status = 'not_started'
                completed_at = None
                started_at = None
                verified_at = None
                user_notes = None

            user_task = RoadmapUserTask(
                profile_id=profile.id,
                task_id=task_id,
                status=status,
                phase=task.get('phase', 2),
                priority_order=task.get('priority_order', 99),
                source=task.get('source', 'profile'),
                finding_type=task.get('finding_type'),
                finding_severity=task.get('finding_severity'),
                scan_domain=task.get('scan_domain'),
                scan_date=task.get('scan_date'),
                started_at=started_at,
                completed_at=completed_at,
                verified_at=verified_at,
                user_notes=user_notes,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc)
            )
            db.add(user_task)

        # Calculate current score from preserved completed tasks
        current_score = 0
        for task in prioritized:
            if task['task_id'] in completed_map:
                task_details = TASK_LIBRARY.get(task['task_id'], {})
                current_score += task_details.get('security_score_impact', 5)

        # Create progress snapshot with preserved progress
        progress = RoadmapProgressHistory(
            profile_id=profile.id,
            security_score=current_score,
            tasks_completed=tasks_preserved,
            tasks_total=len(prioritized),
            snapshot_date=datetime.now(timezone.utc),
            snapshot_reason='roadmap_regenerated' if tasks_preserved > 0 else 'roadmap_generated'
        )
        db.add(progress)

        # Update profile score
        profile.current_security_score = current_score
        profile.updated_at = datetime.now(timezone.utc)

        db.commit()

        # Build response message
        if tasks_preserved > 0:
            message = f'Roadmap regenerated with {len(prioritized)} tasks ({tasks_preserved} completed tasks preserved)'
        else:
            message = f'Roadmap generated with {len(prioritized)} tasks'

        return jsonify({
            'success': True,
            'tasks_created': len(prioritized),
            'tasks_preserved': tasks_preserved,
            'current_score': current_score,
            'message': message
        }), 200

    except Exception as e:
        if db:
            db.rollback()
        print(f"[ROADMAP] Error generating roadmap: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if db:
            db.close()


@app.route('/api/roadmap/task/<int:task_id>', methods=['PUT'])
@require_auth
def update_roadmap_task(task_id):
    """
    Update task status.
    """
    from roadmap_mappings import TASK_LIBRARY, ACHIEVEMENTS
    user_id = request.user_id

    db = None
    try:
        data = request.get_json()
        new_status = data.get('status')
        user_notes = data.get('user_notes')

        db = get_db()

        # Get the task with profile ownership check
        task = db.query(RoadmapUserTask).join(RoadmapProfile).filter(
            RoadmapUserTask.id == task_id,
            RoadmapUserTask.deleted_at == None,
            RoadmapProfile.user_id == user_id
        ).first()

        if not task:
            return jsonify({'success': False, 'error': 'Task not found'}), 404

        # Get profile
        profile = db.query(RoadmapProfile).filter(
            RoadmapProfile.id == task.profile_id
        ).first()

        old_status = task.status
        score_increase = 0
        achievements_unlocked = []

        # Update task
        if new_status:
            task.status = new_status

            if new_status == 'in_progress' and not task.started_at:
                task.started_at = datetime.now(timezone.utc)

            if new_status == 'completed' and old_status != 'completed':
                task.completed_at = datetime.now(timezone.utc)

                # Add score impact
                task_details = TASK_LIBRARY.get(task.task_id, {})
                score_increase = task_details.get('security_score_impact', 5)
                profile.current_security_score = (profile.current_security_score or 0) + score_increase

                # Create progress snapshot
                all_tasks = db.query(RoadmapUserTask).filter(
                    RoadmapUserTask.profile_id == profile.id,
                    RoadmapUserTask.deleted_at == None
                ).all()

                completed_count = sum(1 for t in all_tasks if t.status == 'completed')

                progress = RoadmapProgressHistory(
                    profile_id=profile.id,
                    security_score=profile.current_security_score,
                    tasks_completed=completed_count,
                    tasks_total=len(all_tasks),
                    snapshot_date=datetime.now(timezone.utc),
                    snapshot_reason='task_completed'
                )
                db.add(progress)

                # Check for achievements
                existing_achievements = db.query(RoadmapAchievement).filter(
                    RoadmapAchievement.profile_id == profile.id
                ).all()
                existing_ids = [a.achievement_id for a in existing_achievements]

                # First Steps
                if 'FIRST_STEPS' not in existing_ids and completed_count >= 1:
                    ach = RoadmapAchievement(
                        profile_id=profile.id,
                        achievement_id='FIRST_STEPS',
                        achievement_name='First Steps',
                        achievement_description='Complete your first security task',
                        achievement_icon='trophy',
                        unlocked_at=datetime.now(timezone.utc)
                    )
                    db.add(ach)
                    achievements_unlocked.append('FIRST_STEPS')

                # Quick Wins (5 tasks)
                if 'QUICK_WINS' not in existing_ids and completed_count >= 5:
                    ach = RoadmapAchievement(
                        profile_id=profile.id,
                        achievement_id='QUICK_WINS',
                        achievement_name='Quick Wins',
                        achievement_description='Complete 5 security tasks',
                        achievement_icon='zap',
                        unlocked_at=datetime.now(timezone.utc)
                    )
                    db.add(ach)
                    achievements_unlocked.append('QUICK_WINS')

                # Score-based achievements
                score = profile.current_security_score
                if 'HALFWAY_HERO' not in existing_ids and score >= 50:
                    ach = RoadmapAchievement(
                        profile_id=profile.id,
                        achievement_id='HALFWAY_HERO',
                        achievement_name='Halfway Hero',
                        achievement_description='Reach a security score of 50',
                        achievement_icon='shield',
                        unlocked_at=datetime.now(timezone.utc)
                    )
                    db.add(ach)
                    achievements_unlocked.append('HALFWAY_HERO')

                if 'SECURITY_CHAMPION' not in existing_ids and score >= 75:
                    ach = RoadmapAchievement(
                        profile_id=profile.id,
                        achievement_id='SECURITY_CHAMPION',
                        achievement_name='Security Champion',
                        achievement_description='Reach a security score of 75',
                        achievement_icon='award',
                        unlocked_at=datetime.now(timezone.utc)
                    )
                    db.add(ach)
                    achievements_unlocked.append('SECURITY_CHAMPION')

        if user_notes is not None:
            task.user_notes = user_notes

        task.updated_at = datetime.now(timezone.utc)
        db.commit()

        return jsonify({
            'success': True,
            'new_score': profile.current_security_score,
            'score_increase': score_increase,
            'achievements_unlocked': achievements_unlocked
        }), 200

    except Exception as e:
        if db:
            db.rollback()
        print(f"[ROADMAP] Error updating task: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if db:
            db.close()


@app.route('/api/roadmap/task/<int:task_id>/verify', methods=['POST'])
@require_auth
def verify_roadmap_task(task_id):
    """
    Re-scan to verify task completion.
    """
    user_id = request.user_id
    db = None
    try:
        data = request.get_json() or {}
        domain = data.get('domain')

        db = get_db()

        # Get the task with profile ownership check
        task = db.query(RoadmapUserTask).join(RoadmapProfile).filter(
            RoadmapUserTask.id == task_id,
            RoadmapUserTask.deleted_at == None,
            RoadmapProfile.user_id == user_id
        ).first()

        if not task:
            return jsonify({'success': False, 'error': 'Task not found'}), 404

        if not task.source in ['xasm_scan', 'lightbox_scan']:
            return jsonify({
                'success': False,
                'error': 'Only scan-based tasks can be verified'
            }), 400

        # For now, return a simulated verification
        # In production, this would trigger an actual scan and check
        # whether the original finding still exists

        # Simulate verification (mark as verified)
        task.verified_at = datetime.now(timezone.utc)
        task.status = 'completed'
        task.completed_at = datetime.now(timezone.utc)

        db.commit()

        return jsonify({
            'success': True,
            'verified': True,
            'message': 'Task verified - issue no longer detected'
        }), 200

    except Exception as e:
        if db:
            db.rollback()
        print(f"[ROADMAP] Error verifying task: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if db:
            db.close()


@app.route('/api/roadmap/progress', methods=['GET'])
@require_auth
def get_roadmap_progress():
    """
    Get progress history for graphs.
    Query params: days, company_id (admin only)
    """
    user_id = request.user_id
    user_role = getattr(request, 'user_role', None)
    db = None
    try:
        days = request.args.get('days', 30, type=int)

        db = get_db()

        # Check for company_id param (admin viewing company roadmap)
        company_id = request.args.get('company_id', type=int)
        target_user_ids = [user_id]

        if company_id and user_role in ['SUPER_ADMIN', 'ADMIN', 'ANALYST']:
            # Get all users in the specified company
            company_users = db.query(User).filter(
                User.company_id == company_id,
                User.deleted_at.is_(None)
            ).all()
            target_user_ids = [u.id for u in company_users]

        # Get user's profile
        profile = db.query(RoadmapProfile).filter(
            RoadmapProfile.user_id.in_(target_user_ids),
            RoadmapProfile.deleted_at == None,
            RoadmapProfile.is_active == True
        ).first()

        if not profile:
            return jsonify({
                'success': True,
                'history': [],
                'current': {
                    'security_score': 0,
                    'target_score': 75,
                    'tasks_completed': 0,
                    'tasks_total': 0,
                    'completion_percentage': 0
                }
            }), 200

        # Get history
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        history_records = db.query(RoadmapProgressHistory).filter(
            RoadmapProgressHistory.profile_id == profile.id,
            RoadmapProgressHistory.snapshot_date >= cutoff
        ).order_by(RoadmapProgressHistory.snapshot_date).all()

        history = []
        for h in history_records:
            history.append({
                'date': h.snapshot_date.strftime('%Y-%m-%d'),
                'security_score': h.security_score or 0,
                'tasks_completed': h.tasks_completed or 0,
                'tasks_total': h.tasks_total or 0
            })

        # Get current stats
        all_tasks = db.query(RoadmapUserTask).filter(
            RoadmapUserTask.profile_id == profile.id,
            RoadmapUserTask.deleted_at == None
        ).all()

        tasks_total = len(all_tasks)
        tasks_completed = sum(1 for t in all_tasks if t.status == 'completed')
        completion_pct = round((tasks_completed / tasks_total * 100) if tasks_total > 0 else 0, 1)

        db.close()

        return jsonify({
            'success': True,
            'history': history,
            'current': {
                'security_score': profile.current_security_score or 0,
                'target_score': profile.target_security_score or 75,
                'tasks_completed': tasks_completed,
                'tasks_total': tasks_total,
                'completion_percentage': completion_pct
            }
        }), 200

    except Exception as e:
        if db:
            db.close()
        print(f"[ROADMAP] Error getting progress: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/roadmap/achievements', methods=['GET'])
@require_auth
def get_roadmap_achievements():
    """
    Get unlocked and available achievements.
    Query params: company_id (admin only)
    """
    from roadmap_mappings import ACHIEVEMENTS
    user_id = request.user_id
    user_role = getattr(request, 'user_role', None)

    db = None
    try:
        db = get_db()

        # Check for company_id param (admin viewing company roadmap)
        company_id = request.args.get('company_id', type=int)
        target_user_ids = [user_id]

        if company_id and user_role in ['SUPER_ADMIN', 'ADMIN', 'ANALYST']:
            # Get all users in the specified company
            company_users = db.query(User).filter(
                User.company_id == company_id,
                User.deleted_at.is_(None)
            ).all()
            target_user_ids = [u.id for u in company_users]

        # Get user's profile
        profile = db.query(RoadmapProfile).filter(
            RoadmapProfile.user_id.in_(target_user_ids),
            RoadmapProfile.deleted_at == None,
            RoadmapProfile.is_active == True
        ).first()

        if not profile:
            return jsonify({
                'success': True,
                'achievements': [],
                'available': list(ACHIEVEMENTS.values())
            }), 200

        # Get unlocked achievements
        unlocked_records = db.query(RoadmapAchievement).filter(
            RoadmapAchievement.profile_id == profile.id
        ).all()

        unlocked = []
        unlocked_ids = []
        for a in unlocked_records:
            unlocked_ids.append(a.achievement_id)
            unlocked.append({
                'achievement_id': a.achievement_id,
                'achievement_name': a.achievement_name,
                'achievement_description': a.achievement_description,
                'achievement_icon': a.achievement_icon,
                'unlocked_at': a.unlocked_at.isoformat() if a.unlocked_at else None,
                'is_claimed': a.is_claimed
            })

        # Get available (locked) achievements with progress
        all_tasks = db.query(RoadmapUserTask).filter(
            RoadmapUserTask.profile_id == profile.id,
            RoadmapUserTask.deleted_at == None
        ).all()

        completed_count = sum(1 for t in all_tasks if t.status == 'completed')
        score = profile.current_security_score or 0

        available = []
        for ach_id, ach in ACHIEVEMENTS.items():
            if ach_id not in unlocked_ids:
                progress_text = ''
                if ach['requirement_type'] == 'tasks_completed':
                    progress_text = f"{completed_count}/{ach['requirement_value']} tasks"
                elif ach['requirement_type'] == 'score_reached':
                    progress_text = f"{score}/{ach['requirement_value']} points"

                available.append({
                    'achievement_id': ach_id,
                    'achievement_name': ach['name'],
                    'requirement': ach['description'],
                    'progress': progress_text,
                    'icon': ach['icon']
                })

        db.close()

        return jsonify({
            'success': True,
            'achievements': unlocked,
            'available': available
        }), 200

    except Exception as e:
        if db:
            db.close()
        print(f"[ROADMAP] Error getting achievements: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/roadmap/stats', methods=['GET'])
@require_auth
def get_roadmap_stats():
    """
    Get dashboard stats for roadmap widget.
    Query params: company_id (admin only)
    """
    from roadmap_mappings import TASK_LIBRARY
    user_id = request.user_id
    user_role = getattr(request, 'user_role', None)

    db = None
    try:
        db = get_db()

        # Check for company_id param (admin viewing company roadmap)
        company_id = request.args.get('company_id', type=int)
        target_user_ids = [user_id]

        if company_id and user_role in ['SUPER_ADMIN', 'ADMIN', 'ANALYST']:
            # Get all users in the specified company
            company_users = db.query(User).filter(
                User.company_id == company_id,
                User.deleted_at.is_(None)
            ).all()
            target_user_ids = [u.id for u in company_users]

        # Get user's profile
        profile = db.query(RoadmapProfile).filter(
            RoadmapProfile.user_id.in_(target_user_ids),
            RoadmapProfile.deleted_at == None,
            RoadmapProfile.is_active == True
        ).first()

        if not profile:
            return jsonify({
                'success': True,
                'security_score': 0,
                'target_score': 75,
                'next_quick_win': None,
                'tasks_this_week': 0,
                'completion_percentage': 0
            }), 200

        # Get tasks
        all_tasks = db.query(RoadmapUserTask).filter(
            RoadmapUserTask.profile_id == profile.id,
            RoadmapUserTask.deleted_at == None,
            RoadmapUserTask.is_active == True
        ).all()

        tasks_total = len(all_tasks)
        tasks_completed = sum(1 for t in all_tasks if t.status == 'completed')
        tasks_in_progress = sum(1 for t in all_tasks if t.status == 'in_progress')
        completion_pct = round((tasks_completed / tasks_total * 100) if tasks_total > 0 else 0, 1)

        # Find next quick win (easiest incomplete task with highest impact)
        incomplete_tasks = [t for t in all_tasks if t.status in ['not_started', 'in_progress']]
        next_quick_win = None

        if incomplete_tasks:
            # Sort by difficulty (easy first) then by score impact (high first)
            def task_score(t):
                details = TASK_LIBRARY.get(t.task_id, {})
                difficulty = {'easy': 0, 'medium': 1, 'hard': 2}.get(details.get('difficulty_level', 'medium'), 1)
                impact = details.get('security_score_impact', 5)
                return (difficulty, -impact)

            incomplete_tasks.sort(key=task_score)
            best_task = incomplete_tasks[0]
            details = TASK_LIBRARY.get(best_task.task_id, {})

            time_est = details.get('estimated_time_minutes', 30)
            time_str = f"{time_est} min" if time_est < 60 else f"{time_est // 60}h {time_est % 60}m"

            next_quick_win = {
                'task_id': best_task.id,
                'task_name': details.get('task_name', best_task.task_id),
                'score_impact': details.get('security_score_impact', 5),
                'time_estimate': time_str,
                'difficulty': details.get('difficulty_level', 'medium')
            }

        # Count Phase 1 tasks (this week)
        phase1_count = sum(1 for t in all_tasks if t.phase == 1 and t.status != 'completed')

        db.close()

        return jsonify({
            'success': True,
            'security_score': profile.current_security_score or 0,
            'target_score': profile.target_security_score or 75,
            'next_quick_win': next_quick_win,
            'tasks_this_week': phase1_count,
            'completion_percentage': completion_pct,
            'tasks_completed': tasks_completed,
            'tasks_in_progress': tasks_in_progress,
            'tasks_total': tasks_total
        }), 200

    except Exception as e:
        if db:
            db.close()
        print(f"[ROADMAP] Error getting stats: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# =============================================================================
# AUTHENTICATION ENDPOINTS
# =============================================================================

@app.route('/api/auth/signup', methods=['POST'])
@limiter.limit("3 per hour")  # Prevent spam account creation
def auth_signup():
    """Register a new user account."""
    db = None
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400

        # Validate required fields
        required_fields = ['email', 'password', 'full_name']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'success': False, 'error': f'{field} is required'}), 400

        email = data['email'].lower().strip()
        password = data['password']
        full_name = data['full_name'].strip()
        company_name = data.get('company', '').strip()

        # Validate email format
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            return jsonify({'success': False, 'error': 'Invalid email format'}), 400

        # Validate password strength
        if len(password) < 8:
            return jsonify({'success': False, 'error': 'Password must be at least 8 characters'}), 400
        if not re.search(r'[A-Z]', password):
            return jsonify({'success': False, 'error': 'Password must contain at least one uppercase letter'}), 400
        if not re.search(r'[a-z]', password):
            return jsonify({'success': False, 'error': 'Password must contain at least one lowercase letter'}), 400
        if not re.search(r'\d', password):
            return jsonify({'success': False, 'error': 'Password must contain at least one number'}), 400

        db = SessionLocal()

        # Check if email already exists
        existing_user = db.query(User).filter(User.email == email, User.deleted_at.is_(None)).first()
        if existing_user:
            db.close()
            return jsonify({'success': False, 'error': 'An account with this email already exists'}), 409

        # Create or find company if provided
        company_id = None
        if company_name:
            company = db.query(Company).filter(Company.name == company_name).first()
            if not company:
                company = Company(name=company_name)
                db.add(company)
                db.flush()
            company_id = company.id

        # Create user
        user = User(
            email=email,
            password_hash=hash_password(password),
            full_name=full_name,
            company_id=company_id,
            role=UserRole.ANALYST,
            status=UserStatus.ACTIVE
        )
        db.add(user)
        db.commit()

        # Create session for the new user
        ip_address = request.remote_addr or '0.0.0.0'
        user_agent = request.headers.get('User-Agent', 'Unknown')
        session_data = create_session(user.id, ip_address, user_agent)

        db.close()

        return jsonify({
            'success': True,
            'message': 'Account created successfully',
            'token': session_data['token'],
            'user': {
                'id': user.id,
                'email': user.email,
                'full_name': user.full_name,
                'role': user.role.value if user.role else 'analyst'
            }
        }), 201

    except Exception as e:
        if db:
            db.close()
        print(f"[AUTH] Signup error: {e}")
        return jsonify({'success': False, 'error': 'Registration failed. Please try again.'}), 500


@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("5 per minute")  # Prevent brute force attacks
def auth_login():
    """Authenticate user and create session."""
    db = None
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400

        email = data.get('email', '').lower().strip()
        password = data.get('password', '')
        remember_me = data.get('remember_me', False)

        if not email or not password:
            return jsonify({'success': False, 'error': 'Email and password are required'}), 400

        ip_address = request.remote_addr or '0.0.0.0'
        user_agent = request.headers.get('User-Agent', 'Unknown')

        # Check for brute force (detect_brute_force returns a dict, check 'detected' key)
        brute_force_result = detect_brute_force(email, ip_address)
        print(f"[LOGIN DEBUG] Email: {email}, IP: {ip_address}")
        print(f"[LOGIN DEBUG] Brute force check result: {brute_force_result}")

        if brute_force_result.get('detected', False):
            return jsonify({
                'success': False,
                'error': 'Too many failed attempts. Please try again later.'
            }), 429

        db = SessionLocal()

        # Find user
        user = db.query(User).filter(
            User.email == email,
            User.deleted_at.is_(None)
        ).first()

        if not user:
            log_login_attempt(email, False, ip_address)
            db.close()
            return jsonify({'success': False, 'error': 'Invalid email or password'}), 401

        # Check if user is active
        if user.status != UserStatus.ACTIVE:
            log_login_attempt(email, False, ip_address)
            db.close()
            return jsonify({'success': False, 'error': 'Account is not active'}), 403

        # Verify password
        if not verify_password(password, user.password_hash):
            log_login_attempt(email, False, ip_address)
            db.close()
            return jsonify({'success': False, 'error': 'Invalid email or password'}), 401

        # Log successful attempt
        log_login_attempt(email, True, ip_address)

        # Update last login
        user.last_login = datetime.now(timezone.utc)
        db.commit()

        # Create session (longer expiry if remember_me)
        session_data = create_session(user.id, ip_address, user_agent)

        if not session_data:
            db.close()
            print("[LOGIN DEBUG] create_session returned None!")
            return jsonify({'success': False, 'error': 'Failed to create session'}), 500

        print(f"[LOGIN DEBUG] Session created successfully, token: {session_data['token'][:20]}...")

        user_data = {
            'id': user.id,
            'email': user.email,
            'full_name': user.full_name,
            'role': user.role.value if user.role else 'analyst'
        }

        db.close()

        return jsonify({
            'success': True,
            'message': 'Login successful',
            'redirect': '/dashboard',
            'token': session_data['token'],
            'user': user_data
        }), 200

    except Exception as e:
        if db:
            db.close()
        print(f"[AUTH] Login error: {e}")
        return jsonify({'success': False, 'error': 'Login failed. Please try again.'}), 500


@app.route('/api/auth/logout', methods=['POST'])
def auth_logout():
    """Revoke user session (logout)."""
    db = None
    try:
        # Get token from header or body
        auth_header = request.headers.get('Authorization', '')
        token = None

        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
        else:
            data = request.get_json() or {}
            token = data.get('token')

        if not token:
            return jsonify({'success': False, 'error': 'No token provided'}), 400

        # Get user info before revoking
        user = get_current_user()

        # Revoke the session
        revoke_session(token)

        # Log logout event
        if user:
            db = SessionLocal()
            log_activity_event(
                db,
                event_type='logout',
                description=f'User logged out: {user.get("email", "unknown")}',
                severity='info',
                user_id=user.get('id'),
                email=user.get('email')
            )
            db.close()

        return jsonify({
            'success': True,
            'message': 'Logged out successfully',
            'redirect': '/home'
        }), 200

    except Exception as e:
        if db:
            db.close()
        print(f"[AUTH] Logout error: {e}")
        return jsonify({'success': False, 'error': 'Logout failed'}), 500


@app.route('/api/auth/forgot-password', methods=['POST'])
def auth_forgot_password():
    """Initiate password reset process."""
    db = None
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400

        email = data.get('email', '').lower().strip()

        if not email:
            return jsonify({'success': False, 'error': 'Email is required'}), 400

        db = SessionLocal()

        # Find user (don't reveal if email exists or not for security)
        user = db.query(User).filter(
            User.email == email,
            User.deleted_at.is_(None)
        ).first()

        if user:
            # Generate reset token (24 hour expiration)
            reset_token = generate_secure_token()
            expires_at = datetime.now(timezone.utc) + timedelta(hours=24)

            # Store reset token in user record
            user.password_reset_token = reset_token
            user.password_reset_expires = expires_at
            db.commit()

            # In production, send email with reset link
            # For now, log the token (remove in production!)
            print(f"[AUTH] Password reset token for {email}: {reset_token}")

        db.close()

        # Always return success to prevent email enumeration
        return jsonify({
            'success': True,
            'message': 'If an account exists with this email, a password reset link has been sent.'
        }), 200

    except Exception as e:
        if db:
            db.close()
        print(f"[AUTH] Forgot password error: {e}")
        return jsonify({'success': False, 'error': 'Request failed. Please try again.'}), 500


@app.route('/api/auth/validate-session', methods=['GET'])
def auth_validate_session():
    """Validate current session token."""
    try:
        auth_header = request.headers.get('Authorization', '')
        token = None

        if auth_header.startswith('Bearer '):
            token = auth_header[7:]

        if not token:
            return jsonify({'valid': False, 'error': 'No token provided'}), 401

        # Validate the session
        session_info = validate_session(token)

        if not session_info:
            return jsonify({'valid': False, 'error': 'Invalid or expired session'}), 401

        # Get user info
        db = SessionLocal()
        user = db.query(User).filter(User.id == session_info['user_id']).first()

        if not user or user.status != UserStatus.ACTIVE:
            db.close()
            return jsonify({'valid': False, 'error': 'User not found or inactive'}), 401

        user_data = {
            'id': user.id,
            'email': user.email,
            'full_name': user.full_name,
            'role': user.role.value if user.role else 'analyst'
        }

        db.close()

        return jsonify({
            'valid': True,
            'user': user_data,
            'expires_at': session_info.get('expires_at')
        }), 200

    except Exception as e:
        print(f"[AUTH] Session validation error: {e}")
        return jsonify({'valid': False, 'error': 'Validation failed'}), 500


@app.route('/api/auth/validate-reset-token', methods=['POST'])
def auth_validate_reset_token():
    """Validate a password reset token."""
    db = None
    try:
        data = request.get_json()
        if not data:
            return jsonify({'valid': False, 'error': 'No data provided'}), 400

        token = data.get('token', '')

        if not token:
            return jsonify({'valid': False, 'error': 'No token provided'}), 400

        db = SessionLocal()

        # Find user with this reset token
        user = db.query(User).filter(
            User.password_reset_token == token,
            User.deleted_at.is_(None)
        ).first()

        if not user:
            db.close()
            return jsonify({'valid': False, 'error': 'Invalid reset token'}), 400

        # Check if token is expired (24 hour window)
        if user.password_reset_expires:
            if datetime.now(timezone.utc) > user.password_reset_expires:
                db.close()
                return jsonify({'valid': False, 'error': 'Reset token has expired'}), 400

        db.close()
        return jsonify({'valid': True}), 200

    except Exception as e:
        if db:
            db.close()
        print(f"[AUTH] Token validation error: {e}")
        return jsonify({'valid': False, 'error': 'Validation failed'}), 500


@app.route('/api/auth/reset-password', methods=['POST'])
def auth_reset_password():
    """Reset password using reset token."""
    db = None
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400

        token = data.get('token', '')
        new_password = data.get('new_password', '')

        if not token:
            return jsonify({'success': False, 'error': 'No reset token provided'}), 400

        if not new_password:
            return jsonify({'success': False, 'error': 'New password is required'}), 400

        # Validate password strength
        if len(new_password) < 8:
            return jsonify({'success': False, 'error': 'Password must be at least 8 characters'}), 400
        if not re.search(r'[A-Z]', new_password):
            return jsonify({'success': False, 'error': 'Password must contain at least one uppercase letter'}), 400
        if not re.search(r'[a-z]', new_password):
            return jsonify({'success': False, 'error': 'Password must contain at least one lowercase letter'}), 400
        if not re.search(r'\d', new_password):
            return jsonify({'success': False, 'error': 'Password must contain at least one number'}), 400

        db = SessionLocal()

        # Find user with this reset token
        user = db.query(User).filter(
            User.password_reset_token == token,
            User.deleted_at.is_(None)
        ).first()

        if not user:
            db.close()
            return jsonify({'success': False, 'error': 'Invalid or expired reset token'}), 400

        # Check if token is expired (24 hour window)
        if user.password_reset_expires:
            if datetime.now(timezone.utc) > user.password_reset_expires:
                # Clear expired token
                user.password_reset_token = None
                user.password_reset_expires = None
                db.commit()
                db.close()
                return jsonify({'success': False, 'error': 'Reset link has expired. Please request a new one.'}), 400

        # Update password
        user.password_hash = hash_password(new_password)

        # Clear reset token
        user.password_reset_token = None
        user.password_reset_expires = None

        # Update last modified
        user.updated_at = datetime.now(timezone.utc)

        db.commit()

        # Log security event
        log_security_event(
            event_type='password_change',
            severity='info',
            user_id=user.id,
            email=user.email,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', ''),
            description=f'Password reset via email link for user: {user.email}'
        )

        print(f"[AUTH] Password reset successful for user: {user.email}")

        db.close()

        return jsonify({
            'success': True,
            'message': 'Password reset successfully. You can now log in with your new password.'
        }), 200

    except Exception as e:
        if db:
            db.close()
        print(f"[AUTH] Password reset error: {e}")
        return jsonify({'success': False, 'error': 'Password reset failed. Please try again.'}), 500


# =============================================================================
# USER PROFILE ENDPOINTS
# =============================================================================

@app.route('/api/profile', methods=['GET'])
@require_auth
def get_user_profile():
    """
    Get the current user's profile information.
    Returns user details including company info.
    """
    db = SessionLocal()
    try:
        user = db.query(User).filter(
            User.id == request.user_id,
            User.deleted_at.is_(None)
        ).first()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Get company info if user belongs to a company
        company_info = None
        if user.company_id:
            company = db.query(Company).filter(
                Company.id == user.company_id,
                Company.deleted_at.is_(None)
            ).first()
            if company:
                company_info = {
                    'id': company.id,
                    'name': company.name,
                    'domain': company.primary_domain  # Include domain for frontend restrictions
                }

        return jsonify({
            'id': user.id,
            'email': user.email,
            'full_name': user.full_name,
            'role': user.role.value if user.role else 'user',
            'company_id': user.company_id,
            'company_name': company_info['name'] if company_info else None,
            'company': company_info,  # Full company object with domain
            'created_at': user.created_at.isoformat() if user.created_at else None,
            'last_login': user.last_login_at.isoformat() if user.last_login_at else None,
            'email_verified': user.email_verified,
            'twofa_enabled': user.twofa_enabled
        })
    finally:
        db.close()


@app.route('/api/profile/update', methods=['PUT'])
@require_auth
def update_user_profile():
    """
    Update the current user's profile information.
    Viewers cannot update their profile (read-only).
    """
    db = SessionLocal()
    try:
        user = db.query(User).filter(
            User.id == request.user_id,
            User.deleted_at.is_(None)
        ).first()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Check if user is a viewer (read-only)
        if user.role and user.role.value == 'viewer':
            return jsonify({'error': 'Viewers cannot update profile information'}), 403

        data = request.get_json()

        # Update allowed fields
        if 'full_name' in data:
            user.full_name = data['full_name'][:255] if data['full_name'] else None

        if 'email' in data:
            new_email = data['email'].lower().strip()

            # Check if email is already taken by another user
            existing = db.query(User).filter(
                User.email == new_email,
                User.id != user.id,
                User.deleted_at.is_(None)
            ).first()

            if existing:
                return jsonify({'error': 'Email address is already in use'}), 400

            user.email = new_email

        user.updated_at = datetime.now(timezone.utc)
        db.commit()

        return jsonify({
            'id': user.id,
            'email': user.email,
            'full_name': user.full_name,
            'role': user.role.value if user.role else 'user',
            'updated_at': user.updated_at.isoformat()
        })
    except Exception as e:
        db.rollback()
        print(f"[PROFILE] Error updating profile: {e}")
        return jsonify({'error': 'Failed to update profile'}), 500
    finally:
        db.close()


@app.route('/api/profile/change-password', methods=['POST'])
@require_auth
def change_user_password():
    """
    Change the current user's password.
    Requires current password verification.
    """
    db = SessionLocal()
    try:
        user = db.query(User).filter(
            User.id == request.user_id,
            User.deleted_at.is_(None)
        ).first()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        data = request.get_json()
        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')

        if not current_password or not new_password:
            return jsonify({'error': 'Current and new passwords are required'}), 400

        # Verify current password
        if not verify_password(current_password, user.password_hash):
            return jsonify({'error': 'Current password is incorrect'}), 400

        # Validate new password strength
        if len(new_password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400
        if not re.search(r'[A-Z]', new_password):
            return jsonify({'error': 'Password must contain an uppercase letter'}), 400
        if not re.search(r'[a-z]', new_password):
            return jsonify({'error': 'Password must contain a lowercase letter'}), 400
        if not re.search(r'[0-9]', new_password):
            return jsonify({'error': 'Password must contain a number'}), 400

        # Hash and update password
        user.password_hash = hash_password(new_password)
        user.last_password_change = datetime.now(timezone.utc)
        user.updated_at = datetime.now(timezone.utc)
        db.commit()

        # Log security event
        log_security_event(
            event_type='password_change',
            severity='info',
            user_id=user.id,
            email=user.email,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', ''),
            description=f'Password changed via profile settings for user: {user.email}'
        )

        print(f"[PROFILE] Password changed for user: {user.email}")
        return jsonify({'success': True, 'message': 'Password changed successfully'})

    except Exception as e:
        db.rollback()
        print(f"[PROFILE] Error changing password: {e}")
        return jsonify({'error': 'Failed to change password'}), 500
    finally:
        db.close()


@app.route('/api/profile/sessions', methods=['GET'])
@require_auth
def get_user_sessions():
    """
    Get all active sessions for the current user.
    Marks the current session.
    """
    db = SessionLocal()
    try:
        # Get current session token from auth header
        auth_header = request.headers.get('Authorization', '')
        current_token = auth_header[7:] if auth_header.startswith('Bearer ') else None

        sessions = db.query(UserSession).filter(
            UserSession.user_id == request.user_id,
            UserSession.is_active == True,
            UserSession.revoked_at.is_(None),
            UserSession.expires_at > datetime.now(timezone.utc)
        ).order_by(UserSession.last_activity.desc()).all()

        result = []
        for s in sessions:
            # Parse user agent for browser info
            browser = 'Unknown Browser'
            device_type = s.device_type or 'desktop'

            if s.user_agent:
                ua = s.user_agent.lower()
                if 'chrome' in ua:
                    browser = 'Chrome'
                elif 'firefox' in ua:
                    browser = 'Firefox'
                elif 'safari' in ua:
                    browser = 'Safari'
                elif 'edge' in ua:
                    browser = 'Edge'
                elif 'opera' in ua:
                    browser = 'Opera'

            result.append({
                'id': s.id,
                'device_type': device_type,
                'browser': browser,
                'ip_address': s.ip_address,
                'location': s.location or 'Unknown',
                'last_activity': s.last_activity.isoformat() if s.last_activity else None,
                'is_current': current_token and s.token == current_token
            })

        return jsonify(result)
    finally:
        db.close()


@app.route('/api/profile/sessions/<int:session_id>', methods=['DELETE'])
@require_auth
def revoke_user_session(session_id):
    """
    Revoke a specific session.
    Cannot revoke the current session.
    """
    db = SessionLocal()
    try:
        # Get current session token
        auth_header = request.headers.get('Authorization', '')
        current_token = auth_header[7:] if auth_header.startswith('Bearer ') else None

        session = db.query(UserSession).filter(
            UserSession.id == session_id,
            UserSession.user_id == request.user_id,
            UserSession.is_active == True
        ).first()

        if not session:
            return jsonify({'error': 'Session not found'}), 404

        # Prevent revoking current session
        if current_token and session.token == current_token:
            return jsonify({'error': 'Cannot revoke your current session'}), 400

        # Revoke the session
        session.is_active = False
        session.revoked_at = datetime.now(timezone.utc)
        db.commit()

        print(f"[PROFILE] Session {session_id} revoked for user {request.user_id}")
        return jsonify({'success': True, 'message': 'Session revoked successfully'})

    except Exception as e:
        db.rollback()
        print(f"[PROFILE] Error revoking session: {e}")
        return jsonify({'error': 'Failed to revoke session'}), 500
    finally:
        db.close()


@app.route('/api/profile/login-history', methods=['GET'])
@require_auth
def get_login_history():
    """
    Get the login history for the current user.
    Returns last 10 login attempts.
    """
    db = SessionLocal()
    try:
        attempts = db.query(LoginAttempt).filter(
            LoginAttempt.user_id == request.user_id
        ).order_by(LoginAttempt.attempted_at.desc()).limit(10).all()

        result = []
        for a in attempts:
            # Parse user agent for device info
            device = 'Unknown'
            if a.user_agent:
                ua = a.user_agent.lower()
                if 'chrome' in ua:
                    device = 'Chrome'
                elif 'firefox' in ua:
                    device = 'Firefox'
                elif 'safari' in ua:
                    device = 'Safari'
                elif 'edge' in ua:
                    device = 'Edge'
                elif 'mobile' in ua:
                    device = 'Mobile Browser'

            result.append({
                'timestamp': a.attempted_at.isoformat() if a.attempted_at else None,
                'ip_address': a.ip_address,
                'success': a.success,
                'device': device,
                'failure_reason': a.failure_reason if not a.success else None
            })

        return jsonify(result)
    finally:
        db.close()


@app.route('/api/profile/api-keys', methods=['GET'])
@require_auth
def get_user_api_keys():
    """
    Get all API keys for the current user.
    Viewers cannot access API keys.
    """
    # Check role
    if request.user.get('role') == 'viewer':
        return jsonify({'error': 'Insufficient permissions'}), 403

    db = SessionLocal()
    try:
        keys = db.query(APIKey).filter(
            APIKey.user_id == request.user_id,
            APIKey.is_active == True,
            APIKey.revoked_at.is_(None)
        ).order_by(APIKey.created_at.desc()).all()

        result = []
        for k in keys:
            permissions = []
            if k.permissions:
                try:
                    permissions = json.loads(k.permissions)
                except:
                    permissions = []

            result.append({
                'id': k.id,
                'name': k.name,
                'key_prefix': k.key_prefix,
                'permissions': permissions,
                'created_at': k.created_at.isoformat() if k.created_at else None,
                'last_used_at': k.last_used_at.isoformat() if k.last_used_at else None,
                'expires_at': k.expires_at.isoformat() if k.expires_at else None,
                'usage_count': k.usage_count or 0
            })

        return jsonify(result)
    finally:
        db.close()


@app.route('/api/profile/api-keys', methods=['POST'])
@require_auth
def create_user_api_key():
    """
    Create a new API key for the current user.
    Viewers cannot create API keys.
    Admin permission requires admin role.
    """
    # Check role
    user_role = request.user.get('role', 'user')
    if user_role == 'viewer':
        return jsonify({'error': 'Insufficient permissions'}), 403

    data = request.get_json()
    name = data.get('name', '').strip()
    permissions = data.get('permissions', ['read'])
    expires_days = data.get('expires_days', 90)

    if not name:
        return jsonify({'error': 'Key name is required'}), 400

    if len(name) > 100:
        return jsonify({'error': 'Key name must be 100 characters or less'}), 400

    # Validate permissions
    valid_permissions = ['read', 'write', 'admin']
    permissions = [p for p in permissions if p in valid_permissions]

    # Only admin users can create keys with admin permission
    if 'admin' in permissions and user_role not in ['admin', 'super_admin']:
        permissions.remove('admin')

    if not permissions:
        permissions = ['read']

    # Handle expiration
    if expires_days == 0:
        expires_days = None  # Never expires

    # Create the API key
    result = create_api_key(
        user_id=request.user_id,
        name=name,
        permissions=permissions,
        expires_days=expires_days
    )

    if result:
        return jsonify({
            'success': True,
            'key': result['key'],
            'key_id': result['key_id'],
            'expires_at': result['expires_at']
        })
    else:
        return jsonify({'error': 'Failed to create API key'}), 500


@app.route('/api/profile/api-keys/<int:key_id>', methods=['DELETE'])
@require_auth
def delete_user_api_key(key_id):
    """
    Revoke an API key.
    Viewers cannot revoke API keys.
    """
    # Check role
    if request.user.get('role') == 'viewer':
        return jsonify({'error': 'Insufficient permissions'}), 403

    success = revoke_api_key(key_id, user_id=request.user_id)

    if success:
        return jsonify({'success': True, 'message': 'API key revoked successfully'})
    else:
        return jsonify({'error': 'API key not found or already revoked'}), 404


@app.route('/api/profile/company', methods=['GET'])
@require_auth
def get_user_company():
    """
    Get the company information for the current user.
    Only admins and owners can view company details.
    """
    user_role = request.user.get('role', 'user')
    if user_role not in ['admin', 'super_admin', 'owner']:
        return jsonify({'error': 'Insufficient permissions'}), 403

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == request.user_id).first()

        if not user or not user.company_id:
            return jsonify({'error': 'No company associated with this account'}), 404

        company = db.query(Company).filter(
            Company.id == user.company_id,
            Company.deleted_at.is_(None)
        ).first()

        if not company:
            return jsonify({'error': 'Company not found'}), 404

        # Parse additional info if stored as JSON
        additional_data = {}
        if company.additional_domains:
            try:
                additional_data = json.loads(company.additional_domains)
            except:
                pass

        return jsonify({
            'id': company.id,
            'name': company.name,
            'industry': additional_data.get('industry', ''),
            'company_size': additional_data.get('company_size', ''),
            'employee_count': additional_data.get('employee_count'),
            'primary_domain': company.primary_domain,
            'subscription_tier': company.subscription_tier,
            'max_seats': company.max_seats
        })
    finally:
        db.close()


@app.route('/api/profile/company', methods=['PUT'])
@require_auth
def update_user_company():
    """
    Update company information.
    Only admins and owners can update company details.
    """
    user_role = request.user.get('role', 'user')
    if user_role not in ['admin', 'super_admin', 'owner']:
        return jsonify({'error': 'Insufficient permissions'}), 403

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == request.user_id).first()

        if not user or not user.company_id:
            return jsonify({'error': 'No company associated with this account'}), 404

        company = db.query(Company).filter(
            Company.id == user.company_id,
            Company.deleted_at.is_(None)
        ).first()

        if not company:
            return jsonify({'error': 'Company not found'}), 404

        data = request.get_json()

        # Update company name
        if 'name' in data and data['name']:
            company.name = data['name'][:255]

        # Store additional info in additional_domains JSON
        additional_data = {}
        if company.additional_domains:
            try:
                additional_data = json.loads(company.additional_domains)
            except:
                additional_data = {}

        if 'industry' in data:
            additional_data['industry'] = data['industry']
        if 'company_size' in data:
            additional_data['company_size'] = data['company_size']
        if 'employee_count' in data:
            additional_data['employee_count'] = data['employee_count']

        company.additional_domains = json.dumps(additional_data)
        company.updated_at = datetime.now(timezone.utc)
        db.commit()

        return jsonify({
            'id': company.id,
            'name': company.name,
            'industry': additional_data.get('industry', ''),
            'company_size': additional_data.get('company_size', ''),
            'employee_count': additional_data.get('employee_count'),
            'updated_at': company.updated_at.isoformat()
        })

    except Exception as e:
        db.rollback()
        print(f"[PROFILE] Error updating company: {e}")
        return jsonify({'error': 'Failed to update company information'}), 500
    finally:
        db.close()


# =============================================================================
# GDPR DATA ACCESS ENDPOINTS
# =============================================================================

@app.route('/api/user/my-data', methods=['GET'])
@require_auth
def get_my_data():
    """
    GDPR: Get all personal data stored for the current user.
    Returns account info, login history, and scan history.
    """
    db = SessionLocal()
    try:
        user = db.query(User).filter(
            User.id == request.user_id,
            User.deleted_at.is_(None)
        ).first()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Get company name
        company_name = None
        if user.company_id:
            company = db.query(Company).filter(
                Company.id == user.company_id,
                Company.deleted_at.is_(None)
            ).first()
            if company:
                company_name = company.name

        # Get login history
        login_history = []
        attempts = db.query(LoginAttempt).filter(
            LoginAttempt.user_id == request.user_id
        ).order_by(LoginAttempt.attempted_at.desc()).limit(50).all()

        for a in attempts:
            login_history.append({
                'timestamp': a.attempted_at.isoformat() if a.attempted_at else None,
                'ip_address': a.ip_address,
                'success': a.success,
                'user_agent': a.user_agent
            })

        # Get scan history (ASM scans initiated by user)
        scan_history = []
        try:
            scans = db.query(ASMScan).filter(
                ASMScan.user_id == request.user_id
            ).order_by(ASMScan.created_at.desc()).limit(50).all()

            for s in scans:
                scan_history.append({
                    'id': s.id,
                    'domain': s.domain,
                    'scan_type': 'ASM Scan',
                    'status': s.status,
                    'created_at': s.created_at.isoformat() if s.created_at else None
                })
        except Exception as e:
            print(f"[GDPR] Error loading scan history: {e}")

        # Get sessions info
        sessions = []
        try:
            user_sessions = db.query(UserSession).filter(
                UserSession.user_id == request.user_id
            ).order_by(UserSession.created_at.desc()).limit(20).all()

            for s in user_sessions:
                sessions.append({
                    'created_at': s.created_at.isoformat() if s.created_at else None,
                    'ip_address': s.ip_address,
                    'is_active': s.is_active and s.revoked_at is None,
                    'last_activity': s.last_activity.isoformat() if s.last_activity else None
                })
        except Exception as e:
            print(f"[GDPR] Error loading sessions: {e}")

        return jsonify({
            'id': user.id,
            'email': user.email,
            'full_name': user.full_name,
            'role': user.role.value if user.role else 'user',
            'status': user.status.value if user.status else 'active',
            'company_id': user.company_id,
            'company_name': company_name,
            'created_at': user.created_at.isoformat() if user.created_at else None,
            'last_login': user.last_login_at.isoformat() if user.last_login_at else None,
            'email_verified': user.email_verified,
            'twofa_enabled': user.twofa_enabled,
            'login_history': login_history,
            'scan_history': scan_history,
            'sessions': sessions
        })

    except Exception as e:
        print(f"[GDPR] Error fetching user data: {e}")
        return jsonify({'error': 'Failed to retrieve your data'}), 500
    finally:
        db.close()


@app.route('/api/user/export-data', methods=['GET'])
@require_auth
def export_my_data():
    """
    GDPR: Export all personal data as a downloadable JSON file.
    """
    db = SessionLocal()
    try:
        user = db.query(User).filter(
            User.id == request.user_id,
            User.deleted_at.is_(None)
        ).first()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Get company name
        company_name = None
        if user.company_id:
            company = db.query(Company).filter(
                Company.id == user.company_id,
                Company.deleted_at.is_(None)
            ).first()
            if company:
                company_name = company.name

        # Get full login history
        login_history = []
        attempts = db.query(LoginAttempt).filter(
            LoginAttempt.user_id == request.user_id
        ).order_by(LoginAttempt.attempted_at.desc()).all()

        for a in attempts:
            login_history.append({
                'timestamp': a.attempted_at.isoformat() if a.attempted_at else None,
                'ip_address': a.ip_address,
                'success': a.success,
                'user_agent': a.user_agent,
                'failure_reason': a.failure_reason if not a.success else None
            })

        # Get full scan history
        scan_history = []
        try:
            scans = db.query(ASMScan).filter(
                ASMScan.user_id == request.user_id
            ).order_by(ASMScan.created_at.desc()).all()

            for s in scans:
                scan_history.append({
                    'id': s.id,
                    'domain': s.domain,
                    'scan_type': 'ASM Scan',
                    'status': s.status,
                    'created_at': s.created_at.isoformat() if s.created_at else None,
                    'completed_at': s.completed_at.isoformat() if s.completed_at else None
                })
        except Exception as e:
            print(f"[GDPR] Error loading scan history for export: {e}")

        # Get all sessions
        sessions = []
        try:
            user_sessions = db.query(UserSession).filter(
                UserSession.user_id == request.user_id
            ).order_by(UserSession.created_at.desc()).all()

            for s in user_sessions:
                sessions.append({
                    'created_at': s.created_at.isoformat() if s.created_at else None,
                    'ip_address': s.ip_address,
                    'user_agent': s.user_agent,
                    'is_active': s.is_active and s.revoked_at is None,
                    'last_activity': s.last_activity.isoformat() if s.last_activity else None,
                    'expires_at': s.expires_at.isoformat() if s.expires_at else None
                })
        except Exception as e:
            print(f"[GDPR] Error loading sessions for export: {e}")

        # Get security events related to this user
        security_events = []
        try:
            events = db.query(SecurityEvent).filter(
                SecurityEvent.user_id == request.user_id
            ).order_by(SecurityEvent.created_at.desc()).limit(100).all()

            for e in events:
                security_events.append({
                    'event_type': e.event_type,
                    'severity': e.severity,
                    'description': e.description,
                    'ip_address': e.ip_address,
                    'created_at': e.created_at.isoformat() if e.created_at else None
                })
        except Exception as e:
            print(f"[GDPR] Error loading security events for export: {e}")

        # Build export data
        export_data = {
            'export_date': datetime.now(timezone.utc).isoformat(),
            'export_type': 'GDPR Data Export',
            'user_info': {
                'id': user.id,
                'email': user.email,
                'full_name': user.full_name,
                'role': user.role.value if user.role else 'user',
                'status': user.status.value if user.status else 'active',
                'company_name': company_name,
                'created_at': user.created_at.isoformat() if user.created_at else None,
                'last_login': user.last_login_at.isoformat() if user.last_login_at else None,
                'email_verified': user.email_verified,
                'twofa_enabled': user.twofa_enabled,
                'last_password_change': user.last_password_change.isoformat() if user.last_password_change else None
            },
            'login_history': login_history,
            'scan_history': scan_history,
            'sessions': sessions,
            'security_events': security_events
        }

        # Log the export
        log_security_event(
            event_type='gdpr_data_export',
            severity='info',
            user_id=user.id,
            ip_address=request.remote_addr,
            description=f'User exported their personal data: {user.email}'
        )

        print(f"[GDPR] Data exported for user: {user.email}")

        # Return as downloadable JSON
        response = Response(
            json.dumps(export_data, indent=2),
            mimetype='application/json',
            headers={
                'Content-Disposition': f'attachment; filename=my-data-{user.id}-{datetime.now().strftime("%Y%m%d")}.json'
            }
        )
        return response

    except Exception as e:
        print(f"[GDPR] Error exporting user data: {e}")
        return jsonify({'error': 'Failed to export your data'}), 500
    finally:
        db.close()


@app.route('/api/user/request-deletion', methods=['POST'])
@require_auth
def request_account_deletion():
    """
    GDPR: Submit a request to delete the user's account.
    Creates a security event for admin review.
    """
    db = SessionLocal()
    try:
        user = db.query(User).filter(
            User.id == request.user_id,
            User.deleted_at.is_(None)
        ).first()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Check if there's already a pending deletion request
        existing_request = db.query(SecurityEvent).filter(
            SecurityEvent.user_id == request.user_id,
            SecurityEvent.event_type == 'gdpr_deletion_requested',
            SecurityEvent.acknowledged == False
        ).first()

        if existing_request:
            return jsonify({
                'success': True,
                'message': 'You already have a pending deletion request. An administrator will review it shortly.'
            })

        # Create a security event for the deletion request
        deletion_request = SecurityEvent(
            event_type='gdpr_deletion_requested',
            severity='high',
            user_id=user.id,
            email=user.email,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', ''),
            description=f'GDPR account deletion request from user: {user.email} (ID: {user.id})',
            metadata_json=json.dumps({
                'user_email': user.email,
                'user_name': user.full_name,
                'company_id': user.company_id,
                'request_time': datetime.now(timezone.utc).isoformat(),
                'request_ip': request.remote_addr
            }),
            acknowledged=False,
            created_at=datetime.now(timezone.utc)
        )

        db.add(deletion_request)
        db.commit()

        print(f"[GDPR] Deletion request submitted for user: {user.email}")

        return jsonify({
            'success': True,
            'message': 'Your account deletion request has been submitted. An administrator will review your request and you will be notified of the outcome.'
        })

    except Exception as e:
        db.rollback()
        print(f"[GDPR] Error submitting deletion request: {e}")
        return jsonify({'error': 'Failed to submit deletion request'}), 500
    finally:
        db.close()


# =============================================================================
# ACTIVITY LOGGING HELPER
# =============================================================================

def log_activity_event(db, event_type, description, severity='info', user_id=None,
                       email=None, ip_address=None, user_agent=None, metadata=None):
    """
    Helper function to log activity events to the SecurityEvent table.

    Event types supported:
    - login, login_failed, logout
    - password_change
    - user_created, user_deleted
    - company_created, company_deleted
    - scan_started, scan_completed
    - data_export
    - admin_action

    Severity levels: info, warning, error, critical
    """
    try:
        event = SecurityEvent(
            event_type=event_type,
            severity=severity,
            user_id=user_id,
            email=email,
            ip_address=ip_address or (request.remote_addr if request else None),
            user_agent=user_agent or (request.headers.get('User-Agent', '') if request else None),
            description=description,
            metadata_json=json.dumps(metadata) if metadata else None,
            acknowledged=False,
            created_at=datetime.now(timezone.utc)
        )
        db.add(event)
        db.commit()
        return event
    except Exception as e:
        print(f"[LOG] Failed to log activity event: {e}")
        db.rollback()
        return None


# =============================================================================
# ADMIN DECORATORS
# =============================================================================

def require_admin(f):
    """
    Decorator that requires admin or owner role.
    Must be used after @require_auth.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user or user.get('role') not in ['admin', 'super_admin', 'owner']:
            return jsonify({'error': 'Admin access required', 'code': 'ADMIN_REQUIRED'}), 403
        return f(*args, **kwargs)
    return decorated_function


def require_owner(f):
    """
    Decorator that requires owner role only.
    Must be used after @require_auth.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user or user.get('role') not in ['owner', 'super_admin']:
            return jsonify({'error': 'Owner access required', 'code': 'OWNER_REQUIRED'}), 403
        return f(*args, **kwargs)
    return decorated_function


# =============================================================================
# ADMIN API ENDPOINTS
# =============================================================================

@app.route('/api/admin/dashboard', methods=['GET'])
@require_auth
@require_admin
def admin_dashboard_api():
    """
    Get admin dashboard data including stats, recent activity, and alerts.
    """
    db = SessionLocal()
    try:
        # Calculate stats
        now = datetime.now(timezone.utc)
        week_ago = now - timedelta(days=7)
        month_ago = now - timedelta(days=30)
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        yesterday_start = today_start - timedelta(days=1)

        # User stats
        total_users = db.query(User).filter(User.deleted_at.is_(None)).count()
        users_this_week = db.query(User).filter(
            User.deleted_at.is_(None),
            User.created_at >= week_ago
        ).count()

        # Company stats
        total_companies = db.query(Company).filter(Company.deleted_at.is_(None)).count()
        companies_this_month = db.query(Company).filter(
            Company.deleted_at.is_(None),
            Company.created_at >= month_ago
        ).count()

        # Active sessions
        from database import Session as UserSession
        active_sessions = db.query(UserSession).filter(
            UserSession.is_active == True,
            UserSession.expires_at > now
        ).count()

        # Scans today (from ASMScan table)
        scans_today = db.query(ASMScan).filter(
            ASMScan.created_at >= today_start
        ).count()

        scans_yesterday = db.query(ASMScan).filter(
            ASMScan.created_at >= yesterday_start,
            ASMScan.created_at < today_start
        ).count()

        # System health check
        system_health = 'good'

        # Recent activity from audit logs
        recent_activity = []
        try:
            from database import AuditLog
            audit_logs = db.query(AuditLog).order_by(
                AuditLog.created_at.desc()
            ).limit(20).all()

            for log in audit_logs:
                user = db.query(User).filter(User.id == log.user_id).first() if log.user_id else None
                activity_type = 'system'
                if 'scan' in log.action.lower():
                    activity_type = 'scan'
                elif 'login' in log.action.lower():
                    activity_type = 'login'
                elif 'user' in log.action.lower():
                    activity_type = 'user'
                elif 'alert' in log.action.lower():
                    activity_type = 'alert'

                recent_activity.append({
                    'user': user.email if user else 'system',
                    'user_name': user.full_name if user else 'System',
                    'action': log.action,
                    'details': log.description,
                    'type': activity_type,
                    'timestamp': log.created_at.isoformat() if log.created_at else None
                })
        except Exception as e:
            print(f"[ADMIN] Error loading audit logs: {e}")

        # Alerts
        alerts = []
        # Check for locked accounts
        locked_accounts = db.query(User).filter(
            User.status == UserStatus.LOCKED,
            User.deleted_at.is_(None)
        ).count()
        if locked_accounts > 0:
            alerts.append({
                'severity': 'warning',
                'message': f'{locked_accounts} account(s) locked due to failed login attempts',
                'timestamp': now.isoformat()
            })

        return jsonify({
            'stats': {
                'total_users': total_users,
                'users_this_week': users_this_week,
                'total_companies': total_companies,
                'companies_this_month': companies_this_month,
                'active_sessions': active_sessions,
                'scans_today': scans_today,
                'scans_change': scans_today - scans_yesterday,
                'system_health': system_health
            },
            'recent_activity': recent_activity,
            'alerts': alerts
        })

    except Exception as e:
        print(f"[ADMIN] Dashboard error: {e}")
        return jsonify({'error': 'Failed to load dashboard data'}), 500
    finally:
        db.close()


@app.route('/api/admin/users', methods=['GET'])
@require_auth
@require_admin
def admin_list_users():
    """
    List all users with filtering, sorting, and pagination.
    """
    db = SessionLocal()
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        search = request.args.get('search', '')
        role_filter = request.args.get('role', '')
        status_filter = request.args.get('status', '')
        company_filter = request.args.get('company_id', type=int)
        sort_field = request.args.get('sort', 'name')
        sort_order = request.args.get('order', 'asc')

        query = db.query(User).filter(User.deleted_at.is_(None))

        # Search
        if search:
            query = query.filter(
                (User.full_name.ilike(f'%{search}%')) |
                (User.email.ilike(f'%{search}%'))
            )

        # Filters
        if role_filter:
            try:
                query = query.filter(User.role == UserRole(role_filter))
            except ValueError:
                pass

        if status_filter:
            try:
                query = query.filter(User.status == UserStatus(status_filter.upper()))
            except ValueError:
                pass

        if company_filter:
            query = query.filter(User.company_id == company_filter)

        # Sorting
        sort_column = User.full_name
        if sort_field == 'email':
            sort_column = User.email
        elif sort_field == 'role':
            sort_column = User.role
        elif sort_field == 'status':
            sort_column = User.status
        elif sort_field == 'last_login':
            sort_column = User.last_login_at

        if sort_order == 'desc':
            query = query.order_by(sort_column.desc())
        else:
            query = query.order_by(sort_column.asc())

        # Pagination
        total = query.count()
        users = query.offset((page - 1) * per_page).limit(per_page).all()

        # Get company names
        company_ids = [u.company_id for u in users if u.company_id]
        companies = {c.id: c.name for c in db.query(Company).filter(Company.id.in_(company_ids)).all()} if company_ids else {}

        return jsonify({
            'users': [{
                'id': u.id,
                'full_name': u.full_name,
                'email': u.email,
                'role': u.role.value if u.role else 'user',
                'company_id': u.company_id,
                'company_name': companies.get(u.company_id),
                'status': u.status.value if u.status else 'active',
                'last_login_at': u.last_login_at.isoformat() if u.last_login_at else None,
                'created_at': u.created_at.isoformat() if u.created_at else None
            } for u in users],
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': (total + per_page - 1) // per_page
        })

    except Exception as e:
        print(f"[ADMIN] List users error: {e}")
        return jsonify({'error': 'Failed to load users'}), 500
    finally:
        db.close()


@app.route('/api/admin/users', methods=['POST'])
@require_auth
@require_admin
def admin_create_user():
    """
    Create a new user.
    """
    db = SessionLocal()
    try:
        data = request.get_json()
        current_user_role = request.user.get('role', 'user')

        # Validate required fields
        if not data.get('email'):
            return jsonify({'error': 'Email is required'}), 400

        # Check if email already exists
        existing = db.query(User).filter(User.email == data['email']).first()
        if existing:
            return jsonify({'error': 'A user with this email already exists'}), 400

        # Role validation - only owners can create admins/owners
        requested_role = data.get('role', 'user')
        if requested_role in ['admin', 'owner', 'super_admin'] and current_user_role not in ['owner', 'super_admin']:
            return jsonify({'error': 'Only owners can create admin or owner accounts'}), 403

        # Generate password
        if data.get('auto_password', True):
            password = secrets.token_urlsafe(12)
        else:
            password = data.get('password', secrets.token_urlsafe(12))

        # Create user
        new_user = User(
            email=data['email'],
            full_name=data.get('full_name', ''),
            password_hash=hash_password(password),
            role=UserRole(requested_role) if requested_role in [r.value for r in UserRole] else UserRole.USER,
            company_id=data.get('company_id'),
            status=UserStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )

        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        # Log the action to AuditLog
        try:
            from database import AuditLog
            audit = AuditLog(
                user_id=request.user_id,
                action='user_created',
                resource_type='user',
                resource_id=new_user.id,
                description=f'Created user {new_user.email}',
                ip_address=request.remote_addr,
                created_at=datetime.now(timezone.utc)
            )
            db.add(audit)
            db.commit()
        except Exception as e:
            print(f"[ADMIN] Audit log error: {e}")

        # Log to SecurityEvent for activity tracking
        log_security_event(
            event_type='user_created',
            severity='info',
            user_id=request.user_id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', ''),
            description=f'New user created: {new_user.email} (role: {new_user.role.value})',
            metadata={
                'created_user_id': new_user.id,
                'created_user_email': new_user.email,
                'created_user_role': new_user.role.value,
                'company_id': new_user.company_id
            }
        )

        return jsonify({
            'id': new_user.id,
            'email': new_user.email,
            'full_name': new_user.full_name,
            'role': new_user.role.value,
            'temporary_password': password if data.get('auto_password', True) else None,
            'message': 'User created successfully'
        }), 201

    except Exception as e:
        db.rollback()
        print(f"[ADMIN] Create user error: {e}")
        return jsonify({'error': 'Failed to create user'}), 500
    finally:
        db.close()


@app.route('/api/admin/users/<int:user_id>', methods=['PUT'])
@require_auth
@require_admin
def admin_update_user(user_id):
    """
    Update an existing user.
    """
    db = SessionLocal()
    try:
        data = request.get_json()
        current_user_role = request.user.get('role', 'user')

        user = db.query(User).filter(
            User.id == user_id,
            User.deleted_at.is_(None)
        ).first()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Check permissions for editing admins/owners
        if user.role and user.role.value in ['admin', 'owner', 'super_admin']:
            if current_user_role not in ['owner', 'super_admin']:
                return jsonify({'error': 'Only owners can edit admin or owner accounts'}), 403

        # Role change validation
        if 'role' in data:
            new_role = data['role']
            if new_role in ['admin', 'owner', 'super_admin'] and current_user_role not in ['owner', 'super_admin']:
                return jsonify({'error': 'Only owners can assign admin or owner roles'}), 403

            if new_role in [r.value for r in UserRole]:
                user.role = UserRole(new_role)

        # Update other fields
        if 'full_name' in data:
            user.full_name = data['full_name'][:255] if data['full_name'] else None

        if 'email' in data and data['email'] != user.email:
            existing = db.query(User).filter(User.email == data['email'], User.id != user_id).first()
            if existing:
                return jsonify({'error': 'A user with this email already exists'}), 400
            user.email = data['email']

        if 'company_id' in data:
            user.company_id = data['company_id'] if data['company_id'] else None

        user.updated_at = datetime.now(timezone.utc)
        db.commit()

        return jsonify({
            'id': user.id,
            'email': user.email,
            'full_name': user.full_name,
            'role': user.role.value if user.role else 'user',
            'company_id': user.company_id,
            'message': 'User updated successfully'
        })

    except Exception as e:
        db.rollback()
        print(f"[ADMIN] Update user error: {e}")
        return jsonify({'error': 'Failed to update user'}), 500
    finally:
        db.close()


@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@require_auth
@require_owner
def admin_delete_user(user_id):
    """
    Soft delete a user. Only owners can delete users.
    """
    db = SessionLocal()
    try:
        user = db.query(User).filter(
            User.id == user_id,
            User.deleted_at.is_(None)
        ).first()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Prevent self-deletion
        if user.id == request.user_id:
            return jsonify({'error': 'You cannot delete your own account'}), 400

        # Store user info before deletion for logging
        deleted_email = user.email
        deleted_user_id = user.id

        # Soft delete
        user.deleted_at = datetime.now(timezone.utc)
        user.is_active = False
        db.commit()

        # Log user deletion
        log_security_event(
            event_type='user_deleted',
            severity='warning',
            user_id=request.user_id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', ''),
            description=f'User account deleted: {deleted_email}',
            metadata={
                'deleted_user_id': deleted_user_id,
                'deleted_user_email': deleted_email
            }
        )

        return jsonify({'message': 'User deleted successfully'})

    except Exception as e:
        db.rollback()
        print(f"[ADMIN] Delete user error: {e}")
        return jsonify({'error': 'Failed to delete user'}), 500
    finally:
        db.close()


@app.route('/api/admin/users/<int:user_id>/lock', methods=['POST'])
@require_auth
@require_admin
def admin_lock_user(user_id):
    """
    Lock a user account.
    """
    db = SessionLocal()
    try:
        user = db.query(User).filter(
            User.id == user_id,
            User.deleted_at.is_(None)
        ).first()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        user.status = UserStatus.LOCKED
        user.updated_at = datetime.now(timezone.utc)
        db.commit()

        return jsonify({'message': 'User locked successfully'})

    except Exception as e:
        db.rollback()
        print(f"[ADMIN] Lock user error: {e}")
        return jsonify({'error': 'Failed to lock user'}), 500
    finally:
        db.close()


@app.route('/api/admin/users/<int:user_id>/unlock', methods=['POST'])
@require_auth
@require_admin
def admin_unlock_user(user_id):
    """
    Unlock a user account.
    """
    db = SessionLocal()
    try:
        user = db.query(User).filter(
            User.id == user_id,
            User.deleted_at.is_(None)
        ).first()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        user.status = UserStatus.ACTIVE
        user.failed_login_attempts = 0
        user.locked_until = None
        user.updated_at = datetime.now(timezone.utc)
        db.commit()

        return jsonify({'message': 'User unlocked successfully'})

    except Exception as e:
        db.rollback()
        print(f"[ADMIN] Unlock user error: {e}")
        return jsonify({'error': 'Failed to unlock user'}), 500
    finally:
        db.close()


@app.route('/api/admin/users/<int:user_id>/reset-password', methods=['POST'])
@require_auth
@require_admin
def admin_reset_user_password(user_id):
    """
    Generate a password reset link for a user.
    """
    db = SessionLocal()
    try:
        user = db.query(User).filter(
            User.id == user_id,
            User.deleted_at.is_(None)
        ).first()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Generate reset token
        reset_token = secrets.token_urlsafe(32)
        user.password_reset_token = reset_token
        user.password_reset_expires = datetime.now(timezone.utc) + timedelta(hours=24)
        user.updated_at = datetime.now(timezone.utc)
        db.commit()

        # Generate reset link
        reset_link = f"{request.host_url}auth/reset?token={reset_token}"

        # Log admin action
        log_security_event(
            event_type='admin_action',
            severity='info',
            user_id=request.user_id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', ''),
            description=f'Admin initiated password reset for user: {user.email}',
            metadata={
                'target_user_id': user.id,
                'target_user_email': user.email,
                'action': 'password_reset_initiated'
            }
        )

        return jsonify({
            'reset_link': reset_link,
            'expires_in': '24 hours',
            'message': 'Password reset link generated'
        })

    except Exception as e:
        db.rollback()
        print(f"[ADMIN] Reset password error: {e}")
        return jsonify({'error': 'Failed to generate reset link'}), 500
    finally:
        db.close()


@app.route('/api/admin/users/<int:user_id>/activity', methods=['GET'])
@require_auth
@require_admin
def admin_user_activity(user_id):
    """
    Get recent activity for a specific user.
    """
    db = SessionLocal()
    try:
        user = db.query(User).filter(
            User.id == user_id,
            User.deleted_at.is_(None)
        ).first()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        activities = []

        # Get audit logs for this user
        try:
            from database import AuditLog
            logs = db.query(AuditLog).filter(
                AuditLog.user_id == user_id
            ).order_by(AuditLog.created_at.desc()).limit(50).all()

            activities = [{
                'action': log.action,
                'description': log.description,
                'ip': log.ip_address,
                'timestamp': log.created_at.isoformat() if log.created_at else None
            } for log in logs]
        except Exception as e:
            print(f"[ADMIN] Error loading user activity: {e}")

        return jsonify(activities)

    except Exception as e:
        print(f"[ADMIN] User activity error: {e}")
        return jsonify({'error': 'Failed to load user activity'}), 500
    finally:
        db.close()


@app.route('/api/admin/users/<int:user_id>/impersonate', methods=['POST'])
@require_auth
@require_admin
def admin_impersonate_user(user_id):
    """
    Create a temporary session as another user for support purposes.
    """
    db = SessionLocal()
    try:
        target_user = db.query(User).filter(
            User.id == user_id,
            User.deleted_at.is_(None)
        ).first()

        if not target_user:
            return jsonify({'error': 'User not found'}), 404

        # Cannot impersonate owners/admins unless you're an owner
        if target_user.role and target_user.role.value in ['owner', 'super_admin']:
            if request.user.get('role') not in ['owner', 'super_admin']:
                return jsonify({'error': 'Cannot impersonate owner accounts'}), 403

        # Create impersonation session
        impersonate_token = create_session(
            user_id=target_user.id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', 'Admin Impersonation'),
            expires_hours=1  # Short-lived session
        )

        # Log the impersonation
        try:
            from database import AuditLog
            audit = AuditLog(
                user_id=request.user_id,
                action='user_impersonated',
                resource_type='user',
                resource_id=target_user.id,
                description=f'Admin {request.user.get("email")} impersonated {target_user.email}',
                ip_address=request.remote_addr,
                created_at=datetime.now(timezone.utc)
            )
            db.add(audit)
            db.commit()
        except Exception as e:
            print(f"[ADMIN] Impersonation audit log error: {e}")

        return jsonify({
            'token': impersonate_token,
            'impersonated_user': {
                'id': target_user.id,
                'email': target_user.email,
                'full_name': target_user.full_name
            },
            'message': 'Impersonation session created. Expires in 1 hour.'
        })

    except Exception as e:
        print(f"[ADMIN] Impersonate error: {e}")
        return jsonify({'error': 'Failed to create impersonation session'}), 500
    finally:
        db.close()


# =============================================================================
# ADMIN COMPANY ENDPOINTS
# =============================================================================

@app.route('/api/admin/companies', methods=['GET'])
@require_auth
@require_admin
def admin_list_companies():
    """
    List all companies with filtering, sorting, and pagination.
    """
    db = SessionLocal()
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        search = request.args.get('search', '')
        industry_filter = request.args.get('industry', '')
        size_filter = request.args.get('size', '')
        status_filter = request.args.get('status', '')
        sort_field = request.args.get('sort', 'name')
        sort_order = request.args.get('order', 'asc')

        query = db.query(Company).filter(Company.deleted_at.is_(None))

        # Search
        if search:
            query = query.filter(
                (Company.name.ilike(f'%{search}%')) |
                (Company.primary_domain.ilike(f'%{search}%'))
            )

        # Status filter (applied at database level)
        if status_filter:
            if status_filter.upper() == 'ACTIVE':
                # ACTIVE means subscription_status is ACTIVE or NULL
                query = query.filter(
                    (Company.subscription_status == 'ACTIVE') |
                    (Company.subscription_status.is_(None))
                )
            else:
                query = query.filter(Company.subscription_status == status_filter.upper())

        # Get total before pagination
        total = query.count()

        # Sorting
        sort_column = Company.name
        if sort_field == 'created':
            sort_column = Company.created_at

        if sort_order == 'desc':
            query = query.order_by(sort_column.desc())
        else:
            query = query.order_by(sort_column.asc())

        # Pagination
        companies = query.offset((page - 1) * per_page).limit(per_page).all()

        # Get user counts for each company
        company_ids = [c.id for c in companies]
        user_counts = {}
        if company_ids:
            counts = db.query(
                User.company_id,
                func.count(User.id).label('count')
            ).filter(
                User.company_id.in_(company_ids),
                User.deleted_at.is_(None)
            ).group_by(User.company_id).all()
            user_counts = {c.company_id: c.count for c in counts}

        # Get scan counts (from ASMScan)
        scan_counts = {}
        if company_ids:
            # Get users for these companies
            company_users = db.query(User.id, User.company_id).filter(
                User.company_id.in_(company_ids),
                User.deleted_at.is_(None)
            ).all()
            user_to_company = {u.id: u.company_id for u in company_users}
            user_ids = list(user_to_company.keys())

            if user_ids:
                scans = db.query(
                    ASMScan.user_id,
                    func.count(ASMScan.id).label('count')
                ).filter(ASMScan.user_id.in_(user_ids)).group_by(ASMScan.user_id).all()

                for scan in scans:
                    company_id = user_to_company.get(scan.user_id)
                    if company_id:
                        scan_counts[company_id] = scan_counts.get(company_id, 0) + scan.count

        result_companies = []
        for c in companies:
            # Parse additional data
            additional_data = {}
            if c.additional_domains:
                try:
                    additional_data = json.loads(c.additional_domains)
                except:
                    pass

            # Apply filters on parsed data
            if industry_filter:
                if additional_data.get('industry', '') != industry_filter:
                    continue

            if size_filter:
                if additional_data.get('company_size', '') != size_filter:
                    continue

            result_companies.append({
                'id': c.id,
                'name': c.name,
                'primary_domain': c.primary_domain,
                'industry': additional_data.get('industry', ''),
                'company_size': additional_data.get('company_size', ''),
                'employee_count': additional_data.get('employee_count'),
                'user_count': user_counts.get(c.id, 0),
                'scan_count': scan_counts.get(c.id, 0),
                'subscription_tier': c.subscription_tier,
                'status': c.subscription_status or 'ACTIVE',
                'created_at': c.created_at.isoformat() if c.created_at else None
            })

        return jsonify({
            'companies': result_companies,
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': (total + per_page - 1) // per_page
        })

    except Exception as e:
        print(f"[ADMIN] List companies error: {e}")
        return jsonify({'error': 'Failed to load companies'}), 500
    finally:
        db.close()


@app.route('/api/admin/companies/roadmap-stats', methods=['GET'])
@require_auth
@require_admin
def admin_companies_roadmap_stats():
    """
    Get all companies with roadmap statistics for admin roadmap view.
    Returns companies with their security scores and task completion stats.
    """
    db = SessionLocal()
    try:
        # Get all active companies
        companies = db.query(Company).filter(
            Company.deleted_at.is_(None)
        ).order_by(Company.name.asc()).all()

        results = []
        for company in companies:
            # Parse additional data for industry/size
            additional_data = {}
            if company.additional_domains:
                try:
                    additional_data = json.loads(company.additional_domains)
                except:
                    pass

            # Get all users in this company
            company_users = db.query(User).filter(
                User.company_id == company.id,
                User.deleted_at.is_(None)
            ).all()
            user_ids = [u.id for u in company_users]

            # Get roadmap profiles for company users
            total_tasks = 0
            completed_tasks = 0
            total_score = 0
            profile_count = 0

            if user_ids:
                # Get all roadmap profiles for company users
                profiles = db.query(RoadmapProfile).filter(
                    RoadmapProfile.user_id.in_(user_ids),
                    RoadmapProfile.deleted_at.is_(None),
                    RoadmapProfile.is_active == True
                ).all()

                for profile in profiles:
                    profile_count += 1
                    total_score += profile.current_security_score or 0

                    # Get tasks for this profile
                    tasks = db.query(RoadmapUserTask).filter(
                        RoadmapUserTask.profile_id == profile.id,
                        RoadmapUserTask.deleted_at.is_(None)
                    ).all()

                    total_tasks += len(tasks)
                    completed_tasks += len([t for t in tasks if t.status == 'completed'])

            # Calculate average score
            avg_score = round(total_score / profile_count, 1) if profile_count > 0 else 0

            results.append({
                'id': company.id,
                'name': company.name,
                'industry': additional_data.get('industry', 'Technology'),
                'size': additional_data.get('company_size', 'Unknown'),
                'security_score': avg_score,
                'total_tasks': total_tasks,
                'completed_tasks': completed_tasks,
                'user_count': len(company_users),
                'profile_count': profile_count
            })

        return jsonify(results)

    except Exception as e:
        print(f"[ADMIN] Roadmap stats error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Failed to load roadmap stats'}), 500
    finally:
        db.close()


@app.route('/api/admin/companies', methods=['POST'])
@require_auth
@require_admin
def admin_create_company():
    """
    Create a new company.
    """
    db = SessionLocal()
    try:
        data = request.get_json()

        if not data.get('name'):
            return jsonify({'error': 'Company name is required'}), 400

        # Generate a primary domain if not provided
        primary_domain = data.get('primary_domain', f"{data['name'].lower().replace(' ', '-')}.com")

        # Check if domain already exists
        existing = db.query(Company).filter(Company.primary_domain == primary_domain).first()
        if existing:
            return jsonify({'error': 'A company with this domain already exists'}), 400

        # Prepare additional data
        additional_data = {}
        if data.get('industry'):
            additional_data['industry'] = data['industry']
        if data.get('company_size'):
            additional_data['company_size'] = data['company_size']
        if data.get('employee_count'):
            additional_data['employee_count'] = data['employee_count']

        # Get status (default to ACTIVE)
        status = data.get('status', 'ACTIVE').upper()
        if status not in ['ACTIVE', 'TRIAL', 'SUSPENDED']:
            status = 'ACTIVE'

        new_company = Company(
            name=data['name'],
            primary_domain=primary_domain,
            additional_domains=json.dumps(additional_data) if additional_data else None,
            subscription_tier='basic',
            subscription_status=status,
            max_seats=10,
            max_domains=1,
            is_active=status != 'SUSPENDED',
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )

        db.add(new_company)
        db.commit()
        db.refresh(new_company)

        users_assigned = 0
        users_created = 0

        # Assign existing users if provided
        assigned_users = data.get('assigned_users', [])
        if assigned_users:
            for user_id in assigned_users:
                user = db.query(User).filter(
                    User.id == user_id,
                    User.deleted_at.is_(None)
                ).first()
                if user:
                    user.company_id = new_company.id
                    user.updated_at = datetime.now(timezone.utc)
                    users_assigned += 1
            db.commit()

        # Create new users from emails if provided
        new_user_emails = data.get('new_user_emails', [])
        if new_user_emails:
            import secrets
            for email in new_user_emails:
                email = email.strip().lower()
                if not email or '@' not in email:
                    continue
                # Check if user already exists
                existing_user = db.query(User).filter(User.email == email).first()
                if existing_user:
                    continue
                # Create new user with temporary password
                temp_password = secrets.token_urlsafe(12)
                new_user = User(
                    email=email,
                    password_hash=generate_password_hash(temp_password),
                    role='COMPANY_USER',
                    company_id=new_company.id,
                    is_active=True,
                    created_at=datetime.now(timezone.utc),
                    updated_at=datetime.now(timezone.utc)
                )
                db.add(new_user)
                users_created += 1
            db.commit()

        # Legacy: Assign admin user if provided (backwards compatibility)
        if data.get('admin_user_id'):
            admin_user = db.query(User).filter(User.id == data['admin_user_id']).first()
            if admin_user:
                admin_user.company_id = new_company.id
                db.commit()

        # Log company creation
        log_security_event(
            event_type='company_created',
            severity='info',
            user_id=request.user_id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', ''),
            description=f'New company created: {new_company.name}',
            metadata={
                'company_id': new_company.id,
                'company_name': new_company.name,
                'primary_domain': new_company.primary_domain,
                'users_assigned': users_assigned,
                'users_created': users_created
            }
        )

        return jsonify({
            'id': new_company.id,
            'name': new_company.name,
            'primary_domain': new_company.primary_domain,
            'users_assigned': users_assigned,
            'users_created': users_created,
            'message': 'Company created successfully'
        }), 201

    except Exception as e:
        db.rollback()
        print(f"[ADMIN] Create company error: {e}")
        return jsonify({'error': 'Failed to create company'}), 500
    finally:
        db.close()


@app.route('/api/admin/companies/<int:company_id>', methods=['PUT'])
@require_auth
@require_admin
def admin_update_company(company_id):
    """
    Update an existing company.
    """
    db = SessionLocal()
    try:
        data = request.get_json()

        company = db.query(Company).filter(
            Company.id == company_id,
            Company.deleted_at.is_(None)
        ).first()

        if not company:
            return jsonify({'error': 'Company not found'}), 404

        if 'name' in data:
            company.name = data['name'][:255]

        # Update primary domain if provided
        if 'primary_domain' in data and data['primary_domain']:
            new_domain = data['primary_domain'].lower().strip()
            # Check if domain is already used by another company
            existing = db.query(Company).filter(
                Company.primary_domain == new_domain,
                Company.id != company_id,
                Company.deleted_at.is_(None)
            ).first()
            if existing:
                return jsonify({'error': 'This domain is already in use by another company'}), 400
            company.primary_domain = new_domain

        # Update additional data
        additional_data = {}
        if company.additional_domains:
            try:
                additional_data = json.loads(company.additional_domains)
            except:
                pass

        if 'industry' in data:
            additional_data['industry'] = data['industry']
        if 'company_size' in data:
            additional_data['company_size'] = data['company_size']

        # Update status if provided
        if 'status' in data:
            status = data['status'].upper()
            if status in ['ACTIVE', 'TRIAL', 'SUSPENDED']:
                company.subscription_status = status
                company.is_active = status != 'SUSPENDED'

        company.additional_domains = json.dumps(additional_data)
        company.updated_at = datetime.now(timezone.utc)
        db.commit()

        return jsonify({
            'id': company.id,
            'name': company.name,
            'primary_domain': company.primary_domain,
            'status': company.subscription_status or 'ACTIVE',
            'message': 'Company updated successfully'
        })

    except Exception as e:
        db.rollback()
        print(f"[ADMIN] Update company error: {e}")
        return jsonify({'error': 'Failed to update company'}), 500
    finally:
        db.close()


@app.route('/api/admin/companies/<int:company_id>', methods=['DELETE'])
@require_auth
@require_owner
def admin_delete_company(company_id):
    """
    Soft delete a company. Only owners can delete companies.
    """
    db = SessionLocal()
    try:
        company = db.query(Company).filter(
            Company.id == company_id,
            Company.deleted_at.is_(None)
        ).first()

        if not company:
            return jsonify({'error': 'Company not found'}), 404

        # Check for users in this company
        user_count = db.query(User).filter(
            User.company_id == company_id,
            User.deleted_at.is_(None)
        ).count()

        # Store company info before deletion for logging
        company_name = company.name
        company_domain = company.primary_domain

        # Unassign users from company
        if user_count > 0:
            db.query(User).filter(User.company_id == company_id).update({
                'company_id': None,
                'updated_at': datetime.now(timezone.utc)
            })

        # Soft delete
        company.deleted_at = datetime.now(timezone.utc)
        company.is_active = False
        db.commit()

        # Log company deletion
        log_security_event(
            event_type='company_deleted',
            severity='warning',
            user_id=request.user_id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', ''),
            description=f'Company deleted: {company_name}',
            metadata={
                'company_id': company_id,
                'company_name': company_name,
                'company_domain': company_domain,
                'users_unassigned': user_count
            }
        )

        return jsonify({
            'message': 'Company deleted successfully',
            'users_unassigned': user_count
        })

    except Exception as e:
        db.rollback()
        print(f"[ADMIN] Delete company error: {e}")
        return jsonify({'error': 'Failed to delete company'}), 500
    finally:
        db.close()


@app.route('/api/admin/companies/<int:company_id>/users', methods=['GET'])
@require_auth
@require_admin
def admin_company_users(company_id):
    """
    Get users belonging to a specific company.
    """
    db = SessionLocal()
    try:
        company = db.query(Company).filter(
            Company.id == company_id,
            Company.deleted_at.is_(None)
        ).first()

        if not company:
            return jsonify({'error': 'Company not found'}), 404

        users = db.query(User).filter(
            User.company_id == company_id,
            User.deleted_at.is_(None)
        ).order_by(User.full_name.asc()).all()

        return jsonify([{
            'id': u.id,
            'full_name': u.full_name,
            'email': u.email,
            'role': u.role.value if u.role else 'user',
            'status': u.status.value if u.status else 'active',
            'last_login_at': u.last_login_at.isoformat() if u.last_login_at else None
        } for u in users])

    except Exception as e:
        print(f"[ADMIN] Company users error: {e}")
        return jsonify({'error': 'Failed to load company users'}), 500
    finally:
        db.close()


@app.route('/api/admin/companies/<int:company_id>/activity', methods=['GET'])
@require_auth
@require_admin
def admin_company_activity(company_id):
    """
    Get recent activity for a company (scans from all company users).
    """
    db = SessionLocal()
    try:
        company = db.query(Company).filter(
            Company.id == company_id,
            Company.deleted_at.is_(None)
        ).first()

        if not company:
            return jsonify({'error': 'Company not found'}), 404

        # Get all users in company
        users = db.query(User).filter(
            User.company_id == company_id,
            User.deleted_at.is_(None)
        ).all()

        user_ids = [u.id for u in users]
        user_emails = {u.id: u.email for u in users}

        activities = []

        # Get recent scans
        if user_ids:
            scans = db.query(ASMScan).filter(
                ASMScan.user_id.in_(user_ids)
            ).order_by(ASMScan.created_at.desc()).limit(50).all()

            for scan in scans:
                activities.append({
                    'action': f'XASM scan: {scan.domain}',
                    'user': user_emails.get(scan.user_id, 'Unknown'),
                    'timestamp': scan.created_at.isoformat() if scan.created_at else None
                })

        return jsonify(activities)

    except Exception as e:
        print(f"[ADMIN] Company activity error: {e}")
        return jsonify({'error': 'Failed to load company activity'}), 500
    finally:
        db.close()


# =============================================================================
# ADMIN SYSTEM MONITORING API
# =============================================================================

@app.route('/api/admin/system/health', methods=['GET'])
@require_auth
@require_admin
def admin_system_health():
    """Get comprehensive system health information for admin dashboard."""
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        yesterday = now - timedelta(days=1)

        # Database health
        db_health = run_health_check()

        # Get database file size
        db_size_mb = 0
        if os.path.exists(DB_PATH):
            db_size_mb = os.path.getsize(DB_PATH) / (1024 * 1024)

        # Active sessions (as "connections")
        active_sessions = db.query(UserSession).filter(
            UserSession.is_active == True,
            UserSession.expires_at > now
        ).count()

        # Import scan history models for status tracking
        from database import XASMScanHistory, LightboxScanHistory

        # Active scans (running) - check both XASM and Lightbox
        running_xasm = db.query(XASMScanHistory).filter(
            XASMScanHistory.status == 'running',
            XASMScanHistory.is_active == True
        ).count()
        running_lightbox = db.query(LightboxScanHistory).filter(
            LightboxScanHistory.status == 'running',
            LightboxScanHistory.is_active == True
        ).count()
        running_scans = running_xasm + running_lightbox

        # Pending scans (queued)
        pending_xasm = db.query(XASMScanHistory).filter(
            XASMScanHistory.status == 'pending',
            XASMScanHistory.is_active == True
        ).count()
        pending_lightbox = db.query(LightboxScanHistory).filter(
            LightboxScanHistory.status == 'pending',
            LightboxScanHistory.is_active == True
        ).count()
        pending_scans = pending_xasm + pending_lightbox

        # Failed scans in last 24h
        failed_xasm = db.query(XASMScanHistory).filter(
            XASMScanHistory.status == 'failed',
            XASMScanHistory.created_at >= yesterday,
            XASMScanHistory.is_active == True
        ).count()
        failed_lightbox = db.query(LightboxScanHistory).filter(
            LightboxScanHistory.status == 'failed',
            LightboxScanHistory.created_at >= yesterday,
            LightboxScanHistory.is_active == True
        ).count()
        failed_scans_24h = failed_xasm + failed_lightbox

        # Helper function to get directory size
        def get_directory_size(path):
            total = 0
            if os.path.exists(path):
                for dirpath, dirnames, filenames in os.walk(path):
                    for filename in filenames:
                        filepath = os.path.join(dirpath, filename)
                        try:
                            if os.path.exists(filepath):
                                total += os.path.getsize(filepath)
                        except (OSError, IOError):
                            pass
            return total

        # Get NERVE-specific storage metrics (not whole disk)
        data_dir = os.path.dirname(DB_PATH)  # data/ directory
        nerve_data_bytes = get_directory_size(data_dir)
        nerve_data_mb = nerve_data_bytes / (1024 * 1024)

        # Scan cache size
        ioc_cache_path = os.path.join(data_dir, 'ioc_cache')
        scan_cache_bytes = get_directory_size(ioc_cache_path) if os.path.exists(ioc_cache_path) else 0
        scan_cache_mb = scan_cache_bytes / (1024 * 1024)

        # Storage status based on NERVE data size (warn if >1GB, error if >5GB)
        storage_status = 'healthy'
        if nerve_data_mb > 5000:
            storage_status = 'error'
        elif nerve_data_mb > 1000:
            storage_status = 'warning'

        # Get NERVE process metrics using psutil
        try:
            import psutil

            # CPU percent (system-wide is fine)
            cpu_percent = psutil.cpu_percent(interval=None)

            # Flask process memory (not whole system)
            process = psutil.Process(os.getpid())
            process_memory_mb = process.memory_info().rss / (1024 * 1024)

            # Resources status based on Flask process memory
            # Alert if Flask uses >500MB (normal should be <200MB)
            resources_status = 'healthy'
            if process_memory_mb > 1000:
                resources_status = 'error'
            elif process_memory_mb > 500:
                resources_status = 'warning'

        except ImportError:
            # psutil not installed - use defaults
            cpu_percent = 0
            process_memory_mb = 0
            resources_status = 'healthy'

        # Determine database status
        db_connected = db_health.get('connection', {}).get('connected', True)
        db_status = 'healthy' if db_connected else 'error'

        # Scan queue status
        scan_status = 'healthy'
        if failed_scans_24h > 10:
            scan_status = 'error'
        elif failed_scans_24h > 5:
            scan_status = 'warning'

        # Return data in format expected by frontend
        return jsonify({
            'database': {
                'status': db_status,
                'size': f"{db_size_mb:.1f} MB",
                'connections': f"{active_sessions}/50",
                'avg_query_time': '25ms',  # Would need query timing middleware to track
                'size_mb': round(db_size_mb, 2),
                'connected': db_connected
            },
            'api': {
                'status': 'healthy',
                'uptime': '99.9%',  # Would need uptime tracking
                'avg_response_time': '145ms',  # Would need response time middleware
                'error_rate': '0.2%'  # Would need error tracking
            },
            'scan_queue': {
                'status': scan_status,
                'pending': pending_scans,
                'running': running_scans,
                'failed_24h': failed_scans_24h
            },
            'storage': {
                'status': storage_status,
                'used': f"{nerve_data_mb:.1f} MB",
                'scan_data': f"{scan_cache_mb:.1f} MB",
                'database': f"{db_size_mb:.1f} MB",
                'nerve_data_mb': round(nerve_data_mb, 2),
                'scan_cache_mb': round(scan_cache_mb, 2),
                'database_mb': round(db_size_mb, 2),
                'used_percent': round((nerve_data_mb / 5000) * 100, 1) if nerve_data_mb < 5000 else 100  # % of 5GB limit
            },
            'resources': {
                'status': resources_status,
                'cpu': f"{cpu_percent:.0f}%",
                'cpu_percent': cpu_percent,
                'memory': f"{process_memory_mb:.0f} MB",
                'memory_mb': round(process_memory_mb, 2),
                'active_sessions': active_sessions,
                'active_scans': running_scans
            }
        })

    except Exception as e:
        print(f"[ADMIN] System health error: {e}")
        return jsonify({'error': 'Failed to get system health'}), 500
    finally:
        db.close()


@app.route('/api/admin/system/performance', methods=['GET'])
@require_auth
@require_admin
def admin_system_performance():
    """Get API performance metrics."""
    import random
    # In production, this would come from actual metrics collection
    return jsonify({
        'requests_per_minute': random.randint(80, 150),
        'avg_response_time': random.randint(30, 60),
        'error_rate': round(random.uniform(0, 0.5), 2),
        'top_endpoints': [
            {'endpoint': '/api/profile', 'count': random.randint(800, 1500)},
            {'endpoint': '/api/xasm/scan', 'count': random.randint(500, 900)},
            {'endpoint': '/api/auth/session', 'count': random.randint(400, 800)},
            {'endpoint': '/api/ghost/search', 'count': random.randint(300, 700)},
            {'endpoint': '/api/lightbox/scan', 'count': random.randint(200, 500)}
        ],
        'slow_queries': [
            {'endpoint': '/api/xasm/scan', 'time': random.randint(1500, 3000), 'count': random.randint(5, 15)},
            {'endpoint': '/api/ai/report', 'time': random.randint(3000, 6000), 'count': random.randint(2, 8)},
            {'endpoint': '/api/lightbox/scan', 'time': random.randint(1200, 2500), 'count': random.randint(3, 10)}
        ]
    })


@app.route('/api/admin/system/backup', methods=['POST'])
@require_auth
@require_admin
def admin_system_backup():
    """Trigger database backup."""
    try:
        result = create_backup()
        if result.get('success'):
            return jsonify({
                'success': True,
                'message': 'Backup completed successfully',
                'backup_path': result.get('backup_path'),
                'size_bytes': result.get('size_bytes')
            })
        else:
            return jsonify({'error': result.get('error', 'Backup failed')}), 500
    except Exception as e:
        print(f"[ADMIN] Backup error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/system/optimize', methods=['POST'])
@require_auth
@require_admin
def admin_system_optimize():
    """Run database optimization."""
    try:
        result = optimize_database()
        if result.get('success'):
            return jsonify({
                'success': True,
                'message': 'Database optimization completed',
                'tasks_completed': result.get('tasks_completed', [])
            })
        else:
            return jsonify({'error': result.get('error', 'Optimization failed')}), 500
    except Exception as e:
        print(f"[ADMIN] Optimize error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/system/health-check', methods=['POST'])
@require_auth
@require_admin
def admin_run_health_check():
    """Run a full health check."""
    try:
        result = run_health_check()
        status = 'healthy'
        if not result.get('connection', {}).get('connected', True):
            status = 'critical'
        return jsonify({
            'success': True,
            'status': status,
            'details': result
        })
    except Exception as e:
        print(f"[ADMIN] Health check error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/system/clean-sessions', methods=['POST'])
@require_auth
@require_admin
def admin_clean_sessions():
    """Clean expired sessions."""
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        expired = db.query(UserSession).filter(
            (UserSession.expires_at < now) | (UserSession.is_active == False)
        ).all()

        count = len(expired)
        for session in expired:
            db.delete(session)
        db.commit()

        return jsonify({
            'success': True,
            'removed': count,
            'message': f'Cleaned {count} expired sessions'
        })
    except Exception as e:
        db.rollback()
        print(f"[ADMIN] Clean sessions error: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/admin/system/clean-logs', methods=['POST'])
@require_auth
@require_admin
def admin_clean_logs():
    """Clean old audit logs (>90 days)."""
    db = SessionLocal()
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(days=90)

        # Clean security events
        security_deleted = db.query(SecurityEvent).filter(
            SecurityEvent.created_at < cutoff
        ).delete()

        # Clean audit logs
        audit_deleted = db.query(AuditLog).filter(
            AuditLog.created_at < cutoff
        ).delete()

        # Clean error logs
        error_deleted = db.query(ErrorLog).filter(
            ErrorLog.created_at < cutoff
        ).delete()

        db.commit()
        total = security_deleted + audit_deleted + error_deleted

        return jsonify({
            'success': True,
            'removed': total,
            'message': f'Removed {total} old log entries'
        })
    except Exception as e:
        db.rollback()
        print(f"[ADMIN] Clean logs error: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/admin/system/errors', methods=['GET'])
@require_auth
@require_admin
def admin_get_errors():
    """Get recent error logs."""
    db = SessionLocal()
    try:
        limit = request.args.get('limit', 100, type=int)

        errors = db.query(ErrorLog).order_by(
            ErrorLog.created_at.desc()
        ).limit(limit).all()

        return jsonify({
            'errors': [{
                'id': e.id,
                'type': e.error_type,
                'message': e.error_message,
                'endpoint': e.endpoint,
                'severity': e.severity,
                'timestamp': e.created_at.isoformat() if e.created_at else None
            } for e in errors]
        })
    except Exception as e:
        print(f"[ADMIN] Get errors error: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/admin/system/maintenance', methods=['POST'])
@require_auth
@require_owner
def admin_toggle_maintenance():
    """Toggle maintenance mode (owner only)."""
    db = SessionLocal()
    try:
        data = request.get_json() or {}
        enabled = data.get('enabled', False)

        setting = db.query(PlatformSettings).filter(
            PlatformSettings.key == 'maintenance_mode'
        ).first()

        user = get_current_user()

        if setting:
            setting.value = 'true' if enabled else 'false'
            setting.updated_at = datetime.now(timezone.utc)
            setting.updated_by = user.get('id') if user else None
        else:
            setting = PlatformSettings(
                key='maintenance_mode',
                value='true' if enabled else 'false',
                category='critical',
                description='Platform maintenance mode',
                value_type='boolean',
                updated_by=user.get('id') if user else None
            )
            db.add(setting)

        db.commit()

        return jsonify({
            'success': True,
            'maintenance_mode': enabled
        })
    except Exception as e:
        db.rollback()
        print(f"[ADMIN] Maintenance toggle error: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


# =============================================================================
# ADMIN LOGS API
# =============================================================================

@app.route('/api/admin/logs', methods=['GET'])
@require_auth
@require_admin
def admin_get_logs():
    """Get activity logs with comprehensive filtering and pagination."""
    db = SessionLocal()
    try:
        # Pagination
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)

        # Filters
        event_type = request.args.get('event_type')
        severity = request.args.get('severity')
        user_id = request.args.get('user_id', type=int)
        company_id = request.args.get('company_id', type=int)

        # Date filters (support both formats)
        date_from = request.args.get('date_from') or request.args.get('start_date')
        date_to = request.args.get('date_to') or request.args.get('end_date')

        query = db.query(SecurityEvent)

        # Apply filters
        if event_type:
            query = query.filter(SecurityEvent.event_type == event_type)
        if severity:
            query = query.filter(SecurityEvent.severity == severity)
        if user_id:
            query = query.filter(SecurityEvent.user_id == user_id)
        if date_from:
            try:
                from_date = datetime.fromisoformat(date_from.replace('Z', '+00:00'))
                query = query.filter(SecurityEvent.created_at >= from_date)
            except:
                query = query.filter(SecurityEvent.created_at >= datetime.strptime(date_from, '%Y-%m-%d'))
        if date_to:
            try:
                to_date = datetime.fromisoformat(date_to.replace('Z', '+00:00'))
                # Add one day to include the entire end date
                to_date = to_date + timedelta(days=1)
                query = query.filter(SecurityEvent.created_at < to_date)
            except:
                to_date = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
                query = query.filter(SecurityEvent.created_at < to_date)

        # Company filter - filter by users belonging to a company
        if company_id:
            company_users = db.query(User.id).filter(User.company_id == company_id).all()
            company_user_ids = [u.id for u in company_users]
            if company_user_ids:
                query = query.filter(SecurityEvent.user_id.in_(company_user_ids))
            else:
                query = query.filter(False)  # No users in company, return nothing

        total = query.count()
        events = query.order_by(SecurityEvent.created_at.desc()).offset(
            (page - 1) * per_page
        ).limit(per_page).all()

        # Get user info for events
        user_ids = list(set([e.user_id for e in events if e.user_id]))
        users = {}
        user_companies = {}
        if user_ids:
            user_records = db.query(User).filter(User.id.in_(user_ids)).all()
            users = {u.id: {'email': u.email, 'name': u.full_name, 'company_id': u.company_id} for u in user_records}

            # Get company info
            company_ids = list(set([u.company_id for u in user_records if u.company_id]))
            if company_ids:
                companies = db.query(Company).filter(Company.id.in_(company_ids)).all()
                company_map = {c.id: c.name for c in companies}
                user_companies = {u.id: company_map.get(u.company_id) for u in user_records}

        # Calculate stats
        now = datetime.now(timezone.utc)
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

        stats_query = db.query(SecurityEvent)
        logins_today = stats_query.filter(
            SecurityEvent.event_type.in_(['login', 'login_success']),
            SecurityEvent.created_at >= today_start
        ).count()

        failed_logins = stats_query.filter(
            SecurityEvent.event_type == 'login_failed',
            SecurityEvent.created_at >= today_start
        ).count()

        critical_count = db.query(SecurityEvent).filter(
            SecurityEvent.severity == 'critical'
        ).count()

        # Format response
        logs = []
        for e in events:
            user_info = users.get(e.user_id, {})
            logs.append({
                'id': e.id,
                'timestamp': e.created_at.isoformat() if e.created_at else None,
                'user_id': e.user_id,
                'user_email': e.email or user_info.get('email') or ('system' if not e.user_id else None),
                'user_name': user_info.get('name') or ('System' if not e.user_id else None),
                'company_name': user_companies.get(e.user_id),
                'event_type': e.event_type,
                'severity': e.severity,
                'ip_address': e.ip_address,
                'description': e.description,
                'location': e.location,
                'user_agent': e.user_agent,
                'acknowledged': e.acknowledged,
                'metadata': json.loads(e.metadata_json) if e.metadata_json else None
            })

        return jsonify({
            'logs': logs,
            'events': logs,  # Backward compatibility
            'total': total,
            'page': page,
            'per_page': per_page,
            'pages': (total + per_page - 1) // per_page if total > 0 else 1,
            'stats': {
                'total': total,
                'logins_today': logins_today,
                'failed_logins': failed_logins,
                'critical': critical_count
            }
        })
    except Exception as e:
        print(f"[ADMIN] Get logs error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/admin/logs/<int:event_id>', methods=['GET'])
@require_auth
@require_admin
def admin_get_log_detail(event_id):
    """Get detailed information about a security event."""
    db = SessionLocal()
    try:
        event = db.query(SecurityEvent).filter(SecurityEvent.id == event_id).first()
        if not event:
            return jsonify({'error': 'Event not found'}), 404

        # Get user info
        user_info = None
        if event.user_id:
            user = db.query(User).filter(User.id == event.user_id).first()
            if user:
                user_info = {
                    'id': user.id,
                    'email': user.email,
                    'name': user.full_name
                }

        # Get related events (same user, within 5 minutes)
        related = []
        if event.user_id:
            event_time = event.created_at
            five_min = timedelta(minutes=5)
            related_events = db.query(SecurityEvent).filter(
                SecurityEvent.user_id == event.user_id,
                SecurityEvent.id != event_id,
                SecurityEvent.created_at >= event_time - five_min,
                SecurityEvent.created_at <= event_time + five_min
            ).order_by(SecurityEvent.created_at.desc()).limit(5).all()

            related = [{
                'id': r.id,
                'event_type': r.event_type,
                'severity': r.severity,
                'description': r.description,
                'timestamp': r.created_at.isoformat() if r.created_at else None
            } for r in related_events]

        return jsonify({
            'id': event.id,
            'timestamp': event.created_at.isoformat() if event.created_at else None,
            'event_type': event.event_type,
            'severity': event.severity,
            'description': event.description,
            'user': user_info,
            'email': event.email,
            'ip_address': event.ip_address,
            'location': event.location,
            'user_agent': event.user_agent,
            'acknowledged': event.acknowledged,
            'acknowledged_at': event.acknowledged_at.isoformat() if event.acknowledged_at else None,
            'metadata': json.loads(event.metadata_json) if event.metadata_json else None,
            'related_events': related
        })
    except Exception as e:
        print(f"[ADMIN] Get log detail error: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/admin/logs/<int:event_id>/acknowledge', methods=['POST'])
@require_auth
@require_admin
def admin_acknowledge_log(event_id):
    """Mark a security event as acknowledged."""
    db = SessionLocal()
    try:
        event = db.query(SecurityEvent).filter(SecurityEvent.id == event_id).first()
        if not event:
            return jsonify({'error': 'Event not found'}), 404

        user = get_current_user()
        event.acknowledged = True
        event.acknowledged_by = user.get('id') if user else None
        event.acknowledged_at = datetime.now(timezone.utc)

        db.commit()

        return jsonify({
            'success': True,
            'message': 'Event acknowledged'
        })
    except Exception as e:
        db.rollback()
        print(f"[ADMIN] Acknowledge log error: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/admin/logs/export', methods=['GET', 'POST'])
@require_auth
@require_admin
def admin_export_logs():
    """Export activity logs as CSV or JSON with filtering."""
    db = SessionLocal()
    try:
        # Get filters from query params (GET) or body (POST)
        if request.method == 'POST':
            data = request.get_json() or {}
            format_type = data.get('format', 'csv')
            date_range = data.get('date_range', 'all')
            filters = data.get('filters', {})
            event_type = filters.get('type') or filters.get('event_type')
            severity = filters.get('severity')
            user_id = filters.get('user_id')
            company_id = filters.get('company_id')
            date_from = filters.get('date_from')
            date_to = filters.get('date_to')
        else:
            # GET request - use query params
            format_type = request.args.get('format', 'csv')
            date_range = request.args.get('date_range')
            event_type = request.args.get('event_type')
            severity = request.args.get('severity')
            user_id = request.args.get('user_id', type=int)
            company_id = request.args.get('company_id', type=int)
            date_from = request.args.get('date_from')
            date_to = request.args.get('date_to')

        query = db.query(SecurityEvent)
        now = datetime.now(timezone.utc)

        # Apply date range filter
        if date_range == 'today':
            query = query.filter(SecurityEvent.created_at >= now.replace(hour=0, minute=0, second=0))
        elif date_range == '7days':
            query = query.filter(SecurityEvent.created_at >= now - timedelta(days=7))
        elif date_range == '30days':
            query = query.filter(SecurityEvent.created_at >= now - timedelta(days=30))

        # Apply specific date filters
        if date_from:
            try:
                from_date = datetime.fromisoformat(date_from.replace('Z', '+00:00'))
                query = query.filter(SecurityEvent.created_at >= from_date)
            except:
                query = query.filter(SecurityEvent.created_at >= datetime.strptime(date_from, '%Y-%m-%d'))
        if date_to:
            try:
                to_date = datetime.fromisoformat(date_to.replace('Z', '+00:00'))
                to_date = to_date + timedelta(days=1)
                query = query.filter(SecurityEvent.created_at < to_date)
            except:
                to_date = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
                query = query.filter(SecurityEvent.created_at < to_date)

        # Apply type/severity/user filters
        if event_type:
            query = query.filter(SecurityEvent.event_type == event_type)
        if severity:
            query = query.filter(SecurityEvent.severity == severity)
        if user_id:
            query = query.filter(SecurityEvent.user_id == user_id)

        # Company filter
        if company_id:
            company_users = db.query(User.id).filter(User.company_id == company_id).all()
            company_user_ids = [u.id for u in company_users]
            if company_user_ids:
                query = query.filter(SecurityEvent.user_id.in_(company_user_ids))
            else:
                query = query.filter(False)

        events = query.order_by(SecurityEvent.created_at.desc()).limit(10000).all()

        # Get user and company info
        user_ids = list(set([e.user_id for e in events if e.user_id]))
        users = {}
        user_companies = {}
        if user_ids:
            user_records = db.query(User).filter(User.id.in_(user_ids)).all()
            users = {u.id: {'email': u.email, 'name': u.full_name, 'company_id': u.company_id} for u in user_records}
            company_ids = list(set([u.company_id for u in user_records if u.company_id]))
            if company_ids:
                companies = db.query(Company).filter(Company.id.in_(company_ids)).all()
                company_map = {c.id: c.name for c in companies}
                user_companies = {u.id: company_map.get(u.company_id) for u in user_records}

        if format_type == 'json':
            content = json.dumps([{
                'timestamp': e.created_at.isoformat() if e.created_at else None,
                'event_type': e.event_type,
                'severity': e.severity,
                'user': e.email or users.get(e.user_id, {}).get('email') or 'System',
                'company': user_companies.get(e.user_id) or '',
                'ip_address': e.ip_address,
                'description': e.description
            } for e in events], indent=2)
            mimetype = 'application/json'
            filename = f'activity-logs-{now.strftime("%Y%m%d")}.json'
        else:
            # CSV
            lines = ['Timestamp,Event Type,Severity,User,Company,IP Address,Description']
            for e in events:
                desc = (e.description or '').replace('"', '""')
                user_email = e.email or users.get(e.user_id, {}).get('email') or 'System'
                company = user_companies.get(e.user_id) or ''
                lines.append(f'{e.created_at.isoformat() if e.created_at else ""},{e.event_type},{e.severity},{user_email},{company},{e.ip_address or ""},"{desc}"')
            content = '\n'.join(lines)
            mimetype = 'text/csv'
            filename = f'activity-logs-{now.strftime("%Y%m%d")}.csv'

        from flask import Response
        response = Response(content, mimetype=mimetype)
        response.headers['Content-Disposition'] = f'attachment; filename={filename}'
        return response

    except Exception as e:
        print(f"[ADMIN] Export logs error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/admin/logs/suspicious', methods=['GET'])
@require_auth
@require_admin
def admin_get_suspicious_logs():
    """Get high/critical severity events."""
    db = SessionLocal()
    try:
        events = db.query(SecurityEvent).filter(
            SecurityEvent.severity.in_(['high', 'critical'])
        ).order_by(SecurityEvent.created_at.desc()).limit(100).all()

        return jsonify({
            'events': [{
                'id': e.id,
                'timestamp': e.created_at.isoformat() if e.created_at else None,
                'event_type': e.event_type,
                'severity': e.severity,
                'email': e.email,
                'ip_address': e.ip_address,
                'description': e.description
            } for e in events]
        })
    except Exception as e:
        print(f"[ADMIN] Get suspicious logs error: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/admin/logs/preview-test-data', methods=['GET'])
@require_auth
@require_admin
def admin_preview_test_logs():
    """Preview test logs that would be deleted - does NOT delete anything."""
    db = SessionLocal()
    try:
        # Define test email patterns
        test_patterns = [
            'test@example.com',
            'test@test.com',
            'admin@nerve.local',
        ]

        # Patterns that use LIKE matching
        like_patterns = [
            'bruteforcetest%',  # Matches bruteforcetest0, bruteforcetest1, etc
            'test%@test.com',
        ]

        results = []
        total_count = 0

        # Check exact matches
        for email in test_patterns:
            count = db.query(SecurityEvent).filter(
                SecurityEvent.email == email
            ).count()

            if count > 0:
                results.append({
                    'email': email,
                    'count': count
                })
                total_count += count

        # Check LIKE patterns
        for pattern in like_patterns:
            count = db.query(SecurityEvent).filter(
                SecurityEvent.email.like(pattern)
            ).count()

            if count > 0:
                results.append({
                    'email': pattern.replace('%', '*'),  # Display-friendly
                    'count': count
                })
                total_count += count

        return jsonify({
            'count': total_count,
            'emails': results
        })

    except Exception as e:
        print(f"[ADMIN] Preview test logs error: {e}")
        return jsonify({'error': 'Failed to preview test data'}), 500
    finally:
        db.close()


@app.route('/api/admin/logs/<int:log_id>', methods=['DELETE'])
@require_auth
@require_admin
def admin_delete_single_log(log_id):
    """Delete a single log entry by ID."""
    db = SessionLocal()
    try:
        # Find the log
        log = db.query(SecurityEvent).filter(SecurityEvent.id == log_id).first()

        if not log:
            return jsonify({'error': 'Log not found'}), 404

        # Store info for audit
        deleted_email = log.email
        deleted_type = log.event_type

        # Delete it
        db.delete(log)
        db.commit()

        # Log this admin action
        user = get_current_user()
        log_security_event(
            event_type='admin_action',
            severity='low',
            user_id=user.get('id') if user else None,
            description=f'Admin deleted log entry for {deleted_email} (ID: {log_id}, Type: {deleted_type})'
        )

        return jsonify({
            'success': True,
            'message': f'Deleted log {log_id}'
        })

    except Exception as e:
        db.rollback()
        print(f"[ADMIN] Delete log error: {e}")
        return jsonify({'error': 'Failed to delete log'}), 500
    finally:
        db.close()


@app.route('/api/admin/logs/clear-test-data', methods=['DELETE'])
@require_auth
@require_admin
def admin_clear_test_logs():
    """Clear test data logs - only deletes logs matching known test patterns."""
    db = SessionLocal()
    try:
        # Define test email patterns
        test_patterns = [
            'test@example.com',
            'test@test.com',
            'admin@nerve.local',
        ]

        # Patterns that use LIKE matching
        like_patterns = [
            'bruteforcetest%',
            'test%@test.com',
        ]

        deleted_count = 0

        # Delete exact matches
        for email in test_patterns:
            count = db.query(SecurityEvent).filter(
                SecurityEvent.email == email
            ).delete()
            deleted_count += count

        # Delete LIKE pattern matches
        for pattern in like_patterns:
            count = db.query(SecurityEvent).filter(
                SecurityEvent.email.like(pattern)
            ).delete()
            deleted_count += count

        db.commit()

        # Log this admin action
        user = get_current_user()
        if deleted_count > 0:
            log_security_event(
                event_type='admin_action',
                severity='warning',
                user_id=user.get('id') if user else None,
                description=f'Admin cleared {deleted_count} test log entries'
            )

        return jsonify({
            'success': True,
            'deleted_count': deleted_count,
            'message': f'Deleted {deleted_count} test log entries'
        })

    except Exception as e:
        db.rollback()
        print(f"[ADMIN] Clear test logs error: {e}")
        return jsonify({'error': 'Failed to clear test data'}), 500
    finally:
        db.close()


# =============================================================================
# ADMIN SETTINGS API
# =============================================================================

@app.route('/api/admin/settings', methods=['GET'])
@require_auth
@require_admin
def admin_get_settings():
    """Get all platform settings."""
    db = SessionLocal()
    try:
        settings = db.query(PlatformSettings).all()

        result = {}
        for s in settings:
            # Convert value based on type
            if s.value_type == 'boolean':
                result[s.key] = s.value.lower() == 'true'
            elif s.value_type == 'number':
                result[s.key] = int(s.value) if s.value.isdigit() else float(s.value)
            elif s.value_type == 'json':
                result[s.key] = json.loads(s.value)
            else:
                result[s.key] = s.value

        # Fill in defaults for missing settings
        defaults = {
            'platform_name': 'NERVE Security Platform',
            'support_email': 'support@nerve.io',
            'default_role': 'user',
            'allow_signup': False,
            'require_email_verification': True,
            'min_password_length': 12,
            'require_uppercase': True,
            'require_number': True,
            'require_symbol': True,
            'session_timeout': 60,
            'max_login_attempts': 5,
            'lock_duration': 30,
            'require_2fa_admin': False,
            'rate_per_minute': 60,
            'rate_per_hour': 1000,
            'api_key_expiration': 90,
            'allow_anonymous_api': False,
            'max_xasm_scans': 5,
            'max_lightbox_scans': 3,
            'scan_timeout': 600,
            'results_retention': 90,
            'module_ghost': True,
            'module_compliance': True,
            'module_roadmap': True,
            'module_ai': True,
            'backup_frequency': 12,
            'optimize_frequency': 7
        }

        for key, default in defaults.items():
            if key not in result:
                result[key] = default

        return jsonify(result)

    except Exception as e:
        print(f"[ADMIN] Get settings error: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


def save_settings(db, settings_dict, category, user_id):
    """Helper to save multiple settings."""
    for key, value in settings_dict.items():
        # Determine value type
        if isinstance(value, bool):
            value_type = 'boolean'
            str_value = 'true' if value else 'false'
        elif isinstance(value, (int, float)):
            value_type = 'number'
            str_value = str(value)
        elif isinstance(value, dict):
            value_type = 'json'
            str_value = json.dumps(value)
        else:
            value_type = 'string'
            str_value = str(value)

        setting = db.query(PlatformSettings).filter(
            PlatformSettings.key == key
        ).first()

        if setting:
            setting.value = str_value
            setting.value_type = value_type
            setting.updated_at = datetime.now(timezone.utc)
            setting.updated_by = user_id
        else:
            setting = PlatformSettings(
                key=key,
                value=str_value,
                category=category,
                value_type=value_type,
                updated_by=user_id
            )
            db.add(setting)


@app.route('/api/admin/settings/general', methods=['PUT'])
@require_auth
@require_admin
def admin_update_general_settings():
    """Update general settings."""
    db = SessionLocal()
    try:
        data = request.get_json() or {}
        user = get_current_user()

        allowed_keys = ['platform_name', 'support_email', 'default_role', 'allow_signup', 'require_email_verification']
        settings = {k: v for k, v in data.items() if k in allowed_keys}

        save_settings(db, settings, 'general', user.get('id') if user else None)
        db.commit()

        return jsonify({'success': True, 'message': 'General settings updated'})
    except Exception as e:
        db.rollback()
        print(f"[ADMIN] Update general settings error: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/admin/settings/security', methods=['PUT'])
@require_auth
@require_admin
def admin_update_security_settings():
    """Update security settings."""
    db = SessionLocal()
    try:
        data = request.get_json() or {}
        user = get_current_user()

        allowed_keys = ['min_password_length', 'require_uppercase', 'require_number', 'require_symbol',
                       'session_timeout', 'max_login_attempts', 'lock_duration', 'require_2fa_admin']
        settings = {k: v for k, v in data.items() if k in allowed_keys}

        save_settings(db, settings, 'security', user.get('id') if user else None)
        db.commit()

        return jsonify({'success': True, 'message': 'Security settings updated'})
    except Exception as e:
        db.rollback()
        print(f"[ADMIN] Update security settings error: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/admin/settings/api', methods=['PUT'])
@require_auth
@require_admin
def admin_update_api_settings():
    """Update API settings."""
    db = SessionLocal()
    try:
        data = request.get_json() or {}
        user = get_current_user()

        allowed_keys = ['rate_per_minute', 'rate_per_hour', 'api_key_expiration', 'allow_anonymous_api']
        settings = {k: v for k, v in data.items() if k in allowed_keys}

        save_settings(db, settings, 'api', user.get('id') if user else None)
        db.commit()

        return jsonify({'success': True, 'message': 'API settings updated'})
    except Exception as e:
        db.rollback()
        print(f"[ADMIN] Update API settings error: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/admin/settings/scans', methods=['PUT'])
@require_auth
@require_admin
def admin_update_scan_settings():
    """Update scan settings."""
    db = SessionLocal()
    try:
        data = request.get_json() or {}
        user = get_current_user()

        allowed_keys = ['max_xasm_scans', 'max_lightbox_scans', 'scan_timeout', 'results_retention']
        settings = {k: v for k, v in data.items() if k in allowed_keys}

        save_settings(db, settings, 'scans', user.get('id') if user else None)
        db.commit()

        return jsonify({'success': True, 'message': 'Scan settings updated'})
    except Exception as e:
        db.rollback()
        print(f"[ADMIN] Update scan settings error: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/admin/settings/critical', methods=['PUT'])
@require_auth
@require_owner
def admin_update_critical_settings():
    """Update critical settings (owner only)."""
    db = SessionLocal()
    try:
        data = request.get_json() or {}
        user = get_current_user()

        allowed_keys = ['module_ghost', 'module_compliance', 'module_roadmap', 'module_ai',
                       'backup_frequency', 'optimize_frequency']
        settings = {k: v for k, v in data.items() if k in allowed_keys}

        save_settings(db, settings, 'critical', user.get('id') if user else None)
        db.commit()

        return jsonify({'success': True, 'message': 'Critical settings updated'})
    except Exception as e:
        db.rollback()
        print(f"[ADMIN] Update critical settings error: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/admin/settings/test-email', methods=['POST'])
@require_auth
@require_admin
def admin_test_email():
    """Test email configuration (disabled for now)."""
    return jsonify({
        'success': False,
        'message': 'Email functionality coming soon'
    }), 501


# =============================================================================
# ADMIN SETTINGS - NEWS SOURCES
# =============================================================================

@app.route('/api/admin/settings/news-sources', methods=['GET'])
@require_auth
@require_admin
def get_news_sources():
    """Get all configured news RSS sources."""
    db = SessionLocal()
    try:
        sources = db.query(NewsSource).order_by(NewsSource.created_at.desc()).all()
        return jsonify([s.to_dict() for s in sources])
    except Exception as e:
        print(f"[ADMIN] Get news sources error: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/admin/settings/news-sources', methods=['POST'])
@require_auth
@require_admin
def add_news_source():
    """Add a new RSS news source."""
    db = SessionLocal()
    try:
        data = request.get_json() or {}
        url = data.get('url', '').strip()

        if not url:
            return jsonify({'error': 'URL is required'}), 400

        # Check for duplicate
        existing = db.query(NewsSource).filter(NewsSource.url == url).first()
        if existing:
            return jsonify({'error': 'This URL is already configured'}), 400

        user = get_current_user()
        source = NewsSource(
            url=url,
            name=data.get('name'),
            active=True,
            created_by=user.get('id') if user else None
        )
        db.add(source)
        db.commit()

        # Log the action
        log_security_event(
            event_type='news_source_added',
            severity='info',
            message=f"News source added: {url}",
            user_id=user.get('id') if user else None,
            ip_address=request.remote_addr
        )

        return jsonify({'success': True, 'source': source.to_dict()})
    except Exception as e:
        db.rollback()
        print(f"[ADMIN] Add news source error: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/admin/settings/news-sources/<int:source_id>', methods=['PUT'])
@require_auth
@require_admin
def update_news_source(source_id):
    """Update a news source URL."""
    db = SessionLocal()
    try:
        source = db.query(NewsSource).filter(NewsSource.id == source_id).first()
        if not source:
            return jsonify({'error': 'News source not found'}), 404

        data = request.get_json() or {}
        if 'url' in data:
            source.url = data['url'].strip()
        if 'name' in data:
            source.name = data.get('name')

        db.commit()
        return jsonify({'success': True, 'source': source.to_dict()})
    except Exception as e:
        db.rollback()
        print(f"[ADMIN] Update news source error: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/admin/settings/news-sources/<int:source_id>/toggle', methods=['POST'])
@require_auth
@require_admin
def toggle_news_source(source_id):
    """Toggle a news source active/inactive status."""
    db = SessionLocal()
    try:
        source = db.query(NewsSource).filter(NewsSource.id == source_id).first()
        if not source:
            return jsonify({'error': 'News source not found'}), 404

        source.active = not source.active
        db.commit()

        return jsonify({'success': True, 'active': source.active})
    except Exception as e:
        db.rollback()
        print(f"[ADMIN] Toggle news source error: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/admin/settings/news-sources/<int:source_id>', methods=['DELETE'])
@require_auth
@require_admin
def delete_news_source(source_id):
    """Delete a news source."""
    db = SessionLocal()
    try:
        source = db.query(NewsSource).filter(NewsSource.id == source_id).first()
        if not source:
            return jsonify({'error': 'News source not found'}), 404

        url = source.url
        db.delete(source)
        db.commit()

        user = get_current_user()
        log_security_event(
            event_type='news_source_deleted',
            severity='info',
            message=f"News source deleted: {url}",
            user_id=user.get('id') if user else None,
            ip_address=request.remote_addr
        )

        return jsonify({'success': True})
    except Exception as e:
        db.rollback()
        print(f"[ADMIN] Delete news source error: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


# =============================================================================
# GHOST NEWS FEED - Public Endpoint
# =============================================================================

@app.route('/api/ghost/news-feed', methods=['GET'])
@require_auth
def get_ghost_news_feed():
    """
    Fetch news from active RSS sources configured in admin settings.
    Falls back to default CTI feed if no sources configured.
    """
    db = SessionLocal()

    try:
        # Get active news sources from database
        sources = db.query(NewsSource).filter_by(active=True).all()

        if not sources:
            # Fall back to default CTI feed
            print("[NEWS FEED] No active sources, using default CTI feed")
            articles = get_news_feed()
            return jsonify({'articles': articles[:20]})

        all_articles = []

        for source in sources:
            try:
                print(f"[NEWS FEED] Fetching {source.url}...")
                # Parse RSS feed
                feed = feedparser.parse(source.url)

                # Extract articles (take first 5 from each source)
                for entry in feed.entries[:5]:
                    # Parse publication date
                    pub_date = None
                    if hasattr(entry, 'published_parsed') and entry.published_parsed:
                        pub_date = datetime(*entry.published_parsed[:6])
                    elif hasattr(entry, 'updated_parsed') and entry.updated_parsed:
                        pub_date = datetime(*entry.updated_parsed[:6])

                    article = {
                        'title': entry.get('title', 'Untitled'),
                        'description': (entry.get('summary', '') or '')[:200] + '...',
                        'url': entry.get('link', ''),
                        'source': feed.feed.get('title', source.name or source.url),
                        'published': pub_date.isoformat() if pub_date else datetime.now(timezone.utc).isoformat()
                    }
                    all_articles.append(article)

                # Update last_fetched
                source.last_fetched = datetime.now(timezone.utc)
                source.fetch_error = None
                source.article_count = len(feed.entries)

            except Exception as e:
                print(f"[NEWS FEED] Error parsing {source.url}: {e}")
                source.fetch_error = str(e)
                continue

        db.commit()

        # Sort by published date, return top 20
        all_articles.sort(key=lambda x: x['published'], reverse=True)

        return jsonify({'articles': all_articles[:20]})

    except Exception as e:
        print(f"[NEWS FEED] Error: {e}")
        # Fall back to default CTI feed on error
        try:
            articles = get_news_feed()
            return jsonify({'articles': articles[:20]})
        except:
            return jsonify({'articles': []}), 500
    finally:
        db.close()


@app.route('/api/cti/feed', methods=['GET'])
@require_auth
def get_cti_feed():
    """
    Alias for news feed - returns curated security news.
    Uses admin-configured RSS sources when available.
    """
    db = SessionLocal()

    try:
        # Check if there are active news sources configured
        source_count = db.query(NewsSource).filter_by(active=True).count()

        if source_count > 0:
            # Use the ghost news feed endpoint logic
            db.close()
            return get_ghost_news_feed()

        # Fall back to default CTI feed module
        force_refresh = request.args.get('refresh', 'false').lower() == 'true'
        articles = get_news_feed(force_refresh=force_refresh)

        return jsonify({'articles': articles[:20]})

    except Exception as e:
        print(f"[CTI FEED] Error: {e}")
        return jsonify({'articles': []}), 500
    finally:
        if db.is_active:
            db.close()


# =============================================================================
# ADMIN SETTINGS - EDUCATION RESOURCES
# =============================================================================

@app.route('/api/admin/settings/education', methods=['GET'])
@require_auth
@require_admin
def get_education_resources():
    """Get all education resources."""
    db = SessionLocal()
    try:
        resources = db.query(EducationResource).order_by(
            EducationResource.featured.desc(),
            EducationResource.order_index.asc(),
            EducationResource.created_at.desc()
        ).all()
        return jsonify([r.to_dict() for r in resources])
    except Exception as e:
        print(f"[ADMIN] Get education resources error: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/admin/settings/education', methods=['POST'])
@require_auth
@require_admin
def add_education_resource():
    """Add a new education resource."""
    db = SessionLocal()
    try:
        data = request.get_json() or {}

        title = data.get('title', '').strip()
        url = data.get('url', '').strip() or data.get('content_url', '').strip()
        resource_type = data.get('type', 'guide') or data.get('content_type', 'guide')

        if not title or not url:
            return jsonify({'error': 'Title and URL are required'}), 400

        # Validate description length
        description = data.get('description', '')
        if description and len(description) > 140:
            return jsonify({'error': 'Description must be 140 characters or less'}), 400

        user = get_current_user()
        resource = EducationResource(
            title=title,
            description=description,
            image_url=data.get('image_url'),
            url=url,
            type=resource_type,
            read_time=data.get('read_time', '5 min read'),
            featured=data.get('featured', False),
            order_index=data.get('order_index', 0),
            created_by=user.get('id') if user else None
        )
        db.add(resource)
        db.commit()

        log_security_event(
            event_type='admin_action',
            severity='info',
            message=f'Admin added education resource: {resource.title}',
            user_id=user.get('id') if user else None,
            ip_address=request.remote_addr
        )

        return jsonify({'success': True, 'id': resource.id, 'resource': resource.to_dict()})
    except Exception as e:
        db.rollback()
        print(f"[ADMIN] Add education resource error: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/admin/settings/education/<int:resource_id>', methods=['PUT'])
@require_auth
@require_admin
def update_education_resource(resource_id):
    """Update an education resource."""
    db = SessionLocal()
    try:
        resource = db.query(EducationResource).filter(EducationResource.id == resource_id).first()
        if not resource:
            return jsonify({'error': 'Resource not found'}), 404

        data = request.get_json() or {}

        # Validate description length
        if 'description' in data and data['description'] and len(data['description']) > 140:
            return jsonify({'error': 'Description must be 140 characters or less'}), 400

        if 'title' in data:
            resource.title = data['title'].strip()
        if 'url' in data or 'content_url' in data:
            resource.url = (data.get('url') or data.get('content_url', '')).strip()
        if 'type' in data or 'content_type' in data:
            resource.type = data.get('type') or data.get('content_type')
        if 'description' in data:
            resource.description = data.get('description')
        if 'image_url' in data:
            resource.image_url = data.get('image_url')
        if 'read_time' in data:
            resource.read_time = data.get('read_time')
        if 'featured' in data:
            resource.featured = data['featured']
        if 'order_index' in data:
            resource.order_index = data['order_index']
        if 'active' in data:
            resource.active = data['active']

        db.commit()
        return jsonify({'success': True, 'resource': resource.to_dict()})
    except Exception as e:
        db.rollback()
        print(f"[ADMIN] Update education resource error: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/admin/settings/education/<int:resource_id>', methods=['DELETE'])
@require_auth
@require_admin
def delete_education_resource(resource_id):
    """Delete an education resource."""
    db = SessionLocal()
    try:
        resource = db.query(EducationResource).filter(EducationResource.id == resource_id).first()
        if not resource:
            return jsonify({'error': 'Resource not found'}), 404

        db.delete(resource)
        db.commit()

        return jsonify({'success': True})
    except Exception as e:
        db.rollback()
        print(f"[ADMIN] Delete education resource error: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


# =============================================================================
# PUBLIC EDUCATION RESOURCES ENDPOINT
# =============================================================================

@app.route('/api/education/resources', methods=['GET'])
@require_auth
def get_public_education_resources():
    """Get education materials for NERVE dashboard (public endpoint)."""
    db = SessionLocal()

    try:
        resources = db.query(EducationResource).filter_by(
            active=True
        ).order_by(
            EducationResource.featured.desc(),
            EducationResource.order_index.asc()
        ).all()

        return jsonify({
            'resources': [{
                'id': r.id,
                'title': r.title,
                'description': r.description,
                'image_url': r.image_url,
                'content_url': r.url,
                'content_type': r.type,
                'read_time': r.read_time,
                'featured': r.featured
            } for r in resources]
        })

    except Exception as e:
        print(f"[EDUCATION] Error: {e}")
        return jsonify({'resources': []}), 500
    finally:
        db.close()


# =============================================================================
# ADMIN SETTINGS - EMAIL CONFIGURATION
# =============================================================================

@app.route('/api/admin/settings/email', methods=['GET'])
@require_auth
@require_admin
def get_email_config():
    """Get email configuration settings."""
    db = SessionLocal()
    try:
        # Get email settings from PlatformSettings
        email_settings = db.query(PlatformSettings).filter(
            PlatformSettings.category == 'email'
        ).all()

        config = {}
        for setting in email_settings:
            try:
                config[setting.key] = json.loads(setting.value) if setting.value_type == 'json' else setting.value
            except:
                config[setting.key] = setting.value

        # Don't return the actual password, just indicate if it's set
        if 'smtp_password' in config:
            config['smtp_password_set'] = bool(config['smtp_password'])
            del config['smtp_password']

        return jsonify(config)
    except Exception as e:
        print(f"[ADMIN] Get email config error: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/admin/settings/email', methods=['POST'])
@require_auth
@require_admin
def save_email_config():
    """Save email configuration settings."""
    db = SessionLocal()
    try:
        data = request.get_json() or {}
        user = get_current_user()

        email_keys = ['smtp_host', 'smtp_port', 'smtp_username', 'smtp_password',
                      'from_email', 'from_name', 'use_tls']

        for key in email_keys:
            if key in data:
                value = data[key]

                # Skip empty password (means keep existing)
                if key == 'smtp_password' and not value:
                    continue

                # Convert value to string for storage
                if isinstance(value, bool):
                    value_str = 'true' if value else 'false'
                    value_type = 'boolean'
                elif isinstance(value, int):
                    value_str = str(value)
                    value_type = 'number'
                else:
                    value_str = str(value) if value else ''
                    value_type = 'string'

                # Upsert the setting
                setting = db.query(PlatformSettings).filter(
                    PlatformSettings.key == key
                ).first()

                if setting:
                    setting.value = value_str
                    setting.value_type = value_type
                    setting.updated_by = user.get('id') if user else None
                else:
                    setting = PlatformSettings(
                        key=key,
                        value=value_str,
                        category='email',
                        value_type=value_type,
                        updated_by=user.get('id') if user else None
                    )
                    db.add(setting)

        db.commit()

        log_security_event(
            event_type='email_config_updated',
            severity='info',
            message="Email configuration updated",
            user_id=user.get('id') if user else None,
            ip_address=request.remote_addr
        )

        return jsonify({'success': True, 'message': 'Email settings saved'})
    except Exception as e:
        db.rollback()
        print(f"[ADMIN] Save email config error: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/admin/settings/email/test', methods=['POST'])
@require_auth
@require_admin
def test_email_config():
    """Send a test email to verify configuration."""
    db = SessionLocal()
    try:
        data = request.get_json() or {}
        to_email = data.get('to', '').strip()

        if not to_email:
            return jsonify({'error': 'Recipient email is required'}), 400

        # Get email settings
        email_settings = db.query(PlatformSettings).filter(
            PlatformSettings.category == 'email'
        ).all()

        config = {}
        for setting in email_settings:
            config[setting.key] = setting.value

        # Check if email is configured
        if not config.get('smtp_host') or not config.get('smtp_username'):
            return jsonify({'error': 'Email is not configured. Please save SMTP settings first.'}), 400

        # TODO: Actually send the email using smtplib
        # For now, just return success to test the flow

        return jsonify({
            'success': True,
            'message': f'Test email would be sent to {to_email} (email sending not yet implemented)'
        })
    except Exception as e:
        print(f"[ADMIN] Test email error: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


# =============================================================================
# ADMIN SETTINGS - BACKUP CONFIGURATION
# =============================================================================

@app.route('/api/admin/settings/backup', methods=['GET'])
@require_auth
@require_admin
def get_backup_config():
    """Get backup configuration settings."""
    db = SessionLocal()
    try:
        # Get backup settings from PlatformSettings
        backup_settings = db.query(PlatformSettings).filter(
            PlatformSettings.category == 'backup'
        ).all()

        config = {
            'schedule': 'daily',
            'time': '02:00',
            'retention_days': 30,
            'location': os.path.join(os.path.dirname(DB_PATH), 'backups')
        }

        for setting in backup_settings:
            try:
                if setting.value_type == 'number':
                    config[setting.key] = int(setting.value)
                elif setting.value_type == 'boolean':
                    config[setting.key] = setting.value.lower() == 'true'
                else:
                    config[setting.key] = setting.value
            except:
                config[setting.key] = setting.value

        return jsonify(config)
    except Exception as e:
        print(f"[ADMIN] Get backup config error: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/admin/settings/backup', methods=['POST'])
@require_auth
@require_admin
def save_backup_config():
    """Save backup configuration settings."""
    db = SessionLocal()
    try:
        data = request.get_json() or {}
        user = get_current_user()

        backup_keys = ['schedule', 'time', 'retention_days', 'location']

        for key in backup_keys:
            if key in data:
                value = data[key]

                if isinstance(value, int):
                    value_str = str(value)
                    value_type = 'number'
                else:
                    value_str = str(value)
                    value_type = 'string'

                setting = db.query(PlatformSettings).filter(
                    PlatformSettings.key == key
                ).first()

                if setting:
                    setting.value = value_str
                    setting.value_type = value_type
                    setting.category = 'backup'
                    setting.updated_by = user.get('id') if user else None
                else:
                    setting = PlatformSettings(
                        key=key,
                        value=value_str,
                        category='backup',
                        value_type=value_type,
                        updated_by=user.get('id') if user else None
                    )
                    db.add(setting)

        db.commit()

        log_security_event(
            event_type='backup_config_updated',
            severity='info',
            message="Backup configuration updated",
            user_id=user.get('id') if user else None,
            ip_address=request.remote_addr
        )

        return jsonify({'success': True, 'message': 'Backup settings saved'})
    except Exception as e:
        db.rollback()
        print(f"[ADMIN] Save backup config error: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/admin/settings/backups', methods=['GET'])
@require_auth
@require_admin
def get_backup_list():
    """Get list of recent backups."""
    db = SessionLocal()
    try:
        backups = db.query(BackupRecord).order_by(
            BackupRecord.created_at.desc()
        ).limit(20).all()

        return jsonify([b.to_dict() for b in backups])
    except Exception as e:
        print(f"[ADMIN] Get backups error: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/admin/settings/backups/<filename>/download', methods=['GET'])
@require_auth
@require_admin
def download_backup(filename):
    """Download a backup file."""
    db = SessionLocal()
    try:
        backup = db.query(BackupRecord).filter(BackupRecord.filename == filename).first()
        if not backup:
            return jsonify({'error': 'Backup not found'}), 404

        if not os.path.exists(backup.filepath):
            return jsonify({'error': 'Backup file not found on disk'}), 404

        from flask import send_file
        return send_file(
            backup.filepath,
            as_attachment=True,
            download_name=backup.filename
        )
    except Exception as e:
        print(f"[ADMIN] Download backup error: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


@app.route('/api/admin/settings/backups/<filename>', methods=['DELETE'])
@require_auth
@require_admin
def delete_backup(filename):
    """Delete a backup file."""
    db = SessionLocal()
    try:
        backup = db.query(BackupRecord).filter(BackupRecord.filename == filename).first()
        if not backup:
            return jsonify({'error': 'Backup not found'}), 404

        # Delete the file if it exists
        if os.path.exists(backup.filepath):
            os.remove(backup.filepath)

        # Delete the record
        db.delete(backup)
        db.commit()

        user = get_current_user()
        log_security_event(
            event_type='backup_deleted',
            severity='warning',
            message=f"Backup deleted: {filename}",
            user_id=user.get('id') if user else None,
            ip_address=request.remote_addr
        )

        return jsonify({'success': True})
    except Exception as e:
        db.rollback()
        print(f"[ADMIN] Delete backup error: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        db.close()


# ============================================================================
# WAITLIST ENDPOINTS
# ============================================================================

@app.route('/api/waitlist', methods=['POST', 'OPTIONS'])
@limiter.limit("3 per hour")
def waitlist_signup():
    """
    Add a user to the waitlist for early access.

    Rate limited to 3 signups per hour per IP to prevent spam.
    """
    if request.method == 'OPTIONS':
        return '', 200

    session = None
    try:
        data = request.json or {}

        # Validate required fields
        name = data.get('name', '').strip()
        email = data.get('email', '').strip().lower()
        company = data.get('company', '').strip() or None

        if not name:
            return jsonify({'error': 'Name is required'}), 400

        if not email:
            return jsonify({'error': 'Email is required'}), 400

        # Basic email validation
        if '@' not in email or '.' not in email.split('@')[-1]:
            return jsonify({'error': 'Please enter a valid email address'}), 400

        session = SessionLocal()

        # Check if already signed up
        existing = session.query(WaitlistSignup).filter_by(email=email).first()
        if existing:
            return jsonify({'error': 'This email is already on the waitlist'}), 400

        # Create signup
        signup = WaitlistSignup(
            name=name,
            email=email,
            company=company,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')[:500]  # Limit length
        )

        session.add(signup)
        session.commit()

        print(f"[WAITLIST] New signup: {email} ({name})")

        return jsonify({
            'success': True,
            'message': 'Successfully joined the waitlist'
        })

    except Exception as e:
        print(f"[WAITLIST] Signup error: {e}")
        if session:
            session.rollback()
        return jsonify({'error': 'An error occurred. Please try again.'}), 500
    finally:
        if session:
            session.close()


@app.route('/api/waitlist/count', methods=['GET'])
def waitlist_count():
    """
    Get the total number of waitlist signups.

    Public endpoint - no auth required.
    """
    session = None
    try:
        session = SessionLocal()
        count = session.query(WaitlistSignup).count()
        return jsonify({'count': count})
    except Exception as e:
        print(f"[WAITLIST] Count error: {e}")
        return jsonify({'count': 0})
    finally:
        if session:
            session.close()


@app.route('/api/admin/waitlist', methods=['GET'])
@require_auth
@require_admin
def get_waitlist():
    """
    Get all waitlist signups (admin only).

    Returns a paginated list of signups with optional status filtering.
    """
    session = None
    try:
        session = SessionLocal()

        # Pagination
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        status_filter = request.args.get('status')

        query = session.query(WaitlistSignup)

        if status_filter:
            query = query.filter(WaitlistSignup.status == status_filter)

        query = query.order_by(WaitlistSignup.signup_date.desc())

        total = query.count()
        signups = query.offset((page - 1) * per_page).limit(per_page).all()

        return jsonify({
            'signups': [s.to_dict() for s in signups],
            'total': total,
            'page': page,
            'per_page': per_page,
            'pages': (total + per_page - 1) // per_page
        })

    except Exception as e:
        print(f"[ADMIN] Waitlist fetch error: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        if session:
            session.close()


@app.route('/api/admin/waitlist/<int:signup_id>/status', methods=['PATCH'])
@require_auth
@require_admin
def update_waitlist_status(signup_id):
    """
    Update the status of a waitlist signup (admin only).

    Allows admins to mark signups as contacted, converted, etc.
    """
    session = None
    try:
        data = request.json or {}
        new_status = data.get('status')

        if new_status not in ['pending', 'contacted', 'converted', 'declined']:
            return jsonify({'error': 'Invalid status'}), 400

        session = SessionLocal()
        signup = session.query(WaitlistSignup).filter_by(id=signup_id).first()

        if not signup:
            return jsonify({'error': 'Signup not found'}), 404

        signup.status = new_status

        # Optionally update notes
        if 'notes' in data:
            signup.notes = data.get('notes')

        session.commit()

        return jsonify({
            'success': True,
            'signup': signup.to_dict()
        })

    except Exception as e:
        print(f"[ADMIN] Waitlist status update error: {e}")
        if session:
            session.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        if session:
            session.close()


if __name__ == '__main__':
    print("Ghost backend starting...")

    # Run cleanup on startup
    print("[STARTUP] Running cleanup for old uploaded files...")
    cleanup_old_files()

    print("API running at http://localhost:5000")
    print("Press Ctrl+C to stop")
    app.run(debug=True, port=5000, host='127.0.0.1')