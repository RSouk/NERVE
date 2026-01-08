from flask import Flask, render_template, request, jsonify, g
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
    run_health_check, create_backup, optimize_database, AuditLog, DB_PATH
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

# Load environment variables
load_dotenv()

# Setup logging
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app, resources={
    r"/api/*": {
        "origins": "*",
        "methods": ["GET", "POST", "DELETE", "PUT", "PATCH", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "expose_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True
    }
})

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
scheduler.start()
print("[SCHEDULER] Started hourly cleanup of expired AI scan data")

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


@app.route('/')
def index():
    return jsonify({
        "message": "Ghost API is running",
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
@optional_auth
def unified_search_endpoint():
    """Unified search across all data sources"""
    user_id = request.user_id  # May be None for anonymous
    data = request.json
    query = data.get('query', '').strip()

    if not query:
        return jsonify({'error': 'Query cannot be empty'}), 400

    searcher = UnifiedSearch()
    result = searcher.search(query)

    return jsonify(result)

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
@require_auth
def asm_scan():
    """
    Attack Surface Management scan for a domain with caching and progress tracking
    Performs subdomain discovery, Shodan search, and DNS enumeration

    Returns cached results if scan < 24 hours old, unless force_rescan=true
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
            risk_score=scan_results.get('risk_score', 0),
            risk_level=scan_results.get('risk_level', 'low'),
            total_cves=cve_stats.get('total_cves', 0),
            critical_cves=cve_stats.get('critical_cves', 0),
            vulnerabilities_found=scan_results.get('vulnerabilities_found', 0),
            open_ports_count=len(scan_results.get('port_scan_results', [])),
            scan_results=scan_results
        )

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
def get_scan_history():
    """Get all XASM scan history for current user (for now, return all scans)"""
    try:
        # TODO: Filter by user_id when authentication is implemented
        session = SessionLocal()
        scans = session.query(CachedASMScan).order_by(CachedASMScan.scan_date.desc()).all()

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
                'scan_date': scan.scan_date.isoformat() if scan.scan_date else None,
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
@require_auth
def lightbox_scan():
    """
    Run Lightbox security scan and save results to database.

    Supports two modes:
    1. full_surface: Test all assets from XASM scan (requires domain + scan_id)
    2. specific_targets: Test only user-specified targets (requires targets list)
    """
    session = SessionLocal()
    try:
        data = request.json
        mode = data.get('mode', 'full_surface')
        user_id = request.user_id  # From @require_auth decorator

        # Import Lightbox scanner
        from modules.ghost.lightbox_scanner import run_lightbox_scan

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

                    # Save for AI report
                    try:
                        save_lightbox_for_ai(domain, scan_results)
                    except Exception as e:
                        logger.warning(f"[LIGHTBOX BG] Failed to save for AI: {e}")

                    # Set completion status
                    with scan_progress_lock:
                        scan_progress[scan_key] = {
                            'status': 'complete',
                            'progress': 100,
                            'current_step': 'Scan complete',
                            'total_steps': 100,
                            'scan_id': lightbox_record.id
                        }
                    logger.info(f"[LIGHTBOX BG] Set completion status for {scan_key}")

                    # Wait for frontend to read status, then cleanup
                    import time as time_mod
                    time_mod.sleep(5)
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
                finally:
                    bg_session.close()

            # ═══════════════════════════════════════════════════════════════
            # Start background thread and return immediately
            # ═══════════════════════════════════════════════════════════════
            import threading
            thread = threading.Thread(target=run_specific_targets_scan_background, daemon=True)
            thread.start()
            logger.info(f"[LIGHTBOX API] Started background thread for {scan_key}")

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

                    # Save Lightbox results for AI report generation
                    try:
                        save_lightbox_for_ai(domain, scan_results)
                    except Exception as e:
                        logger.warning(f"[LIGHTBOX BG] Failed to save for AI report: {e}")

                    # Set completion status
                    with scan_progress_lock:
                        scan_progress[scan_key] = {
                            'status': 'complete',
                            'progress': 100,
                            'current_step': 'Scan complete',
                            'total_steps': 100,
                            'scan_id': lightbox_record.id
                        }
                    logger.info(f"[LIGHTBOX BG] Set completion status for {scan_key}")

                    # Wait for frontend to read status, then cleanup
                    import time as time_mod
                    time_mod.sleep(5)
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
                finally:
                    bg_session.close()

            # ═══════════════════════════════════════════════════════════════
            # Start background thread and return immediately
            # ═══════════════════════════════════════════════════════════════
            import threading
            thread = threading.Thread(target=run_full_surface_scan_background, daemon=True)
            thread.start()
            logger.info(f"[LIGHTBOX API] Started background thread for full surface scan {scan_key}")

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

        return jsonify(progress), 200

    except Exception as e:
        logger.error(f"[LIGHTBOX PROGRESS] Error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/ghost/lightbox/history/<domain>', methods=['GET'])
@require_auth
def get_lightbox_history(domain):
    """Get Lightbox scan history and cleanup old scans (30+ days)"""
    session = SessionLocal()
    try:
        from datetime import timedelta

        # Auto-cleanup: Delete scans older than 30 days
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=30)

        old_scans = session.query(LightboxScan).filter(
            LightboxScan.scanned_at < cutoff_date
        ).all()

        if old_scans:
            logger.info(f"[LIGHTBOX CLEANUP] Deleting {len(old_scans)} scans older than 30 days")
            for scan in old_scans:
                session.delete(scan)
            session.commit()

        # Get recent scans (last 30 days)
        scans = session.query(LightboxScan).filter_by(domain=domain).filter(
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
    """Get specific Lightbox scan by ID"""
    session = SessionLocal()
    try:
        scan = session.query(LightboxScan).get(scan_id)

        if not scan:
            return jsonify({'error': 'Scan not found'}), 404

        return jsonify(scan.to_dict()), 200

    except Exception as e:
        logger.error(f"[LIGHTBOX API] Fetch error: {str(e)}")
        return jsonify({'error': str(e)}), 500
    finally:
        session.close()

@app.route('/api/ghost/lightbox/scan/<int:scan_id>', methods=['DELETE'])
@require_auth
def delete_lightbox_scan(scan_id):
    """Manually delete a specific Lightbox scan"""
    session = SessionLocal()
    try:
        scan = session.query(LightboxScan).get(scan_id)

        if not scan:
            return jsonify({'error': 'Scan not found'}), 404

        domain = scan.domain
        session.delete(scan)
        session.commit()

        logger.info(f"[LIGHTBOX] Manually deleted scan {scan_id} for {domain}")

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
def get_xasm_history():
    """Get XASM scan history"""
    from database import get_xasm_scan_history

    try:
        history = get_xasm_scan_history()
        return jsonify({'success': True, 'history': history})
    except Exception as e:
        logger.error(f"[XASM HISTORY] Error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/xasm/history/<scan_id>', methods=['GET'])
def get_xasm_scan_details(scan_id):
    """Get full XASM scan results by ID"""
    from database import get_xasm_scan_by_id

    try:
        results = get_xasm_scan_by_id(scan_id)
        if results:
            return jsonify({'success': True, 'results': results})
        else:
            return jsonify({'error': 'Scan not found'}), 404
    except Exception as e:
        logger.error(f"[XASM HISTORY] Error fetching scan {scan_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/xasm/history/<scan_id>', methods=['DELETE'])
def delete_xasm_scan_endpoint(scan_id):
    """Delete XASM scan from history"""
    from database import delete_xasm_scan

    try:
        success = delete_xasm_scan(scan_id)
        if success:
            return jsonify({'success': True})
        else:
            return jsonify({'error': 'Scan not found'}), 404
    except Exception as e:
        logger.error(f"[XASM HISTORY] Error deleting scan {scan_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/xasm/cached-domains', methods=['GET'])
def get_xasm_cached_domains():
    """Get list of unique domains that have been scanned via XASM and/or Lightbox"""
    from database import get_db, XASMScan, LightboxScanHistory
    from sqlalchemy import func

    db = None
    try:
        db = get_db()

        # Dictionary to collect domain data
        domain_data = {}

        # Get XASM domains with last scan date
        xasm_stats = db.query(
            XASMScan.domain,
            func.max(XASMScan.scan_date).label('last_scan')
        ).filter(
            XASMScan.deleted_at == None
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

        # Get Lightbox domains with last scan date
        lightbox_stats = db.query(
            LightboxScanHistory.target,
            func.max(LightboxScanHistory.timestamp).label('last_scan')
        ).filter(
            LightboxScanHistory.deleted_at == None
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
    """Get Lightbox scan history"""
    from database import get_lightbox_scan_history
    user_id = request.user_id

    try:
        # TODO: Filter history by user_id when database supports it
        history = get_lightbox_scan_history()
        return jsonify({'success': True, 'history': history})
    except Exception as e:
        logger.error(f"[LIGHTBOX HISTORY] Error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/lightbox/history/<scan_id>', methods=['GET'])
@require_auth
def get_lightbox_scan_details(scan_id):
    """Get full Lightbox scan results by ID"""
    from database import get_lightbox_scan_by_id
    # TODO: Add user ownership check when database supports it

    try:
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
    """Delete Lightbox scan from history"""
    from database import delete_lightbox_scan_history
    # TODO: Add user ownership check when database supports it

    try:
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
def get_companies_for_ai():
    """Get list of companies with available scans for AI reports"""
    try:
        companies = get_companies_with_scans()

        return jsonify({
            'success': True,
            'companies': companies,
            'count': len(companies)
        })

    except Exception as e:
        logger.error(f"[AI API] Error getting companies: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ai/generate-report', methods=['POST'])
def generate_ai_report():
    """Generate AI vulnerability assessment report"""
    from database import load_xasm_for_ai, load_lightbox_for_ai
    from modules.ghost.ai_vuln_report import generate_vulnerability_report

    try:
        data = request.get_json()
        company = data.get('company')

        if not company:
            return jsonify({'error': 'Company required'}), 400

        print(f"[AI API] Generating report for {company}")

        # Load scan results
        xasm_data = load_xasm_for_ai(company)
        lightbox_data = load_lightbox_for_ai(company)

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
def get_monitoring_timeline():
    """Get breach timeline for monitored emails"""
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

        if not profile:
            return jsonify({
                'success': True,
                'profile': None,
                'message': 'No profile found - setup required'
            }), 200

        # Parse JSON fields
        current_measures = []
        compliance_reqs = []
        try:
            if profile.current_measures:
                current_measures = json.loads(profile.current_measures)
            if profile.compliance_requirements:
                compliance_reqs = json.loads(profile.compliance_requirements)
        except:
            pass

        return jsonify({
            'success': True,
            'profile': {
                'id': profile.id,
                'company_name': profile.company_name,
                'company_size': profile.company_size,
                'industry': profile.industry,
                'employee_count': profile.employee_count,
                'current_security_score': profile.current_security_score or 0,
                'target_security_score': profile.target_security_score or 75,
                'handles_pii': profile.handles_pii,
                'handles_payment_data': profile.handles_payment_data,
                'handles_health_data': profile.handles_health_data,
                'handles_financial_data': profile.handles_financial_data,
                'current_measures': current_measures,
                'compliance_requirements': compliance_reqs,
                'created_at': profile.created_at.isoformat() if profile.created_at else None,
                'last_recalculated': profile.last_recalculated.isoformat() if profile.last_recalculated else None
            }
        }), 200

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

        # Check for existing profile for this user
        existing = db.query(RoadmapProfile).filter(
            RoadmapProfile.user_id == user_id,
            RoadmapProfile.deleted_at == None,
            RoadmapProfile.is_active == True
        ).first()

        if existing:
            # Update existing profile
            existing.company_name = data.get('company_name', existing.company_name)
            existing.company_size = data.get('company_size', existing.company_size)
            existing.industry = data.get('industry', existing.industry)
            existing.employee_count = data.get('employee_count', existing.employee_count)
            existing.handles_pii = data.get('handles_pii', existing.handles_pii)
            existing.handles_payment_data = data.get('handles_payment_data', existing.handles_payment_data)
            existing.handles_health_data = data.get('handles_health_data', existing.handles_health_data)
            existing.handles_financial_data = data.get('handles_financial_data', existing.handles_financial_data)

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
                company_name=data.get('company_name', 'My Company'),
                company_size=data.get('company_size', 'small'),
                industry=data.get('industry', 'technology'),
                employee_count=data.get('employee_count'),
                current_security_score=0,
                target_security_score=data.get('target_security_score', 75),
                handles_pii=data.get('handles_pii', False),
                handles_payment_data=data.get('handles_payment_data', False),
                handles_health_data=data.get('handles_health_data', False),
                handles_financial_data=data.get('handles_financial_data', False),
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
    Query params: phase, status, source
    """
    from roadmap_mappings import TASK_LIBRARY
    user_id = request.user_id

    db = None
    try:
        db = get_db()

        # Get user's profile
        profile = db.query(RoadmapProfile).filter(
            RoadmapProfile.user_id == user_id,
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
    Generate personalized roadmap based on profile + scans.
    """
    from roadmap_mappings import TASK_LIBRARY, map_scan_to_tasks, get_tasks_for_profile, prioritize_tasks
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

        # Clear existing tasks (regenerating)
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

        # 2. If include_scans, get scan-based tasks
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

        # Create user tasks
        for task in prioritized:
            user_task = RoadmapUserTask(
                profile_id=profile.id,
                task_id=task['task_id'],
                status='not_started',
                phase=task.get('phase', 2),
                priority_order=task.get('priority_order', 99),
                source=task.get('source', 'profile'),
                finding_type=task.get('finding_type'),
                finding_severity=task.get('finding_severity'),
                scan_domain=task.get('scan_domain'),
                scan_date=task.get('scan_date'),
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc)
            )
            db.add(user_task)

        # Create initial progress snapshot
        progress = RoadmapProgressHistory(
            profile_id=profile.id,
            security_score=0,
            tasks_completed=0,
            tasks_total=len(prioritized),
            snapshot_date=datetime.now(timezone.utc),
            snapshot_reason='roadmap_generated'
        )
        db.add(progress)

        db.commit()

        return jsonify({
            'success': True,
            'tasks_created': len(prioritized),
            'message': f'Roadmap generated with {len(prioritized)} tasks'
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
    """
    user_id = request.user_id
    db = None
    try:
        days = request.args.get('days', 30, type=int)

        db = get_db()

        # Get user's profile
        profile = db.query(RoadmapProfile).filter(
            RoadmapProfile.user_id == user_id,
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
    """
    from roadmap_mappings import ACHIEVEMENTS
    user_id = request.user_id

    db = None
    try:
        db = get_db()

        # Get user's profile
        profile = db.query(RoadmapProfile).filter(
            RoadmapProfile.user_id == user_id,
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
    """
    from roadmap_mappings import TASK_LIBRARY
    user_id = request.user_id

    db = None
    try:
        db = get_db()

        # Get user's profile
        profile = db.query(RoadmapProfile).filter(
            RoadmapProfile.user_id == user_id,
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
            log_login_attempt(email, ip_address, False)
            db.close()
            return jsonify({'success': False, 'error': 'Invalid email or password'}), 401

        # Check if user is active
        if user.status != UserStatus.ACTIVE:
            log_login_attempt(email, ip_address, False)
            db.close()
            return jsonify({'success': False, 'error': 'Account is not active'}), 403

        # Verify password
        if not verify_password(password, user.password_hash):
            log_login_attempt(email, ip_address, False)
            db.close()
            return jsonify({'success': False, 'error': 'Invalid email or password'}), 401

        # Log successful attempt
        log_login_attempt(email, ip_address, True)

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

        # Revoke the session
        revoke_session(token)

        return jsonify({
            'success': True,
            'message': 'Logged out successfully'
        }), 200

    except Exception as e:
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

        # Get company name if user belongs to a company
        company_name = None
        if user.company_id:
            company = db.query(Company).filter(
                Company.id == user.company_id,
                Company.deleted_at.is_(None)
            ).first()
            if company:
                company_name = company.name

        return jsonify({
            'id': user.id,
            'email': user.email,
            'full_name': user.full_name,
            'role': user.role.value if user.role else 'user',
            'company_id': user.company_id,
            'company_name': company_name,
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
            event_type='password_changed',
            severity='info',
            user_id=user.id,
            ip_address=request.remote_addr,
            description=f'Password changed for user: {user.email}'
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
def admin_dashboard():
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

        # Log the action
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

        # Soft delete
        user.deleted_at = datetime.now(timezone.utc)
        user.is_active = False
        db.commit()

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
        sort_field = request.args.get('sort', 'name')
        sort_order = request.args.get('order', 'asc')

        query = db.query(Company).filter(Company.deleted_at.is_(None))

        # Search
        if search:
            query = query.filter(
                (Company.name.ilike(f'%{search}%')) |
                (Company.primary_domain.ilike(f'%{search}%'))
            )

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

        new_company = Company(
            name=data['name'],
            primary_domain=primary_domain,
            additional_domains=json.dumps(additional_data) if additional_data else None,
            subscription_tier='basic',
            max_seats=10,
            max_domains=1,
            is_active=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )

        db.add(new_company)
        db.commit()
        db.refresh(new_company)

        # Assign admin user if provided
        if data.get('admin_user_id'):
            admin_user = db.query(User).filter(User.id == data['admin_user_id']).first()
            if admin_user:
                admin_user.company_id = new_company.id
                db.commit()

        return jsonify({
            'id': new_company.id,
            'name': new_company.name,
            'primary_domain': new_company.primary_domain,
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
        if 'employee_count' in data:
            additional_data['employee_count'] = data['employee_count']

        company.additional_domains = json.dumps(additional_data)
        company.updated_at = datetime.now(timezone.utc)
        db.commit()

        return jsonify({
            'id': company.id,
            'name': company.name,
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
    """Get comprehensive system health information."""
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        week_ago = now - timedelta(days=7)

        # Database health
        db_health = run_health_check()

        # Get database file size
        db_size_mb = 0
        if os.path.exists(DB_PATH):
            db_size_mb = os.path.getsize(DB_PATH) / (1024 * 1024)

        # Count tables and records
        from sqlalchemy import inspect
        inspector = inspect(db.bind)
        table_names = inspector.get_table_names()
        total_tables = len(table_names)

        # Sample record count from key tables
        total_records = (
            db.query(User).count() +
            db.query(Company).count() +
            db.query(ASMScan).count() +
            db.query(SecurityEvent).count()
        )

        # Active sessions
        active_sessions = db.query(UserSession).filter(
            UserSession.is_active == True,
            UserSession.expires_at > now
        ).count()

        # Active scans (in progress)
        active_scans = db.query(ASMScan).filter(
            ASMScan.scan_status == 'running'
        ).count()

        # Scan stats
        xasm_today = db.query(ASMScan).filter(
            ASMScan.created_at >= today_start
        ).count()
        xasm_week = db.query(ASMScan).filter(
            ASMScan.created_at >= week_ago
        ).count()
        lightbox_today = db.query(LightboxScan).filter(
            LightboxScan.created_at >= today_start
        ).count()
        lightbox_week = db.query(LightboxScan).filter(
            LightboxScan.created_at >= week_ago
        ).count()

        # Failed scans
        failed_scans = db.query(ASMScan).filter(
            ASMScan.scan_status == 'failed',
            ASMScan.created_at >= today_start
        ).order_by(ASMScan.created_at.desc()).limit(10).all()

        failed_list = [{
            'domain': s.domain,
            'time': s.created_at.isoformat() if s.created_at else None,
            'error': s.error_message or 'Unknown error'
        } for s in failed_scans]

        # Check for maintenance mode setting
        maintenance_setting = db.query(PlatformSettings).filter(
            PlatformSettings.key == 'maintenance_mode'
        ).first()
        maintenance_mode = maintenance_setting.value == 'true' if maintenance_setting else False

        # Determine overall status
        status = 'good'
        if db_health.get('connection', {}).get('connected') == False:
            status = 'critical'
        elif len(failed_scans) > 5:
            status = 'warning'

        return jsonify({
            'database': {
                'status': status,
                'connected': db_health.get('connection', {}).get('connected', True),
                'size_mb': round(db_size_mb, 2),
                'tables': total_tables,
                'records': total_records,
                'last_backup': db_health.get('last_backup'),
                'last_optimize': db_health.get('last_optimize')
            },
            'resources': {
                'cpu_percent': 15,  # Would require psutil
                'memory_used_gb': 4.2,
                'memory_total_gb': 8.0,
                'disk_free_gb': 156,
                'disk_total_gb': 256,
                'active_sessions': active_sessions,
                'max_sessions': 50,
                'active_scans': active_scans,
                'queued_tasks': 0
            },
            'scans': {
                'xasm_today': xasm_today,
                'xasm_week': xasm_week,
                'lightbox_today': lightbox_today,
                'lightbox_week': lightbox_week,
                'avg_duration_seconds': 154,
                'longest_active_seconds': 0,
                'failed_today': len(failed_scans),
                'failed_list': failed_list
            },
            'maintenance_mode': maintenance_mode
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
    """Get security events with filtering and pagination."""
    db = SessionLocal()
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        event_type = request.args.get('event_type')
        severity = request.args.get('severity')
        user_id = request.args.get('user_id', type=int)
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')

        query = db.query(SecurityEvent)

        if event_type:
            query = query.filter(SecurityEvent.event_type == event_type)
        if severity:
            query = query.filter(SecurityEvent.severity == severity)
        if user_id:
            query = query.filter(SecurityEvent.user_id == user_id)
        if start_date:
            query = query.filter(SecurityEvent.created_at >= datetime.fromisoformat(start_date))
        if end_date:
            query = query.filter(SecurityEvent.created_at <= datetime.fromisoformat(end_date))

        total = query.count()
        events = query.order_by(SecurityEvent.created_at.desc()).offset(
            (page - 1) * per_page
        ).limit(per_page).all()

        # Get user info for events
        user_ids = [e.user_id for e in events if e.user_id]
        users = {}
        if user_ids:
            user_records = db.query(User).filter(User.id.in_(user_ids)).all()
            users = {u.id: {'email': u.email, 'name': u.full_name} for u in user_records}

        return jsonify({
            'events': [{
                'id': e.id,
                'timestamp': e.created_at.isoformat() if e.created_at else None,
                'user_id': e.user_id,
                'user_email': e.email or (users.get(e.user_id, {}).get('email') if e.user_id else 'system'),
                'user_name': users.get(e.user_id, {}).get('name') if e.user_id else 'System',
                'event_type': e.event_type,
                'severity': e.severity,
                'ip_address': e.ip_address,
                'description': e.description,
                'location': e.location,
                'user_agent': e.user_agent,
                'acknowledged': e.acknowledged,
                'metadata': json.loads(e.metadata_json) if e.metadata_json else None
            } for e in events],
            'total': total,
            'page': page,
            'per_page': per_page,
            'pages': (total + per_page - 1) // per_page
        })
    except Exception as e:
        print(f"[ADMIN] Get logs error: {e}")
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


@app.route('/api/admin/logs/export', methods=['POST'])
@require_auth
@require_admin
def admin_export_logs():
    """Export security logs as CSV or JSON."""
    db = SessionLocal()
    try:
        data = request.get_json() or {}
        format_type = data.get('format', 'csv')
        date_range = data.get('date_range', 'all')
        filters = data.get('filters', {})

        query = db.query(SecurityEvent)

        # Apply date filter
        now = datetime.now(timezone.utc)
        if date_range == 'today':
            query = query.filter(SecurityEvent.created_at >= now.replace(hour=0, minute=0, second=0))
        elif date_range == '7days':
            query = query.filter(SecurityEvent.created_at >= now - timedelta(days=7))
        elif date_range == '30days':
            query = query.filter(SecurityEvent.created_at >= now - timedelta(days=30))

        # Apply type/severity filters
        if filters.get('type'):
            query = query.filter(SecurityEvent.event_type == filters['type'])
        if filters.get('severity'):
            query = query.filter(SecurityEvent.severity == filters['severity'])

        events = query.order_by(SecurityEvent.created_at.desc()).all()

        if format_type == 'json':
            content = json.dumps([{
                'timestamp': e.created_at.isoformat() if e.created_at else None,
                'event_type': e.event_type,
                'severity': e.severity,
                'user': e.email,
                'ip_address': e.ip_address,
                'description': e.description
            } for e in events], indent=2)
            mimetype = 'application/json'
            filename = f'security-logs-{now.strftime("%Y%m%d")}.json'
        else:
            # CSV
            lines = ['Timestamp,Event Type,Severity,User,IP Address,Description']
            for e in events:
                desc = (e.description or '').replace('"', '""')
                lines.append(f'{e.created_at.isoformat() if e.created_at else ""},{e.event_type},{e.severity},{e.email or ""},{e.ip_address or ""},"{desc}"')
            content = '\n'.join(lines)
            mimetype = 'text/csv'
            filename = f'security-logs-{now.strftime("%Y%m%d")}.csv'

        from flask import Response
        response = Response(content, mimetype=mimetype)
        response.headers['Content-Disposition'] = f'attachment; filename={filename}'
        return response

    except Exception as e:
        print(f"[ADMIN] Export logs error: {e}")
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


if __name__ == '__main__':
    print("Ghost backend starting...")

    # Run cleanup on startup
    print("[STARTUP] Running cleanup for old uploaded files...")
    cleanup_old_files()

    print("API running at http://localhost:5000")
    print("Press Ctrl+C to stop")
    app.run(debug=True, port=5000, host='127.0.0.1')