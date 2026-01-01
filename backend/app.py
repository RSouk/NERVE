from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from database import get_db, SessionLocal, Profile, SocialMedia, Breach, Device, BaitToken, BaitAccess, UploadedFile, UploadedCredential, GitHubFinding, PasteBinFinding, OpsychSearchResult, ASMScan, CachedASMScan, LightboxScan, save_xasm_for_ai, save_lightbox_for_ai, get_companies_with_scans, cleanup_expired_ai_scans
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
CORS(app, resources={r"/api/*": {"origins": "*", "methods": ["GET", "POST", "DELETE", "OPTIONS"], "allow_headers": ["Content-Type"]}})

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
def search():
    """Search for existing profiles"""
    query = request.args.get('q', '')
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
def unified_search_endpoint():
    """Unified search across all data sources"""
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
def analyze_adversary():
    """Analyze threat landscape based on organization profile"""
    try:
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
def asm_scan():
    """
    Attack Surface Management scan for a domain with caching and progress tracking
    Performs subdomain discovery, Shodan search, and DNS enumeration

    Returns cached results if scan < 24 hours old, unless force_rescan=true
    """
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
def lightbox_scan():
    """Run Lightbox security scan and save results to database"""
    session = SessionLocal()
    try:
        data = request.json
        domain = data.get('domain')
        scan_id = data.get('scan_id')

        logger.info(f"[LIGHTBOX API] Starting scan for {domain} (XASM scan ID: {scan_id})")

        if not domain or not scan_id:
            return jsonify({'error': 'Missing domain or scan_id parameter'}), 400

        # Get XASM scan results from database
        asm_scan = session.query(CachedASMScan).filter_by(id=scan_id).first()

        if not asm_scan:
            logger.error(f"[LIGHTBOX API] XASM scan {scan_id} not found")
            return jsonify({'error': 'XASM scan not found. Please run an XASM scan first.'}), 404

        # Import and run Lightbox scanner
        from modules.ghost.lightbox_scanner import run_lightbox_scan

        # Generate scan key for progress tracking
        scan_key = f"{domain}_{int(time.time())}"

        # Define progress callback function
        def update_progress(progress_data):
            """Update global progress dictionary with scan status"""
            with scan_progress_lock:
                scan_progress[scan_key] = progress_data
            logger.info(f"[LIGHTBOX PROGRESS] {progress_data.get('current_step')} - {progress_data.get('progress')}%")

        logger.info(f"[LIGHTBOX API] Running Lightbox scan with progress tracking (key: {scan_key})...")
        scan_results = run_lightbox_scan(asm_scan.scan_results, domain, update_progress)

        # Extract findings from the dictionary structure
        # run_lightbox_scan returns: {'critical': [], 'high': [], 'medium': [], 'low': [], 'info': [], ...}
        if isinstance(scan_results, dict):
            # Extract severity counts from the dict structure
            critical_findings = scan_results.get('critical', [])
            high_findings = scan_results.get('high', [])
            medium_findings = scan_results.get('medium', [])
            low_findings = scan_results.get('low', [])
            info_findings = scan_results.get('info', [])

            critical = len(critical_findings)
            high = len(high_findings)
            medium = len(medium_findings)
            low = len(low_findings)

            # Flatten all findings into a single list for storage
            all_findings = critical_findings + high_findings + medium_findings + low_findings + info_findings
            total_findings = len(all_findings)

            logger.info(f"[LIGHTBOX API] Scan complete - {total_findings} findings (C:{critical}, H:{high}, M:{medium}, L:{low})")
        else:
            logger.error(f"[LIGHTBOX API] ERROR: Expected dict but got {type(scan_results)}")
            # Fallback: treat as empty results
            all_findings = []
            total_findings = 0
            critical = high = medium = low = 0

        # Save to database - Convert to JSON strings for SQLite compatibility
        lightbox_record = LightboxScan(
            domain=domain,
            total_findings=total_findings,
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            findings=json.dumps(all_findings),  # Convert list to JSON string
            scan_metadata=json.dumps({  # Convert dict to JSON string
                'asm_scan_id': scan_id,
                'assets_tested': len(asm_scan.scan_results.get('subdomains', [])),
                'checks_run': scan_results.get('total_tests', 915) if isinstance(scan_results, dict) else 915,
                'templates_used': scan_results.get('templates_used', 1) if isinstance(scan_results, dict) else 1
            })
        )

        session.add(lightbox_record)
        session.commit()
        session.refresh(lightbox_record)  # Get the ID

        logger.info(f"[LIGHTBOX API] Saved to database with ID {lightbox_record.id}")

        # Save Lightbox results for AI report generation
        try:
            save_lightbox_for_ai(domain, scan_results)
        except Exception as e:
            logger.warning(f"[LIGHTBOX] Failed to save for AI report: {e}")
            # Don't fail the scan if storage fails

        # Clean up progress tracking
        with scan_progress_lock:
            if scan_key in scan_progress:
                del scan_progress[scan_key]
                logger.info(f"[LIGHTBOX API] Cleaned up progress tracking for {scan_key}")

        # Extract test_results from scan_results (comprehensive tracking structure for frontend cards)
        test_results = scan_results.get('test_results', {}) if isinstance(scan_results, dict) else {}

        return jsonify({
            'success': True,
            'scan_id': lightbox_record.id,
            'scan_key': scan_key,  # Return for frontend progress tracking
            'findings': all_findings,  # Return as list to frontend
            'scan_metadata': json.loads(lightbox_record.scan_metadata),  # Parse JSON string for response
            'test_results': test_results,  # NEW: Include comprehensive test tracking for frontend cards
            'nuclei_results': {
                'findings': scan_results.get('info', []),
                'templates_used': scan_results.get('templates_used', 500)
            },
            'summary': {
                'total': total_findings,
                'critical': critical,
                'high': high,
                'medium': medium,
                'low': low
            }
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

# ============================================================================
# LIGHTBOX SCAN HISTORY ENDPOINTS
# ============================================================================

@app.route('/api/lightbox/history', methods=['GET'])
def get_lightbox_history_endpoint():
    """Get Lightbox scan history"""
    from database import get_lightbox_scan_history

    try:
        history = get_lightbox_scan_history()
        return jsonify({'success': True, 'history': history})
    except Exception as e:
        logger.error(f"[LIGHTBOX HISTORY] Error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/lightbox/history/<scan_id>', methods=['GET'])
def get_lightbox_scan_details(scan_id):
    """Get full Lightbox scan results by ID"""
    from database import get_lightbox_scan_by_id

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
def delete_lightbox_scan_history_endpoint(scan_id):
    """Delete Lightbox scan from history"""
    from database import delete_lightbox_scan_history

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

if __name__ == '__main__':
    print("Ghost backend starting...")

    # Run cleanup on startup
    print("[STARTUP] Running cleanup for old uploaded files...")
    cleanup_old_files()

    print("API running at http://localhost:5000")
    print("Press Ctrl+C to stop")
    app.run(debug=True, port=5000, host='127.0.0.1')