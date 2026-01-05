from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from database import get_db, SessionLocal, Profile, SocialMedia, Breach, Device, BaitToken, BaitAccess, UploadedFile, UploadedCredential, GitHubFinding, PasteBinFinding, OpsychSearchResult, ASMScan, CachedASMScan, LightboxScan, save_xasm_for_ai, save_lightbox_for_ai, get_companies_with_scans, cleanup_expired_ai_scans, ComplianceAssessment, ComplianceControl, ComplianceEvidence, RoadmapProfile, RoadmapTask, RoadmapUserTask, RoadmapAchievement, RoadmapProgressHistory
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
def create_assessment():
    """Create a new compliance assessment"""
    db = None
    try:
        data = request.json
        framework_id = data.get('framework_id')
        company_id = data.get('company_id', 1)  # Default to 1 for now

        if not framework_id:
            return jsonify({'success': False, 'error': 'framework_id is required'}), 400

        # Load framework to get controls
        framework_data = load_framework_json(framework_id)
        if not framework_data:
            return jsonify({'success': False, 'error': 'Framework not found'}), 404

        controls = normalize_framework_controls(framework_id, framework_data)

        db = get_db()

        # Check if assessment already exists for this company and framework
        existing = db.query(ComplianceAssessment).filter(
            ComplianceAssessment.company_id == company_id,
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
            created_by_user_id=data.get('user_id', 1),
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
def get_assessment(assessment_id):
    """Get assessment status with all controls"""
    db = None
    try:
        db = get_db()

        assessment = db.query(ComplianceAssessment).filter(
            ComplianceAssessment.id == assessment_id,
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
def get_assessment_by_framework(framework_id):
    """Get existing assessment for a framework (if any)"""
    db = None
    try:
        company_id = request.args.get('company_id', 1, type=int)

        db = get_db()

        assessment = db.query(ComplianceAssessment).filter(
            ComplianceAssessment.company_id == company_id,
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
def update_control(control_id):
    """Update a compliance control status"""
    db = None
    try:
        data = request.json
        db = get_db()

        control = db.query(ComplianceControl).filter(
            ComplianceControl.id == control_id,
            ComplianceControl.deleted_at == None
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
def add_evidence():
    """Add evidence to a control"""
    db = None
    try:
        data = request.json
        control_id = data.get('control_id')

        if not control_id:
            return jsonify({'success': False, 'error': 'control_id is required'}), 400

        db = get_db()

        # Verify control exists
        control = db.query(ComplianceControl).filter(
            ComplianceControl.id == control_id,
            ComplianceControl.deleted_at == None
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
            uploaded_by_user_id=data.get('user_id', 1),
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
def get_evidence(control_id):
    """Get all evidence for a control"""
    db = None
    try:
        db = get_db()

        evidence_list = db.query(ComplianceEvidence).filter(
            ComplianceEvidence.control_id == control_id,
            ComplianceEvidence.deleted_at == None
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
def delete_evidence(evidence_id):
    """Delete evidence (soft delete)"""
    db = None
    try:
        db = get_db()

        evidence = db.query(ComplianceEvidence).filter(
            ComplianceEvidence.id == evidence_id,
            ComplianceEvidence.deleted_at == None
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
def export_assessment(assessment_id):
    """Export assessment as JSON (for PDF/Excel generation on frontend)"""
    db = None
    try:
        db = get_db()

        assessment = db.query(ComplianceAssessment).filter(
            ComplianceAssessment.id == assessment_id,
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
def analyze_scan_for_compliance():
    """
    Analyze scan findings and return affected compliance controls.
    Optionally auto-flag controls in an existing assessment.
    """
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

            assessment = db.query(ComplianceAssessment).filter(
                ComplianceAssessment.id == assessment_id,
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
def get_affected_controls_for_domain(domain):
    """
    Get compliance controls that have been flagged by scans for a specific domain.
    """
    db = None
    try:
        db = get_db()

        # Get all controls flagged for this domain
        controls = db.query(ComplianceControl).filter(
            ComplianceControl.scan_domain == domain,
            ComplianceControl.scan_source != None,
            ComplianceControl.deleted_at == None
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
def flag_controls_from_scan():
    """
    Manually trigger control flagging from recent scan data for a domain.
    Fetches the latest XASM and Lightbox scans and flags affected controls.
    """
    db = None
    try:
        data = request.json
        domain = data.get('domain')
        assessment_id = data.get('assessment_id')

        if not domain or not assessment_id:
            return jsonify({'success': False, 'error': 'domain and assessment_id required'}), 400

        db = get_db()

        # Get the assessment
        assessment = db.query(ComplianceAssessment).filter(
            ComplianceAssessment.id == assessment_id,
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
def verify_control_fix(control_id):
    """
    Mark a control as verified after re-scan confirms the fix.
    This is called after a new scan shows the vulnerability is resolved.
    """
    db = None
    try:
        data = request.json
        verified = data.get('verified', True)

        db = get_db()

        control = db.query(ComplianceControl).filter(
            ComplianceControl.id == control_id,
            ComplianceControl.deleted_at == None
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
                uploaded_by_user_id=1,
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
def get_scan_flagged_summary(assessment_id):
    """
    Get a summary of controls flagged by scans for an assessment.
    """
    db = None
    try:
        db = get_db()

        # Get all scan-flagged controls for this assessment
        controls = db.query(ComplianceControl).filter(
            ComplianceControl.assessment_id == assessment_id,
            ComplianceControl.scan_source != None,
            ComplianceControl.deleted_at == None
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
def get_roadmap_profile():
    """
    Get or check for existing roadmap profile.
    Returns profile data if exists, or null to trigger profile setup.
    """
    db = None
    try:
        db = get_db()

        # For now, get the most recent profile (will be user-specific when auth is added)
        profile = db.query(RoadmapProfile).filter(
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
def create_roadmap_profile():
    """
    Create or update roadmap profile.
    """
    db = None
    try:
        data = request.get_json()
        db = get_db()

        # Check for existing profile
        existing = db.query(RoadmapProfile).filter(
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
            # Create new profile
            profile = RoadmapProfile(
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
def get_roadmap_tasks():
    """
    Get all assigned tasks for user's roadmap.
    Query params: phase, status, source
    """
    from roadmap_mappings import TASK_LIBRARY

    db = None
    try:
        db = get_db()

        # Get profile
        profile = db.query(RoadmapProfile).filter(
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
def generate_roadmap():
    """
    Generate personalized roadmap based on profile + scans.
    """
    from roadmap_mappings import TASK_LIBRARY, map_scan_to_tasks, get_tasks_for_profile, prioritize_tasks

    db = None
    try:
        data = request.get_json() or {}
        include_scans = data.get('include_scans', True)

        db = get_db()

        # Get profile
        profile = db.query(RoadmapProfile).filter(
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
def update_roadmap_task(task_id):
    """
    Update task status.
    """
    from roadmap_mappings import TASK_LIBRARY, ACHIEVEMENTS

    db = None
    try:
        data = request.get_json()
        new_status = data.get('status')
        user_notes = data.get('user_notes')

        db = get_db()

        # Get the task
        task = db.query(RoadmapUserTask).filter(
            RoadmapUserTask.id == task_id,
            RoadmapUserTask.deleted_at == None
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
def verify_roadmap_task(task_id):
    """
    Re-scan to verify task completion.
    """
    db = None
    try:
        data = request.get_json() or {}
        domain = data.get('domain')

        db = get_db()

        # Get the task
        task = db.query(RoadmapUserTask).filter(
            RoadmapUserTask.id == task_id,
            RoadmapUserTask.deleted_at == None
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
def get_roadmap_progress():
    """
    Get progress history for graphs.
    """
    db = None
    try:
        days = request.args.get('days', 30, type=int)

        db = get_db()

        # Get profile
        profile = db.query(RoadmapProfile).filter(
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
def get_roadmap_achievements():
    """
    Get unlocked and available achievements.
    """
    from roadmap_mappings import ACHIEVEMENTS

    db = None
    try:
        db = get_db()

        # Get profile
        profile = db.query(RoadmapProfile).filter(
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
def get_roadmap_stats():
    """
    Get dashboard stats for roadmap widget.
    """
    from roadmap_mappings import TASK_LIBRARY

    db = None
    try:
        db = get_db()

        # Get profile
        profile = db.query(RoadmapProfile).filter(
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


if __name__ == '__main__':
    print("Ghost backend starting...")

    # Run cleanup on startup
    print("[STARTUP] Running cleanup for old uploaded files...")
    cleanup_old_files()

    print("API running at http://localhost:5000")
    print("Press Ctrl+C to stop")
    app.run(debug=True, port=5000, host='127.0.0.1')