from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from database import get_db, Profile, SocialMedia, Breach, Device, BaitToken, BaitAccess, UploadedFile, UploadedCredential, GitHubFinding, PasteBinFinding
from modules.ghost.osint import scan_profile_breaches
import os
import json
from datetime import datetime, timedelta
from sqlalchemy import func, distinct
from modules.ghost.unified_search import UnifiedSearch
from modules.ghost.adversary_matcher import AdversaryMatcher
from modules.ghost.bait_generator import BaitGenerator
from modules.ghost.bait_seeder import BaitSeeder
from modules.ghost.ip_intelligence import check_ip_reputation as check_ip_intel, get_ip_badge_type
from modules.ghost.attacker_fingerprinting import analyze_attacker, get_evidence_badge_info, get_attribution_badge_info
from modules.ghost.cti_newsfeed import get_news_feed, get_feed_stats
import re
import secrets
import time
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*", "methods": ["GET", "POST", "DELETE", "OPTIONS"], "allow_headers": ["Content-Type"]}})

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
        today = datetime.utcnow().date()
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
# FILE UPLOAD ENDPOINTS
# ============================================================================

# Ensure upload directory exists
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'uploaded_files')
os.makedirs(UPLOAD_DIR, exist_ok=True)

def cleanup_old_files():
    """Delete files older than 24 hours"""
    try:
        db = get_db()
        cutoff_time = datetime.utcnow() - timedelta(hours=24)

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
            upload_time=datetime.utcnow()
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

if __name__ == '__main__':
    print("Ghost backend starting...")

    # Run cleanup on startup
    print("[STARTUP] Running cleanup for old uploaded files...")
    cleanup_old_files()

    print("API running at http://localhost:5000")
    print("Press Ctrl+C to stop")
    app.run(debug=True, port=5000, host='127.0.0.1')