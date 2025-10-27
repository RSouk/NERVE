"""
NERVE GHOST - BAIT Honeypot Server
Flask server that catches and logs attempts to use fake credentials.
Part of the GHOST module for detecting credential theft and usage.
Integrated with centralized database.py for bait tracking.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from database import get_db, BaitToken, BaitAccess, init_db
import json
from datetime import datetime
from typing import Dict, Optional
from flask import Flask, request, jsonify, Response
from werkzeug.exceptions import HTTPException
import logging
import requests

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Flask app
app = Flask(__name__)


def get_geolocation(ip: str) -> str:
    """
    Get geolocation for an IP address using ip-api.com

    Args:
        ip: IP address to geolocate

    Returns:
        Geolocation string in format "City, Country" or "Unknown"
    """
    try:
        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=3)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                city = data.get('city', 'Unknown')
                country = data.get('country', 'Unknown')
                return f"{city}, {country}"
    except Exception as e:
        logger.debug(f"Failed to get geolocation for {ip}: {e}")

    return "Unknown"


def determine_threat_level(source_ip: str, user_agent: str, bait_id: int, db) -> str:
    """
    Determine threat level based on access patterns

    Args:
        source_ip: Source IP address
        user_agent: User agent string
        bait_id: Bait token ID
        db: Database session

    Returns:
        Threat level: 'low', 'medium', 'high', or 'critical'
    """
    # Check for multiple rapid attempts from same IP
    recent_attempts = db.query(BaitAccess).filter(
        BaitAccess.bait_id == bait_id,
        BaitAccess.source_ip == source_ip
    ).count()

    if recent_attempts >= 5:
        return 'critical'

    # Check for known scanner user agents
    user_agent_lower = user_agent.lower()
    scanner_keywords = ['curl', 'wget', 'python', 'scanner', 'bot', 'crawler',
                        'nikto', 'sqlmap', 'nmap', 'masscan', 'metasploit']

    if any(keyword in user_agent_lower for keyword in scanner_keywords):
        return 'high'

    return 'medium'


def log_access(bait_id: str, request_data: Dict) -> bool:
    """
    Log a bait access attempt to the database

    Args:
        bait_id: Bait identifier (just the ID part, e.g., "abc123")
        request_data: Dictionary containing request information with keys:
            - type: Request type (http, api, ssh, database)
            - ip: Source IP address
            - user_agent: User agent string
            - method: HTTP method
            - path: Request path
            - headers: Request headers dict
            - body: Request body (optional)

    Returns:
        True if logged successfully, False otherwise
    """
    db = None
    try:
        db = get_db()

        # Reconstruct full identifier
        full_identifier = f"bait_{bait_id}"

        # Query BaitToken by identifier
        bait_token = db.query(BaitToken).filter(BaitToken.identifier == full_identifier).first()

        if not bait_token:
            logger.error(f"Bait token not found: {full_identifier}")
            return False

        # Extract data from request_data
        source_ip = request_data.get('ip', 'Unknown')
        user_agent = request_data.get('user_agent', 'Unknown')
        request_type = request_data.get('type', 'http')

        # Get geolocation
        geolocation = get_geolocation(source_ip)

        # Determine threat level
        threat_level = determine_threat_level(source_ip, user_agent, bait_token.id, db)

        # Create BaitAccess record
        bait_access = BaitAccess(
            bait_id=bait_token.id,
            source_ip=source_ip,
            user_agent=user_agent,
            request_type=request_type,
            request_headers=json.dumps(request_data.get('headers', {})),
            request_body=json.dumps(request_data.get('body')) if request_data.get('body') else None,
            geolocation=geolocation,
            threat_level=threat_level,
            fingerprint=json.dumps(request_data)
        )

        db.add(bait_access)

        # Update BaitToken fields
        if bait_token.first_access is None:
            bait_token.first_access = datetime.utcnow()

        bait_token.access_count += 1
        bait_token.last_access = datetime.utcnow()
        bait_token.status = 'triggered'

        # Commit both records
        db.commit()

        # Print alert
        logger.critical(
            f"[BAIT TRIGGERED] ID: {bait_id} | "
            f"IP: {source_ip} | "
            f"Location: {geolocation} | "
            f"Threat: {threat_level.upper()}"
        )

        return True

    except Exception as e:
        logger.error(f"Failed to log bait access: {e}")
        if db:
            db.rollback()
        return False

    finally:
        if db:
            db.close()


# ============================================================================
# HONEYPOT ROUTE HANDLERS
# ============================================================================

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "online", "service": "bait-honeypot"}), 200


@app.route('/aws/<bait_id>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@app.route('/aws/<bait_id>/<path:subpath>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def aws_honeypot(bait_id, subpath=None):
    """AWS credentials honeypot endpoint"""
    try:
        # Build comprehensive request data
        request_data = {
            'type': 'aws_api',
            'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', 'Unknown'),
            'method': request.method,
            'path': request.path,
            'headers': dict(request.headers)
        }

        # Include body for POST/PUT requests
        if request.method in ['POST', 'PUT']:
            try:
                request_data['body'] = request.get_json(silent=True) or request.get_data(as_text=True)
            except:
                request_data['body'] = None

        # Log the access
        log_access(bait_id, request_data)

        return jsonify({
            "error": "InvalidClientTokenId",
            "message": "The security token included in the request is invalid."
        }), 403

    except Exception as e:
        logger.error(f"Error in aws_honeypot: {e}")
        return jsonify({"error": "internal_error"}), 500


@app.route('/api/<bait_id>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@app.route('/api/<bait_id>/<path:subpath>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def api_honeypot(bait_id, subpath=None):
    """API token honeypot endpoint"""
    try:
        # Build comprehensive request data
        request_data = {
            'type': 'api_token',
            'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', 'Unknown'),
            'method': request.method,
            'path': request.path,
            'headers': dict(request.headers)
        }

        # Include body for POST/PUT requests
        if request.method in ['POST', 'PUT']:
            try:
                request_data['body'] = request.get_json(silent=True) or request.get_data(as_text=True)
            except:
                request_data['body'] = None

        # Log the access
        log_access(bait_id, request_data)

        return jsonify({
            "error": "invalid_token",
            "message": "The provided API token is invalid or expired"
        }), 401

    except Exception as e:
        logger.error(f"Error in api_honeypot: {e}")
        return jsonify({"error": "internal_error"}), 500


@app.route('/db/<bait_id>', methods=['POST'])
@app.route('/database/<bait_id>', methods=['POST'])
def db_honeypot(bait_id):
    """Database credentials honeypot endpoint"""
    try:
        # Build comprehensive request data
        request_data = {
            'type': 'database',
            'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', 'Unknown'),
            'method': request.method,
            'path': request.path,
            'headers': dict(request.headers)
        }

        # Include body
        try:
            request_data['body'] = request.get_json(silent=True) or request.get_data(as_text=True)
        except:
            request_data['body'] = None

        # Log the access
        log_access(bait_id, request_data)

        return jsonify({
            "error": "authentication_failed",
            "message": "Invalid username or password"
        }), 401

    except Exception as e:
        logger.error(f"Error in db_honeypot: {e}")
        return jsonify({"error": "internal_error"}), 500


# ============================================================================
# ADMIN ENDPOINTS
# ============================================================================

@app.route('/admin/baits', methods=['GET'])
def get_all_baits():
    """Get all BaitTokens with their access counts"""
    db = None
    try:
        db = get_db()
        baits = db.query(BaitToken).all()

        result = []
        for bait in baits:
            result.append({
                'id': bait.id,
                'identifier': bait.identifier,
                'bait_type': bait.bait_type,
                'seeded_at': bait.seeded_at.isoformat() if bait.seeded_at else None,
                'seeded_location': bait.seeded_location,
                'first_access': bait.first_access.isoformat() if bait.first_access else None,
                'access_count': bait.access_count,
                'last_access': bait.last_access.isoformat() if bait.last_access else None,
                'status': bait.status
            })

        return jsonify({
            'success': True,
            'count': len(result),
            'baits': result
        }), 200

    except Exception as e:
        logger.error(f"Failed to fetch baits: {e}")
        return jsonify({'error': str(e)}), 500

    finally:
        if db:
            db.close()


@app.route('/admin/bait/<bait_id>/timeline', methods=['GET'])
def get_bait_timeline(bait_id):
    """Get full timeline for specific bait"""
    db = None
    try:
        db = get_db()

        # Get the bait token
        bait = db.query(BaitToken).filter(
            BaitToken.identifier == f"bait_{bait_id}"
        ).first()

        if not bait:
            return jsonify({'error': 'Bait not found'}), 404

        # Get all accesses for this bait
        accesses = db.query(BaitAccess).filter(
            BaitAccess.bait_id == bait.id
        ).order_by(BaitAccess.accessed_at.desc()).all()

        timeline = []
        for access in accesses:
            timeline.append({
                'id': access.id,
                'accessed_at': access.accessed_at.isoformat() if access.accessed_at else None,
                'source_ip': access.source_ip,
                'user_agent': access.user_agent,
                'request_type': access.request_type,
                'geolocation': access.geolocation,
                'threat_level': access.threat_level,
                'request_headers': json.loads(access.request_headers) if access.request_headers else {},
                'request_body': json.loads(access.request_body) if access.request_body else None
            })

        return jsonify({
            'success': True,
            'bait_id': bait_id,
            'bait_info': {
                'identifier': bait.identifier,
                'type': bait.bait_type,
                'seeded_at': bait.seeded_at.isoformat() if bait.seeded_at else None,
                'seeded_location': bait.seeded_location,
                'access_count': bait.access_count,
                'status': bait.status
            },
            'timeline': timeline,
            'count': len(timeline)
        }), 200

    except Exception as e:
        logger.error(f"Failed to fetch bait timeline: {e}")
        return jsonify({'error': str(e)}), 500

    finally:
        if db:
            db.close()


@app.route('/admin/recent-attempts', methods=['GET'])
def get_recent_attempts():
    """Get last 20 BaitAccess records across all baits"""
    db = None
    try:
        db = get_db()

        # Get last 20 accesses
        accesses = db.query(BaitAccess).order_by(
            BaitAccess.accessed_at.desc()
        ).limit(20).all()

        result = []
        for access in accesses:
            # Get the associated bait token
            bait = db.query(BaitToken).filter(BaitToken.id == access.bait_id).first()

            result.append({
                'id': access.id,
                'bait_identifier': bait.identifier if bait else 'Unknown',
                'bait_type': bait.bait_type if bait else 'Unknown',
                'accessed_at': access.accessed_at.isoformat() if access.accessed_at else None,
                'source_ip': access.source_ip,
                'user_agent': access.user_agent,
                'request_type': access.request_type,
                'geolocation': access.geolocation,
                'threat_level': access.threat_level
            })

        return jsonify({
            'success': True,
            'count': len(result),
            'attempts': result
        }), 200

    except Exception as e:
        logger.error(f"Failed to fetch recent attempts: {e}")
        return jsonify({'error': str(e)}), 500

    finally:
        if db:
            db.close()


@app.route('/admin/stats', methods=['GET'])
def get_honeypot_stats():
    """Get honeypot statistics"""
    db = None
    try:
        db = get_db()

        # Total baits deployed
        total_baits = db.query(BaitToken).count()

        # Total access attempts
        total_attempts = db.query(BaitAccess).count()

        # Active baits count
        active_baits = db.query(BaitToken).filter(BaitToken.status == 'active').count()

        # Triggered baits count
        triggered_baits = db.query(BaitToken).filter(BaitToken.status == 'triggered').count()

        # Average time to first access
        baits_with_access = db.query(BaitToken).filter(
            BaitToken.first_access.isnot(None)
        ).all()

        avg_time_to_first_access = None
        if baits_with_access:
            time_diffs = []
            for bait in baits_with_access:
                if bait.first_access and bait.seeded_at:
                    diff = (bait.first_access - bait.seeded_at).total_seconds()
                    time_diffs.append(diff)

            if time_diffs:
                avg_seconds = sum(time_diffs) / len(time_diffs)
                # Convert to human readable format
                hours = int(avg_seconds / 3600)
                minutes = int((avg_seconds % 3600) / 60)
                avg_time_to_first_access = f"{hours}h {minutes}m"

        # Threat level distribution
        threat_levels = db.query(
            BaitAccess.threat_level,
            db.func.count(BaitAccess.id)
        ).group_by(BaitAccess.threat_level).all()

        threat_distribution = {level: count for level, count in threat_levels}

        # Top targeted baits
        top_baits = db.query(BaitToken).order_by(
            BaitToken.access_count.desc()
        ).limit(5).all()

        top_baits_list = []
        for bait in top_baits:
            top_baits_list.append({
                'identifier': bait.identifier,
                'type': bait.bait_type,
                'access_count': bait.access_count,
                'last_access': bait.last_access.isoformat() if bait.last_access else None
            })

        return jsonify({
            'success': True,
            'stats': {
                'total_baits_deployed': total_baits,
                'total_access_attempts': total_attempts,
                'active_baits_count': active_baits,
                'triggered_baits_count': triggered_baits,
                'avg_time_to_first_access': avg_time_to_first_access,
                'threat_level_distribution': threat_distribution,
                'top_targeted_baits': top_baits_list
            }
        }), 200

    except Exception as e:
        logger.error(f"Failed to fetch stats: {e}")
        return jsonify({'error': str(e)}), 500

    finally:
        if db:
            db.close()


# Error handlers
@app.errorhandler(Exception)
def handle_exception(e):
    """Handle any unhandled exceptions"""
    if isinstance(e, HTTPException):
        return e

    logger.error(f"Unhandled exception: {e}")
    return jsonify({
        "error": "internal_server_error",
        "message": "An internal error occurred"
    }), 500


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("NERVE GHOST - BAIT Honeypot Server (Database Integrated)")
    print("=" * 70)

    # Initialize database tables
    try:
        init_db()
        print(f"\n[OK] Database initialized")

        # Print available admin endpoints
        print("\n" + "=" * 70)
        print("ADMIN ENDPOINTS:")
        print("=" * 70)
        print("  GET  /admin/baits              - List all bait tokens")
        print("  GET  /admin/bait/<id>/timeline - Get timeline for specific bait")
        print("  GET  /admin/recent-attempts    - Get last 20 access attempts")
        print("  GET  /admin/stats              - Get honeypot statistics")
        print("\n" + "=" * 70)
        print("HONEYPOT ENDPOINTS:")
        print("=" * 70)
        print("  *    /aws/<bait_id>            - AWS credentials honeypot")
        print("  *    /api/<bait_id>            - API token honeypot")
        print("  POST /db/<bait_id>             - Database credentials honeypot")
        print("=" * 70)

        # Start the honeypot server
        print(f"\n[*] Starting honeypot server on 0.0.0.0:5001")
        print("[!] All access attempts will be logged to database")
        print("\nPress Ctrl+C to stop\n")

        app.run(host='0.0.0.0', port=5001, debug=True)

    except KeyboardInterrupt:
        print("\n\n[INFO] Honeypot server stopped by user")

    except Exception as e:
        print(f"\n[ERROR] Failed to start honeypot: {e}")
        import traceback
        traceback.print_exc()
