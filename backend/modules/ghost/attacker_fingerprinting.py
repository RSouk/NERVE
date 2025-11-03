"""
Attacker Fingerprinting Module
Analyzes HTTP headers and request patterns to determine attacker attribution type
and legal evidence strength for BAIT honeypot system.
"""

import json
from typing import Dict, Any, Optional


def analyze_attacker(access_record: Any) -> Dict[str, Any]:
    """
    Analyze an access record to determine attacker type and evidence strength

    Args:
        access_record: BaitAccess database record with headers and metadata

    Returns:
        Dictionary containing:
        - attribution_type: 'human', 'bot', 'tool', 'spoofed'
        - tool_name: Name of the identified tool/browser
        - evidence_strength: 'court_ready', 'moderate', 'weak'
        - legal_notes: Assessment of legal pursuability
        - is_browser: Boolean indicating if request came from real browser
        - is_automated: Boolean indicating if request came from automated tool
        - fingerprint_score: 0-100 score of fingerprint completeness
    """

    # Extract data from access record
    user_agent = getattr(access_record, 'user_agent', '') or ''
    accept_language = getattr(access_record, 'accept_language', None)
    referer = getattr(access_record, 'referer', None)
    sec_fetch_headers = getattr(access_record, 'sec_fetch_headers', None)
    source_ip = getattr(access_record, 'source_ip', 'Unknown')

    # Try to parse sec_fetch_headers if it's a JSON string
    sec_fetch_data = {}
    if sec_fetch_headers:
        try:
            sec_fetch_data = json.loads(sec_fetch_headers)
        except:
            pass

    # Initialize result
    result = {
        'attribution_type': 'unknown',
        'tool_name': 'Unknown',
        'evidence_strength': 'weak',
        'legal_notes': '',
        'is_browser': False,
        'is_automated': False,
        'fingerprint_score': 0,
        'confidence': 'low'
    }

    # Analyze User-Agent
    ua_lower = user_agent.lower()

    # Detect automated tools
    tool_patterns = {
        'curl': 'cURL Command Line Tool',
        'wget': 'Wget Download Tool',
        'python-requests': 'Python Requests Library',
        'python-urllib': 'Python urllib Library',
        'node-fetch': 'Node.js Fetch Library',
        'axios': 'Axios HTTP Library',
        'go-http-client': 'Go HTTP Client',
        'java': 'Java HTTP Client',
        'okhttp': 'OkHttp Library',
        'aws-cli': 'AWS Command Line Interface',
        'aws-sdk': 'AWS SDK',
        'boto': 'Boto3 AWS SDK for Python',
        'postman': 'Postman API Client',
        'insomnia': 'Insomnia REST Client',
        'httpclient': 'Generic HTTP Client',
        'libwww-perl': 'Perl LWP Library',
        'ruby': 'Ruby HTTP Library'
    }

    detected_tool = None
    for keyword, tool_name in tool_patterns.items():
        if keyword in ua_lower:
            detected_tool = tool_name
            result['is_automated'] = True
            result['attribution_type'] = 'tool'
            result['tool_name'] = tool_name
            break

    # Detect browser patterns
    browser_patterns = {
        'chrome': 'Google Chrome',
        'firefox': 'Mozilla Firefox',
        'safari': 'Apple Safari',
        'edge': 'Microsoft Edge',
        'opera': 'Opera',
        'msie': 'Internet Explorer',
        'trident': 'Internet Explorer'
    }

    detected_browser = None
    has_mozilla = 'mozilla' in ua_lower
    for keyword, browser_name in browser_patterns.items():
        if keyword in ua_lower:
            detected_browser = browser_name
            break

    # Determine if real browser or spoofed
    if has_mozilla and detected_browser:
        # Check for Sec-Fetch headers (modern browsers send these)
        has_sec_fetch = bool(sec_fetch_data.get('site') or sec_fetch_data.get('mode') or sec_fetch_data.get('dest'))

        if has_sec_fetch:
            # Real browser with Sec-Fetch headers = likely human
            result['is_browser'] = True
            result['attribution_type'] = 'human'
            result['tool_name'] = detected_browser
            result['confidence'] = 'high'
            result['fingerprint_score'] = 85
        elif accept_language:
            # Browser UA + Accept-Language but no Sec-Fetch = older browser or spoofed
            result['is_browser'] = True
            result['attribution_type'] = 'human'
            result['tool_name'] = f"{detected_browser} (older version)"
            result['confidence'] = 'medium'
            result['fingerprint_score'] = 60
        else:
            # Browser UA but missing typical headers = likely spoofed
            result['attribution_type'] = 'spoofed'
            result['tool_name'] = f"Spoofed {detected_browser}"
            result['confidence'] = 'medium'
            result['fingerprint_score'] = 30

    # Bot detection
    bot_keywords = ['bot', 'crawler', 'spider', 'scraper', 'scan']
    if any(keyword in ua_lower for keyword in bot_keywords):
        result['attribution_type'] = 'bot'
        result['tool_name'] = f"Bot/Crawler: {user_agent[:50]}"
        result['is_automated'] = True
        result['fingerprint_score'] = 40

    # Calculate fingerprint score for tools
    if result['is_automated'] and result['attribution_type'] == 'tool':
        result['fingerprint_score'] = 50  # Tools have consistent signatures

    # Add points for additional headers
    if accept_language:
        result['fingerprint_score'] += 10
    if referer:
        result['fingerprint_score'] += 5
    if has_sec_fetch:
        result['fingerprint_score'] += 15

    # Cap at 100
    result['fingerprint_score'] = min(100, result['fingerprint_score'])

    # Determine evidence strength based on attribution and IP reputation
    # Note: IP reputation should be checked separately via ip_intelligence module

    if result['attribution_type'] == 'human':
        # Human browser with full headers
        if result['fingerprint_score'] >= 80:
            result['evidence_strength'] = 'court_ready'
            result['legal_notes'] = (
                "HIGH ATTRIBUTION: Real browser with complete headers. "
                "If residential IP, ISP can provide subscriber information via legal subpoena. "
                "Strong evidence for legal action."
            )
        elif result['fingerprint_score'] >= 60:
            result['evidence_strength'] = 'moderate'
            result['legal_notes'] = (
                "MODERATE ATTRIBUTION: Likely real browser with partial headers. "
                "If residential IP, legal pursuit possible with ISP cooperation. "
                "Additional correlation recommended."
            )
        else:
            result['evidence_strength'] = 'weak'
            result['legal_notes'] = (
                "WEAK ATTRIBUTION: Incomplete browser fingerprint. "
                "May be privacy-focused browser or VPN. "
                "Difficult to trace to individual without additional evidence."
            )

    elif result['attribution_type'] == 'tool':
        # Automated tool
        result['evidence_strength'] = 'moderate'
        result['legal_notes'] = (
            f"TOOL DETECTED: {result['tool_name']}. "
            "Attribution depends on IP reputation. "
            "If datacenter IP, contact hosting provider. "
            "If residential IP, tool was run by end-user and ISP can identify."
        )

    elif result['attribution_type'] == 'spoofed':
        # Spoofed user agent
        result['evidence_strength'] = 'weak'
        result['legal_notes'] = (
            "SPOOFED FINGERPRINT: Browser user-agent with missing expected headers. "
            "Likely script with fake UA. Attribution relies heavily on IP reputation. "
            "VPN/proxy usage probable - identity may be hidden."
        )

    elif result['attribution_type'] == 'bot':
        # Bot/crawler
        result['evidence_strength'] = 'moderate'
        result['legal_notes'] = (
            "BOT/CRAWLER DETECTED: Automated scanning. "
            "May be reconnaissance for targeted attack. "
            "Attribution possible if datacenter/residential IP can be traced."
        )

    else:
        # Unknown
        result['evidence_strength'] = 'weak'
        result['legal_notes'] = (
            "UNKNOWN FINGERPRINT: Unable to classify attacker type. "
            "Unusual or minimal headers. "
            "Limited attribution potential without additional investigation."
        )

    return result


def get_evidence_badge_info(evidence_strength: str) -> Dict[str, str]:
    """
    Get badge display information for evidence strength

    Args:
        evidence_strength: 'court_ready', 'moderate', or 'weak'

    Returns:
        Dictionary with emoji, text, and CSS class
    """
    badges = {
        'court_ready': {
            'emoji': '⚖️',
            'text': 'COURT READY',
            'class': 'court-ready',
            'color': '#10b981'
        },
        'moderate': {
            'emoji': '📋',
            'text': 'MODERATE',
            'class': 'moderate',
            'color': '#fbbf24'
        },
        'weak': {
            'emoji': '❌',
            'text': 'WEAK',
            'class': 'weak',
            'color': '#ef4444'
        }
    }
    return badges.get(evidence_strength, badges['weak'])


def get_attribution_badge_info(attribution_type: str) -> Dict[str, str]:
    """
    Get badge display information for attribution type

    Args:
        attribution_type: 'human', 'bot', 'tool', 'spoofed', or 'unknown'

    Returns:
        Dictionary with emoji, text, and CSS class
    """
    badges = {
        'human': {
            'emoji': '👤',
            'text': 'HUMAN',
            'class': 'human',
            'color': '#3b82f6'
        },
        'bot': {
            'emoji': '🤖',
            'text': 'BOT',
            'class': 'bot',
            'color': '#8b5cf6'
        },
        'tool': {
            'emoji': '🛠️',
            'text': 'TOOL',
            'class': 'tool',
            'color': '#f97316'
        },
        'spoofed': {
            'emoji': '🎭',
            'text': 'SPOOFED',
            'class': 'spoofed',
            'color': '#ef4444'
        },
        'unknown': {
            'emoji': '❓',
            'text': 'UNKNOWN',
            'class': 'unknown',
            'color': '#6b7280'
        }
    }
    return badges.get(attribution_type, badges['unknown'])
