"""
AI-Powered Vulnerability Assessment
Generates detailed analysis for each critical/high finding using Gemini AI
Links to threat actors and provides remediation guidance
"""

import os
import google.generativeai as genai
from dotenv import load_dotenv
from datetime import datetime

# Load environment variables
load_dotenv()

# Configure Gemini API
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)


def generate_vuln_assessment(xasm_results, lightbox_results):
    """
    Generate AI-powered vulnerability assessment for critical/high findings

    Args:
        xasm_results (dict): ASM scan results
        lightbox_results (dict): Lightbox scan results

    Returns:
        dict: Detailed assessment per vulnerability
    """
    print(f"\n{'='*60}")
    print(f"[VULN ASSESSMENT] Generating AI-powered analysis...")
    print(f"{'='*60}\n")

    if not GEMINI_API_KEY or GEMINI_API_KEY == 'your_gemini_api_key_here':
        print(f"[VULN ASSESSMENT] ⚠️  Gemini API key not configured")
        return {
            'success': False,
            'error': 'Gemini API key not configured',
            'assessments': []
        }

    try:
        # Collect all critical/high findings
        findings_to_assess = []

        # Extract from XASM results
        for finding in xasm_results.get('critical_findings', []):
            if finding.get('severity') in ['CRITICAL', 'HIGH']:
                findings_to_assess.append({
                    'source': 'ASM',
                    'severity': finding.get('severity'),
                    'type': finding.get('type'),
                    'description': finding.get('description'),
                    'asset': finding.get('asset', 'Unknown'),
                    'details': finding
                })

        # Extract from Shodan results (CVEs and risky services)
        for shodan in xasm_results.get('shodan_results', []):
            if shodan.get('vulnerabilities'):
                for cve in shodan.get('vulnerabilities', []):
                    findings_to_assess.append({
                        'source': 'Shodan',
                        'severity': 'CRITICAL',
                        'type': 'Known Vulnerability (CVE)',
                        'description': f"{cve} on {shodan.get('service')} {shodan.get('version')}",
                        'asset': f"{shodan.get('ip')}:{shodan.get('port')}",
                        'cve': cve,
                        'details': shodan
                    })

            # Flag risky services
            if shodan.get('risk') in ['CRITICAL', 'HIGH']:
                findings_to_assess.append({
                    'source': 'Shodan',
                    'severity': shodan.get('risk'),
                    'type': 'Risky Service Exposed',
                    'description': f"{shodan.get('service')} {shodan.get('version')} on port {shodan.get('port')}",
                    'asset': f"{shodan.get('ip')}:{shodan.get('port')}",
                    'details': shodan
                })

        # Extract from Lightbox results
        for severity in ['critical', 'high']:
            for finding in lightbox_results.get(severity, []):
                findings_to_assess.append({
                    'source': 'Lightbox',
                    'severity': finding.get('severity'),
                    'type': finding.get('type'),
                    'description': finding.get('description'),
                    'asset': finding.get('asset'),
                    'url': finding.get('url'),
                    'details': finding
                })

        print(f"[VULN ASSESSMENT] Found {len(findings_to_assess)} critical/high findings to assess")

        # Generate assessment for each finding
        assessments = []

        for idx, finding in enumerate(findings_to_assess, 1):
            print(f"[VULN ASSESSMENT] Analyzing finding {idx}/{len(findings_to_assess)}: {finding['type']}...")

            assessment = generate_single_assessment(
                finding=finding,
                domain=xasm_results.get('domain', 'Unknown'),
                index=idx
            )

            if assessment:
                assessments.append(assessment)

        print(f"\n{'='*60}")
        print(f"[VULN ASSESSMENT] ✓ Generated {len(assessments)} assessments")
        print(f"{'='*60}\n")

        return {
            'success': True,
            'assessments': assessments,
            'total_findings': len(findings_to_assess),
            'assessed_count': len(assessments),
            'generated_at': datetime.utcnow().isoformat()
        }

    except Exception as e:
        print(f"[VULN ASSESSMENT] ❌ Error: {e}")
        import traceback
        traceback.print_exc()

        return {
            'success': False,
            'error': str(e),
            'assessments': []
        }


def generate_single_assessment(finding, domain, index):
    """
    Generate detailed assessment for a single vulnerability

    Args:
        finding (dict): Vulnerability finding
        domain (str): Target domain
        index (int): Finding index

    Returns:
        dict: Detailed assessment
    """
    try:
        # Build context-aware prompt
        prompt = build_assessment_prompt(finding, domain)

        # Call Gemini API
        model = genai.GenerativeModel('models/gemini-2.5-flash')
        response = model.generate_content(prompt)

        # Parse response
        ai_analysis = response.text

        # Query threat actors (if CVE present)
        threat_actors = []
        if finding.get('cve'):
            threat_actors = query_threat_actors_for_cve(finding['cve'])

        assessment = {
            'finding_id': f"VULN-{index:03d}",
            'severity': finding['severity'],
            'type': finding['type'],
            'asset': finding['asset'],
            'description': finding['description'],
            'source': finding['source'],
            'ai_analysis': ai_analysis,
            'threat_actors': threat_actors,
            'cve': finding.get('cve', None),
            'assessed_at': datetime.utcnow().isoformat(),
            'raw_finding': finding.get('details', {})
        }

        print(f"[VULN ASSESSMENT] ✓ Assessment generated for {finding['type']}")

        return assessment

    except Exception as e:
        print(f"[VULN ASSESSMENT] ❌ Error assessing {finding['type']}: {e}")
        return None


def build_assessment_prompt(finding, domain):
    """
    Build detailed prompt for Gemini AI

    Args:
        finding (dict): Vulnerability finding
        domain (str): Target domain

    Returns:
        str: Formatted prompt
    """
    severity = finding['severity']
    vuln_type = finding['type']
    description = finding['description']
    asset = finding['asset']

    prompt = f"""You are a cybersecurity expert performing a vulnerability assessment for {domain}.

## VULNERABILITY DETAILS

**Severity:** {severity}
**Type:** {vuln_type}
**Asset:** {asset}
**Description:** {description}
"""

    # Add CVE details if present
    if finding.get('cve'):
        prompt += f"\n**CVE:** {finding['cve']}\n"

    # Add service details from Shodan
    if finding.get('details', {}).get('service'):
        details = finding['details']
        prompt += f"""
**Service Information:**
- Service: {details.get('service')} {details.get('version', '')}
- Port: {details.get('port')}
- Organization: {details.get('organization', 'Unknown')}
- Location: {details.get('location', {}).get('city', 'Unknown')}, {details.get('location', {}).get('country', 'Unknown')}
"""

    # Add Lightbox details
    if finding.get('url'):
        prompt += f"\n**URL:** {finding['url']}\n"
        prompt += f"**Status Code:** {finding.get('details', {}).get('status_code', 'Unknown')}\n"

    prompt += """

## ASSESSMENT REQUIREMENTS

Provide a comprehensive security assessment in the following format:

### 1. VULNERABILITY EXPLANATION
Explain what this vulnerability is and why it's dangerous in 2-3 sentences. Use clear, non-technical language that executives can understand.

### 2. EXPLOIT AVAILABILITY
- Are there public exploits available? (Yes/No)
- Exploit difficulty: Trivial / Easy / Moderate / Difficult
- Common attack tools used to exploit this

### 3. BUSINESS IMPACT
Specific impact for THIS company based on the asset and vulnerability type:
- Data at risk (customer data, financial info, credentials, etc.)
- Operational impact (service disruption, downtime)
- Compliance impact (GDPR, PCI-DSS, HIPAA)
- Financial impact estimate (Low: <$10K, Medium: $10K-$100K, High: $100K-$1M, Critical: >$1M)

### 4. THREAT LANDSCAPE
- Which threat actor groups commonly exploit this? (APT groups, ransomware gangs, script kiddies)
- Recent attacks using this vulnerability
- Likelihood of exploitation: Very Low / Low / Medium / High / Very High

### 5. REMEDIATION STEPS
Provide specific, actionable steps with priority levels:

**P0 (Critical - Fix within 24 hours):**
- [Specific action steps]

**P1 (High - Fix within 1 week):**
- [Specific action steps]

**P2 (Medium - Fix within 1 month):**
- [Specific action steps]

### 6. ESTIMATED FIX TIME
- Minimum time: X hours/days
- Maximum time: X hours/days
- Required team: Security / DevOps / Infrastructure / Development
- Complexity: Low / Medium / High

### 7. TEMPORARY MITIGATIONS
Quick actions to reduce risk while permanent fix is implemented:
- [Mitigation 1]
- [Mitigation 2]
- [Mitigation 3]

---

Be specific, technical, and actionable. Focus on REAL risks and PRACTICAL remediation.
"""

    return prompt


def query_threat_actors_for_cve(cve):
    """
    Query Adversary module for threat actors associated with CVE

    Args:
        cve (str): CVE identifier

    Returns:
        list: Associated threat actors
    """
    try:
        # Import adversary data
        import sys
        import os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

        from modules.cti.adversary_search import load_threat_actors

        threat_actors_data = load_threat_actors()

        # Search for CVE in threat actor TTPs
        associated_actors = []

        for actor in threat_actors_data:
            # Check if CVE mentioned in description or techniques
            actor_text = f"{actor.get('description', '')} {actor.get('techniques', '')}".lower()

            if cve.lower() in actor_text:
                associated_actors.append({
                    'name': actor.get('name'),
                    'country': actor.get('country'),
                    'motivation': actor.get('motivation'),
                    'targets': actor.get('targets', [])
                })

        if associated_actors:
            print(f"[VULN ASSESSMENT] Found {len(associated_actors)} threat actors for {cve}")

        return associated_actors

    except Exception as e:
        print(f"[VULN ASSESSMENT] Error querying threat actors: {e}")
        return []


def format_assessment_as_text(assessments):
    """
    Format assessments as TXT report

    Args:
        assessments (list): List of vulnerability assessments

    Returns:
        str: Formatted TXT report
    """
    txt = "AI-POWERED VULNERABILITY ASSESSMENT REPORT\n"
    txt += "=" * 80 + "\n\n"
    txt += f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
    txt += f"Total Vulnerabilities Assessed: {len(assessments)}\n"
    txt += "=" * 80 + "\n\n"

    for assessment in assessments:
        txt += f"\n{'='*80}\n"
        txt += f"{assessment['finding_id']}: {assessment['type']}\n"
        txt += f"{'='*80}\n\n"

        txt += f"Severity: {assessment['severity']}\n"
        txt += f"Asset: {assessment['asset']}\n"
        txt += f"Description: {assessment['description']}\n"

        if assessment.get('cve'):
            txt += f"CVE: {assessment['cve']}\n"

        txt += f"\n{'-'*80}\n"
        txt += "AI ANALYSIS\n"
        txt += f"{'-'*80}\n\n"

        txt += assessment['ai_analysis']
        txt += "\n\n"

        if assessment.get('threat_actors'):
            txt += f"{'-'*80}\n"
            txt += "ASSOCIATED THREAT ACTORS\n"
            txt += f"{'-'*80}\n\n"

            for actor in assessment['threat_actors']:
                txt += f"- {actor['name']} ({actor['country']})\n"
                txt += f"  Motivation: {actor['motivation']}\n"
                if actor.get('targets'):
                    txt += f"  Targets: {', '.join(actor['targets'][:3])}\n"
                txt += "\n"

        txt += "\n"

    txt += "=" * 80 + "\n"
    txt += "END OF VULNERABILITY ASSESSMENT REPORT\n"
    txt += "=" * 80 + "\n"

    return txt


# Test function
if __name__ == '__main__':
    # Test with sample findings
    test_xasm_results = {
        'domain': 'example.com',
        'critical_findings': [
            {
                'severity': 'CRITICAL',
                'type': 'Admin Subdomain Exposed',
                'description': 'admin.example.com is publicly accessible',
                'asset': 'admin.example.com'
            }
        ],
        'shodan_results': [
            {
                'ip': '192.168.1.1',
                'port': 22,
                'service': 'OpenSSH',
                'version': '7.4',
                'risk': 'HIGH',
                'vulnerabilities': ['CVE-2023-38408'],
                'organization': 'Example Corp',
                'location': {
                    'city': 'San Francisco',
                    'country': 'US'
                }
            }
        ]
    }

    test_lightbox_results = {
        'critical': [
            {
                'severity': 'CRITICAL',
                'type': 'Sensitive File Exposed',
                'description': 'Sensitive file accessible: /.env',
                'asset': 'www.example.com',
                'url': 'https://www.example.com/.env',
                'status_code': 200
            }
        ],
        'high': []
    }

    print("\n🤖 Testing AI Vulnerability Assessment\n")
    result = generate_vuln_assessment(test_xasm_results, test_lightbox_results)

    if result['success']:
        print("\n" + "="*80)
        print("ASSESSMENT RESULTS")
        print("="*80)
        print(f"Total Findings: {result['total_findings']}")
        print(f"Assessed: {result['assessed_count']}")
        print("\nFirst Assessment:")
        print("-"*80)
        if result['assessments']:
            print(result['assessments'][0]['ai_analysis'])
    else:
        print(f"\n❌ Error: {result['error']}\n")
