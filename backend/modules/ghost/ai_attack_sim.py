"""
AI Attack Simulation using Google Gemini
Generates realistic attack scenarios based on discovered assets
"""

import os
import google.generativeai as genai
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure Gemini API
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)


def generate_attack_plan(findings):
    """
    Generate an AI-powered attack simulation plan based on discovered assets

    Args:
        findings (dict): Scan results containing subdomains, cloud assets, Shodan data, etc.

    Returns:
        dict: Attack plan with steps, tools, and scenarios
    """
    print(f"\n{'='*60}")
    print(f"[AI ATTACK SIM] Generating attack plan with Gemini...")
    print(f"{'='*60}\n")

    if not GEMINI_API_KEY or GEMINI_API_KEY == 'your_gemini_api_key_here':
        print(f"[AI ATTACK SIM] ⚠️  Gemini API key not configured")
        return {
            'success': False,
            'error': 'Gemini API key not configured',
            'attack_plan': None
        }

    try:
        # Build findings summary
        findings_summary = build_findings_summary(findings)

        # Create prompt for Gemini
        prompt = create_attack_sim_prompt(findings_summary)

        print(f"[AI ATTACK SIM] Calling Gemini API (model: gemini-2.5-flash)...")

        # Call Gemini API
        model = genai.GenerativeModel('models/gemini-2.5-flash')
        response = model.generate_content(prompt)

        attack_plan = response.text

        print(f"[AI ATTACK SIM] ✓ Attack plan generated ({len(attack_plan)} chars)")
        print(f"{'='*60}\n")

        return {
            'success': True,
            'attack_plan': attack_plan,
            'model': 'gemini-1.5-flash',
            'findings_summary': findings_summary
        }

    except Exception as e:
        print(f"[AI ATTACK SIM] ❌ Error: {e}")
        import traceback
        traceback.print_exc()

        return {
            'success': False,
            'error': str(e),
            'attack_plan': None
        }


def build_findings_summary(findings):
    """
    Build a summary of findings for the AI prompt

    Args:
        findings (dict): Scan results

    Returns:
        dict: Summary of key findings
    """
    summary = {
        'domain': findings.get('domain', 'Unknown'),
        'total_subdomains': len(findings.get('subdomains', [])) + len(findings.get('crt_subdomains', [])),
        'sensitive_subdomains': [],
        'cloud_assets': [],
        'open_ports': [],
        'vulnerabilities': [],
        'critical_findings': findings.get('critical_findings', []),
        'risk_score': findings.get('risk_score', 0),
        'risk_level': findings.get('risk_level', 'low')
    }

    # Extract sensitive subdomains
    sensitive_keywords = ['admin', 'vpn', 'dev', 'staging', 'test', 'db', 'git', 'jenkins']
    for sub in findings.get('subdomains', []):
        subdomain = sub.get('subdomain', '').lower()
        for keyword in sensitive_keywords:
            if keyword in subdomain:
                summary['sensitive_subdomains'].append(subdomain)
                break

    # Extract cloud assets
    for asset in findings.get('cloud_assets', []):
        summary['cloud_assets'].append({
            'type': asset.get('type'),
            'name': asset.get('name'),
            'accessible': asset.get('accessible'),
            'risk': asset.get('risk')
        })

    # Extract Shodan findings (ports and services)
    for shodan in findings.get('shodan_results', []):
        summary['open_ports'].append({
            'ip': shodan.get('ip'),
            'port': shodan.get('port'),
            'service': shodan.get('service'),
            'risk': shodan.get('risk')
        })

        # Extract CVEs
        for cve in shodan.get('vulnerabilities', []):
            summary['vulnerabilities'].append({
                'cve': cve,
                'ip': shodan.get('ip'),
                'port': shodan.get('port'),
                'service': shodan.get('service')
            })

    return summary


def create_attack_sim_prompt(findings_summary):
    """
    Create a detailed prompt for Gemini AI

    Args:
        findings_summary (dict): Summary of findings

    Returns:
        str: Formatted prompt
    """
    domain = findings_summary['domain']
    risk_level = findings_summary['risk_level'].upper()

    prompt = f"""You are a cybersecurity expert performing a penetration test simulation.
Based on the following attack surface scan results for {domain}, generate a realistic, step-by-step attack plan.

## SCAN RESULTS

**Domain:** {domain}
**Risk Score:** {findings_summary['risk_score']}/100 ({risk_level})
**Total Subdomains Discovered:** {findings_summary['total_subdomains']}

"""

    # Add sensitive subdomains
    if findings_summary['sensitive_subdomains']:
        prompt += f"**Sensitive Subdomains Found:**\n"
        for sub in findings_summary['sensitive_subdomains'][:10]:
            prompt += f"- {sub}\n"
        prompt += "\n"

    # Add cloud assets
    if findings_summary['cloud_assets']:
        prompt += f"**Cloud Assets Found:**\n"
        for asset in findings_summary['cloud_assets'][:5]:
            accessible = "PUBLIC ACCESS" if asset['accessible'] else "Private"
            prompt += f"- {asset['type']}: {asset['name']} ({accessible}) - Risk: {asset['risk']}\n"
        prompt += "\n"

    # Add open ports
    if findings_summary['open_ports']:
        prompt += f"**Open Ports/Services:**\n"
        for port_info in findings_summary['open_ports'][:10]:
            prompt += f"- {port_info['ip']}:{port_info['port']} - {port_info['service']} (Risk: {port_info['risk']})\n"
        prompt += "\n"

    # Add vulnerabilities
    if findings_summary['vulnerabilities']:
        prompt += f"**Known Vulnerabilities (CVEs):**\n"
        for vuln in findings_summary['vulnerabilities'][:5]:
            prompt += f"- {vuln['cve']} on {vuln['ip']}:{vuln['port']} ({vuln['service']})\n"
        prompt += "\n"

    # Add critical findings
    if findings_summary['critical_findings']:
        prompt += f"**Critical Security Findings:**\n"
        for finding in findings_summary['critical_findings'][:5]:
            prompt += f"- [{finding['severity']}] {finding['type']}: {finding['description']}\n"
        prompt += "\n"

    prompt += """
## INSTRUCTIONS

Generate a detailed, realistic attack simulation plan with the following sections:

1. **Attack Vector Selection** - Which vulnerabilities/weaknesses would an attacker target first and why?

2. **Initial Access** - Step-by-step method to gain initial foothold (e.g., exploit CVE, brute force weak service, social engineering)

3. **Privilege Escalation** - How would an attacker escalate privileges after initial access?

4. **Lateral Movement** - How could an attacker move through the network using discovered assets?

5. **Data Exfiltration** - What sensitive data could be targeted and how?

6. **Tools & Techniques** - Specific tools an attacker would use (Metasploit, Nmap, Burp Suite, etc.)

7. **Detection Evasion** - How would a sophisticated attacker avoid detection?

8. **Recommendations** - Top 3 immediate remediation steps to prevent this attack

Format the response in clear markdown with headers and bullet points. Be specific and technical.
Focus on realistic attack scenarios a red team would execute.
"""

    return prompt


# Test function
if __name__ == '__main__':
    # Test with sample findings
    test_findings = {
        'domain': 'example.com',
        'risk_score': 65,
        'risk_level': 'high',
        'subdomains': [
            {'subdomain': 'www.example.com'},
            {'subdomain': 'admin.example.com'},
            {'subdomain': 'dev.example.com'},
        ],
        'crt_subdomains': [],
        'cloud_assets': [
            {
                'type': 'AWS S3',
                'name': 'example-backup',
                'accessible': True,
                'risk': 'CRITICAL'
            }
        ],
        'shodan_results': [
            {
                'ip': '192.168.1.1',
                'port': 22,
                'service': 'OpenSSH',
                'risk': 'HIGH',
                'vulnerabilities': ['CVE-2023-12345']
            }
        ],
        'critical_findings': [
            {
                'type': 'Admin Subdomain Exposed',
                'description': 'admin.example.com is publicly accessible',
                'severity': 'CRITICAL'
            }
        ]
    }

    print("\n🤖 Testing AI Attack Simulation\n")
    result = generate_attack_plan(test_findings)

    if result['success']:
        print("\n" + "="*60)
        print("ATTACK PLAN")
        print("="*60)
        print(result['attack_plan'])
        print("="*60 + "\n")
    else:
        print(f"\n❌ Error: {result['error']}\n")
