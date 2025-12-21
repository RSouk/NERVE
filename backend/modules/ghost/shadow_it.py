"""
Shadow IT Discovery
Discovers unauthorized tools and services used by employees
Uses unified_search to find breach sources and categorize by tool type
"""

from datetime import datetime
import sys
import os

# Add backend to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from modules.ghost.unified_search import UnifiedSearch


def discover_shadow_it(company_domain):
    """
    Discover Shadow IT tools and unauthorized services

    Args:
        company_domain (str): Company domain (e.g., "stripe.com")

    Returns:
        dict: Shadow IT findings with tools, employee count, risk level
    """
    print(f"\n{'='*60}")
    print(f"[SHADOW IT] Discovering unauthorized tools for {company_domain}...")
    print(f"{'='*60}\n")

    # Extract company name from domain
    company_name = company_domain.split('.')[0]

    # Use unified search to find breaches
    searcher = UnifiedSearch()

    print(f"[SHADOW IT] Searching for: {company_name}")
    search_results = searcher.search(company_name)

    # Extract tools from breach sources
    tools_found = []
    unique_tools = set()
    employee_emails = set()

    # Process GitHub findings
    for github in search_results.get('github_results', []):
        source = github.get('source', '').lower()
        email = github.get('email', '')

        if email:
            employee_emails.add(email)

        # Extract tool type from source
        tool_info = categorize_tool_from_source(source, github.get('url', ''))

        if tool_info and tool_info['name'] not in unique_tools:
            unique_tools.add(tool_info['name'])
            tools_found.append(tool_info)

    # Process PasteBin findings
    for pastebin in search_results.get('pastebin_results', []):
        source = pastebin.get('source', '').lower()

        tool_info = categorize_tool_from_source(source, pastebin.get('url', ''))

        if tool_info and tool_info['name'] not in unique_tools:
            unique_tools.add(tool_info['name'])
            tools_found.append(tool_info)

    # Process uploaded file credentials
    for cred in search_results.get('uploaded_file_results', []):
        email = cred.get('email', '')
        if email:
            employee_emails.add(email)

    # Process Hudson Rock findings
    for hudson in search_results.get('hudson_rock_results', []):
        computer_name = hudson.get('computer_name', '').lower()
        email = hudson.get('email', '')

        if email:
            employee_emails.add(email)

        # Extract tools from computer name or breach source
        if computer_name:
            tool_info = categorize_tool_from_computer(computer_name)
            if tool_info and tool_info['name'] not in unique_tools:
                unique_tools.add(tool_info['name'])
                tools_found.append(tool_info)

    # Calculate risk level
    risk_level = calculate_shadow_it_risk(tools_found, len(employee_emails))

    # Flag unauthorized tools
    flagged_tools = flag_unauthorized_tools(tools_found)

    print(f"\n[SHADOW IT] Discovery complete:")
    print(f"[SHADOW IT]   Tools Found: {len(tools_found)}")
    print(f"[SHADOW IT]   Flagged Tools: {len(flagged_tools)}")
    print(f"[SHADOW IT]   Unique Employees: {len(employee_emails)}")
    print(f"[SHADOW IT]   Risk Level: {risk_level}")
    print(f"{'='*60}\n")

    return {
        'success': True,
        'tools': tools_found,
        'flagged_tools': flagged_tools,
        'employee_count': len(employee_emails),
        'risk_level': risk_level,
        'total_exposures': len(search_results.get('github_results', [])) +
                          len(search_results.get('pastebin_results', [])) +
                          len(search_results.get('hudson_rock_results', []))
    }


def categorize_tool_from_source(source, url=''):
    """
    Categorize tool type from breach source

    Args:
        source (str): Source description
        url (str): Source URL

    Returns:
        dict: Tool information or None
    """
    # Common SaaS tools
    saas_tools = {
        'slack': {'type': 'Communications', 'risk': 'HIGH', 'authorized': False},
        'trello': {'type': 'Project Management', 'risk': 'MEDIUM', 'authorized': False},
        'asana': {'type': 'Project Management', 'risk': 'MEDIUM', 'authorized': False},
        'jira': {'type': 'Project Management', 'risk': 'MEDIUM', 'authorized': True},
        'github': {'type': 'Code Repository', 'risk': 'HIGH', 'authorized': True},
        'gitlab': {'type': 'Code Repository', 'risk': 'HIGH', 'authorized': True},
        'dropbox': {'type': 'Storage', 'risk': 'HIGH', 'authorized': False},
        'box': {'type': 'Storage', 'risk': 'MEDIUM', 'authorized': False},
        'google drive': {'type': 'Storage', 'risk': 'MEDIUM', 'authorized': True},
        'onedrive': {'type': 'Storage', 'risk': 'MEDIUM', 'authorized': True},
        'zoom': {'type': 'Communications', 'risk': 'LOW', 'authorized': True},
        'teams': {'type': 'Communications', 'risk': 'LOW', 'authorized': True},
        'notion': {'type': 'Collaboration', 'risk': 'MEDIUM', 'authorized': False},
        'airtable': {'type': 'Database', 'risk': 'MEDIUM', 'authorized': False},
        'salesforce': {'type': 'CRM', 'risk': 'HIGH', 'authorized': True},
        'hubspot': {'type': 'CRM', 'risk': 'MEDIUM', 'authorized': False},
        'zendesk': {'type': 'Support', 'risk': 'MEDIUM', 'authorized': True},
        'intercom': {'type': 'Support', 'risk': 'MEDIUM', 'authorized': False},
        'mailchimp': {'type': 'Marketing', 'risk': 'MEDIUM', 'authorized': False},
        'sendgrid': {'type': 'Email Service', 'risk': 'MEDIUM', 'authorized': True},
        'aws': {'type': 'Cloud Infrastructure', 'risk': 'CRITICAL', 'authorized': True},
        'azure': {'type': 'Cloud Infrastructure', 'risk': 'CRITICAL', 'authorized': True},
        'gcp': {'type': 'Cloud Infrastructure', 'risk': 'CRITICAL', 'authorized': True},
        'heroku': {'type': 'Cloud Platform', 'risk': 'HIGH', 'authorized': False},
        'digitalocean': {'type': 'Cloud Platform', 'risk': 'HIGH', 'authorized': False}
    }

    # Check source for tool keywords
    source_lower = source.lower()
    url_lower = url.lower()

    for tool_name, tool_data in saas_tools.items():
        if tool_name in source_lower or tool_name in url_lower:
            return {
                'name': tool_name.title(),
                'type': tool_data['type'],
                'risk': tool_data['risk'],
                'authorized': tool_data['authorized'],
                'source': source[:100]  # Truncate
            }

    # If no match, return generic finding
    if source and len(source) > 3:
        return {
            'name': source[:50],
            'type': 'Unknown',
            'risk': 'LOW',
            'authorized': False,
            'source': source[:100]
        }

    return None


def categorize_tool_from_computer(computer_name):
    """
    Extract tool information from computer name

    Args:
        computer_name (str): Computer/machine name

    Returns:
        dict: Tool information or None
    """
    # Look for tool indicators in computer names
    tool_indicators = {
        'slack': 'Communications',
        'zoom': 'Communications',
        'teams': 'Communications',
        'dropbox': 'Storage',
        'onedrive': 'Storage'
    }

    for tool, category in tool_indicators.items():
        if tool in computer_name.lower():
            return {
                'name': tool.title(),
                'type': category,
                'risk': 'MEDIUM',
                'authorized': False,
                'source': f'Computer: {computer_name}'
            }

    return None


def flag_unauthorized_tools(tools):
    """
    Flag unauthorized tools from the list

    Args:
        tools (list): List of discovered tools

    Returns:
        list: Flagged unauthorized tools
    """
    flagged = []

    for tool in tools:
        if not tool.get('authorized', False):
            flagged.append(tool)

    return flagged


def calculate_shadow_it_risk(tools, employee_count):
    """
    Calculate overall Shadow IT risk level

    Args:
        tools (list): Discovered tools
        employee_count (int): Number of unique employees found

    Returns:
        str: Risk level (LOW, MEDIUM, HIGH, CRITICAL)
    """
    risk_score = 0

    # Count by risk level
    for tool in tools:
        tool_risk = tool.get('risk', 'LOW')

        if tool_risk == 'CRITICAL':
            risk_score += 10
        elif tool_risk == 'HIGH':
            risk_score += 7
        elif tool_risk == 'MEDIUM':
            risk_score += 4
        elif tool_risk == 'LOW':
            risk_score += 2

    # Factor in employee count
    if employee_count > 50:
        risk_score += 15
    elif employee_count > 20:
        risk_score += 10
    elif employee_count > 10:
        risk_score += 5

    # Factor in unauthorized tools
    unauthorized_count = sum(1 for t in tools if not t.get('authorized', False))
    risk_score += unauthorized_count * 5

    # Determine risk level
    if risk_score >= 50:
        return 'CRITICAL'
    elif risk_score >= 30:
        return 'HIGH'
    elif risk_score >= 15:
        return 'MEDIUM'
    else:
        return 'LOW'


# Test function
if __name__ == '__main__':
    # Test with a domain
    test_domain = 'stripe.com'
    print(f"\n🔍 Testing Shadow IT Discovery with {test_domain}\n")

    results = discover_shadow_it(test_domain)

    print("\n" + "="*60)
    print("SHADOW IT DISCOVERY RESULTS")
    print("="*60)
    print(f"Tools Found: {len(results['tools'])}")
    print(f"Flagged (Unauthorized): {len(results['flagged_tools'])}")
    print(f"Employees Exposed: {results['employee_count']}")
    print(f"Risk Level: {results['risk_level']}")
    print(f"Total Exposures: {results['total_exposures']}")
    print("="*60 + "\n")

    if results['tools']:
        print("Discovered Tools:")
        for tool in results['tools'][:10]:
            auth_status = "✓ Authorized" if tool['authorized'] else "✗ Unauthorized"
            print(f"  - {tool['name']} ({tool['type']}) [{tool['risk']}] {auth_status}")
