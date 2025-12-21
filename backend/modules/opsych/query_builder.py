"""
OPSYCH Query Builder - Smart routing based on input combinations
Routes queries to appropriate data sources based on available information
"""

def build_advanced_queries(name=None, email=None, phone=None, username=None,
                          company=None, location=None, age=None, context=None):
    """
    Build optimized query plan based on input combination
    Returns dict with data source routing and parameters
    """

    query_plan = {
        'sources': [],
        'parameters': {},
        'priority': [],  # Order of execution
        'false_positive_risk': 'low',  # low, medium, high
        'confidence_factors': []
    }

    # Store all available parameters
    params = {
        'name': name,
        'email': email,
        'phone': phone,
        'username': username,
        'company': company,
        'location': location,
        'age': age,
        'context': context
    }

    query_plan['parameters'] = {k: v for k, v in params.items() if v}

    # Count unique identifiers
    unique_identifiers = sum([
        1 if email else 0,
        1 if phone else 0,
        1 if username else 0
    ])

    # === EMAIL ONLY ===
    if email and not any([name, phone, username, company, location, age]):
        query_plan['sources'] = ['hunter', 'ghost_breaches', 'reverse_email', 'google_dork']
        query_plan['priority'] = ['ghost_breaches', 'hunter', 'reverse_email', 'google_dork']
        query_plan['false_positive_risk'] = 'low'
        query_plan['confidence_factors'].append({'email_unique': 90})
        return query_plan

    # === PHONE ONLY ===
    if phone and not any([name, email, username, company, location, age]):
        query_plan['sources'] = ['reverse_phone', 'whitepages_phone', 'ghost_breaches']
        query_plan['priority'] = ['reverse_phone', 'whitepages_phone', 'ghost_breaches']
        query_plan['false_positive_risk'] = 'low'
        query_plan['confidence_factors'].append({'phone_unique': 85})
        return query_plan

    # === USERNAME ONLY ===
    if username and not any([name, email, phone, company, location, age]):
        query_plan['sources'] = ['sherlock', 'github_search', 'twitter_search', 'social_enum']
        query_plan['priority'] = ['sherlock', 'github_search', 'twitter_search', 'social_enum']
        query_plan['false_positive_risk'] = 'medium'
        query_plan['confidence_factors'].append({'username_common': 60})
        return query_plan

    # === NAME ONLY (HIGH FALSE POSITIVE RISK) ===
    if name and not any([email, phone, username, company, location, age]):
        query_plan['sources'] = ['whitepages_name', 'google_dork', 'linkedin_search']
        query_plan['priority'] = ['whitepages_name', 'google_dork', 'linkedin_search']
        query_plan['false_positive_risk'] = 'high'
        query_plan['confidence_factors'].append({'name_only_low_confidence': 20})
        query_plan['warning'] = 'Common name detected - results may include multiple people. Add location, age, or company to improve accuracy.'
        return query_plan

    # === NAME + LOCATION ===
    if name and location and not any([email, phone, username]):
        query_plan['sources'] = ['whitepages_filtered', 'property_records', 'voter_records', 'google_dork']
        query_plan['priority'] = ['whitepages_filtered', 'property_records', 'google_dork']
        query_plan['false_positive_risk'] = 'medium'
        query_plan['confidence_factors'].append({'name_location_match': 60})
        return query_plan

    # === NAME + COMPANY ===
    if name and company and not any([email, phone, username]):
        query_plan['sources'] = ['linkedin_search', 'hunter_domain', 'google_dork', 'clearbit']
        query_plan['priority'] = ['linkedin_search', 'hunter_domain', 'google_dork']
        query_plan['false_positive_risk'] = 'medium'
        query_plan['confidence_factors'].append({'name_company_match': 70})
        return query_plan

    # === NAME + AGE ===
    if name and age and not any([email, phone, username]):
        query_plan['sources'] = ['whitepages_age_filter', 'property_records', 'voter_records']
        query_plan['priority'] = ['whitepages_age_filter', 'property_records']
        query_plan['false_positive_risk'] = 'medium'
        query_plan['confidence_factors'].append({'name_age_match': 55})
        return query_plan

    # === EMAIL + NAME (Common combination) ===
    if email and name:
        query_plan['sources'] = ['hunter', 'ghost_breaches', 'reverse_email', 'linkedin_search', 'google_dork']
        query_plan['priority'] = ['ghost_breaches', 'hunter', 'reverse_email', 'linkedin_search']
        query_plan['false_positive_risk'] = 'low'
        query_plan['confidence_factors'].append({'email_name_match': 95})
        return query_plan

    # === PHONE + NAME ===
    if phone and name:
        query_plan['sources'] = ['reverse_phone', 'whitepages_phone', 'ghost_breaches', 'google_dork']
        query_plan['priority'] = ['reverse_phone', 'whitepages_phone', 'ghost_breaches']
        query_plan['false_positive_risk'] = 'low'
        query_plan['confidence_factors'].append({'phone_name_match': 90})
        return query_plan

    # === USERNAME + NAME ===
    if username and name:
        query_plan['sources'] = ['sherlock', 'github_search', 'twitter_search', 'linkedin_search', 'google_dork']
        query_plan['priority'] = ['sherlock', 'github_search', 'twitter_search', 'linkedin_search']
        query_plan['false_positive_risk'] = 'medium'
        query_plan['confidence_factors'].append({'username_name_match': 75})
        return query_plan

    # === NAME + LOCATION + AGE (Good combination) ===
    if name and location and age:
        query_plan['sources'] = ['whitepages_filtered', 'property_records', 'voter_records', 'google_dork']
        query_plan['priority'] = ['whitepages_filtered', 'property_records', 'voter_records']
        query_plan['false_positive_risk'] = 'low'
        query_plan['confidence_factors'].append({'name_location_age_match': 85})
        return query_plan

    # === NAME + LOCATION + COMPANY ===
    if name and location and company:
        query_plan['sources'] = ['linkedin_search', 'whitepages_filtered', 'hunter_domain', 'google_dork']
        query_plan['priority'] = ['linkedin_search', 'whitepages_filtered', 'hunter_domain']
        query_plan['false_positive_risk'] = 'low'
        query_plan['confidence_factors'].append({'name_location_company_match': 90})
        return query_plan

    # === COMPREHENSIVE QUERY (Multiple identifiers) ===
    if unique_identifiers >= 2:
        # When we have multiple unique identifiers, cross-reference everything
        query_plan['sources'] = [
            'ghost_breaches', 'hunter', 'reverse_email', 'reverse_phone',
            'whitepages_filtered', 'sherlock', 'linkedin_search',
            'github_search', 'google_dork'
        ]
        query_plan['priority'] = [
            'ghost_breaches', 'reverse_phone', 'reverse_email',
            'hunter', 'whitepages_filtered', 'sherlock', 'linkedin_search'
        ]
        query_plan['false_positive_risk'] = 'low'
        query_plan['confidence_factors'].append({'multi_identifier_cross_reference': 95})
        return query_plan

    # === DEFAULT: Use all available data sources ===
    all_sources = []
    if email:
        all_sources.extend(['hunter', 'ghost_breaches', 'reverse_email'])
    if phone:
        all_sources.extend(['reverse_phone', 'whitepages_phone'])
    if username:
        all_sources.extend(['sherlock', 'github_search', 'twitter_search'])
    if name:
        all_sources.extend(['whitepages_filtered', 'linkedin_search'])
    if company:
        all_sources.extend(['hunter_domain', 'linkedin_search'])

    # Always add Google dorking for any combination
    all_sources.append('google_dork')

    # Remove duplicates while preserving order
    query_plan['sources'] = list(dict.fromkeys(all_sources))
    query_plan['priority'] = query_plan['sources']

    # Risk assessment based on specificity
    if unique_identifiers >= 1:
        query_plan['false_positive_risk'] = 'low'
    elif name and (location or company or age):
        query_plan['false_positive_risk'] = 'medium'
    else:
        query_plan['false_positive_risk'] = 'high'

    return query_plan


def get_query_description(query_plan):
    """
    Generate human-readable description of the query plan
    """
    sources = query_plan.get('sources', [])
    risk = query_plan.get('false_positive_risk', 'unknown')

    descriptions = {
        'hunter': 'Email intelligence via Hunter.io',
        'ghost_breaches': 'Breach database search',
        'reverse_email': 'Reverse email lookup',
        'reverse_phone': 'Reverse phone lookup',
        'whitepages_phone': 'Phone number directory search',
        'whitepages_name': 'Name directory search',
        'whitepages_filtered': 'Filtered directory search',
        'whitepages_age_filter': 'Age-filtered directory search',
        'sherlock': 'Username enumeration across platforms',
        'github_search': 'GitHub profile and activity search',
        'twitter_search': 'Twitter profile search',
        'linkedin_search': 'LinkedIn profile search',
        'google_dork': 'Advanced Google search',
        'social_enum': 'Social media enumeration',
        'property_records': 'Public property records',
        'voter_records': 'Voter registration records',
        'hunter_domain': 'Company domain email search',
        'clearbit': 'Business intelligence lookup'
    }

    source_descriptions = [descriptions.get(s, s) for s in sources]

    return {
        'sources': source_descriptions,
        'risk_level': risk,
        'warning': query_plan.get('warning', None)
    }
