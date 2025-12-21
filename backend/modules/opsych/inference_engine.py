"""
OPSYCH Inference Engine
Cross-references multiple data sources to build comprehensive intelligence profiles
Handles ambiguity, multiple matches, and confidence scoring
"""

import re
from datetime import datetime


def infer_intelligence(raw_data, query_params):
    """
    Build comprehensive intelligence profile from raw data sources

    Args:
        raw_data: Dict containing results from all data sources
        query_params: Original query parameters

    Returns:
        {
            'profiles': [list of potential profile matches],
            'confidence_level': 'high' | 'medium' | 'low',
            'ambiguity_detected': bool,
            'recommendation': str
        }
    """

    result = {
        'profiles': [],
        'confidence_level': 'low',
        'ambiguity_detected': False,
        'recommendation': None,
        'total_sources_checked': 0,
        'sources_with_hits': 0,
        'cross_reference_strength': 0
    }

    # Count sources
    result['total_sources_checked'] = len([v for v in raw_data.values() if v])
    result['sources_with_hits'] = len([v for v in raw_data.values() if v and _has_data(v)])

    # Build profiles from data
    profiles = _build_profiles(raw_data, query_params)

    if not profiles:
        result['recommendation'] = "No data found. Try adding more search parameters or checking spelling."
        return result

    # Merge and deduplicate profiles
    merged_profiles = _merge_similar_profiles(profiles)

    # Calculate confidence for each profile
    for profile in merged_profiles:
        profile['confidence_score'] = _calculate_profile_confidence(profile, query_params)
        profile['field_confidence'] = _calculate_field_confidence(profile)

    # Sort by confidence
    merged_profiles = sorted(merged_profiles, key=lambda x: x['confidence_score'], reverse=True)

    result['profiles'] = merged_profiles

    # Determine overall confidence level
    if merged_profiles:
        top_confidence = merged_profiles[0]['confidence_score']
        if top_confidence >= 80:
            result['confidence_level'] = 'high'
        elif top_confidence >= 50:
            result['confidence_level'] = 'medium'
        else:
            result['confidence_level'] = 'low'

    # Detect ambiguity (multiple high-confidence matches)
    high_confidence_matches = [p for p in merged_profiles if p['confidence_score'] >= 60]
    if len(high_confidence_matches) > 1:
        result['ambiguity_detected'] = True
        result['recommendation'] = f"Found {len(high_confidence_matches)} potential matches. Add more details (location, age, company) to narrow results."

    # Calculate cross-reference strength
    if merged_profiles:
        result['cross_reference_strength'] = _calculate_cross_reference_strength(merged_profiles[0])

    return result


def _build_profiles(raw_data, query_params):
    """
    Build individual profiles from each data source
    """

    profiles = []

    # === Email-based profile ===
    if raw_data.get('reverse_email'):
        email_data = raw_data['reverse_email']
        profile = {
            'name': email_data.get('name'),
            'email': query_params.get('email'),
            'company': email_data.get('company'),
            'position': email_data.get('position'),
            'location': email_data.get('location'),
            'phone': email_data.get('phone'),
            'social_accounts': email_data.get('social_accounts', []),
            'breaches': email_data.get('breaches', []),
            'sources': ['reverse_email']
        }
        profiles.append(profile)

    # === Phone-based profile ===
    if raw_data.get('reverse_phone'):
        phone_data = raw_data['reverse_phone']
        profile = {
            'name': phone_data.get('name'),
            'phone': query_params.get('phone'),
            'location': phone_data.get('location'),
            'carrier': phone_data.get('carrier'),
            'line_type': phone_data.get('line_type'),
            'addresses': phone_data.get('addresses', []),
            'relatives': phone_data.get('relatives', []),
            'emails': phone_data.get('associated_emails', []),
            'social_accounts': phone_data.get('social_profiles', []),
            'sources': ['reverse_phone']
        }
        profiles.append(profile)

    # === Whitepages profiles (can be multiple) ===
    if raw_data.get('whitepages'):
        wp_data = raw_data['whitepages']
        for match in wp_data.get('matches', []):
            profile = {
                'name': match.get('name'),
                'age': match.get('age'),
                'location': match.get('location'),
                'phones': match.get('phones', []),
                'addresses': match.get('addresses', []),
                'relatives': match.get('relatives', []),
                'sources': ['whitepages'],
                'whitepages_confidence': match.get('confidence_score', 0)
            }
            profiles.append(profile)

    # === Social media profile ===
    if raw_data.get('sherlock'):
        sherlock_data = raw_data['sherlock']
        profile = {
            'username': query_params.get('username'),
            'name': sherlock_data.get('real_name'),
            'social_accounts': sherlock_data.get('platforms_found', []),
            'emails': sherlock_data.get('emails_discovered', []),
            'sources': ['sherlock']
        }
        if profile['name'] or profile['social_accounts']:
            profiles.append(profile)

    # === Hunter.io profile ===
    if raw_data.get('hunter'):
        hunter_data = raw_data['hunter']
        profile = {
            'name': hunter_data.get('name'),
            'email': hunter_data.get('email'),
            'company': hunter_data.get('company'),
            'position': hunter_data.get('position'),
            'sources': ['hunter']
        }
        profiles.append(profile)

    # === Ghost breach data ===
    if raw_data.get('ghost_breaches'):
        breach_data = raw_data['ghost_breaches']
        if breach_data.get('credentials'):
            # Create profile from breach data
            for cred in breach_data['credentials'][:3]:  # Limit to top 3
                profile = {
                    'email': cred.get('email'),
                    'name': cred.get('name'),
                    'phone': cred.get('phone'),
                    'breaches': [cred],
                    'sources': ['ghost_breaches']
                }
                profiles.append(profile)

    return profiles


def _merge_similar_profiles(profiles):
    """
    Merge profiles that appear to be the same person
    Uses name matching, email matching, phone matching
    """

    if not profiles:
        return []

    merged = []
    used_indices = set()

    for i, profile1 in enumerate(profiles):
        if i in used_indices:
            continue

        # Start with this profile
        merged_profile = profile1.copy()
        matched_indices = {i}

        # Find all similar profiles
        for j, profile2 in enumerate(profiles):
            if j <= i or j in used_indices:
                continue

            if _profiles_match(profile1, profile2):
                # Merge profile2 into merged_profile
                merged_profile = _merge_two_profiles(merged_profile, profile2)
                matched_indices.add(j)
                used_indices.add(j)

        used_indices.update(matched_indices)
        merged.append(merged_profile)

    return merged


def _profiles_match(profile1, profile2):
    """
    Determine if two profiles represent the same person
    """

    # Name matching
    name1 = profile1.get('name', '').lower().strip()
    name2 = profile2.get('name', '').lower().strip()

    if name1 and name2 and name1 == name2:
        return True

    # Email matching
    email1 = profile1.get('email', '').lower()
    email2 = profile2.get('email', '').lower()

    if email1 and email2 and email1 == email2:
        return True

    # Phone matching
    phone1 = _normalize_phone(profile1.get('phone', ''))
    phone2 = _normalize_phone(profile2.get('phone', ''))

    if phone1 and phone2 and phone1 == phone2:
        return True

    # Username matching
    username1 = profile1.get('username', '').lower()
    username2 = profile2.get('username', '').lower()

    if username1 and username2 and username1 == username2:
        return True

    return False


def _merge_two_profiles(profile1, profile2):
    """
    Merge two profiles into one, combining all data
    """

    merged = profile1.copy()

    # Merge sources
    sources1 = set(profile1.get('sources', []))
    sources2 = set(profile2.get('sources', []))
    merged['sources'] = list(sources1.union(sources2))

    # Merge fields (prefer non-null values)
    for key in profile2.keys():
        if key == 'sources':
            continue

        value2 = profile2[key]

        if isinstance(value2, list):
            # Merge lists
            existing = merged.get(key, [])
            if isinstance(existing, list):
                merged[key] = existing + [v for v in value2 if v not in existing]
            else:
                merged[key] = value2
        elif value2 and not merged.get(key):
            # Use value2 if value1 is None/empty
            merged[key] = value2

    return merged


def _calculate_profile_confidence(profile, query_params):
    """
    Calculate overall confidence score for a profile (0-100)
    """

    confidence = 0

    # Source count bonus
    num_sources = len(profile.get('sources', []))
    confidence += min(num_sources * 15, 45)  # Max 45 points for sources

    # Unique identifier matches
    if query_params.get('email') and profile.get('email'):
        if query_params['email'].lower() == profile['email'].lower():
            confidence += 25

    if query_params.get('phone') and profile.get('phone'):
        if _normalize_phone(query_params['phone']) == _normalize_phone(profile['phone']):
            confidence += 25

    # Name match
    if query_params.get('name') and profile.get('name'):
        if _names_match(query_params['name'], profile['name']):
            confidence += 15

    # Location match
    if query_params.get('location') and profile.get('location'):
        if query_params['location'].lower() in profile['location'].lower():
            confidence += 10

    # Age match
    if query_params.get('age') and profile.get('age'):
        if _age_matches(query_params['age'], profile['age']):
            confidence += 10

    # Company match
    if query_params.get('company') and profile.get('company'):
        if query_params['company'].lower() in profile['company'].lower():
            confidence += 10

    # Whitepages confidence bonus
    if 'whitepages' in profile.get('sources', []):
        wp_conf = profile.get('whitepages_confidence', 0)
        confidence += wp_conf * 0.2  # Scale whitepages confidence

    return min(confidence, 100)


def _calculate_field_confidence(profile):
    """
    Calculate confidence score for each individual field
    Returns dict mapping field -> confidence percentage
    """

    field_confidence = {}
    num_sources = len(profile.get('sources', []))

    for field, value in profile.items():
        if field in ['sources', 'confidence_score', 'field_confidence']:
            continue

        if not value:
            field_confidence[field] = 0
            continue

        # Base confidence on number of confirming sources
        if num_sources >= 3:
            field_confidence[field] = 90
        elif num_sources == 2:
            field_confidence[field] = 70
        else:
            field_confidence[field] = 50

    return field_confidence


def _calculate_cross_reference_strength(profile):
    """
    Calculate how well data cross-references (0-100)
    High score = data from multiple sources agrees
    """

    num_sources = len(profile.get('sources', []))

    if num_sources >= 4:
        return 95
    elif num_sources == 3:
        return 80
    elif num_sources == 2:
        return 60
    else:
        return 30


def handle_ambiguity(results, query):
    """
    Handle cases where multiple potential matches are found
    Provides recommendations for narrowing search
    """

    profiles = results.get('profiles', [])

    if len(profiles) <= 1:
        return results  # No ambiguity

    # Add ambiguity handling
    results['ambiguity_status'] = {
        'total_matches': len(profiles),
        'high_confidence_matches': len([p for p in profiles if p['confidence_score'] >= 60]),
        'recommendation': None,
        'missing_fields': []
    }

    # Determine what fields could help narrow results
    missing_fields = []

    if not query.get('location'):
        missing_fields.append('location')
    if not query.get('age'):
        missing_fields.append('age')
    if not query.get('company'):
        missing_fields.append('company')
    if not query.get('phone') and not query.get('email'):
        missing_fields.append('phone or email')

    results['ambiguity_status']['missing_fields'] = missing_fields

    if missing_fields:
        results['ambiguity_status']['recommendation'] = (
            f"Multiple potential matches found. Add {', '.join(missing_fields[:2])} to narrow results."
        )

    # Highlight differences between top matches
    if len(profiles) >= 2:
        diff = _highlight_profile_differences(profiles[0], profiles[1])
        results['ambiguity_status']['top_matches_differ_by'] = diff

    return results


def _highlight_profile_differences(profile1, profile2):
    """
    Show key differences between two profiles
    """

    differences = []

    if profile1.get('location') != profile2.get('location'):
        differences.append({
            'field': 'location',
            'profile1': profile1.get('location'),
            'profile2': profile2.get('location')
        })

    if profile1.get('age') != profile2.get('age'):
        differences.append({
            'field': 'age',
            'profile1': profile1.get('age'),
            'profile2': profile2.get('age')
        })

    if profile1.get('company') != profile2.get('company'):
        differences.append({
            'field': 'company',
            'profile1': profile1.get('company'),
            'profile2': profile2.get('company')
        })

    return differences


# ============= HELPER FUNCTIONS =============

def _has_data(data_dict):
    """Check if data dict has any actual data"""
    if not data_dict:
        return False
    if isinstance(data_dict, dict):
        return any(v for k, v in data_dict.items() if k not in ['error', 'sources'] and v)
    return False


def _normalize_phone(phone):
    """Normalize phone to digits only"""
    if not phone:
        return ''
    return re.sub(r'[^0-9]', '', str(phone))


def _names_match(name1, name2):
    """Check if two names match (fuzzy)"""
    if not name1 or not name2:
        return False

    n1 = name1.lower().strip()
    n2 = name2.lower().strip()

    return n1 == n2 or n1 in n2 or n2 in n1


def _age_matches(search_age, actual_age):
    """Check if age matches search criteria"""
    if not actual_age:
        return False

    try:
        actual = int(re.search(r'\d+', str(actual_age)).group())

        if '-' in str(search_age):
            min_age, max_age = map(int, search_age.split('-'))
            return min_age <= actual <= max_age
        else:
            target = int(search_age)
            return abs(actual - target) <= 2
    except:
        return False
