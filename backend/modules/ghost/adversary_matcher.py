import json
from typing import List, Dict

class AdversaryMatcher:
    def __init__(self):
        self.threat_actors = []
        self.load_threat_actors()
    
    def load_threat_actors(self):
        """Load MISP threat actor database"""
        try:
            with open('data/misp_threat_actors.json', 'r', encoding='utf-8') as f:
                self.threat_actors = json.load(f)
            print(f"✓ Loaded {len(self.threat_actors)} threat actors")
        except Exception as e:
            print(f"❌ Error loading threat actors: {e}")
            self.threat_actors = []
    
    def analyze_threat_landscape(self, profile: Dict) -> List[Dict]:
        """
        Match user profile against threat actor database
        
        Args:
            profile: Dict with keys:
                - industry
                - location
                - company_size
                - tech_stack
                - cloud_usage
                - remote_work
                - security_maturity
                - internet_facing
                - critical_assets
                - data_sensitivity
        
        Returns:
            List of matched threat actors with risk explanations
        """
        
        matched_threats = []
        
        for actor in self.threat_actors:
            match_score = 0
            match_reasons = []
            
            # 1. INDUSTRY MATCHING (Most important)
            industry_match = self._match_industry(profile['industry'], actor)
            if industry_match['matched']:
                match_score += 35
                match_reasons.append(industry_match['reason'])
            
            # 2. GEOGRAPHIC TARGETING
            region_match = self._match_region(profile['location'], actor)
            if region_match['matched']:
                match_score += 25
                match_reasons.append(region_match['reason'])
            
            # 3. TECH STACK TARGETING
            tech_match = self._match_tech_stack(profile['tech_stack'], profile['cloud_usage'], actor)
            if tech_match['matched']:
                match_score += 20
                match_reasons.append(tech_match['reason'])
            
            # 4. ATTACK SURFACE (Internet-facing + Remote work)
            surface_match = self._match_attack_surface(
                profile['internet_facing'],
                profile['remote_work'],
                actor
            )
            if surface_match['matched']:
                match_score += 10
                match_reasons.append(surface_match['reason'])
            
            # 5. DATA VALUE (Critical assets + sensitivity)
            data_match = self._match_data_value(
                profile['critical_assets'],
                profile['data_sensitivity'],
                actor
            )
            if data_match['matched']:
                match_score += 10
                match_reasons.append(data_match['reason'])
            
            # Only include if there's a meaningful match
            if match_score >= 30:  # At least one major match
                threat_info = self._build_threat_profile(actor, match_score, match_reasons, profile)
                matched_threats.append(threat_info)
        
        # Sort by match score (highest first)
        matched_threats.sort(key=lambda x: x['match_score'], reverse=True)
        
        # Return top 10
        return matched_threats[:10]
    
    def _match_industry(self, user_industry: str, actor: Dict) -> Dict:
        """Match user's industry against threat actor targets"""
        
        # Industry mapping: user input -> MISP categories
        industry_map = {
            'financial': ['Financial', 'Banking', 'Finance', 'Private sector', 'Financial services'],
            'healthcare': ['Healthcare', 'Health', 'Pharmaceuticals', 'Medical', 'Hospital'],
            'technology': ['Technology', 'Software', 'IT', 'Information technology', 'Tech'],
            'energy': ['Energy', 'Oil', 'Gas', 'Utilities', 'Power'],
            'government': ['Government', 'Defense', 'Military', 'Public sector', 'Federal'],
            'retail': ['Retail', 'E-commerce', 'Consumer', 'Shopping'],
            'manufacturing': ['Manufacturing', 'Industrial', 'Production'],
            'telecommunications': ['Telecommunications', 'Telecoms', 'Telecom', 'Communications'],
            'education': ['Education', 'University', 'Academic', 'School'],
            'media': ['Media', 'Entertainment', 'Broadcasting', 'Publishing'],
            'critical-infrastructure': ['Critical infrastructure', 'Infrastructure', 'Utilities'],
            'transportation': ['Transportation', 'Logistics', 'Aviation', 'Maritime']
        }
        
        user_keywords = industry_map.get(user_industry, [user_industry])
        
        # Check target_categories field
        target_cats = actor.get('target_categories', [])
        for keyword in user_keywords:
            for category in target_cats:
                if keyword.lower() in category.lower():
                    return {
                        'matched': True,
                        'reason': f"Actively targets {category} sector"
                    }
        
        # Check description for industry mentions
        description = actor.get('description', '').lower()
        for keyword in user_keywords:
            if keyword.lower() in description:
                return {
                    'matched': True,
                    'reason': f"Known to target {keyword} organizations"
                }
        
        return {'matched': False, 'reason': ''}
    
    def _match_region(self, user_location: str, actor: Dict) -> Dict:
        """Match user's location against threat actor targeting"""
        
        # Region mapping
        region_map = {
            'north-america': ['United States', 'Canada', 'Mexico', 'US', 'USA', 'North America'],
            'europe': ['United Kingdom', 'Germany', 'France', 'Europe', 'EU', 'UK', 'Spain', 'Italy'],
            'asia-pacific': ['China', 'Japan', 'South Korea', 'Taiwan', 'Singapore', 'Australia', 'India', 'Asia'],
            'middle-east': ['Israel', 'Saudi Arabia', 'UAE', 'Middle East', 'Iran', 'Turkey'],
            'latin-america': ['Brazil', 'Argentina', 'Colombia', 'Latin America', 'South America'],
            'africa': ['South Africa', 'Nigeria', 'Africa', 'Kenya']
        }
        
        user_countries = region_map.get(user_location, [user_location])
        
        # Check victims field
        victims = actor.get('victims', [])
        for country in user_countries:
            for victim in victims:
                if country.lower() in victim.lower():
                    return {
                        'matched': True,
                        'reason': f"Has previously targeted organizations in {victim}"
                    }
        
        return {'matched': False, 'reason': ''}
    
    def _match_tech_stack(self, tech_stack: str, cloud_usage: str, actor: Dict) -> Dict:
        """Match tech stack against threat actor capabilities"""
        
        # Check description for tech stack mentions
        description = actor.get('description', '').lower()
        
        tech_keywords = {
            'windows': ['windows', 'microsoft', 'active directory', 'rdp'],
            'linux': ['linux', 'unix', 'ssh'],
            'cloud-aws': ['aws', 'amazon', 'cloud'],
            'cloud-azure': ['azure', 'microsoft cloud'],
            'cloud-gcp': ['google cloud', 'gcp'],
            'hybrid': ['hybrid', 'cloud', 'on-premise'],
            'on-premise': ['on-premise', 'local']
        }
        
        keywords = tech_keywords.get(tech_stack, [tech_stack])
        for keyword in keywords:
            if keyword in description:
                return {
                    'matched': True,
                    'reason': f"Targets {tech_stack.replace('-', ' ')} environments"
                }
        
        return {'matched': False, 'reason': ''}
    
    def _match_attack_surface(self, internet_facing: str, remote_work: str, actor: Dict) -> Dict:
        """Match attack surface against threat actor TTPs"""
        
        description = actor.get('description', '').lower()
        
        # Look for attack vectors
        if internet_facing in ['extensive', 'high']:
            if any(keyword in description for keyword in ['vpn', 'remote', 'exploit', 'vulnerability']):
                return {
                    'matched': True,
                    'reason': "Exploits internet-facing systems and VPNs"
                }
        
        if remote_work in ['mostly', 'full', 'hybrid']:
            if any(keyword in description for keyword in ['remote', 'vpn', 'credential']):
                return {
                    'matched': True,
                    'reason': "Targets remote workforce infrastructure"
                }
        
        return {'matched': False, 'reason': ''}
    
    def _match_data_value(self, critical_assets, data_sensitivity: str, actor: Dict) -> Dict:
        """Match data value against threat actor motivations"""
        
        description = actor.get('description', '').lower()
        incident_type = actor.get('incident_types', '')
        
        # Handle critical_assets as list or string
        if isinstance(critical_assets, list):
            assets_list = critical_assets
        else:
            assets_list = [critical_assets]
        
        # Financial motivation
        if any(asset in ['financial', 'customer-data'] for asset in assets_list) or data_sensitivity in ['regulated', 'confidential']:
            if 'ransom' in description or 'financial' in description:
                return {
                    'matched': True,
                    'reason': "Targets high-value financial data for extortion"
                }
        
        # Espionage motivation
        if any(asset in ['ip', 'government', 'classified'] for asset in assets_list):
            if 'espionage' in incident_type.lower() or 'espionage' in description:
                return {
                    'matched': True,
                    'reason': "Conducts cyber espionage for intellectual property theft"
                }
        
        # Critical infrastructure
        if 'infrastructure' in ' '.join(assets_list):
            if 'infrastructure' in description or 'scada' in description or 'ics' in description:
                return {
                    'matched': True,
                    'reason': "Targets critical infrastructure and operational technology"
                }
        
        return {'matched': False, 'reason': ''}
    
    def _build_threat_profile(self, actor: Dict, score: int, reasons: List[str], user_profile: Dict) -> Dict:
        """Build detailed threat profile with risk explanation"""
        
        # Extract key info
        name = actor.get('name', 'Unknown')
        aliases = actor.get('aliases', [])
        origin = actor.get('origin', 'Unknown')
        state_sponsor = actor.get('state_sponsor', origin)
        description = actor.get('description', 'No description available')
        
        # Generate personalized risk explanation
        risk_explanation = self._generate_risk_explanation(actor, reasons, user_profile)
        
        # Extract TTPs (simplified)
        ttps = self._extract_ttps(actor)
        
        return {
            'name': name,
            'aliases': ', '.join(aliases[:3]) if aliases else None,
            'origin': origin,
            'state_sponsor': state_sponsor,
            'match_score': score,
            'description': description[:500],  # Truncate long descriptions
            'risk_explanation': risk_explanation,
            'why_you': ' | '.join(reasons),
            'sophistication': self._determine_sophistication(actor),
            'active_since': self._extract_active_since(description),
            'recent_activity': self._extract_recent_activity(description),
            'ttps': ttps
        }
    
    def _determine_sophistication(self, actor: Dict) -> str:
        """Determine sophistication level from available data"""
        
        # Check if sophistication is explicitly set
        soph = actor.get('sophistication')
        if soph and soph != 'Unknown':
            return soph
        
        # Infer from state sponsor
        state_sponsor = actor.get('state_sponsor', '')
        if state_sponsor in ['China', 'Russia', 'Iran', 'North Korea']:
            return "Advanced (State-Sponsored)"
        
        # Infer from description keywords
        description = actor.get('description', '').lower()
        
        if any(word in description for word in ['advanced', 'sophisticated', 'apt', 'state-sponsored']):
            return "Advanced"
        elif any(word in description for word in ['ransomware', 'financially motivated']):
            return "Intermediate"
        
        # Check incident type
        incident = actor.get('incident_types', '')
        if isinstance(incident, str) and 'espionage' in incident.lower():
            return "Advanced"
        elif isinstance(incident, list) and any('espionage' in str(i).lower() for i in incident):
            return "Advanced"

    def _generate_risk_explanation(self, actor: Dict, reasons: List[str], profile: Dict) -> str:
        """Generate personalized risk explanation"""
        
        name = actor.get('name', 'This threat actor')
        incident_type = actor.get('incident_types', 'cyber attacks')
        
        explanation = f"{name} poses a significant threat to your organization because:\n\n"
        
        # Add specific reasons
        for i, reason in enumerate(reasons, 1):
            explanation += f"{i}. {reason}\n"
        
        explanation += f"\n{name} is known for {incident_type}. "
        
        # Add likely attack scenario
        if profile['internet_facing'] in ['extensive', 'high']:
            explanation += "With your extensive internet-facing infrastructure, they will likely exploit public-facing applications or VPN vulnerabilities for initial access. "
        
        if profile['security_maturity'] in ['basic', 'developing']:
            explanation += "Your developing security posture makes you a softer target compared to more mature organizations. "
        
        if profile['data_sensitivity'] in ['regulated', 'classified', 'confidential']:
            explanation += f"Your {profile['critical_assets']} data makes you a high-value target for both extortion and espionage operations."
        
        return explanation
    
    def _extract_ttps(self, actor: Dict) -> List[str]:
        """Extract common TTPs from description"""
        
        description = actor.get('description', '').lower()
        
        common_ttps = []
        
        ttp_keywords = {
            'Spearphishing emails with malicious attachments': ['phishing', 'spearphishing', 'malicious attachment'],
            'Exploitation of public-facing applications': ['exploit', 'vulnerability', 'cve'],
            'Credential dumping and password theft': ['credential', 'password', 'lsass', 'mimikatz'],
            'Living-off-the-land techniques': ['powershell', 'wmi', 'native tools'],
            'Ransomware deployment': ['ransomware', 'encryption', 'ransom'],
            'Data exfiltration': ['exfiltration', 'data theft', 'steal'],
            'Lateral movement via RDP/SMB': ['rdp', 'smb', 'lateral movement']
        }
        
        for ttp, keywords in ttp_keywords.items():
            if any(keyword in description for keyword in keywords):
                common_ttps.append(ttp)
        
        # If none found, add generic ones
        if not common_ttps:
            common_ttps = [
                'Initial access via phishing or exploit',
                'Credential theft and privilege escalation',
                'Lateral movement across network',
                'Data collection and exfiltration',
                'Persistence mechanisms'
            ]
        
        return common_ttps[:5]  # Return top 5
    
    def _extract_active_since(self, description: str) -> str:
        """Extract when the group became active"""
        import re
        
        # Look for "active since" patterns
        since_pattern = re.search(r'active since (?:at least )?(\d{4})', description.lower())
        if since_pattern:
            return since_pattern.group(1)
        
        # Look for any 4-digit year in the description
        years = re.findall(r'\b(19\d{2}|20[0-2]\d)\b', description)
        if years:
            # Return the earliest year found
            earliest = min(years)
            return f"{earliest}"
        
        return "Unknown"
    
    def _extract_recent_activity(self, description: str) -> str:
        """Extract recent activity mentions"""
        
        # Check for specific campaign or operation mentions
        if 'campaign' in description.lower():
            import re
            campaign = re.search(r'([A-Z][a-zA-Z\s]+(?:Campaign|Operation))', description)
            if campaign:
                return f"Known for {campaign.group(1)}"
        
        # Check for recent years
        if '2025' in description:
            return "Active in 2025"
        elif '2024' in description:
            return "Active in 2024"
        elif '2023' in description:
            return "Active in 2023"
        elif '2022' in description:
            return "Active in 2022-2023"
        elif '2021' in description or '2020' in description:
            return "Active 2020-2021"
        
        return "Ongoing threat"


# Test function
if __name__ == "__main__":
    matcher = AdversaryMatcher()
    
    # Test profile
    test_profile = {
        'industry': 'financial',
        'location': 'north-america',
        'company_size': 'large',
        'tech_stack': 'windows',
        'cloud_usage': 'partial',
        'remote_work': 'hybrid',
        'security_maturity': 'mature',
        'internet_facing': 'moderate',
        'critical_assets': 'financial',
        'data_sensitivity': 'regulated'
    }
    
    print("\n🎯 Testing Adversary Matcher...\n")
    threats = matcher.analyze_threat_landscape(test_profile)
    
    print(f"Found {len(threats)} matching threats:\n")
    for i, threat in enumerate(threats[:3], 1):
        print(f"{i}. {threat['name']} ({threat['match_score']}% match)")
        print(f"   Origin: {threat['origin']}")
        print(f"   Why: {threat['why_you']}")
        print()