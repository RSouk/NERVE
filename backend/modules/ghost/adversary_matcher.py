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
            print(f"[+] Loaded {len(self.threat_actors)} threat actors")
        except Exception as e:
            print(f"[!] Error loading threat actors: {e}")
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
            match_reasons = []  # Now stores structured dicts

            # 1. INDUSTRY MATCHING (Most important - 35 points)
            industry_match = self._match_industry(profile['industry'], actor)
            if industry_match['matched']:
                points = 35
                match_score += points
                match_reasons.append({
                    'factor': 'Industry Target',
                    'points': points,
                    'strength': self._get_strength(points),
                    'evidence': industry_match['evidence']
                })

            # 2. GEOGRAPHIC TARGETING (25 points)
            region_match = self._match_region(profile['location'], actor)
            if region_match['matched']:
                points = 25
                match_score += points
                match_reasons.append({
                    'factor': 'Geographic Target',
                    'points': points,
                    'strength': self._get_strength(points),
                    'evidence': region_match['evidence']
                })

            # 3. TECH STACK TARGETING (20 points)
            tech_match = self._match_tech_stack(profile['tech_stack'], profile['cloud_usage'], actor)
            if tech_match['matched']:
                points = 20
                match_score += points
                match_reasons.append({
                    'factor': 'Technology Stack',
                    'points': points,
                    'strength': self._get_strength(points),
                    'evidence': tech_match['evidence']
                })

            # 4. ATTACK SURFACE (10 points)
            surface_match = self._match_attack_surface(
                profile['internet_facing'],
                profile['remote_work'],
                actor
            )
            if surface_match['matched']:
                points = 10
                match_score += points
                match_reasons.append({
                    'factor': 'Attack Surface',
                    'points': points,
                    'strength': self._get_strength(points),
                    'evidence': surface_match['evidence']
                })

            # 5. DATA VALUE (10 points)
            data_match = self._match_data_value(
                profile['critical_assets'],
                profile['data_sensitivity'],
                actor
            )
            if data_match['matched']:
                points = 10
                match_score += points
                match_reasons.append({
                    'factor': 'Data Value',
                    'points': points,
                    'strength': self._get_strength(points),
                    'evidence': data_match['evidence']
                })

            # Only include if there's a meaningful match
            if match_score >= 30:  # At least one major match
                threat_info = self._build_threat_profile(actor, match_score, match_reasons, profile)
                matched_threats.append(threat_info)

        # Sort by match score (highest first)
        matched_threats.sort(key=lambda x: x['match_score'], reverse=True)

        # Return top 10
        return matched_threats[:10]

    def _get_strength(self, points: int) -> str:
        """Determine strength level based on points"""
        if points > 20:
            return 'high'
        elif points >= 10:
            return 'medium'
        else:
            return 'low'

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
                        'evidence': f"Actively targets {category} sector"
                    }

        # Check description for industry mentions
        description = actor.get('description', '').lower()
        for keyword in user_keywords:
            if keyword.lower() in description:
                return {
                    'matched': True,
                    'evidence': f"Known to target {keyword} organizations"
                }

        return {'matched': False, 'evidence': ''}
    
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
                        'evidence': f"Has previously targeted organizations in {victim}"
                    }

        return {'matched': False, 'evidence': ''}
    
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
                    'evidence': f"Targets {tech_stack.replace('-', ' ')} environments"
                }

        return {'matched': False, 'evidence': ''}
    
    def _match_attack_surface(self, internet_facing: str, remote_work: str, actor: Dict) -> Dict:
        """Match attack surface against threat actor TTPs"""
        
        description = actor.get('description', '').lower()
        
        # Look for attack vectors
        if internet_facing in ['extensive', 'high']:
            if any(keyword in description for keyword in ['vpn', 'remote', 'exploit', 'vulnerability']):
                return {
                    'matched': True,
                    'evidence': "Exploits internet-facing systems and VPNs"
                }

        if remote_work in ['mostly', 'full', 'hybrid']:
            if any(keyword in description for keyword in ['remote', 'vpn', 'credential']):
                return {
                    'matched': True,
                    'evidence': "Targets remote workforce infrastructure"
                }

        return {'matched': False, 'evidence': ''}
    
    def _match_data_value(self, critical_assets, data_sensitivity: str, actor: Dict) -> Dict:
        """Match data value against threat actor motivations"""

        description = actor.get('description', '').lower()

        # Handle incident_types as string, list, or missing
        incident_types = actor.get('incident_types', [])
        if isinstance(incident_types, str):
            incident_type = incident_types.lower()
        elif isinstance(incident_types, list) and len(incident_types) > 0:
            incident_type = ' '.join(incident_types).lower()
        else:
            incident_type = ''

        # Handle critical_assets as list or string - normalize to lowercase list
        if isinstance(critical_assets, list):
            assets_list = [asset.lower() if isinstance(asset, str) else str(asset).lower() for asset in critical_assets]
        else:
            assets_list = [critical_assets.lower() if isinstance(critical_assets, str) else str(critical_assets).lower()]

        # Financial motivation
        if any(asset in ['financial', 'customer-data'] for asset in assets_list) or data_sensitivity in ['regulated', 'confidential']:
            if 'ransom' in description or 'financial' in description:
                return {
                    'matched': True,
                    'evidence': "Targets high-value financial data for extortion"
                }

        # Espionage motivation
        if any(asset in ['ip', 'government', 'classified'] for asset in assets_list):
            if 'espionage' in incident_type or 'espionage' in description:
                return {
                    'matched': True,
                    'evidence': "Conducts cyber espionage for intellectual property theft"
                }

        # Critical infrastructure
        if 'infrastructure' in ' '.join(assets_list):
            if 'infrastructure' in description or 'scada' in description or 'ics' in description:
                return {
                    'matched': True,
                    'evidence': "Targets critical infrastructure and operational technology"
                }

        return {'matched': False, 'evidence': ''}
    
    def _build_threat_profile(self, actor: Dict, score: int, reasons: List[Dict], user_profile: Dict) -> Dict:
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

        # Generate attack path simulation
        attack_path = self._generate_attack_path(actor, user_profile)

        # For backward compatibility, create why_you from reasons evidence
        why_you_parts = [reason['evidence'] for reason in reasons] if reasons else []

        return {
            'name': name,
            'aliases': ', '.join(aliases[:3]) if aliases else None,
            'origin': origin,
            'state_sponsor': state_sponsor,
            'match_score': score,
            'match_reasons': reasons,  # Structured match reasons
            'description': description[:500],  # Truncate long descriptions
            'risk_explanation': risk_explanation,
            'why_you': ' | '.join(why_you_parts),  # Legacy format
            'sophistication': self._determine_sophistication(actor),
            'active_since': self._extract_active_since(description),
            'recent_activity': self._extract_recent_activity(description),
            'ttps': ttps,
            'attack_path': attack_path  # NEW: Intelligent attack chain simulation
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

    def _generate_risk_explanation(self, actor: Dict, reasons: List[Dict], profile: Dict) -> str:
        """Generate personalized risk explanation"""

        name = actor.get('name', 'This threat actor')

        # Handle incident_types as string, list, or missing
        incident_types = actor.get('incident_types', 'cyber attacks')
        if isinstance(incident_types, list) and len(incident_types) > 0:
            incident_type = ', '.join(incident_types)
        elif isinstance(incident_types, str):
            incident_type = incident_types
        else:
            incident_type = 'cyber attacks'

        explanation = f"{name} poses a significant threat to your organization because:\n\n"

        # Add specific reasons from structured data
        for i, reason in enumerate(reasons, 1):
            evidence = reason.get('evidence', 'Unknown reason')
            explanation += f"{i}. {evidence}\n"

        explanation += f"\n{name} is known for {incident_type}. "

        # Add likely attack scenario
        if profile['internet_facing'] in ['extensive', 'high']:
            explanation += "With your extensive internet-facing infrastructure, they will likely exploit public-facing applications or VPN vulnerabilities for initial access. "

        if profile['security_maturity'] in ['basic', 'developing']:
            explanation += "Your developing security posture makes you a softer target compared to more mature organizations. "

        if profile['data_sensitivity'] in ['regulated', 'classified', 'confidential']:
            # Handle critical_assets as list or string
            assets = profile.get('critical_assets', [])
            if isinstance(assets, list):
                assets_str = ', '.join(assets) if assets else 'critical'
            else:
                assets_str = str(assets)
            explanation += f"Your {assets_str} data makes you a high-value target for both extortion and espionage operations."

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

    def _extract_apt_capabilities(self, actor: Dict) -> Dict:
        """Extract APT's actual capabilities from description and TTPs"""
        description = actor.get('description', '').lower()
        ttps = actor.get('ttps', [])
        ttp_text = ' '.join([t.lower() for t in ttps]) if ttps else ''
        combined_text = f"{description} {ttp_text}"

        capabilities = {
            'initial_access': [],
            'credential_access': [],
            'lateral_movement': [],
            'exfiltration_methods': [],
            'malware_families': [],
            'exploit_preferences': []
        }

        # Initial Access techniques
        if any(k in combined_text for k in ['phishing', 'spearphishing', 'spear-phishing']):
            capabilities['initial_access'].append('phishing')
        if any(k in combined_text for k in ['supply chain', 'third-party', 'vendor compromise']):
            capabilities['initial_access'].append('supply_chain')
        if any(k in combined_text for k in ['vpn', 'remote access', 'vpn exploit']):
            capabilities['initial_access'].append('vpn_exploit')
        if any(k in combined_text for k in ['watering hole', 'strategic web compromise']):
            capabilities['initial_access'].append('watering_hole')
        if any(k in combined_text for k in ['exploit', 'vulnerability', 'cve', '0-day', 'zero-day']):
            capabilities['initial_access'].append('exploit')

        # Credential Access
        if any(k in combined_text for k in ['credential', 'password', 'lsass', 'mimikatz']):
            capabilities['credential_access'].append('credential_dumping')
        if any(k in combined_text for k in ['brute force', 'password spray']):
            capabilities['credential_access'].append('brute_force')
        if any(k in combined_text for k in ['token', 'session', 'cookie']):
            capabilities['credential_access'].append('token_theft')
        if any(k in combined_text for k in ['keylog']):
            capabilities['credential_access'].append('keylogging')

        # Lateral Movement
        if any(k in combined_text for k in ['powershell', 'wmi', 'native tools', 'living off']):
            capabilities['lateral_movement'].append('living_off_land')
        if any(k in combined_text for k in ['rdp', 'remote desktop']):
            capabilities['lateral_movement'].append('rdp')
        if any(k in combined_text for k in ['smb', 'psexec']):
            capabilities['lateral_movement'].append('smb')
        if any(k in combined_text for k in ['custom', 'backdoor', 'rat', 'implant']):
            capabilities['lateral_movement'].append('custom_malware')

        # Exfiltration
        if any(k in combined_text for k in ['exfiltration', 'data theft', 'steal']):
            capabilities['exfiltration_methods'].append('data_exfiltration')
        if any(k in combined_text for k in ['ransomware', 'encryption', 'ransom']):
            capabilities['exfiltration_methods'].append('ransomware')
        if any(k in combined_text for k in ['c2', 'command and control', 'c&c']):
            capabilities['exfiltration_methods'].append('c2_channel')

        return capabilities

    def _generate_attack_path(self, actor: Dict, user_profile: Dict) -> List[Dict]:
        """Generate realistic attack chain based on APT's TTPs and user's profile"""
        # Handle critical_assets as list and normalize to lowercase
        critical_assets = user_profile.get('critical_assets', [])
        if isinstance(critical_assets, str):
            critical_assets = [critical_assets]

        # Convert all to lowercase for comparison
        critical_assets = [asset.lower() if isinstance(asset, str) else str(asset).lower() for asset in critical_assets]

        # Create a modified profile with normalized critical_assets
        profile = user_profile.copy()
        profile['critical_assets'] = critical_assets

        description = actor.get('description', '').lower()
        capabilities = self._extract_apt_capabilities(actor)
        attack_steps = []
        step_num = 1

        # STEP 1: INITIAL ACCESS
        initial_access = self._generate_initial_access(
            capabilities, profile, actor, step_num
        )
        if initial_access:
            attack_steps.append(initial_access)
            step_num += 1

        # STEP 2: CREDENTIAL ACCESS
        credential_access = self._generate_credential_access(
            capabilities, profile, actor, step_num
        )
        if credential_access:
            attack_steps.append(credential_access)
            step_num += 1

        # STEP 3: PRIVILEGE ESCALATION (if needed)
        if profile.get('security_maturity') in ['mature', 'advanced']:
            priv_esc = self._generate_privilege_escalation(
                capabilities, profile, actor, step_num
            )
            if priv_esc:
                attack_steps.append(priv_esc)
                step_num += 1

        # STEP 4: LATERAL MOVEMENT
        lateral_movement = self._generate_lateral_movement(
            capabilities, profile, actor, step_num
        )
        if lateral_movement:
            attack_steps.append(lateral_movement)
            step_num += 1

        # STEP 5: EXFILTRATION/IMPACT
        impact = self._generate_impact(
            capabilities, profile, actor, step_num
        )
        if impact:
            attack_steps.append(impact)

        return attack_steps[:6]  # Cap at 6 steps

    def _generate_initial_access(self, capabilities: Dict, profile: Dict, actor: Dict, step: int) -> Dict:
        """Generate initial access step based on APT capabilities and user attack surface"""
        initial_methods = capabilities['initial_access']
        description_lower = actor.get('description', '').lower()

        # Prioritize based on APT's known methods + user vulnerabilities
        if 'supply_chain' in initial_methods and profile.get('cloud_usage') in ['mostly', 'full']:
            return {
                'step': step,
                'phase': 'Initial Access',
                'tactic': 'Supply Chain Compromise',
                'description': f"Compromise third-party SaaS vendor used for {profile.get('tech_stack', 'cloud')} infrastructure management",
                'likelihood': 'high' if profile.get('security_maturity') in ['basic', 'developing'] else 'medium',
                'impact': 'Vendor credentials provide access to production cloud environment',
                'mitigation': 'Enforce vendor security assessments, implement SaaS Security Posture Management (SSPM), isolate third-party integrations',
                'evidence': 'APT known for supply chain attacks' if 'supply chain' in description_lower else 'APT targets third-party vendors'
            }

        if 'vpn_exploit' in initial_methods and profile.get('internet_facing') in ['extensive', 'high', 'moderate']:
            return {
                'step': step,
                'phase': 'Initial Access',
                'tactic': 'Exploit Public-Facing Application',
                'description': 'Exploit unpatched VPN gateway vulnerability (e.g., CVE-2023-XXXX style)',
                'likelihood': 'high' if profile.get('security_maturity') == 'basic' else 'medium',
                'impact': 'Remote code execution on VPN appliance, access to internal network',
                'mitigation': 'Deploy immediate patches for VPN/edge devices, implement network segmentation, enable MFA on VPN',
                'evidence': 'APT exploits VPN vulnerabilities' if 'vpn' in description_lower else 'APT targets internet-facing infrastructure'
            }

        if 'phishing' in initial_methods and profile.get('remote_work') in ['mostly', 'full', 'hybrid']:
            return {
                'step': step,
                'phase': 'Initial Access',
                'tactic': 'Spearphishing Attachment',
                'description': f"Spearphish remote employees with malicious document leveraging {profile.get('industry', 'industry-specific')} context",
                'likelihood': 'high' if profile.get('security_maturity') in ['basic', 'developing'] else 'medium',
                'impact': 'Execute malware on employee endpoint, establish initial foothold',
                'mitigation': 'Deploy phishing-resistant MFA (hardware tokens/passkeys), advanced email filtering, security awareness training',
                'evidence': 'APT known for targeted phishing campaigns' if 'phishing' in description_lower else 'APT uses social engineering'
            }

        if 'watering_hole' in initial_methods:
            return {
                'step': step,
                'phase': 'Initial Access',
                'tactic': 'Watering Hole Attack',
                'description': f"Compromise {profile.get('industry', 'industry')}-specific forum or news site to deliver exploits",
                'likelihood': 'medium',
                'impact': 'Drive-by download infects employees who visit compromised site',
                'mitigation': 'Deploy endpoint detection and response (EDR), browser isolation, web content filtering',
                'evidence': 'APT uses watering hole tactics'
            }

        # Default exploit-based initial access
        if 'exploit' in initial_methods or not initial_methods:
            return {
                'step': step,
                'phase': 'Initial Access',
                'tactic': 'Exploit Public-Facing Application',
                'description': f"Scan and exploit vulnerabilities in {profile.get('internet_facing', 'internet-facing')} systems",
                'likelihood': 'medium',
                'impact': 'Gain unauthorized access to external-facing services',
                'mitigation': 'Implement vulnerability management program, deploy WAF, reduce attack surface',
                'evidence': 'APT exploits known vulnerabilities'
            }

    def _generate_credential_access(self, capabilities: Dict, profile: Dict, actor: Dict, step: int) -> Dict:
        """Generate credential access step"""
        cred_methods = capabilities['credential_access']
        tech_stack = profile.get('tech_stack', 'windows')

        if 'credential_dumping' in cred_methods and 'windows' in tech_stack:
            return {
                'step': step,
                'phase': 'Credential Access',
                'tactic': 'OS Credential Dumping',
                'description': 'Dump LSASS process memory, extract plaintext passwords and Kerberos tickets',
                'likelihood': 'high' if profile.get('security_maturity') in ['basic', 'developing'] else 'medium',
                'impact': 'Obtain domain admin credentials for lateral movement',
                'mitigation': 'Enable Credential Guard, disable NTLM, implement PAW (Privileged Access Workstations)',
                'evidence': 'APT uses credential dumping tools like Mimikatz'
            }

        if 'token_theft' in cred_methods and profile.get('cloud_usage') in ['mostly', 'full']:
            cloud_provider = 'AWS' if 'aws' in tech_stack else 'Azure' if 'azure' in tech_stack else 'cloud'
            return {
                'step': step,
                'phase': 'Credential Access',
                'tactic': 'Steal Application Access Token',
                'description': f"Harvest {cloud_provider} IAM credentials from compromised instance metadata service",
                'likelihood': 'high' if profile.get('security_maturity') == 'basic' else 'medium',
                'impact': f"Access {cloud_provider} APIs with stolen credentials, enumerate cloud resources",
                'mitigation': f"Implement IMDSv2, enforce least-privilege IAM, enable {cloud_provider} GuardDuty",
                'evidence': 'APT targets cloud credentials'
            }

        if 'brute_force' in cred_methods or profile.get('security_maturity') == 'basic':
            return {
                'step': step,
                'phase': 'Credential Access',
                'tactic': 'Brute Force',
                'description': 'Password spray attack against accounts without MFA protection',
                'likelihood': 'high' if profile.get('security_maturity') == 'basic' else 'low',
                'impact': 'Compromise user accounts with weak/common passwords',
                'mitigation': 'Enforce strong password policy, deploy MFA everywhere, implement account lockout',
                'evidence': 'APT uses password attacks'
            }

        # Default
        return {
            'step': step,
            'phase': 'Credential Access',
            'tactic': 'Unsecured Credentials',
            'description': 'Search for credentials in configuration files, scripts, browser storage',
            'likelihood': 'medium',
            'impact': 'Discover hardcoded credentials or API keys',
            'mitigation': 'Use secrets management (HashiCorp Vault, AWS Secrets Manager), scan code for secrets',
            'evidence': 'APT hunts for exposed credentials'
        }

    def _generate_privilege_escalation(self, capabilities: Dict, profile: Dict, actor: Dict, step: int) -> Dict:
        """Generate privilege escalation step for mature environments"""
        return {
            'step': step,
            'phase': 'Privilege Escalation',
            'tactic': 'Exploitation for Privilege Escalation',
            'description': 'Exploit kernel vulnerability or misconfigured service to gain SYSTEM/root privileges',
            'likelihood': 'medium',
            'impact': 'Achieve administrative access on compromised system',
            'mitigation': 'Deploy EDR, enable kernel exploit protections, patch management, principle of least privilege',
            'evidence': 'APT employs privilege escalation techniques'
        }

    def _generate_lateral_movement(self, capabilities: Dict, profile: Dict, actor: Dict, step: int) -> Dict:
        """Generate lateral movement step"""
        lateral_methods = capabilities['lateral_movement']
        tech_stack = profile.get('tech_stack', 'windows')

        if 'living_off_land' in lateral_methods and 'windows' in tech_stack:
            return {
                'step': step,
                'phase': 'Lateral Movement',
                'tactic': 'Remote Services',
                'description': 'Use PowerShell remoting and WMI to move laterally across Windows domain',
                'likelihood': 'high',
                'impact': 'Spread to additional systems, reach high-value targets',
                'mitigation': 'Implement application whitelisting, PowerShell logging/AMSI, network segmentation',
                'evidence': 'APT uses living-off-the-land techniques'
            }

        if profile.get('cloud_usage') in ['mostly', 'full']:
            return {
                'step': step,
                'phase': 'Lateral Movement',
                'tactic': 'Use Alternate Authentication Material',
                'description': 'Abuse federated SSO to pivot across SaaS applications and cloud workloads',
                'likelihood': 'high' if profile.get('security_maturity') in ['basic', 'developing'] else 'medium',
                'impact': 'Access multiple cloud services with stolen SAML tokens',
                'mitigation': 'Implement conditional access policies, monitor for abnormal SSO usage, session timeout',
                'evidence': 'APT exploits cloud federation trust relationships'
            }

        if 'rdp' in lateral_methods:
            return {
                'step': step,
                'phase': 'Lateral Movement',
                'tactic': 'Remote Desktop Protocol',
                'description': 'RDP to additional systems using compromised credentials',
                'likelihood': 'medium',
                'impact': 'Interactive access to multiple workstations and servers',
                'mitigation': 'Restrict RDP access, require jump hosts, implement network segmentation',
                'evidence': 'APT uses RDP for lateral movement'
            }

        # Default
        return {
            'step': step,
            'phase': 'Lateral Movement',
            'tactic': 'Remote Services',
            'description': 'Pivot to additional systems using stolen credentials',
            'likelihood': 'medium',
            'impact': 'Expand access across network',
            'mitigation': 'Network segmentation, zero-trust architecture, monitor east-west traffic',
            'evidence': 'APT moves laterally to reach objectives'
        }

    def _generate_impact(self, capabilities: Dict, profile: Dict, actor: Dict, step: int) -> Dict:
        """Generate final impact step based on critical assets and APT motivation"""
        exfil_methods = capabilities['exfiltration_methods']
        # critical_assets is already normalized to lowercase list in _generate_attack_path
        assets = profile.get('critical_assets', [])

        description_lower = actor.get('description', '').lower()

        # Handle incident_types as string, list, or missing
        incident_types = actor.get('incident_types', [])
        if isinstance(incident_types, str):
            incident_type = incident_types.lower()
        elif isinstance(incident_types, list) and len(incident_types) > 0:
            incident_type = ' '.join(incident_types).lower()
        else:
            incident_type = ''

        # Ransomware APT + Financial data
        if 'ransomware' in exfil_methods or 'ransom' in description_lower:
            if any(a in ['financial', 'customer-data'] for a in assets):
                return {
                    'step': step,
                    'phase': 'Impact',
                    'tactic': 'Data Encrypted for Impact',
                    'description': 'Deploy ransomware, encrypt critical databases, exfiltrate sensitive data for double extortion',
                    'likelihood': 'high',
                    'impact': f"Business disruption, regulatory fines (GDPR/CCPA), reputational damage from data leak",
                    'mitigation': 'Offline backups, immutable storage, ransomware-specific EDR, incident response plan',
                    'evidence': 'APT conducts ransomware operations'
                }

        # Espionage APT + IP/Government data
        if 'espionage' in incident_type or 'espionage' in description_lower:
            if any(a in ['ip', 'government', 'classified'] for a in assets):
                return {
                    'step': step,
                    'phase': 'Collection & Exfiltration',
                    'tactic': 'Data from Information Repositories',
                    'description': 'Establish persistent access, continuously exfiltrate intellectual property and sensitive documents over encrypted C2',
                    'likelihood': 'high',
                    'impact': 'Loss of trade secrets, competitive disadvantage, potential national security implications',
                    'mitigation': 'Data loss prevention (DLP), network traffic analysis, threat hunting, insider threat program',
                    'evidence': 'APT conducts long-term espionage operations'
                }

        # Financial motivation
        if any(a in ['financial', 'customer-data'] for a in assets):
            return {
                'step': step,
                'phase': 'Collection & Exfiltration',
                'tactic': 'Data from Local System',
                'description': 'Exfiltrate customer PII, payment card data, and financial records via encrypted tunnel',
                'likelihood': 'high',
                'impact': 'Regulatory penalties, customer notification costs, fraud liability',
                'mitigation': 'Encrypt data at rest, network segmentation, DLP, monitor for large data transfers',
                'evidence': 'APT targets financial data for monetization'
            }

        # Infrastructure targeting
        if 'infrastructure' in ' '.join(assets):
            return {
                'step': step,
                'phase': 'Impact',
                'tactic': 'Inhibit System Recovery',
                'description': 'Deploy destructive malware to disrupt critical infrastructure operations',
                'likelihood': 'medium',
                'impact': 'Operational disruption, safety risks, recovery time measured in weeks',
                'mitigation': 'Air-gap critical systems, implement ICS-specific security controls, disaster recovery',
                'evidence': 'APT targets critical infrastructure'
            }

        # Default exfiltration
        return {
            'step': step,
            'phase': 'Exfiltration',
            'tactic': 'Exfiltration Over C2 Channel',
            'description': 'Exfiltrate collected data through established command and control infrastructure',
            'likelihood': 'medium',
            'impact': 'Loss of sensitive business data, competitive intelligence',
            'mitigation': 'Network monitoring, proxy/firewall egress filtering, DLP',
            'evidence': 'APT exfiltrates data to achieve objectives'
        }


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
    
    print("\n[*] Testing Adversary Matcher...\n")
    threats = matcher.analyze_threat_landscape(test_profile)
    
    print(f"Found {len(threats)} matching threats:\n")
    for i, threat in enumerate(threats[:3], 1):
        print(f"{i}. {threat['name']} ({threat['match_score']}% match)")
        print(f"   Origin: {threat['origin']}")
        print(f"   Why: {threat['why_you']}")
        print()