"""
Attack Surface Management Scanner
Subdomain discovery, Nmap port scanning, DNS enumeration,
Certificate Transparency, Cloud Asset Discovery, Censys, and Pulsedive
"""

import os
import dns.resolver
import socket
import requests
import json
from datetime import datetime, timezone
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import Censys and Pulsedive enrichment modules
try:
    from modules.ghost.censys_scanner import censys_lookup_ips
    CENSYS_AVAILABLE = True
except ImportError:
    CENSYS_AVAILABLE = False
    print("[ASM] ⚠️  Censys integration not available")

try:
    from modules.ghost.pulsedive_enrichment import enrich_ips
    PULSEDIVE_AVAILABLE = True
except ImportError:
    PULSEDIVE_AVAILABLE = False
    print("[ASM] ⚠️  Pulsedive integration not available")

# Import CVE mapper module
try:
    from modules.ghost.cve_mapper import map_service_to_cves, enrich_cve, add_cve_context
    CVE_MAPPER_AVAILABLE = True
except ImportError:
    CVE_MAPPER_AVAILABLE = False
    print("[ASM] ⚠️  CVE mapper not available")


def scan_domain(domain, progress_callback=None):
    """
    Perform comprehensive attack surface scan on a domain

    Args:
        domain (str): Target domain (e.g., "example.com")
        progress_callback (callable): Optional callback for progress updates
                                     callback(step, progress, total, message)

    Returns:
        dict: Scan results with subdomains, Shodan data, DNS records, and risk score
    """
    def update_progress(step, progress, total, message):
        """Helper to call progress callback if provided"""
        if progress_callback:
            progress_callback(step, progress, total, message)

    print(f"\n{'='*60}")
    print(f"[ASM SCANNER] Starting scan for: {domain}")
    print(f"{'='*60}\n")

    results = {
        'domain': domain,
        'scan_time': datetime.now(timezone.utc).isoformat(),
        'subdomains': [],
        'crt_subdomains': [],
        'cloud_assets': [],
        'shodan_results': [],
        'dns_records': {},
        'risk_score': 0,
        'risk_level': 'low',
        'vulnerabilities_found': 0,
        'open_ports_count': 0,
        'critical_findings': [],
        'errors': []
    }

    # 1. Subdomain Discovery (DNS)
    update_progress('Subdomain Discovery', 10, 100, 'Scanning for subdomains...')
    print(f"\n[ASM] ╔═══════════════════════════════════════════════════════════╗")
    print(f"[ASM] ║ STEP 1: Subdomain Discovery (DNS)                        ║")
    print(f"[ASM] ╚═══════════════════════════════════════════════════════════╝")
    results['subdomains'] = discover_subdomains(domain)
    update_progress('Subdomain Discovery', 20, 100, f'Found {len(results["subdomains"])} subdomains')
    print(f"\n[ASM] ✓ Subdomain Discovery Complete: Found {len(results['subdomains'])} DNS subdomains")

    # NOTE: crt.sh removed - service unreliable. Using DNS + Subfinder instead.

    # 2. Subfinder Discovery (40+ sources)
    update_progress('Subfinder Discovery', 40, 100, 'Running Subfinder (40+ sources)...')
    print(f"\n[ASM] ╔═══════════════════════════════════════════════════════════╗")
    print(f"[ASM] ║ STEP 2.5: Subfinder Multi-Source Discovery               ║")
    print(f"[ASM] ╚═══════════════════════════════════════════════════════════╝")

    subfinder_results = run_subfinder(domain)
    print(f"\n[ASM] ✓ Subfinder Complete: Found {len(subfinder_results)} subdomains")

    # Merge subfinder results with existing subdomains
    # Add any new unique subdomains found by subfinder
    existing_subdomains = {sub['subdomain'] for sub in results['subdomains']}
    for subfinder_sub in subfinder_results:
        if subfinder_sub not in existing_subdomains:
            # Resolve IP for this subdomain
            try:
                answers = dns.resolver.resolve(subfinder_sub, 'A')
                ips = [str(rdata) for rdata in answers]
                results['subdomains'].append({
                    'subdomain': subfinder_sub,
                    'ips': ips,
                    'type': 'A (subfinder)'
                })
            except:
                # Add without IP if resolution fails
                results['subdomains'].append({
                    'subdomain': subfinder_sub,
                    'ips': [],
                    'type': 'subfinder'
                })

    # Merge crt.sh results and deduplicate all subdomains
    print(f"\n[ASM] ╔═══════════════════════════════════════════════════════════╗")
    print(f"[ASM] ║ Deduplicating Subdomains Across All Sources              ║")
    print(f"[ASM] ╚═══════════════════════════════════════════════════════════╝")

    # Collect all unique subdomain names from all sources (DETERMINISTIC)
    all_subdomain_names = set()

    # Add from DNS/Subfinder results (normalize for deduplication)
    for sub in results['subdomains']:
        subdomain = sub['subdomain']
        # Normalize: lowercase and strip whitespace for deterministic deduplication
        if subdomain:
            all_subdomain_names.add(subdomain.lower().strip())

    # Add from crt.sh results (normalize for deduplication)
    for crt_sub in results['crt_subdomains']:
        subdomain_name = crt_sub.get('subdomain', '')
        # Normalize: lowercase and strip whitespace for deterministic deduplication
        if subdomain_name:
            all_subdomain_names.add(subdomain_name.lower().strip())

    print(f"[ASM] Before deduplication: DNS={len(results['subdomains'])}, crt.sh={len(results['crt_subdomains'])}")
    print(f"[ASM] Total unique subdomains: {len(all_subdomain_names)}")

    # Build deduplicated list with IP resolution
    deduplicated_subdomains = []
    for subdomain_name in sorted(all_subdomain_names):
        # Try to resolve IP if not already in results
        existing = next((s for s in results['subdomains'] if s['subdomain'] == subdomain_name), None)

        if existing:
            # Use existing data with IPs
            deduplicated_subdomains.append(existing)
        else:
            # New subdomain from crt.sh - try to resolve
            try:
                answers = dns.resolver.resolve(subdomain_name, 'A')
                ips = [str(rdata) for rdata in answers]
                deduplicated_subdomains.append({
                    'subdomain': subdomain_name,
                    'ips': ips,
                    'type': 'A (crt.sh)'
                })
            except:
                # Add without IP if resolution fails
                deduplicated_subdomains.append({
                    'subdomain': subdomain_name,
                    'ips': [],
                    'type': 'crt.sh'
                })

    # Update results with deduplicated list
    results['subdomains'] = deduplicated_subdomains
    print(f"[ASM] ✓ Deduplication complete: {len(results['subdomains'])} unique subdomains")

    update_progress('Subfinder Discovery', 50, 100, f'Total: {len(results["subdomains"])} unique subdomains')

    # 3. Cloud Asset Enumeration
    update_progress('Cloud Asset Discovery', 55, 100, 'Scanning AWS/Azure/GCP...')
    print(f"\n[ASM] ╔═══════════════════════════════════════════════════════════╗")
    print(f"[ASM] ║ STEP 3: Cloud Asset Enumeration                          ║")
    print(f"[ASM] ╚═══════════════════════════════════════════════════════════╝")
    company_name = domain.split('.')[0]  # Extract company name from domain
    results['cloud_assets'] = enumerate_cloud_assets(company_name, domain)
    update_progress('Cloud Asset Discovery', 60, 100, f'Found {len(results["cloud_assets"])} cloud assets')
    print(f"\n[ASM] ✓ Cloud Asset Enumeration Complete: Found {len(results['cloud_assets'])} cloud assets")

    # 4. DNS Enumeration
    update_progress('DNS Enumeration', 65, 100, 'Collecting DNS records...')
    print(f"\n[ASM] ╔═══════════════════════════════════════════════════════════╗")
    print(f"[ASM] ║ STEP 4: DNS Enumeration                                   ║")
    print(f"[ASM] ╚═══════════════════════════════════════════════════════════╝")
    results['dns_records'] = enumerate_dns(domain)
    update_progress('DNS Enumeration', 70, 100, 'DNS records collected')
    print(f"\n[ASM] ✓ DNS Enumeration Complete: Collected DNS records")

    # 5. Nmap Port Scanning (FREE & UNLIMITED)
    update_progress('Port Scanning', 75, 100, 'Starting Nmap scans...')
    print(f"\n[ASM] ╔═══════════════════════════════════════════════════════════╗")
    print(f"[ASM] ║ STEP 5: Port Scanning with Nmap (FREE)                   ║")
    print(f"[ASM] ╚═══════════════════════════════════════════════════════════╝")

    # Collect all discovered IPs from subdomains
    discovered_ips = []
    for subdomain_data in results['subdomains']:
        discovered_ips.extend(subdomain_data.get('ips', []))

    # Remove duplicates
    discovered_ips = list(set(discovered_ips))
    print(f"[ASM] Collected {len(discovered_ips)} unique IPs from DNS discovery")

    # Run Nmap scan on discovered IPs with progress callback
    results['port_scan_results'] = run_nmap_scan(discovered_ips, progress_callback=progress_callback)
    update_progress('Port Scanning', 90, 100, f'Found {len(results["port_scan_results"])} open ports')
    print(f"\n[ASM] ✓ Port Scanning Complete: Found {len(results['port_scan_results'])} open ports")

    # Keep old key for compatibility but populate with nmap results
    results['shodan_results'] = results['port_scan_results']

    # 5.4. CVE Mapping with NVD API (Optional)
    if CVE_MAPPER_AVAILABLE and os.getenv('NVD_API_KEY'):
        update_progress('CVE Mapping', 90, 100, 'Mapping services to CVEs...')
        print(f"\n[ASM] ╔═══════════════════════════════════════════════════════════╗")
        print(f"[ASM] ║ STEP 5.4: CVE Intelligence Layer (NVD + KEV + ExploitDB) ║")
        print(f"[ASM] ╚═══════════════════════════════════════════════════════════╝")

        try:
            total_cves_found = 0
            total_critical_cves = 0
            total_kev_cves = 0
            total_exploits = 0
            all_cves = []

            # Map each service/port to CVEs
            for port_result in results['port_scan_results']:
                service = port_result.get('service', '').strip()
                version = port_result.get('version', '').strip()
                product = port_result.get('product', '').strip()

                # Use product name if available, otherwise use service
                service_name = product if product else service

                # Skip if no service name or version
                if not service_name or not version:
                    port_result['cves'] = []
                    continue

                print(f"[CVE] Mapping {service_name} {version} (port {port_result['port']})...")

                # Query NVD for CVEs
                cves = map_service_to_cves(service_name, version)

                if cves:
                    # Enrich each CVE with CISA KEV and ExploitDB data
                    enriched_cves = []
                    for cve in cves:
                        # First, enrich with KEV and ExploitDB data
                        enriched_cve = enrich_cve(cve)

                        # Then, add contextual explanations
                        enriched_cve = add_cve_context(enriched_cve, service_name, port_result['port'])

                        enriched_cves.append(enriched_cve)

                        # Add service context to CVE for mapping
                        all_cves.append({
                            **enriched_cve,
                            'service': service_name,
                            'version': version,
                            'port': port_result['port']
                        })

                        # Count statistics
                        total_cves_found += 1

                        # ADD DEBUG LOG
                        print(f"[CVE DEBUG] Found CVE, counter now at: {total_cves_found}")

                        if enriched_cve.get('cvss_score', 0) >= 9.0:
                            total_critical_cves += 1
                        if enriched_cve.get('kev', {}).get('in_kev', False):
                            total_kev_cves += 1
                        if enriched_cve.get('exploit', {}).get('exploit_exists', False):
                            total_exploits += 1

                    port_result['cves'] = enriched_cves
                    print(f"[CVE]   ✓ Found {len(enriched_cves)} CVEs for {service_name} {version}")
                else:
                    port_result['cves'] = []
                    print(f"[CVE]   - No CVEs found for {service_name} {version}")

            # Build service → CVE mapping for quick lookup
            service_cve_map = {}
            for cve_result in all_cves:
                service_key = f"{cve_result['service']}_{cve_result['version']}"
                if service_key not in service_cve_map:
                    service_cve_map[service_key] = []
                service_cve_map[service_key].append(cve_result)

            # Attach CVEs to each port result and calculate risk level
            for port_result in results['port_scan_results']:
                service_name = port_result.get('product', '') or port_result.get('service', '')
                version = port_result.get('version', '')
                service_key = f"{service_name}_{version}"

                # CVEs should already be attached from above, but ensure it's set
                if 'cves' not in port_result:
                    port_result['cves'] = service_cve_map.get(service_key, [])

                # Calculate risk level for this port
                port_result['risk_level'] = calculate_port_risk(port_result)

            # Store CVE statistics
            results['cve_statistics'] = {
                'total_cves': total_cves_found,
                'critical_cves': total_critical_cves,
                'kev_cves': total_kev_cves,
                'exploits_available': total_exploits
            }

            print(f"[CVE DEBUG] Final statistics: {results['cve_statistics']}")

            update_progress('CVE Mapping', 91, 100, f'Found {total_cves_found} CVEs ({total_critical_cves} critical)')
            print(f"\n[ASM] ✓ CVE Mapping Complete:")
            print(f"[ASM]   - Total CVEs: {total_cves_found}")
            print(f"[ASM]   - Critical CVEs (CVSS 9.0+): {total_critical_cves}")
            print(f"[ASM]   - CISA KEV: {total_kev_cves}")
            print(f"[ASM]   - Public Exploits: {total_exploits}")

            # Generate vulnerability summary
            print(f"\n[ASM] ╔═══════════════════════════════════════════════════════════╗")
            print(f"[ASM] ║ Generating Vulnerability Summary & Remediation Plan      ║")
            print(f"[ASM] ╚═══════════════════════════════════════════════════════════╝")

            vulnerability_summary = {
                'total_cves': total_cves_found,
                'critical_issues': [],
                'high_priority': [],
                'quick_wins': []
            }

            # Identify critical issues (immediate action required)
            database_ports = [3306, 5432, 1433, 27017, 6379, 9200]
            exposed_databases = []

            for port_result in results['port_scan_results']:
                port = port_result.get('port', 0)
                service = port_result.get('service', 'Unknown')
                ip = port_result.get('ip', 'Unknown')
                cves = port_result.get('cves', [])

                # Check for databases exposed to internet
                if port in database_ports:
                    exposed_databases.append({
                        'service': service,
                        'port': port,
                        'ip': ip
                    })

                # Check for critical CVEs with public exploits
                for cve in cves:
                    cvss_score = cve.get('cvss_score', 0)
                    has_exploit = cve.get('exploit', {}).get('exploit_exists', False)
                    in_kev = cve.get('kev', {}).get('in_kev', False)

                    if cvss_score >= 9.0 and (has_exploit or in_kev):
                        vulnerability_summary['critical_issues'].append({
                            'title': f"{service} on port {port}",
                            'issue': f"{cve.get('cve_id', 'Unknown')} (CVSS {cvss_score})",
                            'risk': cve.get('why_it_matters', 'Critical vulnerability detected'),
                            'fix': cve.get('how_to_fix', 'Update service immediately'),
                            'urgency': cve.get('urgency', 'HIGH'),
                            'ip': ip
                        })

                # Check for high priority issues (CVSS 7.0-8.9 with exploits)
                for cve in cves:
                    cvss_score = cve.get('cvss_score', 0)
                    has_exploit = cve.get('exploit', {}).get('exploit_exists', False)

                    if 7.0 <= cvss_score < 9.0 and has_exploit:
                        vulnerability_summary['high_priority'].append({
                            'title': f"{service} on port {port}",
                            'issue': f"{cve.get('cve_id', 'Unknown')} (CVSS {cvss_score})",
                            'risk': cve.get('why_it_matters', 'High severity vulnerability'),
                            'fix': cve.get('how_to_fix', 'Update service'),
                            'ip': ip
                        })

            # Quick wins (easy fixes with high impact)
            if exposed_databases:
                for db in exposed_databases:
                    vulnerability_summary['quick_wins'].append({
                        'title': f'{db["service"]} exposed to internet',
                        'fix': f'Add firewall rule to block port {db["port"]} from public',
                        'impact': 'Prevents 90% of database attacks',
                        'ip': db['ip']
                    })

            # Check for SSH with password auth enabled (common quick win)
            ssh_ports = [port_result for port_result in results['port_scan_results']
                        if port_result.get('port') == 22]
            if ssh_ports:
                vulnerability_summary['quick_wins'].append({
                    'title': 'SSH exposed to internet',
                    'fix': 'Disable password authentication, use SSH keys only',
                    'impact': 'Blocks 99% of SSH brute force attacks',
                    'affected_ips': [p.get('ip') for p in ssh_ports]
                })

            # Limit results
            vulnerability_summary['critical_issues'] = vulnerability_summary['critical_issues'][:10]
            vulnerability_summary['high_priority'] = vulnerability_summary['high_priority'][:10]
            vulnerability_summary['quick_wins'] = vulnerability_summary['quick_wins'][:5]

            # Add to results
            results['vulnerability_summary'] = vulnerability_summary

            # Print summary
            print(f"\n[ASM] ✓ Vulnerability Summary Generated:")
            print(f"[ASM]   - Critical Issues: {len(vulnerability_summary['critical_issues'])}")
            print(f"[ASM]   - High Priority: {len(vulnerability_summary['high_priority'])}")
            print(f"[ASM]   - Quick Wins: {len(vulnerability_summary['quick_wins'])}")

        except Exception as e:
            print(f"[ASM] ⚠️  CVE mapping failed: {e}")
            results['cve_statistics'] = {'total_cves': 0, 'critical_cves': 0, 'kev_cves': 0, 'exploits_available': 0}
            results['vulnerability_summary'] = {'total_cves': 0, 'critical_issues': [], 'high_priority': [], 'quick_wins': []}
    else:
        print(f"\n[ASM] - Skipping CVE mapping (not configured)")
        results['cve_statistics'] = {'total_cves': 0, 'critical_cves': 0, 'kev_cves': 0, 'exploits_available': 0}
        results['vulnerability_summary'] = {'total_cves': 0, 'critical_issues': [], 'high_priority': [], 'quick_wins': []}

    # 5.5. Censys API Enrichment (DISABLED - Broken API)
    # if CENSYS_AVAILABLE and os.getenv('CENSYS_API_KEY'):
    #     update_progress('Censys Enrichment', 91, 100, 'Enriching IPs with Censys...')
    #     print(f"\n[ASM] ╔═══════════════════════════════════════════════════════════╗")
    #     print(f"[ASM] ║ STEP 5.5: Censys API Enrichment                          ║")
    #     print(f"[ASM] ╚═══════════════════════════════════════════════════════════╝")
    #
    #     try:
    #         censys_results = censys_lookup_ips(discovered_ips)
    #         results['censys_enrichment'] = censys_results
    #         update_progress('Censys Enrichment', 93, 100, f'Enriched {len(censys_results)} services')
    #         print(f"\n[ASM] ✓ Censys Enrichment Complete: {len(censys_results)} services enriched")
    #
    #         # Merge Censys data into port scan results
    #         for censys_item in censys_results:
    #             # Find matching port scan result
    #             for port_result in results['port_scan_results']:
    #                 if port_result['ip'] == censys_item['ip'] and port_result['port'] == censys_item['port']:
    #                     # Enhance with Censys data
    #                     port_result['censys_banner'] = censys_item.get('banner', 'N/A')
    #                     port_result['censys_data'] = censys_item.get('censys_data', {})
    #                     break
    #     except Exception as e:
    #         print(f"[ASM] ⚠️  Censys enrichment failed: {e}")
    #         results['censys_enrichment'] = []
    # else:
    print(f"\n[ASM] - Censys enrichment disabled (broken API)")
    results['censys_enrichment'] = []

    # 5.6. Pulsedive Threat Intelligence (DISABLED - Rate Limited)
    # if PULSEDIVE_AVAILABLE and os.getenv('PULSEDIVE_API_KEY'):
    #     update_progress('Threat Intelligence', 93, 100, 'Checking IPs for threats...')
    #     print(f"\n[ASM] ╔═══════════════════════════════════════════════════════════╗")
    #     print(f"[ASM] ║ STEP 5.6: Pulsedive Threat Intelligence                  ║")
    #     print(f"[ASM] ╚═══════════════════════════════════════════════════════════╝")
    #
    #     try:
    #         threat_results = enrich_ips(discovered_ips)
    #         results['threat_intelligence'] = threat_results
    #         malicious_count = sum(1 for t in threat_results if t.get('malicious', False))
    #         update_progress('Threat Intelligence', 95, 100, f'Found {malicious_count} malicious IPs')
    #         print(f"\n[ASM] ✓ Threat Intelligence Complete: {malicious_count} malicious IPs detected")
    #
    #         # Merge threat data into port scan results
    #         for threat_item in threat_results:
    #             for port_result in results['port_scan_results']:
    #                 if port_result['ip'] == threat_item['ip']:
    #                     # Enhance with threat intelligence
    #                     port_result['threat_risk'] = threat_item.get('risk_level', 'unknown')
    #                     port_result['threat_malicious'] = threat_item.get('malicious', False)
    #                     port_result['threat_details'] = threat_item.get('threats', [])
    #                     break
    #     except Exception as e:
    #         print(f"[ASM] ⚠️  Pulsedive enrichment failed: {e}")
    #         results['threat_intelligence'] = []
    # else:
    print(f"\n[ASM] - Pulsedive threat intelligence disabled (rate limited)")
    results['threat_intelligence'] = []

    # 6. Generate Executive Summary
    print(f"\n[ASM] ╔═══════════════════════════════════════════════════════════╗")
    print(f"[ASM] ║ Generating Executive Summary                             ║")
    print(f"[ASM] ╚═══════════════════════════════════════════════════════════╝")

    # Build executive summary for decision makers
    total_vulns = results.get('cve_statistics', {}).get('total_cves', 0)
    critical_vulns = results.get('cve_statistics', {}).get('critical_cves', 0)
    kev_count = results.get('cve_statistics', {}).get('kev_cves', 0)

    # Top risks (from vulnerability summary)
    top_risks = []
    vuln_summary = results.get('vulnerability_summary', {})

    # Add critical issues as top risks
    for issue in vuln_summary.get('critical_issues', [])[:3]:
        top_risks.append(f"{issue['title']}: {issue['issue']}")

    # Add exposed database warnings
    database_ports = [3306, 5432, 1433, 27017, 6379, 9200]
    exposed_db_count = sum(1 for p in results.get('port_scan_results', [])
                          if p.get('port') in database_ports)
    if exposed_db_count > 0:
        top_risks.append(f"{exposed_db_count} database(s) exposed to internet with critical access risk")

    # Immediate actions
    immediate_actions = []

    # Add from quick wins
    for quick_win in vuln_summary.get('quick_wins', [])[:3]:
        immediate_actions.append(quick_win['fix'])

    # Add critical CVE patches
    for issue in vuln_summary.get('critical_issues', [])[:2]:
        immediate_actions.append(issue['fix'])

    # Create executive summary
    results['executive_summary'] = {
        'headline': f"{total_vulns} vulnerabilities found - {critical_vulns} critical",
        'top_risks': top_risks[:5],  # Limit to top 5
        'immediate_actions': immediate_actions[:5],  # Limit to top 5
        'stats': {
            'total_vulnerabilities': total_vulns,
            'critical_vulnerabilities': critical_vulns,
            'actively_exploited': kev_count,
            'open_ports': len(results.get('port_scan_results', [])),
            'subdomains_found': len(results.get('subdomains', [])),
            'exposed_databases': exposed_db_count
        }
    }

    print(f"[ASM] ✓ Executive Summary Generated")
    print(f"[ASM]   Headline: {results['executive_summary']['headline']}")
    print(f"[ASM]   Top Risks: {len(top_risks)}")
    print(f"[ASM]   Immediate Actions: {len(immediate_actions)}")

    # 7. Risk Assessment & Categorization
    update_progress('Risk Assessment', 97, 100, 'Calculating risk score...')
    print(f"\n[ASM] ╔═══════════════════════════════════════════════════════════╗")
    print(f"[ASM] ║ Step 7: Risk Assessment & Categorization                 ║")
    print(f"[ASM] ╚═══════════════════════════════════════════════════════════╝")
    results['risk_score'] = calculate_risk_score(results)
    results['risk_level'] = categorize_risk_level(results['risk_score'])
    results['vulnerabilities_found'] = count_vulnerabilities(results)
    results['open_ports_count'] = count_open_ports(results)
    results['critical_findings'] = identify_critical_findings(results)

    update_progress('Complete', 100, 100, f'Scan complete! Risk score: {results["risk_score"]}/100')

    print(f"\n{'='*60}")
    print(f"[ASM SCANNER] Scan Complete!")
    print(f"[ASM] Risk Score: {results['risk_score']}/100")
    print(f"[ASM] Vulnerabilities: {results['vulnerabilities_found']}")
    print(f"[ASM] Open Ports: {results['open_ports_count']}")
    print(f"{'='*60}\n")

    # Save scan to history
    try:
        import time
        from database import save_xasm_scan
        scan_id = f"xasm_{int(time.time())}_{domain.replace('.', '_')}"
        save_xasm_scan(
            scan_id=scan_id,
            target=domain,
            results=results,
            user_id=None  # Will add user tracking later with auth
        )
        results['history_scan_id'] = scan_id
    except Exception as e:
        print(f"[ASM] Warning: Failed to save to history: {e}")

    return results


def discover_subdomains(domain):
    """
    Discover subdomains using DNS queries

    Args:
        domain (str): Target domain

    Returns:
        list: List of discovered subdomains with IPs
    """
    print(f"[SUBDOMAIN] Scanning for common subdomains...")

    # Common subdomain prefixes to check
    common_subdomains = [
        'www', 'api', 'admin', 'dev', 'staging', 'test',
        'mail', 'webmail', 'smtp', 'pop', 'imap',
        'vpn', 'remote', 'gateway',
        'ftp', 'sftp', 'files',
        'blog', 'shop', 'store', 'portal',
        'cdn', 'assets', 'static', 'media',
        'app', 'mobile', 'dashboard',
        'db', 'database', 'sql', 'mysql',
        'git', 'gitlab', 'github',
        'jenkins', 'ci', 'build',
        'status', 'monitoring', 'metrics'
    ]

    discovered = []

    for subdomain_prefix in common_subdomains:
        full_domain = f"{subdomain_prefix}.{domain}"

        try:
            # Try to resolve the subdomain
            answers = dns.resolver.resolve(full_domain, 'A')

            ips = [str(rdata) for rdata in answers]

            discovered.append({
                'subdomain': full_domain,
                'ips': ips,
                'type': 'A'
            })

            print(f"[SUBDOMAIN] ✓ Found: {full_domain} -> {', '.join(ips)}")

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
            # Subdomain doesn't exist or no A record
            pass
        except Exception as e:
            print(f"[SUBDOMAIN] ⚠️  Error checking {full_domain}: {e}")

    # Also try to get the root domain
    try:
        answers = dns.resolver.resolve(domain, 'A')
        ips = [str(rdata) for rdata in answers]

        discovered.insert(0, {
            'subdomain': domain,
            'ips': ips,
            'type': 'A (root)'
        })

        print(f"[SUBDOMAIN] ✓ Root domain: {domain} -> {', '.join(ips)}")

    except Exception as e:
        print(f"[SUBDOMAIN] ⚠️  Error resolving root domain: {e}")

    return discovered


def enumerate_dns(domain):
    """
    Enumerate DNS records for a domain

    Args:
        domain (str): Target domain

    Returns:
        dict: DNS records (A, MX, NS, TXT, etc.)
    """
    print(f"[DNS] Enumerating DNS records for {domain}...")

    dns_records = {
        'A': [],
        'AAAA': [],
        'MX': [],
        'NS': [],
        'TXT': [],
        'SOA': [],
        'CNAME': []
    }

    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']

    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)

            if record_type == 'MX':
                dns_records[record_type] = [
                    {'priority': rdata.preference, 'server': str(rdata.exchange)}
                    for rdata in answers
                ]
            elif record_type == 'SOA':
                for rdata in answers:
                    dns_records[record_type].append({
                        'mname': str(rdata.mname),
                        'rname': str(rdata.rname),
                        'serial': rdata.serial
                    })
            else:
                dns_records[record_type] = [str(rdata) for rdata in answers]

            print(f"[DNS] ✓ {record_type}: {len(dns_records[record_type])} records")

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            print(f"[DNS] - {record_type}: No records found")
        except Exception as e:
            print(f"[DNS] ⚠️  Error querying {record_type}: {e}")

    return dns_records


def calculate_risk_score(results):
    """
    Calculate risk score based on scan results with balanced 100-point scale

    BALANCED SCORING FORMULA (PREVENTS SCORE INFLATION):
    1. Open Ports: Max 20 points
       - Measures exposure surface
    2. Service Exposure: Max 20 points
       - Critical services (DB, SSH, RDP, Admin panels)
    3. Attack Surface Size: Max 20 points
       - Subdomains, cloud assets, endpoints
    4. Configuration Issues: Max 20 points
       - Misconfigurations, weak settings, exposed services
    5. CVE Severity: Max 20 points
       - Critical/High CVEs, KEV, public exploits

    Risk Levels:
    - 0-25 = LOW risk
    - 26-50 = MEDIUM risk
    - 51-75 = HIGH risk
    - 76-100 = CRITICAL risk

    Args:
        results (dict): Scan results

    Returns:
        int: Risk score (0-100)
    """
    score = 0

    # ============ CATEGORY 1: OPEN PORTS (MAX 20 POINTS) ============
    open_port_count = len(results.get('port_scan_results', []))
    if open_port_count >= 20:
        port_points = 20
    elif open_port_count >= 15:
        port_points = 16
    elif open_port_count >= 10:
        port_points = 12
    elif open_port_count >= 5:
        port_points = 8
    elif open_port_count >= 1:
        port_points = 4
    else:
        port_points = 0
    score += port_points

    # ============ CATEGORY 2: SERVICE EXPOSURE (MAX 20 POINTS) ============
    database_ports = [3306, 5432, 1433, 27017, 6379, 9200]
    database_count = 0
    ssh_telnet_count = 0
    rdp_count = 0
    admin_panel_count = 0

    for port_result in results.get('port_scan_results', []):
        port = port_result.get('port', 0)
        service = port_result.get('service', '').lower()

        if port in database_ports:
            database_count += 1
        elif port in [22, 23]:
            ssh_telnet_count += 1
        elif port == 3389:
            rdp_count += 1
        elif 'admin' in service or port in [8080, 8443, 9090]:
            admin_panel_count += 1

    service_points = 0
    service_points += min(database_count * 8, 12)  # Max 12 for databases
    service_points += min(ssh_telnet_count * 3, 4)  # Max 4 for SSH/Telnet
    service_points += min(rdp_count * 6, 6)  # Max 6 for RDP
    service_points += min(admin_panel_count * 2, 4)  # Max 4 for admin panels
    service_points = min(service_points, 20)  # Cap at 20
    score += service_points

    # ============ CATEGORY 3: ATTACK SURFACE SIZE (MAX 20 POINTS) ============
    subdomain_count = len(results.get('subdomains', []))
    cloud_count = len(results.get('cloud_assets', []))

    surface_points = 0
    # Subdomain scoring
    if subdomain_count >= 100:
        surface_points += 12
    elif subdomain_count >= 50:
        surface_points += 10
    elif subdomain_count >= 20:
        surface_points += 6
    elif subdomain_count >= 10:
        surface_points += 3

    # Cloud asset scoring
    surface_points += min(cloud_count * 2, 8)  # Max 8 for cloud
    surface_points = min(surface_points, 20)  # Cap at 20
    score += surface_points

    # ============ CATEGORY 4: CONFIGURATION ISSUES (MAX 20 POINTS) ============
    config_points = 0

    # Malicious IPs indicate compromised or malicious infrastructure
    malicious_ip_count = sum(1 for t in results.get('threat_intelligence', []) if t.get('malicious', False))
    config_points += min(malicious_ip_count * 5, 10)  # Max 10

    # Check for common misconfigurations
    # (This can be expanded with more specific checks)
    for port_result in results.get('port_scan_results', []):
        service = port_result.get('service', '').lower()
        version = port_result.get('version', '').lower()

        # Default credentials indicators
        if 'default' in version or 'admin' in service:
            config_points += 2

        # Unencrypted protocols
        if port_result.get('port') in [21, 23, 80, 110, 143]:  # FTP, Telnet, HTTP, POP3, IMAP
            config_points += 1

    config_points = min(config_points, 20)  # Cap at 20
    score += config_points

    # ============ CATEGORY 5: CVE SEVERITY (MAX 20 POINTS) ============
    cve_critical_count = 0  # CVSS 9.0+
    cve_high_count = 0      # CVSS 7.0-8.9
    cisa_kev_count = 0      # In CISA KEV
    exploit_available_count = 0  # Public exploit exists

    # Analyze CVEs from port scan results
    for port_result in results.get('port_scan_results', []):
        cves = port_result.get('cves', [])
        for cve in cves:
            cvss_score = cve.get('cvss_score', 0.0)

            if cvss_score >= 9.0:
                cve_critical_count += 1
            elif cvss_score >= 7.0:
                cve_high_count += 1

            kev_data = cve.get('kev', {})
            if kev_data.get('in_kev', False):
                cisa_kev_count += 1

            exploit_data = cve.get('exploit', {})
            if exploit_data.get('exploit_exists', False):
                exploit_available_count += 1

    cve_points = 0
    cve_points += min(cve_critical_count * 4, 10)  # Max 10 for critical CVEs
    cve_points += min(cve_high_count * 1, 4)       # Max 4 for high CVEs
    cve_points += min(cisa_kev_count * 5, 8)       # Max 8 for KEV
    cve_points += min(exploit_available_count * 2, 6)  # Max 6 for exploits
    cve_points = min(cve_points, 20)  # Cap at 20
    score += cve_points

    # ============ CAP FINAL SCORE AT 100 ============
    score = min(score, 100)

    # Calculate breakdown components for display
    database_exposed = sum(1 for p in results.get('port_scan_results', []) if p.get('port') in database_ports)
    ssh_exposed = sum(1 for p in results.get('port_scan_results', []) if p.get('port') in [22, 23])
    rdp_exposed = sum(1 for p in results.get('port_scan_results', []) if p.get('port') == 3389)
    public_cloud = sum(1 for c in results.get('cloud_assets', []) if c.get('accessible', False))

    # Store breakdown for display
    results['risk_breakdown'] = {
        'open_ports': port_points,
        'service_exposure': service_points,
        'attack_surface': surface_points,
        'config_issues': config_points,
        'cve_severity': cve_points,
        'subdomain_count': subdomain_count,
        'cve_critical': cve_critical_count,
        'cve_high': cve_high_count,
        'cisa_kev': cisa_kev_count,
        'exploits_available': exploit_available_count,
        'malicious_ips': malicious_ip_count,
        'exposed_databases': database_exposed,
        'exposed_ssh': ssh_exposed,
        'exposed_rdp': rdp_exposed,
        'public_cloud_assets': public_cloud
    }

    # Print detailed risk calculation breakdown
    print(f"\n[RISK SCORING] ==================== BALANCED RISK CALCULATION ====================")
    print(f"[RISK SCORING] Category 1 - Open Ports: {open_port_count} ports → +{port_points}/20")
    print(f"[RISK SCORING] Category 2 - Service Exposure: DB={database_count}, SSH={ssh_telnet_count}, RDP={rdp_count} → +{service_points}/20")
    print(f"[RISK SCORING] Category 3 - Attack Surface: Subdomains={subdomain_count}, Cloud={cloud_count} → +{surface_points}/20")
    print(f"[RISK SCORING] Category 4 - Config Issues: Malicious IPs={malicious_ip_count} → +{config_points}/20")
    print(f"[RISK SCORING] Category 5 - CVE Severity: Critical={cve_critical_count}, High={cve_high_count}, KEV={cisa_kev_count}, Exploits={exploit_available_count} → +{cve_points}/20")
    print(f"[RISK SCORING] ──────────────────────────────────────────────────────────────────────")
    print(f"[RISK SCORING] FINAL SCORE: {score}/100")

    # Determine risk level
    if score >= 76:
        risk_level = "CRITICAL"
    elif score >= 51:
        risk_level = "HIGH"
    elif score >= 26:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    print(f"[RISK SCORING] RISK LEVEL: {risk_level}")
    print(f"[RISK SCORING] ========================================================================\n")

    return score


def count_vulnerabilities(results):
    """
    Count total vulnerabilities found

    Args:
        results (dict): Scan results

    Returns:
        int: Total vulnerability count
    """
    # First check if we have CVE statistics (most accurate)
    if 'cve_statistics' in results:
        return results['cve_statistics'].get('total_cves', 0)

    # Otherwise count from port scan results
    count = 0
    for port_result in results.get('port_scan_results', []):
        count += len(port_result.get('cves', []))

    # Also check shodan results for additional vulnerabilities
    for shodan_result in results.get('shodan_results', []):
        count += len(shodan_result.get('vulnerabilities', []))

    return count


def count_open_ports(results):
    """
    Count unique open ports found

    Args:
        results (dict): Scan results

    Returns:
        int: Unique open port count
    """
    ports = set()
    for shodan_result in results['shodan_results']:
        ports.add(shodan_result.get('port'))
    return len(ports)


def enumerate_cloud_assets(company_name, domain):
    """
    Enumerate potential cloud assets (S3 buckets, Azure blobs, GCP storage)
    with enhanced pattern matching and Lightbox integration

    Args:
        company_name (str): Company name extracted from domain
        domain (str): Target domain

    Returns:
        list: Discovered cloud assets with accessibility status
    """
    print(f"[CLOUD] Enumerating cloud assets for {company_name}...")

    cloud_assets = []

    # Enhanced bucket naming patterns (expanded for comprehensive coverage)
    patterns = [
        # Basic patterns
        company_name,
        domain.replace('.', '-'),
        domain.replace('.', ''),

        # AWS S3 patterns - Production
        f"{company_name}",
        f"{company_name}-backup",
        f"{company_name}-backups",
        f"{company_name}-prod",
        f"{company_name}-production",
        f"{company_name}-data",
        f"{company_name}-assets",
        f"{company_name}-files",

        # AWS S3 patterns - Development & Testing
        f"{company_name}-dev",
        f"{company_name}-development",
        f"{company_name}-staging",
        f"{company_name}-test",
        f"{company_name}-qa",

        # AWS S3 patterns - Content & Media
        f"{company_name}-images",
        f"{company_name}-uploads",
        f"{company_name}-static",
        f"{company_name}-media",
        f"{company_name}-cdn",
        f"{company_name}-downloads",

        # AWS S3 patterns - Logs & Monitoring
        f"{company_name}-logs",
        f"{company_name}-logging",
        f"{company_name}-monitoring",
        f"{company_name}-metrics",

        # AWS S3 patterns - Reversed
        f"backup-{company_name}",
        f"backups-{company_name}",
        f"prod-{company_name}",
        f"dev-{company_name}",
        f"data-{company_name}",
        f"files-{company_name}",

        # Versioned patterns
        f"{company_name}-v1",
        f"{company_name}-v2",
        f"{company_name}-v3",

        # Access level patterns
        f"{company_name}-public",
        f"{company_name}-private",
        f"{company_name}-internal",

        # Common variations
        f"company-{company_name}",
        f"{company_name}-company",
        f"{company_name}-app",
        f"{company_name}-web",
        f"{company_name}-api",
    ]

    # Check AWS S3 buckets
    print(f"[CLOUD] Checking AWS S3 buckets...")
    for pattern in patterns:
        bucket_url = f"https://{pattern}.s3.amazonaws.com"
        accessible, status = check_cloud_asset_access(bucket_url)

        if accessible or status == 403:  # 403 means bucket exists but not public
            public_read, public_write = False, False

            if accessible:
                # Test read/write permissions
                public_read, public_write = test_s3_permissions(bucket_url)

            cloud_assets.append({
                'provider': 'AWS',
                'type': 'AWS S3',
                'bucket_name': pattern,
                'name': pattern,
                'url': bucket_url,
                'accessible': accessible,
                'public_read': public_read,
                'public_write': public_write,
                'status': 'Public' if accessible else 'Private/Exists',
                'risk': 'CRITICAL' if public_write else ('CRITICAL' if public_read else 'LOW')
            })
            print(f"[CLOUD] ✓ Found S3: {pattern} ({'Public Read' if public_read else 'Public Write' if public_write else 'Private'})")

    # Check Azure Blob Storage
    print(f"[CLOUD] Checking Azure Blob Storage...")
    for pattern in patterns:
        blob_url = f"https://{pattern}.blob.core.windows.net"
        accessible, status = check_cloud_asset_access(blob_url)

        if accessible or status == 403:
            public_read, public_write = False, False

            if accessible:
                public_read = True  # If accessible, it's readable

            cloud_assets.append({
                'provider': 'Azure',
                'type': 'Azure Blob',
                'bucket_name': pattern,
                'name': pattern,
                'url': blob_url,
                'accessible': accessible,
                'public_read': public_read,
                'public_write': public_write,
                'status': 'Public' if accessible else 'Private/Exists',
                'risk': 'CRITICAL' if accessible else 'LOW'
            })
            print(f"[CLOUD] ✓ Found Azure: {pattern} ({'Public' if accessible else 'Private'})")

    # Check GCP Storage buckets
    print(f"[CLOUD] Checking GCP Storage buckets...")
    for pattern in patterns:
        gcp_url = f"https://{pattern}.storage.googleapis.com"
        accessible, status = check_cloud_asset_access(gcp_url)

        if accessible or status == 403:
            public_read, public_write = False, False

            if accessible:
                public_read = True

            cloud_assets.append({
                'provider': 'GCP',
                'type': 'GCP Storage',
                'bucket_name': pattern,
                'name': pattern,
                'url': gcp_url,
                'accessible': accessible,
                'public_read': public_read,
                'public_write': public_write,
                'status': 'Public' if accessible else 'Private/Exists',
                'risk': 'CRITICAL' if accessible else 'LOW'
            })
            print(f"[CLOUD] ✓ Found GCP: {pattern} ({'Public' if accessible else 'Private'})")

    # Check for AWS credentials from Lightbox scans
    lightbox_buckets = check_lightbox_aws_credentials(company_name)
    if lightbox_buckets:
        print(f"[CLOUD] Found {len(lightbox_buckets)} buckets from Lightbox AWS credentials")
        for bucket_name in lightbox_buckets:
            bucket_url = f"https://{bucket_name}.s3.amazonaws.com"
            accessible, status = check_cloud_asset_access(bucket_url)

            if accessible or status == 403:
                public_read, public_write = False, False

                if accessible:
                    public_read, public_write = test_s3_permissions(bucket_url)

                cloud_assets.append({
                    'provider': 'AWS',
                    'type': 'AWS S3 (Lightbox)',
                    'bucket_name': bucket_name,
                    'name': bucket_name,
                    'url': bucket_url,
                    'accessible': accessible,
                    'public_read': public_read,
                    'public_write': public_write,
                    'status': 'Public' if accessible else 'Private/Exists',
                    'risk': 'CRITICAL',
                    'source': 'Lightbox AWS Credentials'
                })
                print(f"[CLOUD] ✓ Found S3 from Lightbox: {bucket_name}")

    print(f"[CLOUD] Total cloud assets found: {len(cloud_assets)}")
    return cloud_assets


def check_cloud_asset_access(url):
    """
    Check if a cloud asset is publicly accessible

    Args:
        url (str): URL to check

    Returns:
        tuple: (accessible: bool, status_code: int)
    """
    try:
        response = requests.head(url, timeout=5, allow_redirects=True)
        # 200 = public, 403 = exists but private, 404 = doesn't exist
        accessible = response.status_code == 200
        return accessible, response.status_code
    except requests.exceptions.RequestException:
        return False, 0


def test_s3_permissions(bucket_url):
    """
    Test S3 bucket for read/write permissions

    Args:
        bucket_url (str): S3 bucket URL

    Returns:
        tuple: (public_read: bool, public_write: bool)
    """
    public_read = False
    public_write = False

    # Test public read
    try:
        response = requests.get(bucket_url, timeout=5)
        if response.status_code == 200:
            public_read = True
            print(f"[S3] Public read access confirmed")
    except Exception:
        pass

    # Test public write (safe test - doesn't actually write)
    try:
        test_key = f"test-{secrets.token_hex(8)}.txt"
        test_url = f"{bucket_url}/{test_key}"

        # Use OPTIONS request to check write permissions without actually writing
        response = requests.options(test_url, timeout=5)

        # If we get specific headers or status codes, bucket may be writable
        # Note: This is a conservative check
        if 'Allow' in response.headers or response.status_code in [200, 204]:
            # Don't mark as writable based on OPTIONS alone
            pass
    except Exception:
        pass

    return public_read, public_write


def check_lightbox_aws_credentials(company_name):
    """
    Check if Lightbox has discovered AWS credentials and extract bucket names

    Args:
        company_name (str): Company name to search for

    Returns:
        list: List of bucket names found in AWS credentials
    """
    bucket_names = []

    try:
        # Check if lightbox results exist in database
        from database import get_db, UploadedFile, UploadedCredential

        db = get_db()

        # NOTE: Removed buggy database queries
        # UploadedFile doesn't have 'content' field
        # UploadedCredential doesn't have 'username' or 'service' fields
        # These tables are for storing email:password combos, not AWS credentials

        # TODO: Implement proper AWS credential file parsing when needed

        db.close()

        # Deduplicate
        bucket_names = list(set(bucket_names))

        print(f"[LIGHTBOX] Found {len(bucket_names)} potential bucket names from Lightbox")

    except Exception as e:
        print(f"[LIGHTBOX] Error checking AWS credentials: {e}")

    return bucket_names


# Port risk explanations
PORT_RISK = {
    21: ('FTP', 'HIGH', 'File transfer protocol - often has default credentials'),
    22: ('SSH', 'HIGH', 'Server access - brute force target'),
    23: ('Telnet', 'CRITICAL', 'Unencrypted - credentials sent in plain text'),
    25: ('SMTP', 'LOW', 'Email server'),
    80: ('HTTP', 'MEDIUM', 'Web server - check for admin panels'),
    443: ('HTTPS', 'LOW', 'Secure web - check SSL config'),
    3306: ('MySQL', 'CRITICAL', 'Database directly exposed to internet'),
    3389: ('RDP', 'CRITICAL', 'Remote desktop - ransomware entry point'),
    5432: ('PostgreSQL', 'CRITICAL', 'Database exposed'),
    8080: ('HTTP Alt', 'MEDIUM', 'Alternate web port'),
    8443: ('HTTPS Alt', 'MEDIUM', 'Alternate secure web port'),
    1433: ('MSSQL', 'CRITICAL', 'Microsoft SQL Server exposed'),
    27017: ('MongoDB', 'CRITICAL', 'NoSQL database exposed'),
    6379: ('Redis', 'CRITICAL', 'In-memory database exposed'),
    5672: ('RabbitMQ', 'HIGH', 'Message queue exposed'),
    9200: ('Elasticsearch', 'HIGH', 'Search engine exposed')
}


def calculate_port_risk(port_result):
    """
    Calculate risk level for a specific port based on CVEs and service type

    Args:
        port_result (dict): Port scan result with CVEs attached

    Returns:
        str: Risk level (CRITICAL, HIGH, MEDIUM, LOW)
    """
    cves = port_result.get('cves', [])
    port = port_result.get('port', 0)

    # Check for critical CVEs (CVSS 9.0+)
    if any(cve.get('cvss_score', 0) >= 9.0 for cve in cves):
        return 'CRITICAL'

    # Check for high CVEs (CVSS 7.0+)
    if any(cve.get('cvss_score', 0) >= 7.0 for cve in cves):
        return 'HIGH'

    # Check for CVEs in CISA KEV (actively exploited)
    if any(cve.get('kev', {}).get('in_kev', False) for cve in cves):
        return 'CRITICAL'

    # Check for public exploits
    if any(cve.get('exploit', {}).get('exploit_exists', False) for cve in cves):
        return 'HIGH'

    # Check for sensitive ports (databases, remote access)
    sensitive_ports = [22, 23, 3306, 3389, 5432, 1433, 27017, 6379, 9200]
    if port in sensitive_ports:
        return 'MEDIUM'

    return 'LOW'


def run_nmap_scan(ip_addresses, progress_callback=None):
    """
    Scan IPs with Nmap for open ports and service versions
    FREE, UNLIMITED, and provides service detection for CVE mapping

    Args:
        ip_addresses (list): List of IPs to scan
        progress_callback (callable): Optional callback for progress updates

    Returns:
        list: Scan results with port, service, version, state
    """
    import nmap

    print(f"\n[PORT SCAN] Starting Nmap service detection scan...")
    print(f"[PORT SCAN] Scanning {len(ip_addresses)} discovered IPs")

    if not ip_addresses:
        print(f"[PORT SCAN] ⚠️  No IPs provided for scanning")
        return []

    # Common ports to scan
    ports_to_scan = "21,22,23,25,80,443,3306,3389,5432,8080,8443"

    scan_results = []

    try:
        nm = nmap.PortScanner()
        print(f"[PORT SCAN] Using python-nmap v{nm.nmap_version()}")
        print(f"[PORT SCAN] Scanning ports: {ports_to_scan}")
        print(f"[PORT SCAN] Scan type: Service version detection (-sV)")

    except Exception as e:
        print(f"[PORT SCAN] ❌ Failed to initialize Nmap: {e}")
        print(f"[PORT SCAN] Make sure Nmap is installed: https://nmap.org/download.html")
        print(f"[PORT SCAN] Windows: Download and install from nmap.org")
        print(f"[PORT SCAN] Linux: sudo apt install nmap")
        print(f"[PORT SCAN] Mac: brew install nmap")
        return []

    for idx, ip in enumerate(ip_addresses, 1):
        try:
            print(f"\n[PORT SCAN] [{idx}/{len(ip_addresses)}] Scanning {ip}...")

            # Update progress if callback provided
            if progress_callback:
                base_progress = 75  # Port scanning starts at 75%
                scan_progress = base_progress + int((idx / len(ip_addresses)) * 15)  # 75-90%
                progress_callback('Port Scanning', scan_progress, 100, f'Testing ports on IP {idx}/{len(ip_addresses)}...')

            # Run Nmap scan: -sV (service version), -Pn (skip ping)
            nm.scan(
                hosts=ip,
                ports=ports_to_scan,
                arguments='-sV -Pn --version-intensity 5'
            )

            # Check if host has results
            if ip not in nm.all_hosts():
                print(f"[PORT SCAN]   - No results for {ip}")
                continue

            # Get host info
            host_info = nm[ip]

            # Check host state
            if host_info.state() != 'up':
                print(f"[PORT SCAN]   - Host appears down: {host_info.state()}")
                continue

            # Extract open ports and services
            ports_found = 0
            if 'tcp' in host_info:
                for port, port_info in host_info['tcp'].items():
                    state = port_info.get('state', 'unknown')

                    if state == 'open':
                        service = port_info.get('name', 'Unknown')
                        product = port_info.get('product', '')
                        version = port_info.get('version', '')

                        # Build service name with product
                        service_name = product if product else service

                        # Get port risk information
                        port_info = PORT_RISK.get(port, ('Unknown', 'MEDIUM', 'Service detected'))
                        risk_level = port_info[1]
                        explanation = port_info[2]
                        service_label = port_info[0]

                        scan_results.append({
                            'ip': ip,
                            'port': port,
                            'service': service_name,
                            'version': version,
                            'state': state,
                            'product': product,
                            'risk': risk_level,
                            'service_name': service_label,
                            'risk_level': risk_level,
                            'explanation': explanation,
                            'protocol': 'tcp'
                        })

                        ports_found += 1
                        version_str = f" {version}" if version else ""
                        print(f"[PORT SCAN]   ✓ {ip}:{port} - {service_name}{version_str} (Risk: {risk_level}) - {explanation}")

            if ports_found == 0:
                print(f"[PORT SCAN]   - No open ports found on {ip}")

        except KeyboardInterrupt:
            print(f"\n[PORT SCAN] ⚠️  Scan interrupted by user")
            break
        except Exception as e:
            print(f"[PORT SCAN]   ⚠️  Error scanning {ip}: {type(e).__name__}: {e}")
            continue

    print(f"\n[PORT SCAN] ✓ Scan complete: Found {len(scan_results)} open ports across {len(ip_addresses)} IPs")

    return scan_results


def categorize_risk_level(risk_score):
    """
    Categorize risk score into levels

    Args:
        risk_score (int): Risk score 0-100

    Returns:
        str: Risk level (low, medium, high, critical)
    """
    if risk_score >= 75:
        return 'critical'
    elif risk_score >= 50:
        return 'high'
    elif risk_score >= 25:
        return 'medium'
    else:
        return 'low'


def identify_critical_findings(results):
    """
    Identify critical security findings

    Args:
        results (dict): Scan results

    Returns:
        list: Critical findings with descriptions
    """
    critical = []

    # Check for admin subdomains
    sensitive_keywords = ['admin', 'vpn', 'dev', 'test', 'staging', 'db', 'database']
    for sub in results['subdomains']:
        subdomain = sub['subdomain'].lower()
        for keyword in sensitive_keywords:
            if keyword in subdomain:
                critical.append({
                    'type': 'Sensitive Subdomain',
                    'description': f"Exposed {keyword} subdomain: {sub['subdomain']}",
                    'severity': 'CRITICAL' if keyword in ['admin', 'vpn', 'db'] else 'HIGH'
                })
                break

    # Check for SSH/RDP exposure
    for shodan_result in results['shodan_results']:
        port = shodan_result.get('port')
        if port == 22:
            critical.append({
                'type': 'SSH Exposed',
                'description': f"SSH open on {shodan_result['ip']}:{port}",
                'severity': 'HIGH'
            })
        elif port == 3389:
            critical.append({
                'type': 'RDP Exposed',
                'description': f"RDP open on {shodan_result['ip']}:{port}",
                'severity': 'CRITICAL'
            })

    # Check for CVEs
    for shodan_result in results['shodan_results']:
        if shodan_result.get('vulnerabilities'):
            for cve in shodan_result['vulnerabilities']:
                critical.append({
                    'type': 'Vulnerability',
                    'description': f"{cve} on {shodan_result['ip']}:{shodan_result['port']}",
                    'severity': 'CRITICAL'
                })

    # Check for public cloud assets
    for asset in results['cloud_assets']:
        if asset.get('accessible'):
            critical.append({
                'type': 'Public Cloud Asset',
                'description': f"Publicly accessible {asset['type']}: {asset['name']}",
                'severity': 'CRITICAL'
            })

    return critical[:20]  # Limit to top 20


def enhanced_subdomain_discovery(domain):
    """
    Enhanced subdomain discovery using multiple methods in parallel

    Args:
        domain (str): Target domain

    Returns:
        dict: {subdomains: [], sources_used: [], total_unique: X}
    """
    print(f"\n[ENHANCED DISCOVERY] Starting multi-source subdomain enumeration for {domain}...")

    all_subdomains = set()
    sources_used = []

    # NOTE: crt.sh removed - service unreliable

    # Method 1: DNS Brute Force
    try:
        print(f"[ENHANCED] Method 2: DNS Brute Force")
        dns_results = discover_subdomains(domain)
        for result in dns_results:
            # Normalize for deterministic deduplication
            subdomain = result.get('subdomain') if isinstance(result, dict) else result
            if subdomain:
                all_subdomains.add(subdomain.lower().strip())
        sources_used.append('DNS Brute Force')
        print(f"[ENHANCED] ✓ DNS Brute Force: {len(dns_results)} subdomains")
    except Exception as e:
        print(f"[ENHANCED] ⚠️  DNS Brute Force failed: {e}")

    # Method 3: Subfinder (if available)
    try:
        print(f"[ENHANCED] Method 3: Subfinder (40+ sources)")
        subfinder_results = run_subfinder(domain)
        # Normalize subfinder results
        for subdomain in subfinder_results:
            if subdomain:
                all_subdomains.add(subdomain.lower().strip())
        if subfinder_results:
            sources_used.append('Subfinder')
            print(f"[ENHANCED] ✓ Subfinder: {len(subfinder_results)} subdomains")
        else:
            print(f"[ENHANCED] - Subfinder: binary not found or no results")
    except Exception as e:
        print(f"[ENHANCED] ⚠️  Subfinder failed: {e}")

    # Method 4: Rapid7 FDNS (via OpenData)
    try:
        print(f"[ENHANCED] Method 4: Rapid7 FDNS Dataset")
        fdns_results = query_rapid7_fdns(domain)
        # Normalize FDNS results
        for subdomain in fdns_results:
            if subdomain:
                all_subdomains.add(subdomain.lower().strip())
        if fdns_results:
            sources_used.append('Rapid7 FDNS')
            print(f"[ENHANCED] ✓ Rapid7 FDNS: {len(fdns_results)} subdomains")
        else:
            print(f"[ENHANCED] - Rapid7 FDNS: no results")
    except Exception as e:
        print(f"[ENHANCED] ⚠️  Rapid7 FDNS failed: {e}")

    # Deduplicate and validate (DETERMINISTIC: sorted iteration)
    print(f"\n[ENHANCED] Deduplicating {len(all_subdomains)} total subdomains...")
    validated_subdomains = []

    # Sort for deterministic iteration order
    for subdomain in sorted(all_subdomains):
        if validate_subdomain(subdomain):
            validated_subdomains.append(subdomain)

    print(f"[ENHANCED] ✓ Validated {len(validated_subdomains)} unique subdomains")

    result = {
        'subdomains': sorted(list(validated_subdomains)),
        'sources_used': sources_used,
        'total_unique': len(validated_subdomains),
        'total_raw': len(all_subdomains)
    }

    print(f"[ENHANCED] Discovery complete: {result['total_unique']} subdomains from {len(sources_used)} sources")

    return result


def run_subfinder(domain):
    """
    Run subfinder binary to discover subdomains from 40+ sources
    Includes comprehensive debugging to identify execution issues

    Args:
        domain (str): Target domain

    Returns:
        set: Set of discovered subdomains
    """
    import subprocess
    import os
    import sys

    # FORCE DEBUG - Early path validation (removed - use constructed paths below)
    # Note: Removed hardcoded path that could cause backend/backend duplication

    print(f"\n{'='*70}")
    print(f"[SUBFINDER] COMPREHENSIVE DEBUG MODE")
    print(f"{'='*70}")
    print(f"[SUBFINDER] Starting subdomain discovery for: {domain}")

    subdomains = set()

    # Get absolute paths
    current_dir = os.path.dirname(os.path.abspath(__file__))
    # Go up one level to get to backend directory (not two levels to project root)
    backend_dir = os.path.abspath(os.path.join(current_dir, '..', '..'))

    # Build absolute path to subfinder (in backend/bin directory)
    subfinder_exe_path = os.path.join(backend_dir, 'bin', 'subfinder.exe')
    subfinder_path = os.path.join(backend_dir, 'bin', 'subfinder')

    print(f"\n[SUBFINDER] === PATH INFORMATION ===")
    print(f"[SUBFINDER] Current directory: {current_dir}")
    print(f"[SUBFINDER] Backend directory: {backend_dir}")
    print(f"[SUBFINDER] Working directory: {os.getcwd()}")
    print(f"[SUBFINDER] Python executable: {sys.executable}")
    print(f"[SUBFINDER] Windows path: {subfinder_exe_path}")
    print(f"[SUBFINDER] Linux/Mac path: {subfinder_path}")

    # Check which binary exists
    print(f"\n[SUBFINDER] === BINARY DETECTION ===")
    windows_exists = os.path.isfile(subfinder_exe_path)
    linux_exists = os.path.isfile(subfinder_path)

    print(f"[SUBFINDER] Windows binary exists: {windows_exists}")
    print(f"[SUBFINDER] Linux/Mac binary exists: {linux_exists}")

    # Select the correct binary
    if windows_exists:
        selected_path = subfinder_exe_path
        print(f"[SUBFINDER] ✓ Using Windows binary")
    elif linux_exists:
        selected_path = subfinder_path
        print(f"[SUBFINDER] ✓ Using Linux/Mac binary")
    else:
        print(f"[SUBFINDER] ❌ No binary found")
        print(f"[SUBFINDER] Tried: {subfinder_exe_path}")
        print(f"[SUBFINDER] Tried: {subfinder_path}")
        print(f"[SUBFINDER] Download: https://github.com/projectdiscovery/subfinder/releases")
        print(f"[SUBFINDER] Place at: {subfinder_exe_path} (Windows) or {subfinder_path} (Linux/Mac)")
        return subdomains

    # Get absolute path
    selected_path = os.path.abspath(selected_path)
    print(f"[SUBFINDER] Absolute path: {selected_path}")
    print(f"[SUBFINDER] File size: {os.path.getsize(selected_path)} bytes")

    # Test binary execution with -version
    print(f"\n[SUBFINDER] === BINARY TEST (-version) ===")
    try:
        test_command = [selected_path, '-version']
        print(f"[SUBFINDER] Test command: {' '.join(test_command)}")

        test_result = subprocess.run(
            test_command,
            capture_output=True,
            text=True,
            timeout=5
        )

        print(f"[SUBFINDER] Return code: {test_result.returncode}")
        print(f"[SUBFINDER] stdout: {test_result.stdout[:200] if test_result.stdout else '(empty)'}")
        print(f"[SUBFINDER] stderr: {test_result.stderr[:200] if test_result.stderr else '(empty)'}")

        if test_result.returncode == 0 or test_result.stdout or test_result.stderr:
            version_output = (test_result.stdout or test_result.stderr).strip()
            print(f"[SUBFINDER] ✓ Binary is executable")
            print(f"[SUBFINDER] Version info: {version_output[:100]}")
        else:
            print(f"[SUBFINDER] ⚠️  Binary test failed with code {test_result.returncode}")

    except FileNotFoundError as e:
        print(f"[SUBFINDER] ❌ FileNotFoundError: {e}")
        print(f"[SUBFINDER] Binary not in system PATH and direct path failed")
        return subdomains
    except PermissionError as e:
        print(f"[SUBFINDER] ❌ PermissionError: {e}")
        print(f"[SUBFINDER] Windows: Right-click -> Properties -> Unblock")
        print(f"[SUBFINDER] Linux/Mac: chmod +x {selected_path}")
        return subdomains
    except Exception as e:
        print(f"[SUBFINDER] ⚠️  Test failed: {type(e).__name__}: {e}")
        print(f"[SUBFINDER] Will try with shell=True fallback...")

    # Try direct execution first
    print(f"\n[SUBFINDER] === SUBDOMAIN DISCOVERY (Direct Execution) ===")
    try:
        command = [selected_path, '-d', domain, '-silent', '-all']
        print(f"[SUBFINDER] Command: {' '.join(command)}")
        print(f"[SUBFINDER] Timeout: 60 seconds")
        print(f"[SUBFINDER] Executing...")

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=60,
            cwd=backend_dir
        )

        print(f"[SUBFINDER] Return code: {result.returncode}")
        print(f"[SUBFINDER] stdout length: {len(result.stdout)} chars")
        print(f"[SUBFINDER] stderr length: {len(result.stderr)} chars")

        if result.stderr:
            print(f"[SUBFINDER] stderr: {result.stderr[:300]}")

        # Parse results
        if result.returncode == 0 or result.stdout:
            for line in result.stdout.strip().split('\n'):
                line = line.strip()
                if line and '.' in line and not line.startswith('[') and ' ' not in line:
                    subdomains.add(line)

            print(f"[SUBFINDER] ✓ Found {len(subdomains)} unique subdomains")
            if len(subdomains) > 0:
                print(f"[SUBFINDER] Sample: {list(subdomains)[:5]}")
            return subdomains
        else:
            print(f"[SUBFINDER] ⚠️  Direct execution failed, trying shell=True...")

    except FileNotFoundError as e:
        print(f"[SUBFINDER] ❌ Direct execution FileNotFoundError: {e}")
        print(f"[SUBFINDER] Trying shell=True fallback...")
    except subprocess.TimeoutExpired:
        print(f"[SUBFINDER] ⚠️  Timeout after 60 seconds")
        return subdomains
    except Exception as e:
        print(f"[SUBFINDER] ❌ Direct execution error: {type(e).__name__}: {e}")
        print(f"[SUBFINDER] Trying shell=True fallback...")

    # Fallback: Try with shell=True
    print(f"\n[SUBFINDER] === SUBDOMAIN DISCOVERY (shell=True Fallback) ===")
    try:
        command_str = f'"{selected_path}" -d {domain} -silent -all'
        print(f"[SUBFINDER] Command string: {command_str}")
        print(f"[SUBFINDER] Executing with shell=True...")

        result = subprocess.run(
            command_str,
            shell=True,
            capture_output=True,
            text=True,
            timeout=60,
            cwd=backend_dir
        )

        print(f"[SUBFINDER] Return code: {result.returncode}")
        print(f"[SUBFINDER] stdout length: {len(result.stdout)} chars")

        if result.stderr:
            print(f"[SUBFINDER] stderr: {result.stderr[:300]}")

        # Parse results
        if result.returncode == 0 or result.stdout:
            for line in result.stdout.strip().split('\n'):
                line = line.strip()
                if line and '.' in line and not line.startswith('[') and ' ' not in line:
                    subdomains.add(line)

            print(f"[SUBFINDER] ✓ Found {len(subdomains)} unique subdomains")
            if len(subdomains) > 0:
                print(f"[SUBFINDER] Sample: {list(subdomains)[:5]}")
        else:
            print(f"[SUBFINDER] ❌ Shell execution also failed")
            if result.stderr:
                print(f"[SUBFINDER] Error details: {result.stderr}")

    except Exception as e:
        print(f"[SUBFINDER] ❌ Shell execution error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()

    print(f"\n[SUBFINDER] === FINAL RESULT ===")
    print(f"[SUBFINDER] Total subdomains discovered: {len(subdomains)}")
    print(f"{'='*70}\n")

    return subdomains


def query_rapid7_fdns(domain):
    """
    Query Rapid7 Open Data FDNS dataset for subdomains
    Uses DNS search via free API

    Args:
        domain (str): Target domain

    Returns:
        set: Set of discovered subdomains
    """
    subdomains = set()

    # Note: Rapid7 FDNS is a massive dataset, not easily queryable via API
    # Alternative: Use SecurityTrails, DNSDumpster, or similar services
    # For now, we'll skip this or use a lightweight alternative

    # You could implement SecurityTrails API here if you have a key
    # Or use DNSDumpster scraping (rate-limited)

    print(f"[RAPID7] Skipping - requires massive dataset download or paid API")

    return subdomains


def validate_subdomain(subdomain):
    """
    Validate subdomain by attempting DNS resolution

    Args:
        subdomain (str): Subdomain to validate

    Returns:
        bool: True if subdomain resolves, False otherwise
    """
    try:
        socket.gethostbyname(subdomain)
        return True
    except socket.gaierror:
        return False
    except Exception:
        return False


def validate_cloud_assets(discovered_buckets):
    """
    Validate and test cloud assets (S3 buckets, Azure blobs)

    Args:
        discovered_buckets (list): List of potential bucket names

    Returns:
        list: Validated cloud assets with accessibility details
    """
    print(f"\n[CLOUD VALIDATION] Testing {len(discovered_buckets)} cloud assets...")

    validated_assets = []

    for bucket in discovered_buckets:
        asset_info = test_s3_bucket(bucket)
        if asset_info:
            validated_assets.append(asset_info)

    print(f"[CLOUD VALIDATION] ✓ Validated {len(validated_assets)} cloud assets")

    return validated_assets


def test_s3_bucket(bucket_name):
    """
    Test S3 bucket for existence and accessibility

    Args:
        bucket_name (str): Bucket name to test

    Returns:
        dict: Bucket info with accessibility details, or None if doesn't exist
    """
    bucket_url = f"https://{bucket_name}.s3.amazonaws.com"

    try:
        # Send HTTP HEAD request
        response = requests.head(bucket_url, timeout=5, allow_redirects=False)

        status_code = response.status_code

        # 200 = Public bucket, can list contents
        # 403 = Private bucket, exists but access denied
        # 404 = Bucket doesn't exist

        if status_code == 404:
            return None  # Bucket doesn't exist

        asset_info = {
            'bucket_name': bucket_name,
            'url': bucket_url,
            'accessible': status_code == 200,
            'exists': True,
            'public_read': False,
            'public_write': False,
            'contents': []
        }

        # If publicly accessible, try to list contents
        if status_code == 200:
            try:
                list_response = requests.get(bucket_url, timeout=5)
                if list_response.status_code == 200:
                    asset_info['public_read'] = True
                    # Parse XML to extract file list (simplified)
                    if '<Contents>' in list_response.text:
                        # Extract file keys from XML (basic parsing)
                        import re
                        keys = re.findall(r'<Key>(.+?)</Key>', list_response.text)
                        asset_info['contents'] = keys[:20]  # Limit to first 20 files
                        print(f"[S3] ✓ {bucket_name}: PUBLIC READ - {len(keys)} files found")
                    else:
                        print(f"[S3] ✓ {bucket_name}: PUBLIC ACCESS - empty or no listing")

                # Test for public write (risky!)
                test_upload = requests.put(
                    f"{bucket_url}/test-write-check.txt",
                    data="test",
                    timeout=5
                )
                if test_upload.status_code in [200, 204]:
                    asset_info['public_write'] = True
                    print(f"[S3] ⚠️  {bucket_name}: PUBLIC WRITE - CRITICAL RISK!")
                    # Clean up test file
                    requests.delete(f"{bucket_url}/test-write-check.txt", timeout=5)
            except Exception as e:
                print(f"[S3] ⚠️  Error testing {bucket_name} contents: {e}")

        elif status_code == 403:
            print(f"[S3] - {bucket_name}: Private (exists, access denied)")

        return asset_info

    except requests.exceptions.Timeout:
        print(f"[S3] ⚠️  Timeout testing {bucket_name}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"[S3] ⚠️  Error testing {bucket_name}: {e}")
        return None
    except Exception as e:
        print(f"[S3] ⚠️  Unexpected error for {bucket_name}: {e}")
        return None


# Test function
if __name__ == '__main__':
    # Test with a domain
    test_domain = 'stripe.com'
    print(f"\n🔍 Testing Enhanced ASM Scanner with {test_domain}\n")

    results = scan_domain(test_domain)

    print("\n" + "="*60)
    print("SCAN RESULTS")
    print("="*60)
    print(f"Domain: {results['domain']}")
    print(f"Subdomains (DNS): {len(results['subdomains'])}")
    print(f"Subdomains (crt.sh): {len(results['crt_subdomains'])}")
    print(f"Cloud Assets: {len(results['cloud_assets'])}")
    print(f"Shodan Results: {len(results['shodan_results'])}")
    print(f"Vulnerabilities: {results['vulnerabilities_found']}")
    print(f"Open Ports: {results['open_ports_count']}")
    print(f"Risk Score: {results['risk_score']}/100 ({results['risk_level'].upper()})")
    print(f"Critical Findings: {len(results['critical_findings'])}")
    print("="*60 + "\n")
