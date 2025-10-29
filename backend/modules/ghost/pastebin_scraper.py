"""
PasteBin Archive Scraper for Leaked Credentials
Scrapes public PasteBin archive for breach pastes containing credentials
"""

import requests
import re
import time
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from bs4 import BeautifulSoup
from database import get_db, PasteBinFinding

# Breach indicator keywords
BREACH_KEYWORDS = [
    'combo', 'leak', 'breach', 'database', 'dump', 'credentials',
    'hacked', 'passwords', 'combolist', 'account', 'cracked',
    'combo list', 'db dump', 'data breach', 'email:pass'
]

# Ignore keywords (probably code, not breaches)
IGNORE_KEYWORDS = [
    'code', 'script', 'function', 'class', 'import', 'def ',
    'var ', 'const ', 'let ', 'if(', 'for(', 'while('
]

# Regex patterns for credential extraction
EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
DOMAIN_PATTERN = r'@([A-Za-z0-9.-]+\.[A-Z|a-z]{2,})\b'
USERNAME_PATTERN = r'^[a-zA-Z0-9_]{3,20}$'  # Simple username pattern

EMAIL_PASS_PATTERNS = [
    r'([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,})[:|;|\|]([^\s\r\n]+)',  # email:pass
]

class PasteBinScraper:
    """Scraper for finding credentials in PasteBin archives"""

    def __init__(self):
        self.archive_url = 'https://pastebin.com/archive'
        self.raw_url_template = 'https://pastebin.com/raw/{}'
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

        self.stats = {
            'pastes_checked': 0,
            'pastes_skipped': 0,
            'credentials_found': 0,
            'new_stored': 0,
            'duplicates_skipped': 0,
            'errors': 0
        }

    def fetch_archive_page(self) -> Optional[str]:
        """Fetch the PasteBin archive HTML page"""
        print(f"[Fetching] Archive page from {self.archive_url}")

        try:
            response = self.session.get(self.archive_url, timeout=15)

            if response.status_code == 200:
                print(f"[Fetching] Successfully retrieved archive page")
                return response.text
            else:
                print(f"[ERROR] Archive returned status {response.status_code}")
                return None

        except Exception as e:
            print(f"[ERROR] Failed to fetch archive: {e}")
            return None

    def parse_archive_links(self, html: str) -> List[Dict]:
        """Parse paste links and titles from archive HTML"""
        print(f"[Parsing] Extracting paste links from archive...")

        pastes = []

        try:
            soup = BeautifulSoup(html, 'html.parser')

            # Find all paste links in the archive table
            # Archive page structure: <a href="/XXXXXXXX">Title</a>
            paste_links = soup.find_all('a', href=re.compile(r'^/[a-zA-Z0-9]{8}$'))

            for link in paste_links:
                paste_id = link['href'][1:]  # Remove leading /
                paste_title = link.get_text(strip=True)

                # Get the date (usually in the same row)
                date_elem = link.find_next('td')
                posted_date = date_elem.get_text(strip=True) if date_elem else 'Unknown'

                pastes.append({
                    'paste_id': paste_id,
                    'paste_title': paste_title,
                    'paste_url': f'https://pastebin.com/{paste_id}',
                    'posted_date': posted_date
                })

            print(f"[Parsing] Found {len(pastes)} pastes in archive")

        except Exception as e:
            print(f"[ERROR] Failed to parse archive HTML: {e}")

        return pastes

    def is_breach_paste(self, paste: Dict) -> bool:
        """Check if paste title contains breach indicators"""
        title = paste['paste_title'].lower()

        # Check for breach keywords
        has_breach_keyword = any(keyword in title for keyword in BREACH_KEYWORDS)

        # Check for ignore keywords (code/scripts)
        has_ignore_keyword = any(keyword in title for keyword in IGNORE_KEYWORDS)

        return has_breach_keyword and not has_ignore_keyword

    def fetch_paste_content(self, paste_id: str) -> Optional[str]:
        """Fetch raw content from a paste"""
        raw_url = self.raw_url_template.format(paste_id)

        try:
            # Add delay to be nice to PasteBin
            time.sleep(2)

            response = self.session.get(raw_url, timeout=10)

            if response.status_code == 200:
                return response.text
            elif response.status_code == 404:
                print(f"    [404] Paste {paste_id} not found or deleted")
            else:
                print(f"    [ERROR] Status {response.status_code} for {paste_id}")

        except Exception as e:
            print(f"    [ERROR] Failed to fetch {paste_id}: {e}")

        return None

    def extract_credentials(self, content: str) -> List[Dict]:
        """Extract credentials from paste content"""
        findings = []

        # 1. Extract email:password combos
        for pattern in EMAIL_PASS_PATTERNS:
            matches = re.finditer(pattern, content, re.MULTILINE)
            for match in matches:
                email = match.group(1)
                password = match.group(2)

                # Get context (500 chars around match)
                start = max(0, match.start() - 250)
                end = min(len(content), match.end() + 250)
                context = content[start:end]

                # Extract domain from email
                domain_match = re.search(DOMAIN_PATTERN, email)
                domain = domain_match.group(1) if domain_match else ''

                findings.append({
                    'query_term': email,
                    'query_type': 'email',
                    'credential_password': password,
                    'context': context
                })

                # Also add domain finding
                if domain:
                    findings.append({
                        'query_term': domain,
                        'query_type': 'domain',
                        'credential_password': password,
                        'context': context
                    })

        # 2. Extract standalone emails (if not already found with password)
        emails = re.findall(EMAIL_PATTERN, content)
        found_emails = {f['query_term'] for f in findings if f['query_type'] == 'email'}

        for email in emails[:20]:  # Limit to first 20
            if email not in found_emails:
                # Get context
                match_pos = content.find(email)
                if match_pos != -1:
                    start = max(0, match_pos - 250)
                    end = min(len(content), match_pos + len(email) + 250)
                    context = content[start:end]

                    findings.append({
                        'query_term': email,
                        'query_type': 'email',
                        'credential_password': '',
                        'context': context
                    })

                    found_emails.add(email)

        # 3. Extract domains from emails
        domains = re.findall(DOMAIN_PATTERN, content)
        found_domains = {f['query_term'] for f in findings if f['query_type'] == 'domain'}

        for domain in set(domains[:20]):  # Unique domains, limit 20
            if domain not in found_domains:
                match_pos = content.find(domain)
                if match_pos != -1:
                    start = max(0, match_pos - 250)
                    end = min(len(content), match_pos + len(domain) + 250)
                    context = content[start:end]

                    findings.append({
                        'query_term': domain,
                        'query_type': 'domain',
                        'credential_password': '',
                        'context': context
                    })

                    found_domains.add(domain)

        return findings

    def has_minimum_credentials(self, findings: List[Dict]) -> bool:
        """Check if paste has at least 3 email:password pairs"""
        email_pass_count = sum(
            1 for f in findings
            if f['query_type'] == 'email' and f['credential_password']
        )
        return email_pass_count >= 3

    def store_findings(self, paste: Dict, findings: List[Dict]) -> int:
        """Store findings in database"""
        db = get_db()
        stored_count = 0

        try:
            # Check if paste already exists
            existing = db.query(PasteBinFinding).filter(
                PasteBinFinding.paste_id == paste['paste_id']
            ).first()

            if existing:
                self.stats['duplicates_skipped'] += 1
                db.close()
                return 0

            # Store each finding
            for finding in findings:
                pastebin_finding = PasteBinFinding(
                    paste_id=paste['paste_id'],
                    paste_title=paste['paste_title'],
                    paste_url=paste['paste_url'],
                    posted_date=paste['posted_date'],
                    query_term=finding['query_term'],
                    query_type=finding['query_type'],
                    credential_password=finding['credential_password'],
                    context=finding['context'],
                    discovered_at=datetime.utcnow()
                )

                db.add(pastebin_finding)
                stored_count += 1

            db.commit()
            self.stats['new_stored'] += stored_count

            db.close()
            return stored_count

        except Exception as e:
            print(f"    [ERROR] Failed to store findings: {e}")
            self.stats['errors'] += 1
            db.rollback()
            db.close()
            return 0

    def cleanup_old_findings(self, days: int = 60):
        """Delete findings older than specified days"""
        db = get_db()

        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            deleted = db.query(PasteBinFinding).filter(
                PasteBinFinding.discovered_at < cutoff_date
            ).delete()

            db.commit()

            if deleted > 0:
                print(f"[Cleanup] Deleted {deleted} findings older than {days} days")

            db.close()

        except Exception as e:
            print(f"[ERROR] Cleanup failed: {e}")
            db.rollback()
            db.close()

    def run(self, max_pastes: int = 50):
        """Main scraper execution"""
        print("=" * 60)
        print("PasteBin Archive Credential Scraper")
        print("=" * 60)

        # Fetch archive page
        html = self.fetch_archive_page()

        if not html:
            print("[ERROR] Could not fetch archive page. Exiting.")
            return

        # Parse paste links
        all_pastes = self.parse_archive_links(html)

        if not all_pastes:
            print("[ERROR] No pastes found in archive. Exiting.")
            return

        # Filter for breach pastes
        breach_pastes = [p for p in all_pastes if self.is_breach_paste(p)]
        print(f"\n[Filter] Found {len(breach_pastes)} potential breach pastes")

        # Limit to max_pastes
        pastes_to_check = breach_pastes[:max_pastes]
        print(f"[Processing] Will check {len(pastes_to_check)} pastes (limit: {max_pastes})")

        # Process each paste
        for paste in pastes_to_check:
            self.stats['pastes_checked'] += 1

            print(f"\n[{self.stats['pastes_checked']}/{len(pastes_to_check)}] {paste['paste_id']} - {paste['paste_title'][:50]}")

            # Fetch content
            content = self.fetch_paste_content(paste['paste_id'])

            if not content:
                self.stats['pastes_skipped'] += 1
                continue

            # Extract credentials
            findings = self.extract_credentials(content)

            if not findings:
                print(f"    [Skip] No credentials found")
                self.stats['pastes_skipped'] += 1
                continue

            # Check minimum threshold (3 email:password pairs)
            if not self.has_minimum_credentials(findings):
                print(f"    [Skip] Less than 3 email:password pairs (found {len(findings)} total items)")
                self.stats['pastes_skipped'] += 1
                continue

            print(f"    [Found] {len(findings)} credentials (valid breach paste)")
            self.stats['credentials_found'] += len(findings)

            # Store findings
            stored = self.store_findings(paste, findings)
            if stored > 0:
                print(f"    [Stored] {stored} new findings")

        # Cleanup old findings
        self.cleanup_old_findings(60)

        # Print summary
        print("\n" + "=" * 60)
        print("Scraper Summary")
        print("=" * 60)
        print(f"Pastes Checked: {self.stats['pastes_checked']}")
        print(f"Pastes Skipped: {self.stats['pastes_skipped']}")
        print(f"Credentials Found: {self.stats['credentials_found']}")
        print(f"New Stored: {self.stats['new_stored']}")
        print(f"Duplicates Skipped: {self.stats['duplicates_skipped']}")
        print(f"Errors: {self.stats['errors']}")
        print("=" * 60)


# Test the scraper
if __name__ == "__main__":
    scraper = PasteBinScraper()
    scraper.run(max_pastes=10)  # Test with 10 pastes
