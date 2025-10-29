"""
GitHub Gist Scraper for Leaked Credentials
Searches public gists for exposed credentials, API keys, and secrets
"""

import requests
import re
import os
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Optional
from database import get_db, GitHubFinding
from sqlalchemy import func

# Breach indicator patterns
SUSPICIOUS_FILENAMES = [
    '.env', 'credentials', 'password', 'secret', 'api', 'key',
    'config', 'database', 'db', 'mysql', 'postgres', 'mongo',
    'aws', 'stripe', 'github', 'slack', 'token', 'auth'
]

# Regex patterns for credential extraction
EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
EMAIL_PASS_PATTERNS = [
    r'([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,})[:|;|\|]([^\s]+)',  # email:pass, email;pass, email|pass
    r'"email":\s*"([^"]+)",\s*"password":\s*"([^"]+)"',  # JSON format
    r'email=([^&\s]+).*?password=([^&\s]+)',  # URL parameter format
]

# API key patterns
API_KEY_PATTERNS = {
    'aws_access_key': r'AKIA[0-9A-Z]{16}',
    'aws_secret_key': r'aws_secret_access_key\s*=\s*[\'"]*([A-Za-z0-9/+=]{40})[\'"]*',
    'stripe_live': r'sk_live_[0-9a-zA-Z]{24,}',
    'stripe_test': r'sk_test_[0-9a-zA-Z]{24,}',
    'github_token': r'ghp_[0-9a-zA-Z]{36}',
    'github_oauth': r'gho_[0-9a-zA-Z]{36}',
    'slack_token': r'xoxb-[0-9]{11,}-[0-9]{11,}-[0-9a-zA-Z]{24,}',
    'slack_webhook': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
    'openai_key': r'sk-[a-zA-Z0-9]{48}',
    'google_api': r'AIza[0-9A-Za-z\-_]{35}',
}

# Database connection string patterns
DB_PATTERNS = {
    'postgres': r'postgres(?:ql)?://[^\s<>"]+',
    'mysql': r'mysql://[^\s<>"]+',
    'mongodb': r'mongodb(?:\+srv)?://[^\s<>"]+',
}

class GitHubScraper:
    """Scraper for finding credentials in public GitHub gists"""

    def __init__(self):
        self.token = os.getenv('GITHUB_TOKEN', None)
        self.base_url = 'https://api.github.com/gists/public'
        self.session = requests.Session()

        # Setup headers
        self.headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'NERVE-GHOST-Security-Tool'
        }

        if self.token:
            self.headers['Authorization'] = f'token {self.token}'
            print(f"[GitHub Scraper] Using authenticated API (5000 req/hour)")
        else:
            print(f"[GitHub Scraper] WARNING: No GITHUB_TOKEN found, using unauthenticated API (60 req/hour)")

        self.stats = {
            'gists_checked': 0,
            'credentials_found': 0,
            'new_stored': 0,
            'duplicates_skipped': 0,
            'errors': 0
        }

    def check_rate_limit(self) -> Tuple[int, int]:
        """Check GitHub API rate limit status"""
        try:
            response = self.session.get(
                'https://api.github.com/rate_limit',
                headers=self.headers,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                limit = data['rate']['limit']
                remaining = data['rate']['remaining']
                reset_time = datetime.fromtimestamp(data['rate']['reset'])

                print(f"[Rate Limit] {remaining}/{limit} requests remaining (resets at {reset_time.strftime('%H:%M:%S')})")
                return remaining, limit

        except Exception as e:
            print(f"[Rate Limit] Error checking rate limit: {e}")

        return -1, -1

    def fetch_public_gists(self, limit: int = 100) -> List[Dict]:
        """Fetch latest public gists from GitHub"""
        print(f"\n[Fetching] Retrieving {limit} public gists...")

        gists = []
        per_page = min(limit, 100)  # GitHub max is 100 per page

        try:
            response = self.session.get(
                self.base_url,
                headers=self.headers,
                params={'per_page': per_page},
                timeout=15
            )

            # Check rate limit from headers
            if 'X-RateLimit-Remaining' in response.headers:
                remaining = response.headers['X-RateLimit-Remaining']
                print(f"[API] Rate limit remaining: {remaining}")

                if int(remaining) < 10:
                    print(f"[WARNING] Rate limit low ({remaining}), consider stopping")

            if response.status_code == 200:
                gists = response.json()
                print(f"[Fetching] Retrieved {len(gists)} gists")
            elif response.status_code == 403:
                print(f"[ERROR] Rate limit exceeded. Wait before trying again.")
            else:
                print(f"[ERROR] GitHub API returned status {response.status_code}")

        except Exception as e:
            print(f"[ERROR] Failed to fetch gists: {e}")

        return gists

    def is_suspicious_gist(self, gist: Dict) -> bool:
        """Check if gist contains suspicious filenames or content indicators"""
        files = gist.get('files', {})

        for filename in files.keys():
            filename_lower = filename.lower()

            # Check for suspicious filename patterns
            for indicator in SUSPICIOUS_FILENAMES:
                if indicator in filename_lower:
                    return True

        return False

    def fetch_gist_content(self, raw_url: str) -> Optional[str]:
        """Fetch raw content from a gist file"""
        try:
            response = self.session.get(raw_url, timeout=10)
            if response.status_code == 200:
                return response.text
        except Exception as e:
            print(f"[ERROR] Failed to fetch content from {raw_url}: {e}")

        return None

    def extract_credentials(self, content: str, gist_id: str, filename: str) -> List[Dict]:
        """Extract credentials from gist content"""
        findings = []

        # 1. Extract email:password combos
        for pattern in EMAIL_PASS_PATTERNS:
            matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
            for match in matches:
                email = match.group(1)
                password = match.group(2) if len(match.groups()) > 1 else ''

                # Get context (500 chars around match)
                start = max(0, match.start() - 250)
                end = min(len(content), match.end() + 250)
                context = content[start:end]

                findings.append({
                    'query_term': email,
                    'query_type': 'email',
                    'credential_type': 'password',
                    'credential_value': password,
                    'context': context
                })

        # 2. Extract standalone emails
        emails = re.findall(EMAIL_PATTERN, content)
        for email in emails[:10]:  # Limit to first 10 to avoid spam
            # Only add if not already found with password
            if not any(f['query_term'] == email for f in findings):
                # Get context
                match_pos = content.find(email)
                if match_pos != -1:
                    start = max(0, match_pos - 250)
                    end = min(len(content), match_pos + len(email) + 250)
                    context = content[start:end]

                    findings.append({
                        'query_term': email,
                        'query_type': 'email',
                        'credential_type': 'email_only',
                        'credential_value': '',
                        'context': context
                    })

        # 3. Extract API keys
        for key_type, pattern in API_KEY_PATTERNS.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                key_value = match.group(0)

                # Get context
                start = max(0, match.start() - 250)
                end = min(len(content), match.end() + 250)
                context = content[start:end]

                findings.append({
                    'query_term': key_value[:20] + '...',  # Truncate for query_term
                    'query_type': 'api_key',
                    'credential_type': key_type,
                    'credential_value': key_value,
                    'context': context
                })

        # 4. Extract database connection strings
        for db_type, pattern in DB_PATTERNS.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                conn_string = match.group(0)

                # Get context
                start = max(0, match.start() - 250)
                end = min(len(content), match.end() + 250)
                context = content[start:end]

                findings.append({
                    'query_term': db_type,
                    'query_type': 'database',
                    'credential_type': db_type,
                    'credential_value': conn_string,
                    'context': context
                })

        return findings

    def store_finding(self, gist: Dict, filename: str, finding: Dict) -> bool:
        """Store a finding in the database"""
        db = get_db()

        try:
            # Check if gist_id already exists
            existing = db.query(GitHubFinding).filter(
                GitHubFinding.gist_id == gist['id']
            ).first()

            if existing:
                self.stats['duplicates_skipped'] += 1
                db.close()
                return False

            # Create new finding
            github_finding = GitHubFinding(
                gist_id=gist['id'],
                gist_url=gist['html_url'],
                filename=filename,
                created_at=datetime.fromisoformat(gist['created_at'].replace('Z', '+00:00')),
                query_term=finding['query_term'],
                query_type=finding['query_type'],
                credential_type=finding['credential_type'],
                credential_value=finding['credential_value'],
                context=finding['context'],
                discovered_at=datetime.utcnow()
            )

            db.add(github_finding)
            db.commit()

            self.stats['new_stored'] += 1
            db.close()
            return True

        except Exception as e:
            print(f"[ERROR] Failed to store finding: {e}")
            self.stats['errors'] += 1
            db.rollback()
            db.close()
            return False

    def cleanup_old_findings(self, days: int = 90):
        """Delete findings older than specified days"""
        db = get_db()

        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            deleted = db.query(GitHubFinding).filter(
                GitHubFinding.discovered_at < cutoff_date
            ).delete()

            db.commit()

            if deleted > 0:
                print(f"[Cleanup] Deleted {deleted} findings older than {days} days")

            db.close()

        except Exception as e:
            print(f"[ERROR] Cleanup failed: {e}")
            db.rollback()
            db.close()

    def run(self, limit: int = 100):
        """Main scraper execution"""
        print("=" * 60)
        print("GitHub Gist Credential Scraper")
        print("=" * 60)

        # Check rate limit
        remaining, total = self.check_rate_limit()
        if remaining == 0:
            print("[ERROR] Rate limit exceeded. Exiting.")
            return

        # Fetch gists
        gists = self.fetch_public_gists(limit)

        if not gists:
            print("[ERROR] No gists retrieved. Exiting.")
            return

        # Process each gist
        for gist in gists:
            self.stats['gists_checked'] += 1

            # Check if gist looks suspicious
            if not self.is_suspicious_gist(gist):
                continue

            gist_id = gist['id']
            print(f"\n[Processing] Gist {gist_id} - {gist.get('description', 'No description')[:50]}")

            # Process each file in the gist
            for filename, file_data in gist.get('files', {}).items():
                raw_url = file_data.get('raw_url')

                if not raw_url:
                    continue

                print(f"  [File] {filename}")

                # Fetch content
                content = self.fetch_gist_content(raw_url)

                if not content:
                    continue

                # Extract credentials
                findings = self.extract_credentials(content, gist_id, filename)

                if findings:
                    print(f"    [Found] {len(findings)} potential credentials")
                    self.stats['credentials_found'] += len(findings)

                    # Store findings
                    for finding in findings:
                        self.store_finding(gist, filename, finding)

        # Cleanup old findings
        self.cleanup_old_findings(90)

        # Print summary
        print("\n" + "=" * 60)
        print("Scraper Summary")
        print("=" * 60)
        print(f"Gists Checked: {self.stats['gists_checked']}")
        print(f"Credentials Found: {self.stats['credentials_found']}")
        print(f"New Stored: {self.stats['new_stored']}")
        print(f"Duplicates Skipped: {self.stats['duplicates_skipped']}")
        print(f"Errors: {self.stats['errors']}")
        print("=" * 60)


# Test the scraper
if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv()

    scraper = GitHubScraper()
    scraper.run(limit=30)  # Test with 30 gists
