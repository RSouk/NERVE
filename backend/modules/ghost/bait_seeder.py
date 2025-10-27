"""
NERVE GHOST - BAIT Seeder
Posts bait credentials to public surfaces like Pastebin for detection purposes.
Part of the GHOST module for detecting credential theft and usage.
"""

import os
import time
import json
import logging
import requests
import sys
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin
import random

# Add parent directory to path for database imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from database import BaitToken, SessionLocal

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class BaitSeeder:
    """Seeds bait credentials to public platforms for detection"""

    def __init__(self, pastebin_api_key: Optional[str] = None, use_database: bool = True):
        """
        Initialize the bait seeder

        Args:
            pastebin_api_key: API key for Pastebin (optional)
            use_database: If True, integrate with database for tracking
        """
        self.pastebin_api_key = pastebin_api_key or os.getenv('PASTEBIN_API_KEY')
        self.pastebin_api_url = "https://pastebin.com/api/api_post.php"
        self.deployment_log = []
        self.use_database = use_database

    def _generate_realistic_context(self, credential_type: str) -> Tuple[str, str]:
        """
        Generate realistic context for credentials

        Args:
            credential_type: Type of credential being posted

        Returns:
            Tuple of (title, description)
        """
        contexts = {
            "aws_credentials": [
                ("AWS Config Backup", "Backup of AWS configuration files"),
                ("Production Environment Setup", "Production server AWS credentials"),
                ("CI/CD Pipeline Config", "Jenkins AWS deployment configuration"),
                ("Terraform State Backup", "Backup of terraform state with AWS keys"),
            ],
            "database_credentials": [
                ("Database Connection Strings", "Production database configurations"),
                ("App Config Dump", "Application configuration backup"),
                ("Docker Compose Production", "Production docker-compose.yml"),
                ("Environment Variables", "Production environment variables"),
            ],
            "api_token": [
                ("API Keys Backup", "Third-party API keys configuration"),
                ("Payment Gateway Config", "Stripe and payment configurations"),
                ("Integration Credentials", "External service integrations"),
                ("Monitoring Setup", "DataDog/NewRelic API keys"),
            ],
            "ssh_key": [
                ("SSH Keys Backup", "Production server SSH keys"),
                ("Deploy Keys", "GitHub/GitLab deploy keys"),
                ("Server Access Keys", "Emergency access SSH keys"),
                ("Ansible Vault Keys", "Ansible deployment keys"),
            ],
        }

        context_list = contexts.get(credential_type, [
            ("Configuration Backup", "System configuration backup")
        ])

        return random.choice(context_list)

    def _create_code_snippet(self, credentials: Dict, credential_type: str) -> str:
        """
        Create a realistic code snippet containing credentials

        Args:
            credentials: Credential data
            credential_type: Type of credential

        Returns:
            Code snippet as string
        """
        if credential_type == "aws_credentials":
            return f"""# AWS Configuration
# Region: {credentials.get('region', 'us-east-1')}
# Last updated: {datetime.now().strftime('%Y-%m-%d')}

import boto3

# AWS Credentials
AWS_ACCESS_KEY_ID = "{credentials.get('aws_access_key_id', '')}"
AWS_SECRET_ACCESS_KEY = "{credentials.get('aws_secret_access_key', '')}"
AWS_REGION = "{credentials.get('region', 'us-east-1')}"

# Initialize S3 client
s3_client = boto3.client(
    's3',
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    region_name=AWS_REGION
)

# Production bucket
BUCKET_NAME = 'prod-app-storage'
"""

        elif credential_type == "database_credentials":
            return f"""# Database Configuration
# Environment: Production
# Last updated: {datetime.now().strftime('%Y-%m-%d')}

DATABASE_CONFIG = {{
    'host': '{credentials.get('host', 'localhost')}',
    'port': {credentials.get('port', 5432)},
    'database': '{credentials.get('database', 'production')}',
    'user': '{credentials.get('username', 'admin')}',
    'password': '{credentials.get('password', '')}',
    'sslmode': 'require'
}}

# Connection string for SQLAlchemy
DATABASE_URL = "{credentials.get('connection_string', '')}"

# Redis cache (if using)
REDIS_URL = "redis://:{credentials.get('password', '')}@redis-prod.internal:6379/0"
"""

        elif credential_type == "api_token":
            return f"""# API Keys Configuration
# Service: {credentials.get('service_name', 'Production API')}
# Last updated: {datetime.now().strftime('%Y-%m-%d')}

# API Token
API_TOKEN = "{credentials.get('token', '')}"
API_BASE_URL = "https://api.service.com/v1"

# Request headers
HEADERS = {{
    'Authorization': f'Bearer {{API_TOKEN}}',
    'Content-Type': 'application/json',
    'User-Agent': 'ProductionApp/1.0'
}}

# Example usage
import requests

response = requests.get(
    f'{{API_BASE_URL}}/users',
    headers=HEADERS
)
"""

        elif credential_type == "ssh_key":
            return f"""# SSH Key Configuration
# Server: {credentials.get('key_comment', 'production-server')}
# Last updated: {datetime.now().strftime('%Y-%m-%d')}

# Private Key (keep secure!)
{credentials.get('private_key', '')}

# Public Key
# {credentials.get('public_key', '')}

# Fingerprint: {credentials.get('fingerprint', '')}

# Usage:
# ssh -i /path/to/key root@production-server.com
"""

        else:
            return json.dumps(credentials, indent=2)

    def _create_env_file_content(self, credentials_list: List[Dict]) -> str:
        """
        Create a .env file format with multiple credentials

        Args:
            credentials_list: List of credential dictionaries

        Returns:
            .env file content as string
        """
        env_lines = [
            "# Production Environment Configuration",
            f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "# DO NOT COMMIT TO VERSION CONTROL",
            "",
            "# Application Configuration",
            "NODE_ENV=production",
            "APP_PORT=3000",
            "LOG_LEVEL=info",
            ""
        ]

        for cred in credentials_list:
            cred_type = cred.get('type', 'unknown')

            if cred_type == 'aws_credentials':
                env_lines.extend([
                    "# AWS Configuration",
                    f"AWS_ACCESS_KEY_ID={cred.get('aws_access_key_id', '')}",
                    f"AWS_SECRET_ACCESS_KEY={cred.get('aws_secret_access_key', '')}",
                    f"AWS_REGION={cred.get('region', 'us-east-1')}",
                    f"AWS_BUCKET=prod-storage-{random.randint(1000, 9999)}",
                    ""
                ])

            elif cred_type == 'database_credentials':
                env_lines.extend([
                    "# Database Configuration",
                    f"DATABASE_URL={cred.get('connection_string', '')}",
                    f"DB_HOST={cred.get('host', '')}",
                    f"DB_PORT={cred.get('port', '')}",
                    f"DB_NAME={cred.get('database', '')}",
                    f"DB_USER={cred.get('username', '')}",
                    f"DB_PASSWORD={cred.get('password', '')}",
                    ""
                ])

            elif cred_type == 'api_token':
                service = cred.get('service_name', 'api')
                env_lines.extend([
                    f"# {service.upper()} Configuration",
                    f"{service.upper()}_API_KEY={cred.get('token', '')}",
                    ""
                ])

        return "\n".join(env_lines)

    def seed_to_pastebin(self, title: str, content: str,
                         expiration: str = "1M", privacy: int = 1,
                         bait_data: Optional[Dict] = None) -> Optional[str]:
        """
        Post content to Pastebin

        Args:
            title: Paste title
            content: Paste content
            expiration: Expiration time (10M, 1H, 1D, 1W, 2W, 1M, 6M, 1Y, N)
            privacy: 0=public, 1=unlisted, 2=private
            bait_data: Optional bait data dictionary for database integration

        Returns:
            Paste URL if successful, None otherwise
        """
        if not self.pastebin_api_key:
            logger.error("Pastebin API key not configured")
            # Still try to update database even without API key (for testing)
            paste_url = f"https://pastebin.com/mock_{random.randint(100000, 999999)}"
        else:
            try:
                data = {
                    'api_dev_key': self.pastebin_api_key,
                    'api_option': 'paste',
                    'api_paste_code': content,
                    'api_paste_name': title,
                    'api_paste_expire_date': expiration,
                    'api_paste_private': privacy,
                    'api_paste_format': 'python'  # Syntax highlighting
                }

                response = requests.post(self.pastebin_api_url, data=data, timeout=10)

                if response.status_code == 200 and response.text.startswith('http'):
                    paste_url = response.text.strip()
                    logger.info(f"✓ Posted to Pastebin: {paste_url}")
                else:
                    logger.error(f"Pastebin error: {response.text}")
                    return None

            except Exception as e:
                logger.error(f"Failed to post to Pastebin: {e}")
                return None

        # Log deployment
        self.deployment_log.append({
            "platform": "pastebin",
            "url": paste_url,
            "title": title,
            "timestamp": datetime.now().isoformat(),
            "expiration": expiration
        })

        # Database integration
        if self.use_database and bait_data:
            identifier = bait_data.get('identifier')
            if identifier:
                self._update_database_seeding(identifier, paste_url, bait_data)

        return paste_url

    def _update_database_seeding(self, identifier: str, seeded_location: str, bait_data: Dict):
        """
        Update database with seeding information

        Args:
            identifier: Bait identifier
            seeded_location: URL where bait was seeded
            bait_data: Complete bait data dictionary
        """
        db = None
        try:
            db = SessionLocal()

            # Try to find existing bait token
            bait_token = db.query(BaitToken).filter_by(identifier=identifier).first()

            if bait_token:
                # Update existing record
                bait_token.seeded_location = seeded_location
                if bait_token.seeded_at is None:
                    bait_token.seeded_at = datetime.utcnow()
                logger.info(f"✓ Updated database record for bait: {identifier}")
            else:
                # Create new record
                type_mapping = {
                    'aws_credentials': 'aws_key',
                    'api_token': 'api_token',
                    'database_credentials': 'database',
                    'ssh_key': 'ssh_key',
                    'jwt_token': 'jwt_token',
                    'oauth_token': 'oauth_token'
                }
                bait_type = type_mapping.get(bait_data.get('type'), 'unknown')

                bait_token = BaitToken(
                    identifier=identifier,
                    bait_type=bait_type,
                    token_value=json.dumps(bait_data),
                    seeded_location=seeded_location,
                    status='active'
                )
                db.add(bait_token)
                logger.info(f"✓ Created new database record for bait: {identifier}")

            db.commit()

        except Exception as e:
            logger.error(f"Failed to update database: {e}")
            if db:
                db.rollback()

        finally:
            if db:
                db.close()

    def get_seeded_baits(self) -> List[Dict]:
        """
        Get all bait tokens that have been seeded

        Returns:
            List of dictionaries containing seeded bait information
        """
        db = None
        try:
            db = SessionLocal()

            # Query baits where seeded_location is not None
            seeded_baits = db.query(BaitToken).filter(BaitToken.seeded_location.isnot(None)).all()

            results = []
            for bait in seeded_baits:
                results.append({
                    'id': bait.id,
                    'identifier': bait.identifier,
                    'bait_type': bait.bait_type,
                    'seeded_at': bait.seeded_at.isoformat() if bait.seeded_at else None,
                    'seeded_location': bait.seeded_location,
                    'access_count': bait.access_count,
                    'status': bait.status,
                    'first_access': bait.first_access.isoformat() if bait.first_access else None,
                    'last_access': bait.last_access.isoformat() if bait.last_access else None
                })

            return results

        except Exception as e:
            logger.error(f"Failed to get seeded baits: {e}")
            return []

        finally:
            if db:
                db.close()

    def mark_bait_as_expired(self, identifier: str) -> bool:
        """
        Mark a bait token as expired

        Args:
            identifier: Bait identifier to mark as expired

        Returns:
            True if successful, False otherwise
        """
        db = None
        try:
            db = SessionLocal()

            bait_token = db.query(BaitToken).filter_by(identifier=identifier).first()

            if not bait_token:
                logger.error(f"Bait token not found: {identifier}")
                return False

            bait_token.status = 'expired'
            db.commit()

            logger.info(f"✓ Marked bait as expired: {identifier}")
            return True

        except Exception as e:
            logger.error(f"Failed to mark bait as expired: {e}")
            if db:
                db.rollback()
            return False

        finally:
            if db:
                db.close()

    def seed_to_github_gist(self, title: str, content: str,
                            github_token: Optional[str] = None,
                            public: bool = False) -> Optional[str]:
        """
        Post content to GitHub Gist (requires GitHub token)

        Args:
            title: Gist filename
            content: Gist content
            github_token: GitHub personal access token
            public: Whether gist should be public

        Returns:
            Gist URL if successful, None otherwise
        """
        token = github_token or os.getenv('GITHUB_TOKEN')

        if not token:
            logger.error("GitHub token not configured")
            return None

        try:
            headers = {
                'Authorization': f'token {token}',
                'Accept': 'application/vnd.github.v3+json'
            }

            data = {
                'description': f'{title} - {datetime.now().strftime("%Y-%m-%d")}',
                'public': public,
                'files': {
                    f'{title}.py': {
                        'content': content
                    }
                }
            }

            response = requests.post(
                'https://api.github.com/gists',
                headers=headers,
                json=data,
                timeout=10
            )

            if response.status_code == 201:
                gist_url = response.json().get('html_url')
                logger.info(f"✓ Posted to GitHub Gist: {gist_url}")

                # Log deployment
                self.deployment_log.append({
                    "platform": "github_gist",
                    "url": gist_url,
                    "title": title,
                    "timestamp": datetime.now().isoformat(),
                    "public": public
                })

                return gist_url
            else:
                logger.error(f"GitHub Gist error: {response.status_code} - {response.text}")
                return None

        except Exception as e:
            logger.error(f"Failed to post to GitHub Gist: {e}")
            return None

    def seed_to_local_file(self, title: str, content: str,
                           output_dir: str = "./bait_seeds") -> Optional[str]:
        """
        Save content to a local file (for testing or manual distribution)

        Args:
            title: File title
            content: File content
            output_dir: Directory to save file

        Returns:
            File path if successful, None otherwise
        """
        try:
            os.makedirs(output_dir, exist_ok=True)

            # Create safe filename
            safe_title = "".join(c if c.isalnum() or c in ['-', '_'] else '_' for c in title)
            filename = f"{safe_title}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            filepath = os.path.join(output_dir, filename)

            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)

            logger.info(f"✓ Saved to local file: {filepath}")

            # Log deployment
            self.deployment_log.append({
                "platform": "local_file",
                "path": filepath,
                "title": title,
                "timestamp": datetime.now().isoformat()
            })

            return filepath

        except Exception as e:
            logger.error(f"Failed to save to local file: {e}")
            return None

    def deploy_credential_bait(self, credentials: Dict,
                               platforms: List[str] = ['pastebin'],
                               pastebin_expiry: str = "1M") -> Dict[str, Optional[str]]:
        """
        Deploy bait credentials to specified platforms

        Args:
            credentials: Credential dictionary from BaitGenerator
            platforms: List of platforms to deploy to
                      ('pastebin', 'github_gist', 'local_file')
            pastebin_expiry: Expiration for Pastebin pastes

        Returns:
            Dictionary mapping platform names to URLs/paths
        """
        credential_type = credentials.get('type', 'unknown')
        tracking_id = credentials.get('tracking_id', 'N/A')

        logger.info(f"Deploying {credential_type} bait (Tracking: {tracking_id})")

        # Generate context
        title, description = self._generate_realistic_context(credential_type)

        # Create code snippet
        content = self._create_code_snippet(credentials, credential_type)

        results = {}

        # Deploy to each platform
        for platform in platforms:
            if platform == 'pastebin':
                url = self.seed_to_pastebin(title, content, expiration=pastebin_expiry, bait_data=credentials)
                results['pastebin'] = url

            elif platform == 'github_gist':
                url = self.seed_to_github_gist(title, content, public=False)
                results['github_gist'] = url

            elif platform == 'local_file':
                path = self.seed_to_local_file(title, content)
                results['local_file'] = path

            # Rate limiting - be nice to APIs
            time.sleep(2)

        return results

    def deploy_credential_set(self, credential_set: Dict,
                              platforms: List[str] = ['local_file']) -> Dict[str, any]:
        """
        Deploy a complete set of credentials as a single .env file

        Args:
            credential_set: Complete credential set from BaitGenerator
            platforms: Platforms to deploy to

        Returns:
            Dictionary with deployment results
        """
        identifier = credential_set.get('identifier', 'UNKNOWN')
        tracking_id = credential_set.get('tracking_id', 'N/A')

        logger.info(f"Deploying credential set (ID: {identifier}, Tracking: {tracking_id})")

        # Extract all credentials
        creds = credential_set.get('credentials', {})
        creds_list = list(creds.values())

        # Create .env file content
        title = "Environment Configuration"
        content = self._create_env_file_content(creds_list)

        results = {}

        for platform in platforms:
            if platform == 'pastebin':
                url = self.seed_to_pastebin(title, content, expiration="1M")
                results['pastebin'] = url

            elif platform == 'github_gist':
                url = self.seed_to_github_gist("production.env", content, public=False)
                results['github_gist'] = url

            elif platform == 'local_file':
                path = self.seed_to_local_file("production_env", content)
                results['local_file'] = path

            time.sleep(2)

        return results

    def get_deployment_log(self) -> List[Dict]:
        """
        Get log of all deployments

        Returns:
            List of deployment records
        """
        return self.deployment_log

    def save_deployment_log(self, filepath: str = "deployment_log.json"):
        """
        Save deployment log to file

        Args:
            filepath: Path to save log file
        """
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(self.deployment_log, f, indent=2)

            logger.info(f"Deployment log saved to {filepath}")

        except Exception as e:
            logger.error(f"Failed to save deployment log: {e}")


# Test functions
def test_context_generation():
    """Test realistic context generation"""
    print("\n=== Testing Context Generation ===")
    seeder = BaitSeeder()

    for cred_type in ['aws_credentials', 'database_credentials', 'api_token', 'ssh_key']:
        title, desc = seeder._generate_realistic_context(cred_type)
        print(f"{cred_type}:")
        print(f"  Title: {title}")
        print(f"  Description: {desc}")


def test_code_snippet_generation():
    """Test code snippet generation"""
    print("\n=== Testing Code Snippet Generation ===")
    seeder = BaitSeeder()

    # Test AWS credentials snippet
    aws_creds = {
        'type': 'aws_credentials',
        'aws_access_key_id': 'AKIAIOSFODNN7EXAMPLE',
        'aws_secret_access_key': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        'region': 'us-west-2'
    }

    snippet = seeder._create_code_snippet(aws_creds, 'aws_credentials')
    print("AWS Credentials Snippet:")
    print(snippet[:200] + "...")


def test_env_file_generation():
    """Test .env file generation"""
    print("\n=== Testing .env File Generation ===")
    seeder = BaitSeeder()

    creds_list = [
        {
            'type': 'aws_credentials',
            'aws_access_key_id': 'AKIAIOSFODNN7EXAMPLE',
            'aws_secret_access_key': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            'region': 'us-east-1'
        },
        {
            'type': 'database_credentials',
            'connection_string': 'postgresql://user:pass@localhost:5432/db',
            'host': 'db.example.com',
            'port': 5432,
            'database': 'production',
            'username': 'admin',
            'password': 'SecurePass123'
        }
    ]

    env_content = seeder._create_env_file_content(creds_list)
    print("Generated .env file:")
    print(env_content)


def test_local_file_seeding():
    """Test seeding to local file"""
    print("\n=== Testing Local File Seeding ===")
    seeder = BaitSeeder()

    test_cred = {
        'type': 'aws_credentials',
        'tracking_id': 'test123456789abc',
        'aws_access_key_id': 'AKIAIOSFODNN7EXAMPLE',
        'aws_secret_access_key': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        'region': 'us-east-1'
    }

    results = seeder.deploy_credential_bait(test_cred, platforms=['local_file'])
    print(f"Deployment results: {results}")

    # Check deployment log
    log = seeder.get_deployment_log()
    print(f"Deployment log entries: {len(log)}")


def test_deployment_log():
    """Test deployment logging"""
    print("\n=== Testing Deployment Log ===")
    seeder = BaitSeeder()

    # Simulate some deployments
    seeder.deployment_log.extend([
        {
            "platform": "pastebin",
            "url": "https://pastebin.com/test123",
            "title": "AWS Config",
            "timestamp": datetime.now().isoformat()
        },
        {
            "platform": "local_file",
            "path": "./test.txt",
            "title": "Database Config",
            "timestamp": datetime.now().isoformat()
        }
    ])

    # Save log
    seeder.save_deployment_log("test_deployment_log.json")
    print("✓ Deployment log saved")


def test_database_integration():
    """Test database integration functionality"""
    print("\n=== Testing Database Integration ===")

    # Import BaitGenerator here to avoid circular imports
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))
    from bait_generator import BaitGenerator

    # Generate AWS bait with database save
    print("\n[1/5] Generating AWS credentials with save_to_db=True...")
    generator = BaitGenerator()
    aws_bait = generator.generate_aws_credentials(save_to_db=True)
    identifier = aws_bait.get('identifier')
    db_id = aws_bait.get('db_id')

    if db_id:
        print(f"✓ Generated and saved bait: {identifier}")
        print(f"  Database ID: {db_id}")
    else:
        print("✗ Failed to save to database")
        return

    # Seed the bait using BaitSeeder
    print("\n[2/5] Seeding bait to Pastebin (mock)...")
    seeder = BaitSeeder(use_database=True)  # No API key, will use mock URL
    results = seeder.deploy_credential_bait(aws_bait, platforms=['pastebin'])

    if results.get('pastebin'):
        print(f"✓ Seeded to: {results['pastebin']}")
    else:
        print("✗ Failed to seed")
        return

    # Get seeded baits from database
    print("\n[3/5] Retrieving seeded baits from database...")
    seeded_baits = seeder.get_seeded_baits()
    print(f"✓ Found {len(seeded_baits)} seeded bait(s) in database")

    # Verify our bait appears in the list
    our_bait = None
    for bait in seeded_baits:
        if bait['identifier'] == identifier:
            our_bait = bait
            break

    if our_bait:
        print(f"\n✓ Verified bait in seeded list:")
        print(f"  ID: {our_bait['id']}")
        print(f"  Identifier: {our_bait['identifier']}")
        print(f"  Type: {our_bait['bait_type']}")
        print(f"  Seeded At: {our_bait['seeded_at']}")
        print(f"  Seeded Location: {our_bait['seeded_location']}")
        print(f"  Status: {our_bait['status']}")
        print(f"  Access Count: {our_bait['access_count']}")
    else:
        print(f"✗ Bait not found in seeded list")

    # Test mark as expired
    print("\n[4/5] Testing mark_bait_as_expired()...")
    success = seeder.mark_bait_as_expired(identifier)
    if success:
        print(f"✓ Successfully marked bait as expired")

        # Verify status change
        updated_bait = generator.get_bait_by_identifier(identifier)
        if updated_bait and updated_bait['status'] == 'expired':
            print(f"✓ Verified status changed to: {updated_bait['status']}")
        else:
            print("⚠️  Status update not verified")
    else:
        print("✗ Failed to mark bait as expired")

    # Cleanup
    print("\n[5/5] Cleaning up test data...")
    try:
        db = SessionLocal()
        db.query(BaitToken).filter_by(identifier=identifier).delete()
        db.commit()
        db.close()
        print(f"✓ Cleaned up test bait: {identifier}")
    except Exception as e:
        print(f"⚠️  Cleanup warning: {e}")

    print("\n✅ Database integration tests completed!")


if __name__ == "__main__":
    print("=" * 60)
    print("NERVE GHOST - BAIT Seeder Testing")
    print("=" * 60)

    try:
        test_context_generation()
        test_code_snippet_generation()
        test_env_file_generation()
        test_local_file_seeding()
        test_deployment_log()

        # Test database integration
        test_database_integration()

        print("\n" + "=" * 60)
        print("All tests completed successfully!")
        print("=" * 60)

        # Show deployment log
        print("\n📋 Deployment Summary:")
        seeder = BaitSeeder()
        if os.path.exists("test_deployment_log.json"):
            with open("test_deployment_log.json", 'r') as f:
                log = json.load(f)
                print(f"Total deployments: {len(log)}")
                for entry in log:
                    print(f"  - {entry['platform']}: {entry['title']}")

    except Exception as e:
        print(f"\n[ERROR] Test failed: {e}")
        import traceback
        traceback.print_exc()
