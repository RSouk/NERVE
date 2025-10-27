"""
NERVE GHOST - BAIT Generator
Generates realistic but fake credentials for honeypot/canary token purposes.
Part of the GHOST module for detecting credential theft and usage.
"""

import random
import string
import hashlib
import secrets
import base64
import json
import sys
import os
from datetime import datetime
from typing import Dict, List, Optional

# Add parent directory to path for database imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from database import get_db, BaitToken, SessionLocal


class BaitGenerator:
    """Generates realistic fake credentials for detection purposes"""

    def __init__(self, identifier: Optional[str] = None):
        """
        Initialize the bait generator

        Args:
            identifier: Unique identifier for tracking this bait set
        """
        self.identifier = identifier or self._generate_identifier()
        self.tracking_id = self._generate_tracking_id()

    def _generate_identifier(self) -> str:
        """Generate a unique identifier for this bait set"""
        return f"BAIT-{datetime.now().strftime('%Y%m%d')}-{secrets.token_hex(4).upper()}"

    def _generate_tracking_id(self) -> str:
        """Generate a tracking ID embedded in credentials"""
        return secrets.token_hex(8)

    def _random_string(self, length: int, chars: str = string.ascii_letters + string.digits) -> str:
        """Generate random string of specified length"""
        return ''.join(secrets.choice(chars) for _ in range(length))

    def generate_aws_credentials(self, region: str = "us-east-1", save_to_db: bool = False) -> Dict[str, str]:
        """
        Generate fake AWS access key credentials

        AWS Access Key format: AKIA[20 random chars]
        AWS Secret Key format: 40 random chars (base64-like)

        Args:
            region: AWS region for the credentials
            save_to_db: If True, save to database

        Returns:
            Dict containing AWS credentials with tracking info
        """
        # AWS Access Key ID always starts with AKIA
        access_key_id = f"AKIA{self._random_string(20, string.ascii_uppercase + string.digits)}"

        # AWS Secret Access Key is 40 characters (base64-like)
        secret_chars = string.ascii_letters + string.digits + "+/"
        secret_access_key = self._random_string(40, secret_chars)

        # Embed tracking ID in the session token (optional field)
        session_token = f"{self.tracking_id}{self._random_string(32)}"

        result = {
            "type": "aws_credentials",
            "identifier": self.identifier,
            "tracking_id": self.tracking_id,
            "aws_access_key_id": access_key_id,
            "aws_secret_access_key": secret_access_key,
            "aws_session_token": session_token,
            "region": region,
            "account_id": self._random_string(12, string.digits),
            "generated_at": datetime.now().isoformat(),
            "description": f"AWS IAM credentials for {region} (HONEYPOT)"
        }

        # Save to database if requested
        if save_to_db:
            db_id = self.save_to_database(result)
            result['db_id'] = db_id

        return result

    def generate_api_token(self, service_name: str = "api-service", prefix: str = "sk", save_to_db: bool = False) -> Dict[str, str]:
        """
        Generate fake API token (similar to OpenAI, Stripe, etc.)

        Format: prefix_live_[random]_[tracking]

        Args:
            service_name: Name of the service this token is for
            prefix: Token prefix (e.g., 'sk', 'pk', 'api')
            save_to_db: If True, save to database

        Returns:
            Dict containing API token with tracking info
        """
        # Generate token with tracking embedded
        token_body = self._random_string(32, string.ascii_letters + string.digits)
        token = f"{prefix}_live_{token_body}_{self.tracking_id}"

        result = {
            "type": "api_token",
            "identifier": self.identifier,
            "tracking_id": self.tracking_id,
            "token": token,
            "service_name": service_name,
            "generated_at": datetime.now().isoformat(),
            "description": f"{service_name} API token (HONEYPOT)"
        }

        # Save to database if requested
        if save_to_db:
            db_id = self.save_to_database(result)
            result['db_id'] = db_id

        return result

    def generate_database_credentials(self, db_type: str = "postgresql", save_to_db: bool = False) -> Dict[str, str]:
        """
        Generate fake database connection credentials

        Args:
            db_type: Type of database (postgresql, mysql, mongodb)
            save_to_db: If True, save to database

        Returns:
            Dict containing database credentials with tracking info
        """
        ports = {
            "postgresql": 5432,
            "mysql": 3306,
            "mongodb": 27017,
            "redis": 6379
        }

        username = f"admin_{self._random_string(6, string.ascii_lowercase)}"
        # Password with tracking ID embedded
        password = f"{self._random_string(16, string.ascii_letters + string.digits)}{self.tracking_id}"
        host = f"db-prod-{self._random_string(8, string.ascii_lowercase)}.internal"
        port = ports.get(db_type.lower(), 5432)
        database = f"prod_{self._random_string(8, string.ascii_lowercase)}"

        # Generate connection string
        if db_type.lower() in ["postgresql", "mysql"]:
            connection_string = f"{db_type}://{username}:{password}@{host}:{port}/{database}"
        elif db_type.lower() == "mongodb":
            connection_string = f"mongodb://{username}:{password}@{host}:{port}/{database}?authSource=admin"
        else:
            connection_string = f"{db_type}://{username}:{password}@{host}:{port}/{database}"

        result = {
            "type": "database_credentials",
            "identifier": self.identifier,
            "tracking_id": self.tracking_id,
            "db_type": db_type,
            "host": host,
            "port": port,
            "username": username,
            "password": password,
            "database": database,
            "connection_string": connection_string,
            "generated_at": datetime.now().isoformat(),
            "description": f"{db_type} database credentials (HONEYPOT)"
        }

        # Save to database if requested
        if save_to_db:
            db_id = self.save_to_database(result)
            result['db_id'] = db_id

        return result

    def generate_ssh_key(self, key_name: str = "production", save_to_db: bool = False) -> Dict[str, str]:
        """
        Generate fake SSH private key (realistic looking but non-functional)

        Args:
            key_name: Name/label for the SSH key
            save_to_db: If True, save to database

        Returns:
            Dict containing SSH key information with tracking info
        """
        # Generate realistic-looking but fake RSA private key
        # Real RSA keys are much longer and mathematically valid
        # This is intentionally invalid but looks real

        key_comment = f"root@prod-server-{self._random_string(6, string.ascii_lowercase)}"

        # Fake private key (not a real RSA key, just looks like one)
        private_key_body = []
        for _ in range(25):  # Typical RSA key has ~25 lines
            line = base64.b64encode(
                f"{self.tracking_id}{self._random_string(40)}".encode()
            ).decode()[:64]
            private_key_body.append(line)

        private_key = "-----BEGIN RSA PRIVATE KEY-----\n"
        private_key += "\n".join(private_key_body)
        private_key += "\n-----END RSA PRIVATE KEY-----"

        # Fake public key
        public_key_data = base64.b64encode(
            f"{self.tracking_id}{self._random_string(200)}".encode()
        ).decode()[:372]
        public_key = f"ssh-rsa {public_key_data} {key_comment}"

        result = {
            "type": "ssh_key",
            "identifier": self.identifier,
            "tracking_id": self.tracking_id,
            "key_name": key_name,
            "private_key": private_key,
            "public_key": public_key,
            "key_comment": key_comment,
            "fingerprint": f"SHA256:{base64.b64encode(hashlib.sha256(public_key.encode()).digest()).decode()[:43]}",
            "generated_at": datetime.now().isoformat(),
            "description": f"SSH key for {key_name} server (HONEYPOT)"
        }

        # Save to database if requested
        if save_to_db:
            db_id = self.save_to_database(result)
            result['db_id'] = db_id

        return result

    def generate_jwt_token(self, service_name: str = "internal-api", save_to_db: bool = False) -> Dict[str, str]:
        """
        Generate fake JWT token

        Args:
            service_name: Name of service this JWT is for
            save_to_db: If True, save to database

        Returns:
            Dict containing JWT token with tracking info
        """
        # JWT has three parts: header.payload.signature (all base64 encoded)

        # Fake header
        header = base64.b64encode(
            '{"alg":"HS256","typ":"JWT"}'.encode()
        ).decode().rstrip('=')

        # Fake payload with tracking
        payload_data = {
            "sub": f"user_{self._random_string(8)}",
            "name": "Admin User",
            "iat": int(datetime.now().timestamp()),
            "exp": int(datetime.now().timestamp()) + 86400,
            "tracking": self.tracking_id
        }
        payload = base64.b64encode(
            str(payload_data).encode()
        ).decode().rstrip('=')

        # Fake signature
        signature = base64.b64encode(
            f"{self.tracking_id}{self._random_string(32)}".encode()
        ).decode().rstrip('=')

        jwt_token = f"{header}.{payload}.{signature}"

        result = {
            "type": "jwt_token",
            "identifier": self.identifier,
            "tracking_id": self.tracking_id,
            "token": jwt_token,
            "service_name": service_name,
            "generated_at": datetime.now().isoformat(),
            "description": f"JWT token for {service_name} (HONEYPOT)"
        }

        # Save to database if requested
        if save_to_db:
            db_id = self.save_to_database(result)
            result['db_id'] = db_id

        return result

    def generate_oauth_token(self, provider: str = "google", save_to_db: bool = False) -> Dict[str, str]:
        """
        Generate fake OAuth access token

        Args:
            provider: OAuth provider (google, github, microsoft, etc.)
            save_to_db: If True, save to database

        Returns:
            Dict containing OAuth token with tracking info
        """
        # OAuth tokens are typically long random strings
        access_token = f"{self._random_string(64, string.ascii_letters + string.digits)}{self.tracking_id}"
        refresh_token = f"{self._random_string(64, string.ascii_letters + string.digits)}{self.tracking_id}"

        result = {
            "type": "oauth_token",
            "identifier": self.identifier,
            "tracking_id": self.tracking_id,
            "provider": provider,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "read write admin",
            "generated_at": datetime.now().isoformat(),
            "description": f"{provider} OAuth token (HONEYPOT)"
        }

        # Save to database if requested
        if save_to_db:
            db_id = self.save_to_database(result)
            result['db_id'] = db_id

        return result

    def generate_credential_set(self, include_types: Optional[List[str]] = None) -> Dict[str, any]:
        """
        Generate a complete set of various credential types

        Args:
            include_types: List of credential types to include
                          (if None, includes all types)

        Returns:
            Dict containing multiple credential types
        """
        all_types = [
            "aws", "api_token", "database", "ssh_key",
            "jwt_token", "oauth_token"
        ]

        types_to_generate = include_types if include_types else all_types

        credential_set = {
            "identifier": self.identifier,
            "tracking_id": self.tracking_id,
            "generated_at": datetime.now().isoformat(),
            "credentials": {}
        }

        if "aws" in types_to_generate:
            credential_set["credentials"]["aws"] = self.generate_aws_credentials()

        if "api_token" in types_to_generate:
            credential_set["credentials"]["api_token"] = self.generate_api_token()

        if "database" in types_to_generate:
            credential_set["credentials"]["database"] = self.generate_database_credentials()

        if "ssh_key" in types_to_generate:
            credential_set["credentials"]["ssh_key"] = self.generate_ssh_key()

        if "jwt_token" in types_to_generate:
            credential_set["credentials"]["jwt_token"] = self.generate_jwt_token()

        if "oauth_token" in types_to_generate:
            credential_set["credentials"]["oauth_token"] = self.generate_oauth_token()

        return credential_set

    def generate_env_file(self, filename: Optional[str] = None) -> str:
        """
        Generate a fake .env file content with honeypot credentials

        Args:
            filename: Optional filename for the .env file

        Returns:
            String content of fake .env file
        """
        aws = self.generate_aws_credentials()
        api = self.generate_api_token(service_name="stripe")
        db = self.generate_database_credentials("postgresql")
        jwt_secret = self._random_string(32, string.ascii_letters + string.digits)

        env_content = f"""# Production Environment Configuration
# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
# DO NOT COMMIT TO VERSION CONTROL

# AWS Configuration
AWS_ACCESS_KEY_ID={aws['aws_access_key_id']}
AWS_SECRET_ACCESS_KEY={aws['aws_secret_access_key']}
AWS_REGION={aws['region']}
AWS_BUCKET=prod-storage-{self._random_string(8, string.ascii_lowercase)}

# Database Configuration
DATABASE_URL={db['connection_string']}
DB_HOST={db['host']}
DB_PORT={db['port']}
DB_NAME={db['database']}
DB_USER={db['username']}
DB_PASSWORD={db['password']}

# API Keys
STRIPE_API_KEY={api['token']}
STRIPE_WEBHOOK_SECRET=whsec_{self._random_string(32)}

# JWT Configuration
JWT_SECRET={jwt_secret}
JWT_ALGORITHM=HS256
JWT_EXPIRATION=86400

# Application Configuration
NODE_ENV=production
PORT=3000
LOG_LEVEL=info

# Tracking ID: {self.tracking_id}
"""
        return env_content

    def save_to_database(self, bait_data: Dict) -> Optional[int]:
        """
        Save generated bait to database

        Args:
            bait_data: Bait data dictionary returned by any generate method

        Returns:
            Database ID of the saved bait token, or None if save failed
        """
        db = None
        try:
            db = SessionLocal()

            # Determine bait type from the credential type
            type_mapping = {
                'aws_credentials': 'aws_key',
                'api_token': 'api_token',
                'database_credentials': 'database',
                'ssh_key': 'ssh_key',
                'jwt_token': 'jwt_token',
                'oauth_token': 'oauth_token'
            }

            bait_type = type_mapping.get(bait_data.get('type'), 'unknown')

            # Create BaitToken record
            bait_token = BaitToken(
                identifier=bait_data.get('identifier', self.identifier),
                bait_type=bait_type,
                token_value=json.dumps(bait_data),
                status='active',
                seeded_location=None  # Will be set when seeded
            )

            db.add(bait_token)
            db.commit()
            db.refresh(bait_token)

            return bait_token.id

        except Exception as e:
            print(f"[ERROR] Failed to save bait to database: {e}")
            if db:
                db.rollback()
            return None

        finally:
            if db:
                db.close()

    def get_active_baits(self) -> List[Dict]:
        """
        Get all active bait tokens from database

        Returns:
            List of dictionaries containing bait information
        """
        db = None
        try:
            db = SessionLocal()

            active_baits = db.query(BaitToken).filter_by(status='active').all()

            results = []
            for bait in active_baits:
                results.append({
                    'id': bait.id,
                    'identifier': bait.identifier,
                    'bait_type': bait.bait_type,
                    'seeded_at': bait.seeded_at.isoformat() if bait.seeded_at else None,
                    'access_count': bait.access_count,
                    'seeded_location': bait.seeded_location
                })

            return results

        except Exception as e:
            print(f"[ERROR] Failed to get active baits: {e}")
            return []

        finally:
            if db:
                db.close()

    def get_bait_by_identifier(self, identifier: str) -> Optional[Dict]:
        """
        Get bait token by identifier

        Args:
            identifier: Bait identifier to search for

        Returns:
            Bait data as dictionary, or None if not found
        """
        db = None
        try:
            db = SessionLocal()

            bait = db.query(BaitToken).filter_by(identifier=identifier).first()

            if not bait:
                return None

            # Parse token_value JSON
            token_data = json.loads(bait.token_value)

            return {
                'id': bait.id,
                'identifier': bait.identifier,
                'bait_type': bait.bait_type,
                'token_data': token_data,
                'seeded_at': bait.seeded_at.isoformat() if bait.seeded_at else None,
                'seeded_location': bait.seeded_location,
                'first_access': bait.first_access.isoformat() if bait.first_access else None,
                'access_count': bait.access_count,
                'last_access': bait.last_access.isoformat() if bait.last_access else None,
                'status': bait.status
            }

        except Exception as e:
            print(f"[ERROR] Failed to get bait by identifier: {e}")
            return None

        finally:
            if db:
                db.close()


# Test functions
def test_aws_credentials():
    """Test AWS credential generation"""
    print("\n=== Testing AWS Credentials Generation ===")
    generator = BaitGenerator()
    creds = generator.generate_aws_credentials()

    print(f"Identifier: {creds['identifier']}")
    print(f"Access Key ID: {creds['aws_access_key_id']}")
    print(f"Secret Access Key: {creds['aws_secret_access_key']}")
    print(f"Region: {creds['region']}")
    print(f"Tracking ID: {creds['tracking_id']}")
    print(f"Description: {creds['description']}")


def test_api_token():
    """Test API token generation"""
    print("\n=== Testing API Token Generation ===")
    generator = BaitGenerator()
    token = generator.generate_api_token(service_name="stripe", prefix="sk")

    print(f"Identifier: {token['identifier']}")
    print(f"Service: {token['service_name']}")
    print(f"Token: {token['token']}")
    print(f"Tracking ID: {token['tracking_id']}")


def test_database_credentials():
    """Test database credential generation"""
    print("\n=== Testing Database Credentials Generation ===")
    generator = BaitGenerator()

    for db_type in ["postgresql", "mysql", "mongodb"]:
        print(f"\n{db_type.upper()}:")
        creds = generator.generate_database_credentials(db_type)
        print(f"  Connection String: {creds['connection_string']}")
        print(f"  Username: {creds['username']}")
        print(f"  Password: {creds['password'][:20]}...")
        print(f"  Tracking ID: {creds['tracking_id']}")


def test_ssh_key():
    """Test SSH key generation"""
    print("\n=== Testing SSH Key Generation ===")
    generator = BaitGenerator()
    key = generator.generate_ssh_key("production-server")

    print(f"Identifier: {key['identifier']}")
    print(f"Key Name: {key['key_name']}")
    print(f"Public Key: {key['public_key'][:80]}...")
    print(f"Fingerprint: {key['fingerprint']}")
    print(f"\nPrivate Key Preview:")
    print(key['private_key'][:200] + "...")


def test_credential_set():
    """Test generating a complete credential set"""
    print("\n=== Testing Complete Credential Set Generation ===")
    generator = BaitGenerator(identifier="TEST-BAIT-001")
    cred_set = generator.generate_credential_set()

    print(f"Identifier: {cred_set['identifier']}")
    print(f"Tracking ID: {cred_set['tracking_id']}")
    print(f"Generated At: {cred_set['generated_at']}")
    print(f"\nCredential Types Included:")
    for cred_type in cred_set['credentials'].keys():
        print(f"  - {cred_type}")


def test_env_file():
    """Test .env file generation"""
    print("\n=== Testing .env File Generation ===")
    generator = BaitGenerator()
    env_content = generator.generate_env_file()

    print(env_content)


def test_database_integration():
    """Test database integration functionality"""
    print("\n=== Testing Database Integration ===")
    generator = BaitGenerator()

    saved_identifiers = []

    # Generate and save each type of bait
    print("\n[1/6] Generating and saving AWS credentials...")
    aws = generator.generate_aws_credentials(save_to_db=True)
    if aws.get('db_id'):
        print(f"✓ Saved to database with ID: {aws['db_id']}")
        saved_identifiers.append(aws['identifier'])
    else:
        print("✗ Failed to save to database")

    print("\n[2/6] Generating and saving API token...")
    api = generator.generate_api_token(service_name="stripe", save_to_db=True)
    if api.get('db_id'):
        print(f"✓ Saved to database with ID: {api['db_id']}")
        saved_identifiers.append(api['identifier'])
    else:
        print("✗ Failed to save to database")

    print("\n[3/6] Generating and saving database credentials...")
    db_creds = generator.generate_database_credentials(save_to_db=True)
    if db_creds.get('db_id'):
        print(f"✓ Saved to database with ID: {db_creds['db_id']}")
        saved_identifiers.append(db_creds['identifier'])
    else:
        print("✗ Failed to save to database")

    print("\n[4/6] Generating and saving SSH key...")
    ssh = generator.generate_ssh_key(save_to_db=True)
    if ssh.get('db_id'):
        print(f"✓ Saved to database with ID: {ssh['db_id']}")
        saved_identifiers.append(ssh['identifier'])
    else:
        print("✗ Failed to save to database")

    print("\n[5/6] Generating and saving JWT token...")
    jwt = generator.generate_jwt_token(save_to_db=True)
    if jwt.get('db_id'):
        print(f"✓ Saved to database with ID: {jwt['db_id']}")
        saved_identifiers.append(jwt['identifier'])
    else:
        print("✗ Failed to save to database")

    print("\n[6/6] Generating and saving OAuth token...")
    oauth = generator.generate_oauth_token(save_to_db=True)
    if oauth.get('db_id'):
        print(f"✓ Saved to database with ID: {oauth['db_id']}")
        saved_identifiers.append(oauth['identifier'])
    else:
        print("✗ Failed to save to database")

    # Test get_active_baits
    print("\n" + "-" * 60)
    print("Testing get_active_baits()...")
    active_baits = generator.get_active_baits()
    print(f"✓ Found {len(active_baits)} active bait(s) in database")

    if active_baits:
        print("\nActive Baits:")
        for bait in active_baits:
            print(f"  - ID: {bait['id']} | Type: {bait['bait_type']} | Identifier: {bait['identifier']}")

    # Test get_bait_by_identifier
    if saved_identifiers:
        print("\n" + "-" * 60)
        test_identifier = saved_identifiers[0]
        print(f"Testing get_bait_by_identifier('{test_identifier}')...")

        retrieved_bait = generator.get_bait_by_identifier(test_identifier)
        if retrieved_bait:
            print(f"✓ Successfully retrieved bait:")
            print(f"  - ID: {retrieved_bait['id']}")
            print(f"  - Type: {retrieved_bait['bait_type']}")
            print(f"  - Status: {retrieved_bait['status']}")
            print(f"  - Access Count: {retrieved_bait['access_count']}")
            print(f"  - Seeded At: {retrieved_bait['seeded_at']}")
        else:
            print("✗ Failed to retrieve bait")

    # Cleanup test data
    print("\n" + "-" * 60)
    print("Cleaning up test data from database...")
    try:
        db = SessionLocal()
        for identifier in saved_identifiers:
            db.query(BaitToken).filter_by(identifier=identifier).delete()
        db.commit()
        db.close()
        print(f"✓ Cleaned up {len(saved_identifiers)} test bait(s)")
    except Exception as e:
        print(f"⚠️  Cleanup warning: {e}")

    print("\n✅ Database integration tests completed!")


if __name__ == "__main__":
    print("=" * 60)
    print("NERVE GHOST - BAIT Generator Testing")
    print("=" * 60)

    try:
        test_aws_credentials()
        test_api_token()
        test_database_credentials()
        test_ssh_key()
        test_credential_set()
        test_env_file()

        # Test database integration
        test_database_integration()

        print("\n" + "=" * 60)
        print("All tests completed successfully!")
        print("=" * 60)

    except Exception as e:
        print(f"\n[ERROR] Test failed: {e}")
        import traceback
        traceback.print_exc()
