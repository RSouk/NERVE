"""
NERVE Telegram Breach Channel Scraper v2.0

Scrapes configured Telegram channels for breach data (emails, passwords, domains, IPs)
- Downloads small files (< 10 MB) for parsing
- Logs large file metadata only
- Automatic storage management (500 MB cap)
- Stores in local database for unified search
- Runs weekly (configurable)
"""

import os
import re
from datetime import datetime, timedelta
from telethon import TelegramClient
from telethon.tl.types import Channel, MessageMediaDocument
from dotenv import load_dotenv
import sqlite3
import asyncio

load_dotenv()

# =======================
# CONFIGURATION
# =======================

# Telegram Auth (from .env)
PHONE = os.getenv('TELEGRAM_PHONE')
SESSION_NAME = os.getenv('TELEGRAM_SESSION_NAME', 'nerve_scraper')

# Channels to scrape (EASY TO ADD MORE HERE!)
CHANNELS = [
    # Breach disclosure channels
    '@leakbase',
    '@dataleak',
    '@combolists',
    '@breachforums_archive',
    
    # Infostealer channels (ADD MORE AS YOU FIND THEM)
    # '@stealer_logs',
    # '@raccoon_stealer',
    # '@redline_market',
    
    # Add any channel here in format: '@channel_username'
]

# Scraping limits
MESSAGES_PER_CHANNEL = 50  # Last 50 messages (covers 1-2 weeks)

# File download settings
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB - only download files smaller than this
MAX_TOTAL_STORAGE = 500 * 1024 * 1024  # 500 MB - total storage cap
DOWNLOAD_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'data', 'telegram_files')

# Downloadable file types
ALLOWED_EXTENSIONS = ['.txt', '.csv', '.log', '.json']

# Skip these keywords (compilations, old stuff)
SKIP_KEYWORDS = ['collection', 'combo', 'compilation', 'mega', 'pack', '2010', '2011', '2012', '2013', '2014', '2015', '2016', '2017', '2018']

# Database path
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'data', 'ghost.db')

# =======================
# DATA EXTRACTION PATTERNS
# =======================

# Email pattern
EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

# Domain pattern
DOMAIN_PATTERN = r'\b([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}\b'

# IP pattern
IP_PATTERN = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

# Password combo pattern (email:password or email;password or email|password)
COMBO_PATTERN = r'([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,})[:;|](.+?)(?:\n|$)'


# =======================
# DATABASE SETUP
# =======================

def init_telegram_table():
    """Create telegram_findings table if it doesn't exist"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS telegram_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            query_term TEXT NOT NULL,
            query_type TEXT,
            channel_name TEXT,
            message_id INTEGER,
            message_text TEXT,
            posted_date TEXT,
            data_type TEXT,
            password TEXT,
            file_name TEXT,
            file_size INTEGER,
            discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(query_term, channel_name, message_id)
        )
    ''')
    
    # Create indexes for fast searching
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_query_term ON telegram_findings(query_term)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_query_type ON telegram_findings(query_type)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_channel ON telegram_findings(channel_name)')
    
    conn.commit()
    conn.close()
    print("✓ Telegram findings table ready")


# =======================
# STORAGE MANAGEMENT
# =======================

def get_total_storage_used():
    """Calculate total storage used by downloaded files"""
    if not os.path.exists(DOWNLOAD_DIR):
        return 0
    
    total = 0
    for root, dirs, files in os.walk(DOWNLOAD_DIR):
        for file in files:
            filepath = os.path.join(root, file)
            total += os.path.getsize(filepath)
    
    return total


def cleanup_old_files(days=180):
    """Delete files older than X days to manage storage"""
    if not os.path.exists(DOWNLOAD_DIR):
        return 0
    
    deleted = 0
    cutoff_date = datetime.now() - timedelta(days=days)
    
    for root, dirs, files in os.walk(DOWNLOAD_DIR):
        for file in files:
            filepath = os.path.join(root, file)
            file_time = datetime.fromtimestamp(os.path.getmtime(filepath))
            
            if file_time < cutoff_date:
                try:
                    os.remove(filepath)
                    deleted += 1
                except Exception as e:
                    print(f"⚠️  Could not delete {file}: {e}")
    
    return deleted


def should_download_file(file_name, file_size):
    """Determine if file should be downloaded based on rules"""
    
    # Check file size
    if file_size > MAX_FILE_SIZE:
        return False, f"Too large ({file_size / 1024 / 1024:.1f} MB)"
    
    # Check total storage
    current_storage = get_total_storage_used()
    if current_storage + file_size > MAX_TOTAL_STORAGE:
        return False, f"Storage limit reached ({current_storage / 1024 / 1024:.0f} MB used)"
    
    # Check file extension
    file_ext = os.path.splitext(file_name)[1].lower()
    if file_ext not in ALLOWED_EXTENSIONS:
        return False, f"File type not supported ({file_ext})"
    
    # Check for skip keywords
    file_name_lower = file_name.lower()
    for keyword in SKIP_KEYWORDS:
        if keyword in file_name_lower:
            return False, f"Compilation/old data ('{keyword}' in name)"
    
    return True, "OK"


# =======================
# FILE PARSING
# =======================

def parse_credential_file(file_path):
    """
    Parse a downloaded credential file
    Returns list of findings
    """
    findings = []
    
    try:
        # Try to read file (handle different encodings)
        encodings = ['utf-8', 'latin-1', 'cp1252']
        content = None
        
        for encoding in encodings:
            try:
                with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                    content = f.read(1024 * 1024)  # Read first 1 MB only (prevent huge files)
                break
            except:
                continue
        
        if not content:
            print(f"   ⚠️  Could not read file: {file_path}")
            return findings
        
        # Extract email:password combos
        combos = re.findall(COMBO_PATTERN, content, re.MULTILINE)
        
        for email, password in combos[:10000]:  # Limit to 10k per file
            findings.append({
                'email': email.lower().strip(),
                'password': password.strip()[:100]  # Limit password length
            })
        
        # Also extract standalone emails (if no combos found)
        if len(combos) == 0:
            emails = re.findall(EMAIL_PATTERN, content)
            for email in set(emails[:5000]):  # Limit to 5k
                findings.append({
                    'email': email.lower().strip(),
                    'password': None
                })
        
        print(f"   ✓ Parsed {len(findings)} credentials from file")
        
    except Exception as e:
        print(f"   ⚠️  Error parsing file: {e}")
    
    return findings


# =======================
# DATA EXTRACTION
# =======================

def extract_data_from_message(message_text, channel_name, message_id, posted_date):
    """
    Extract searchable data from a Telegram message text
    Returns list of findings to store in database
    """
    findings = []
    
    if not message_text:
        return findings
    
    # Extract emails
    emails = re.findall(EMAIL_PATTERN, message_text)
    for email in set(emails):
        findings.append({
            'query_term': email.lower(),
            'query_type': 'email',
            'channel_name': channel_name,
            'message_id': message_id,
            'message_text': message_text[:500],
            'posted_date': posted_date,
            'data_type': 'email_mention',
            'password': None,
            'file_name': None,
            'file_size': None
        })
    
    # Extract email:password combos
    combos = re.findall(COMBO_PATTERN, message_text, re.MULTILINE)
    for email, password in combos:
        findings.append({
            'query_term': email.lower(),
            'query_type': 'email',
            'channel_name': channel_name,
            'message_id': message_id,
            'message_text': message_text[:500],
            'posted_date': posted_date,
            'data_type': 'credential',
            'password': password.strip()[:100],
            'file_name': None,
            'file_size': None
        })
    
    # Extract domains
    domains = re.findall(DOMAIN_PATTERN, message_text.lower())
    for domain in set(domains):
        if len(domain[0]) > 4 and domain[0].count('.') >= 1:
            findings.append({
                'query_term': domain[0],
                'query_type': 'domain',
                'channel_name': channel_name,
                'message_id': message_id,
                'message_text': message_text[:500],
                'posted_date': posted_date,
                'data_type': 'domain_mention',
                'password': None,
                'file_name': None,
                'file_size': None
            })
    
    # Extract IPs
    ips = re.findall(IP_PATTERN, message_text)
    for ip in set(ips):
        findings.append({
            'query_term': ip,
            'query_type': 'ip',
            'channel_name': channel_name,
            'message_id': message_id,
            'message_text': message_text[:500],
            'posted_date': posted_date,
            'data_type': 'ip_mention',
            'password': None,
            'file_name': None,
            'file_size': None
        })
    
    return findings


def extract_data_from_file(credentials, channel_name, message_id, posted_date, file_name, file_size):
    """
    Convert parsed credentials from file into findings
    """
    findings = []
    
    for cred in credentials:
        findings.append({
            'query_term': cred['email'],
            'query_type': 'email',
            'channel_name': channel_name,
            'message_id': message_id,
            'message_text': f"Found in file: {file_name}",
            'posted_date': posted_date,
            'data_type': 'credential' if cred['password'] else 'email_mention',
            'password': cred['password'],
            'file_name': file_name,
            'file_size': file_size
        })
    
    return findings


# =======================
# DATABASE STORAGE
# =======================

def store_findings(findings):
    """Store extracted findings in database"""
    if not findings:
        return 0
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    stored_count = 0
    
    for finding in findings:
        try:
            cursor.execute('''
                INSERT OR IGNORE INTO telegram_findings 
                (query_term, query_type, channel_name, message_id, message_text, 
                 posted_date, data_type, password, file_name, file_size)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                finding['query_term'],
                finding['query_type'],
                finding['channel_name'],
                finding['message_id'],
                finding['message_text'],
                finding['posted_date'],
                finding['data_type'],
                finding['password'],
                finding.get('file_name'),
                finding.get('file_size')
            ))
            
            if cursor.rowcount > 0:
                stored_count += 1
                
        except sqlite3.Error as e:
            print(f"⚠️  Error storing finding: {e}")
    
    conn.commit()
    conn.close()
    
    return stored_count


# =======================
# SCRAPER
# =======================

async def scrape_channel(client, channel_username):
    """
    Scrape a single Telegram channel
    Returns tuple: (channel_name, total_findings, files_downloaded)
    """
    print(f"\n📡 Scraping {channel_username}...")
    
    try:
        # Get channel entity
        entity = await client.get_entity(channel_username)
        
        if not isinstance(entity, Channel):
            print(f"⚠️  {channel_username} is not a channel, skipping")
            return (channel_username, 0, 0)
        
        # Get messages
        messages = await client.get_messages(entity, limit=MESSAGES_PER_CHANNEL)
        
        print(f"   Retrieved {len(messages)} messages")
        
        all_findings = []
        files_downloaded = 0
        
        for msg in messages:
            posted_date = msg.date.isoformat() if msg.date else None
            
            # Process message text
            if msg.message:
                text_findings = extract_data_from_message(
                    msg.message,
                    channel_username,
                    msg.id,
                    posted_date
                )
                all_findings.extend(text_findings)
            
            # Process file attachments
            if msg.media and isinstance(msg.media, MessageMediaDocument):
                document = msg.media.document
                
                # Get file info
                file_name = None
                for attr in document.attributes:
                    if hasattr(attr, 'file_name'):
                        file_name = attr.file_name
                        break
                
                if not file_name:
                    file_name = f"file_{msg.id}"
                
                file_size = document.size
                
                # Decide whether to download
                should_download, reason = should_download_file(file_name, file_size)
                
                if should_download:
                    print(f"   📥 Downloading: {file_name} ({file_size / 1024:.1f} KB)")
                    
                    try:
                        # Create download directory
                        os.makedirs(DOWNLOAD_DIR, exist_ok=True)
                        
                        # Download file
                        file_path = os.path.join(DOWNLOAD_DIR, f"{channel_username}_{msg.id}_{file_name}")
                        await client.download_media(msg.media, file_path)
                        
                        # Parse file
                        credentials = parse_credential_file(file_path)
                        
                        # Extract findings from file
                        file_findings = extract_data_from_file(
                            credentials,
                            channel_username,
                            msg.id,
                            posted_date,
                            file_name,
                            file_size
                        )
                        
                        all_findings.extend(file_findings)
                        files_downloaded += 1
                        
                        print(f"   ✓ Downloaded and parsed: {len(credentials)} credentials")
                        
                    except Exception as e:
                        print(f"   ⚠️  Error downloading file: {e}")
                
                else:
                    print(f"   ⏭️  Skipped: {file_name} ({reason})")
                    
                    # Still log the file metadata
                    all_findings.append({
                        'query_term': file_name.lower(),
                        'query_type': 'file',
                        'channel_name': channel_username,
                        'message_id': msg.id,
                        'message_text': f"Large file: {file_name} ({file_size / 1024 / 1024:.1f} MB) - {msg.message or 'No description'}",
                        'posted_date': posted_date,
                        'data_type': 'file_metadata',
                        'password': None,
                        'file_name': file_name,
                        'file_size': file_size
                    })
        
        # Store in database
        stored = store_findings(all_findings)
        
        print(f"   ✓ Extracted {len(all_findings)} items, stored {stored} new findings")
        print(f"   ✓ Downloaded {files_downloaded} files")
        
        return (channel_username, stored, files_downloaded)
        
    except Exception as e:
        print(f"   ❌ Error scraping {channel_username}: {e}")
        return (channel_username, 0, 0)


async def scrape_all_channels():
    """Main scraper function - scrapes all configured channels"""
    
    print("=" * 60)
    print("NERVE Telegram Scraper v2.0")
    print("=" * 60)
    
    # Validate phone number
    if not PHONE:
        print("❌ Error: TELEGRAM_PHONE not set in .env file")
        print("Add: TELEGRAM_PHONE=+1234567890")
        return
    
    print(f"\n📱 Authenticating with phone: {PHONE}")
    print(f"📂 Session file: {SESSION_NAME}.session")
    print(f"🎯 Channels to scrape: {len(CHANNELS)}")
    print(f"💾 Database: {DB_PATH}")
    print(f"📁 Download folder: {DOWNLOAD_DIR}")
    print(f"📊 Max file size: {MAX_FILE_SIZE / 1024 / 1024:.0f} MB")
    print(f"💽 Storage limit: {MAX_TOTAL_STORAGE / 1024 / 1024:.0f} MB")
    
    # Check current storage
    current_storage = get_total_storage_used()
    print(f"📈 Current storage: {current_storage / 1024 / 1024:.1f} MB / {MAX_TOTAL_STORAGE / 1024 / 1024:.0f} MB")
    
    # Cleanup old files
    deleted = cleanup_old_files(180)
    if deleted > 0:
        print(f"🗑️  Cleaned up {deleted} old files")
    
    # Initialize database
    init_telegram_table()
    
    # Create Telegram client
    client = TelegramClient(SESSION_NAME, api_id=None, api_hash=None)
    
    try:
        # Start client (will prompt for phone code on first run)
        await client.start(phone=PHONE)
        
        print("\n✓ Connected to Telegram")
        print(f"✓ Logged in as: {(await client.get_me()).first_name}")
        
        # Scrape each channel
        print(f"\n{'='*60}")
        print("Starting scrape...")
        print(f"{'='*60}")
        
        results = []
        total_new_findings = 0
        total_files_downloaded = 0
        
        for channel in CHANNELS:
            channel_name, findings, files = await scrape_channel(client, channel)
            results.append((channel_name, findings, files))
            total_new_findings += findings
            total_files_downloaded += files
        
        # Summary
        print(f"\n{'='*60}")
        print("SCRAPE COMPLETE")
        print(f"{'='*60}")
        print(f"\n📊 Results:")
        for channel_name, findings, files in results:
            print(f"   {channel_name}: {findings} new findings, {files} files downloaded")
        
        print(f"\n🎯 Total new findings: {total_new_findings}")
        print(f"📥 Total files downloaded: {total_files_downloaded}")
        
        # Final storage check
        final_storage = get_total_storage_used()
        print(f"💽 Final storage: {final_storage / 1024 / 1024:.1f} MB / {MAX_TOTAL_STORAGE / 1024 / 1024:.0f} MB")
        print(f"✓ Data stored in: {DB_PATH}")
        
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
    
    finally:
        await client.disconnect()
        print("\n✓ Disconnected from Telegram")


# =======================
# SEARCH FUNCTION (for unified_search.py to use)
# =======================

def search_telegram_data(query, query_type):
    """
    Search stored Telegram data
    Called by unified_search.py
    
    Args:
        query: Search term (email, domain, IP, etc.)
        query_type: Type of query ('email', 'domain', 'ip')
    
    Returns:
        (results_list, count)
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT channel_name, message_text, posted_date, data_type, password, 
               file_name, file_size, discovered_at
        FROM telegram_findings
        WHERE query_term = ? AND query_type = ?
        ORDER BY posted_date DESC
    ''', (query.lower(), query_type))
    
    rows = cursor.fetchall()
    conn.close()
    
    results = []
    for row in rows:
        results.append({
            'channel': row[0],
            'message': row[1],
            'posted_date': row[2],
            'data_type': row[3],
            'password': row[4],
            'file_name': row[5],
            'file_size': row[6],
            'discovered_at': row[7]
        })
    
    return results, len(results)


# =======================
# MAIN ENTRY POINT
# =======================

if __name__ == "__main__":
    
    print("\n" + "="*60)
    print("NERVE Telegram Scraper v2.0 - Manual Run")
    print("="*60)
    print("\nThis will scrape all configured channels.")
    print("First run: You'll receive a Telegram code - enter it when prompted.")
    print("Later runs: Will use saved session (automatic).")
    print("\nSettings:")
    print(f"  - Max file size: {MAX_FILE_SIZE / 1024 / 1024:.0f} MB")
    print(f"  - Storage limit: {MAX_TOTAL_STORAGE / 1024 / 1024:.0f} MB")
    print(f"  - Messages per channel: {MESSAGES_PER_CHANNEL}")
    print("\n" + "="*60 + "\n")
    
    # Run the scraper
    asyncio.run(scrape_all_channels())
    
    print("\n✓ Scraper finished!")
    print("\nTo run weekly automatically, use Windows Task Scheduler:")
    print("  Task: python backend/modules/ghost/telegram_scraper.py")
    print("  Trigger: Weekly on Sunday at 2 AM")