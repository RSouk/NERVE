"""
Master Scheduler for All Scrapers
Runs GitHub and PasteBin scrapers and logs results
"""

import sys
import os
from datetime import datetime
import traceback

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Setup logging
LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'scraper_logs.txt')

# Ensure data directory exists
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

def log(message, to_file=True, to_console=True):
    """Log message to console and/or file"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    formatted_message = f"[{timestamp}] {message}"

    if to_console:
        print(formatted_message)

    if to_file:
        try:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(formatted_message + '\n')
        except Exception as e:
            print(f"[ERROR] Failed to write to log file: {e}")

def run_github_scraper():
    """Run the GitHub scraper"""
    log("=" * 60)
    log("Starting GitHub Gist Scraper")
    log("=" * 60)

    try:
        from modules.ghost.github_scraper import GitHubScraper

        scraper = GitHubScraper()
        scraper.run(limit=100)

        # Log stats
        log(f"GitHub Scraper Results:")
        log(f"  - Gists Checked: {scraper.stats['gists_checked']}")
        log(f"  - Credentials Found: {scraper.stats['credentials_found']}")
        log(f"  - New Stored: {scraper.stats['new_stored']}")
        log(f"  - Duplicates Skipped: {scraper.stats['duplicates_skipped']}")
        log(f"  - Errors: {scraper.stats['errors']}")

        log("GitHub Scraper completed successfully")
        return True

    except Exception as e:
        log(f"[ERROR] GitHub Scraper failed: {str(e)}")
        log(f"[ERROR] Traceback: {traceback.format_exc()}")
        return False

def run_pastebin_scraper():
    """Run the PasteBin scraper"""
    log("=" * 60)
    log("Starting PasteBin Archive Scraper")
    log("=" * 60)

    try:
        from modules.ghost.pastebin_scraper import PasteBinScraper

        scraper = PasteBinScraper()
        scraper.run(max_pastes=50)

        # Log stats
        log(f"PasteBin Scraper Results:")
        log(f"  - Pastes Checked: {scraper.stats['pastes_checked']}")
        log(f"  - Pastes Skipped: {scraper.stats['pastes_skipped']}")
        log(f"  - Credentials Found: {scraper.stats['credentials_found']}")
        log(f"  - New Stored: {scraper.stats['new_stored']}")
        log(f"  - Duplicates Skipped: {scraper.stats['duplicates_skipped']}")
        log(f"  - Errors: {scraper.stats['errors']}")

        log("PasteBin Scraper completed successfully")
        return True

    except Exception as e:
        log(f"[ERROR] PasteBin Scraper failed: {str(e)}")
        log(f"[ERROR] Traceback: {traceback.format_exc()}")
        return False

def main():
    """Run all scrapers"""
    start_time = datetime.now()

    log("\n" + "=" * 80)
    log("NERVE GHOST - Automated Scraper Run")
    log("=" * 80)
    log(f"Start Time: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    log(f"Log File: {LOG_FILE}")
    log("")

    results = {
        'github': False,
        'pastebin': False
    }

    # Run GitHub scraper
    try:
        results['github'] = run_github_scraper()
    except Exception as e:
        log(f"[CRITICAL] GitHub scraper crashed: {e}")

    log("")  # Blank line between scrapers

    # Run PasteBin scraper (even if GitHub failed)
    try:
        results['pastebin'] = run_pastebin_scraper()
    except Exception as e:
        log(f"[CRITICAL] PasteBin scraper crashed: {e}")

    # Final summary
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    log("")
    log("=" * 80)
    log("Scraper Run Summary")
    log("=" * 80)
    log(f"GitHub Scraper: {'SUCCESS' if results['github'] else 'FAILED'}")
    log(f"PasteBin Scraper: {'SUCCESS' if results['pastebin'] else 'FAILED'}")
    log(f"Total Duration: {duration:.2f} seconds")
    log(f"End Time: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    log("=" * 80)
    log("")

if __name__ == "__main__":
    try:
        # Load environment variables
        from dotenv import load_dotenv
        load_dotenv()

        # Run all scrapers
        main()

    except Exception as e:
        log(f"[CRITICAL] Master scheduler crashed: {e}")
        log(f"[CRITICAL] Traceback: {traceback.format_exc()}")
        sys.exit(1)
