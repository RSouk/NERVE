"""
PasteBin Archive Scraper Runner
Simple script to run the PasteBin scraper manually or via scheduler
"""

import sys
import os
from datetime import datetime

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.ghost.pastebin_scraper import PasteBinScraper

def main():
    """Run the PasteBin scraper"""
    print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Starting PasteBin Archive Scraper\n")

    # Create and run scraper
    scraper = PasteBinScraper()

    # Run with 50 pastes (default)
    # You can adjust this number based on your needs
    scraper.run(max_pastes=50)

    print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Scraper completed\n")

if __name__ == "__main__":
    main()
