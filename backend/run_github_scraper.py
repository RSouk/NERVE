"""
GitHub Gist Scraper Runner
Simple script to run the GitHub gist scraper manually or via scheduler
"""

import sys
import os
from datetime import datetime
from dotenv import load_dotenv

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Load environment variables
load_dotenv()

from modules.ghost.github_scraper import GitHubScraper

def main():
    """Run the GitHub scraper"""
    print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Starting GitHub Gist Scraper\n")

    # Create and run scraper
    scraper = GitHubScraper()

    # Run with 100 gists (default)
    # You can adjust this number based on your needs
    scraper.run(limit=100)

    print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Scraper completed\n")

if __name__ == "__main__":
    main()
