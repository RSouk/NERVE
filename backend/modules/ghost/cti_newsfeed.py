"""
CTI News Feed Module
Aggregates cybersecurity news from multiple RSS feeds with caching
"""

import feedparser
import time
import json
import os
from datetime import datetime, timedelta
from typing import List, Dict, Any

# Cache file location
CACHE_FILE = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'cti_feed_cache.json')
CACHE_DURATION = 6 * 60 * 60  # 6 hours in seconds

# RSS Feed sources
FEEDS = {
    'Krebs on Security': 'https://krebsonsecurity.com/feed/',
    'Bleeping Computer': 'https://www.bleepingcomputer.com/feed/',
    'The Hacker News': 'https://feeds.feedburner.com/TheHackersNews',
    'CISA Advisories': 'https://www.cisa.gov/cybersecurity-advisories/all.xml'
}


def load_cache() -> Dict[str, Any]:
    """
    Load cached feed data from file

    Returns:
        Cached data or None if cache doesn't exist/is expired
    """
    try:
        if os.path.exists(CACHE_FILE):
            with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                cache = json.load(f)

            # Check if cache is still valid
            cache_time = cache.get('timestamp', 0)
            current_time = time.time()

            if current_time - cache_time < CACHE_DURATION:
                print(f"[CTI FEED] Using cached data (age: {int((current_time - cache_time) / 60)} minutes)")
                return cache
            else:
                print(f"[CTI FEED] Cache expired (age: {int((current_time - cache_time) / 3600)} hours)")
    except Exception as e:
        print(f"[CTI FEED] Error loading cache: {e}")

    return None


def save_cache(data: List[Dict[str, Any]]):
    """
    Save feed data to cache file

    Args:
        data: List of news articles to cache
    """
    try:
        # Ensure data directory exists
        os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)

        cache = {
            'timestamp': time.time(),
            'articles': data
        }

        with open(CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(cache, f, indent=2)

        print(f"[CTI FEED] Cached {len(data)} articles")
    except Exception as e:
        print(f"[CTI FEED] Error saving cache: {e}")


def parse_feed(feed_url: str, source_name: str) -> List[Dict[str, Any]]:
    """
    Parse a single RSS feed

    Args:
        feed_url: URL of the RSS feed
        source_name: Name of the news source

    Returns:
        List of article dictionaries
    """
    articles = []

    try:
        print(f"[CTI FEED] Fetching {source_name}...")
        feed = feedparser.parse(feed_url)

        # Cutoff date: 30 days ago
        cutoff_date = datetime.now() - timedelta(days=30)

        for entry in feed.entries:
            try:
                # Parse publication date
                pub_date = None
                if hasattr(entry, 'published_parsed') and entry.published_parsed:
                    pub_date = datetime(*entry.published_parsed[:6])
                elif hasattr(entry, 'updated_parsed') and entry.updated_parsed:
                    pub_date = datetime(*entry.updated_parsed[:6])

                # Skip if too old or no date
                if pub_date and pub_date < cutoff_date:
                    continue

                # Extract article data
                article = {
                    'title': entry.get('title', 'No Title'),
                    'source': source_name,
                    'date': pub_date.isoformat() if pub_date else datetime.now().isoformat(),
                    'link': entry.get('link', '#'),
                    'summary': entry.get('summary', '')[:300]  # First 300 chars
                }

                articles.append(article)

            except Exception as e:
                print(f"[CTI FEED] Error parsing entry from {source_name}: {e}")
                continue

        print(f"[CTI FEED] Fetched {len(articles)} articles from {source_name}")

    except Exception as e:
        print(f"[CTI FEED] Error fetching {source_name}: {e}")

    return articles


def get_news_feed(force_refresh: bool = False) -> List[Dict[str, Any]]:
    """
    Get aggregated news feed from all sources

    Args:
        force_refresh: Force refresh instead of using cache

    Returns:
        List of articles sorted by date (newest first)
    """
    print(f"[CTI FEED] Getting news feed (force_refresh={force_refresh})")

    # Try to load from cache first
    if not force_refresh:
        cache = load_cache()
        if cache:
            return cache.get('articles', [])

    # Fetch fresh data from all feeds
    all_articles = []

    for source_name, feed_url in FEEDS.items():
        articles = parse_feed(feed_url, source_name)
        all_articles.extend(articles)

    # Sort by date (newest first)
    all_articles.sort(key=lambda x: x['date'], reverse=True)

    # Save to cache
    save_cache(all_articles)

    print(f"[CTI FEED] Total articles: {len(all_articles)}")

    return all_articles


def get_feed_stats() -> Dict[str, Any]:
    """
    Get statistics about the news feed

    Returns:
        Dictionary with feed statistics
    """
    cache = load_cache()

    if cache:
        articles = cache.get('articles', [])
        cache_age_minutes = int((time.time() - cache.get('timestamp', 0)) / 60)

        # Count articles by source
        by_source = {}
        for article in articles:
            source = article['source']
            by_source[source] = by_source.get(source, 0) + 1

        return {
            'total_articles': len(articles),
            'cache_age_minutes': cache_age_minutes,
            'articles_by_source': by_source,
            'last_updated': datetime.fromtimestamp(cache.get('timestamp', 0)).isoformat()
        }

    return {
        'total_articles': 0,
        'cache_age_minutes': 0,
        'articles_by_source': {},
        'last_updated': None
    }
