import requests
import json

def scrape_misp_threat_actors():
    """Scrape threat actor data from MISP Galaxy"""
    
    print("🔍 Fetching MISP Galaxy threat actor data...")
    
    # MISP Galaxy threat actors JSON
    url = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"
    
    try:
        response = requests.get(url, timeout=30)
        data = response.json()
        
        threat_actors = []
        
        if 'values' in data:
            actors = data['values']
            print(f"Found {len(actors)} threat actors\n")
            
            for actor in actors:
                # Extract structured data
                actor_data = {
                    'name': actor.get('value', 'Unknown'),
                    'description': actor.get('description', ''),
                    'aliases': [],
                    'origin': None,
                    'industries': [],
                    'regions': [],
                    'techniques': [],
                    'sophistication': None,
                    'observed_sectors': [],
                    'observed_countries': [],
                    'meta': {}
                }
                
                # Extract metadata
                if 'meta' in actor:
                    meta = actor['meta']
                    
                    # Aliases
                    if 'synonyms' in meta:
                        actor_data['aliases'] = meta['synonyms']
                    
                    # Origin/Country
                    if 'country' in meta:
                        actor_data['origin'] = meta['country'][0] if isinstance(meta['country'], list) else meta['country']
                    
                    # Observed sectors (industries)
                    if 'observed-sectors' in meta:
                        actor_data['observed_sectors'] = meta['observed-sectors']
                    
                    # Observed countries (regions)
                    if 'observed-countries' in meta:
                        actor_data['observed_countries'] = meta['observed-countries']
                    
                    # Sophistication level
                    if 'sophistication' in meta:
                        actor_data['sophistication'] = meta['sophistication']
                    
                    # CFR suspected state sponsor
                    if 'cfr-suspected-state-sponsor' in meta:
                        actor_data['state_sponsor'] = meta['cfr-suspected-state-sponsor']
                    
                    # CFR suspected victims
                    if 'cfr-suspected-victims' in meta:
                        actor_data['victims'] = meta['cfr-suspected-victims']
                    
                    # CFR target category
                    if 'cfr-target-category' in meta:
                        actor_data['target_categories'] = meta['cfr-target-category']
                    
                    # CFR type of incident
                    if 'cfr-type-of-incident' in meta:
                        actor_data['incident_types'] = meta['cfr-type-of-incident']
                    
                    # Store full meta for reference
                    actor_data['meta'] = meta
                
                threat_actors.append(actor_data)
                
                # Print sample
                if len(threat_actors) <= 5:
                    print(f"✓ {actor_data['name']}")
                    if actor_data['observed_sectors']:
                        print(f"  Industries: {', '.join(actor_data['observed_sectors'][:3])}")
                    if actor_data['observed_countries']:
                        print(f"  Regions: {', '.join(actor_data['observed_countries'][:3])}")
                    if actor_data['origin']:
                        print(f"  Origin: {actor_data['origin']}")
                    print()
            
            return threat_actors
        else:
            print("❌ No threat actor data found in MISP Galaxy")
            return []
            
    except Exception as e:
        print(f"❌ Error fetching MISP data: {e}")
        return []

def save_threat_actors(actors, filename='misp_threat_actors.json'):
    """Save threat actors to JSON file"""
    
    filepath = f'data/{filename}'
    
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(actors, f, indent=2, ensure_ascii=False)
        
        print(f"\n💾 Saved {len(actors)} threat actors to {filepath}")
        
        # Print statistics
        with_sectors = sum(1 for a in actors if a.get('target_categories'))
        with_countries = sum(1 for a in actors if a.get('victims'))
        with_origin = sum(1 for a in actors if a['origin'])
        
        print(f"\n📊 Statistics:")
        print(f"  - {with_sectors} actors with industry data")
        print(f"  - {with_countries} actors with region data")
        print(f"  - {with_origin} actors with origin data")
        
        return True
        
    except Exception as e:
        print(f"❌ Error saving threat actors: {e}")
        return False

if __name__ == "__main__":
    print("=" * 60)
    print("MISP Galaxy Threat Actor Scraper")
    print("=" * 60 + "\n")
    
    actors = scrape_misp_threat_actors()
    
    if actors:
        save_threat_actors(actors)
        print(f"\n✅ Complete! {len(actors)} threat actors ready for matching.")
    else:
        print("\n❌ Failed to scrape threat actors.")