import requests
from bs4 import BeautifulSoup
import json
import time

def scrape_mitre_groups():
    """Scrape all threat groups from MITRE ATT&CK"""
    
    print("🔍 Scraping MITRE ATT&CK threat groups...")
    
    groups_url = "https://attack.mitre.org/groups/"
    
    try:
        response = requests.get(groups_url, timeout=30)
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Find the groups table
        table = soup.find('table', {'class': 'table'})
        
        if not table:
            print("❌ Could not find groups table")
            return []
        
        groups = []
        rows = table.find_all('tr')[1:]  # Skip header row
        
        print(f"Found {len(rows)} threat groups\n")
        
        for row in rows:
            cols = row.find_all('td')
            if len(cols) >= 2:
                # Extract group ID and name
                group_link = cols[0].find('a')
                if group_link:
                    group_id = group_link.text.strip()
                    group_name = cols[1].text.strip()
                    group_url = "https://attack.mitre.org" + group_link['href']
                    
                    print(f"📥 Scraping {group_id}: {group_name}...")
                    
                    # Scrape individual group page for details
                    group_data = scrape_group_details(group_url, group_id, group_name)
                    
                    if group_data:
                        groups.append(group_data)
                    
                    time.sleep(1)  # Be nice to MITRE's servers
        
        print(f"\n✅ Scraped {len(groups)} threat groups")
        return groups
        
    except Exception as e:
        print(f"❌ Error scraping groups: {e}")
        return []

def scrape_group_details(url, group_id, group_name):
    """Scrape detailed information about a specific group"""
    
    try:
        response = requests.get(url, timeout=30)
        soup = BeautifulSoup(response.content, 'html.parser')
        
        group_data = {
            'id': group_id,
            'name': group_name,
            'url': url,
            'aliases': [],
            'description': '',
            'techniques': [],
            'software': [],
            'associated_groups': []
        }
        
        # Extract description
        desc_div = soup.find('div', {'class': 'description-body'})
        if desc_div:
            group_data['description'] = desc_div.get_text(strip=True)
        
        # Extract aliases
        card_body = soup.find('div', {'class': 'card-body'})
        if card_body:
            aliases_section = card_body.find_all('p')
            for p in aliases_section:
                if 'Associated Groups:' in p.text or 'Aliases:' in p.text:
                    aliases_text = p.get_text()
                    # Extract comma-separated aliases
                    if ':' in aliases_text:
                        aliases = aliases_text.split(':')[1].strip().split(',')
                        group_data['aliases'] = [a.strip() for a in aliases]
        
        # Extract techniques used
        techniques_table = soup.find('table', {'class': 'techniques-used'})
        if techniques_table:
            tech_rows = techniques_table.find_all('tr')[1:]
            for row in tech_rows:
                cols = row.find_all('td')
                if len(cols) >= 2:
                    technique_link = cols[1].find('a')
                    if technique_link:
                        technique_id = cols[0].text.strip()
                        technique_name = technique_link.text.strip()
                        group_data['techniques'].append({
                            'id': technique_id,
                            'name': technique_name
                        })
        
        return group_data
        
    except Exception as e:
        print(f"  ⚠️  Error scraping {group_name}: {e}")
        return None

def save_groups_to_file(groups, filename='mitre_groups.json'):
    """Save scraped groups to JSON file"""
    
    filepath = f'data/{filename}'
    
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(groups, f, indent=2, ensure_ascii=False)
        
        print(f"\n💾 Saved {len(groups)} groups to {filepath}")
        return True
        
    except Exception as e:
        print(f"❌ Error saving groups: {e}")
        return False

if __name__ == "__main__":
    print("=" * 60)
    print("MITRE ATT&CK Threat Group Scraper")
    print("=" * 60 + "\n")
    
    groups = scrape_mitre_groups()
    
    if groups:
        save_groups_to_file(groups)
        print(f"\n✅ Scraping complete! {len(groups)} groups saved.")
    else:
        print("\n❌ Scraping failed.")