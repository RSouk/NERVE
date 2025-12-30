import http.client
import json
import urllib.parse
import os

def search_leakinsight(query, search_type='email', limit=100):
    """
    Search LeakInsight API for breached credentials

    Args:
        query: Email, username, domain, or phone to search
        search_type: 'email', 'username', 'domain', or 'phone'
        limit: Max results to return (default 100)

    Returns:
        List of breach results with passwords and metadata
    """
    try:
        api_key = os.getenv('LEAKINSIGHT_API_KEY')
        if not api_key:
            print("[LEAKINSIGHT] API key not found in environment")
            return []

        encoded_query = urllib.parse.quote(query)

        conn = http.client.HTTPSConnection("leakinsight-api.p.rapidapi.com")

        headers = {
            'x-rapidapi-key': api_key,
            'x-rapidapi-host': "leakinsight-api.p.rapidapi.com"
        }

        endpoint = f"/general/?query={encoded_query}&type={search_type}&offset=0&limit={limit}"

        print(f"[LEAKINSIGHT] Searching for {search_type}: {query}")

        conn.request("GET", endpoint, headers=headers)
        res = conn.getresponse()
        data = res.read()

        response = json.loads(data.decode("utf-8"))

        if not response.get('success'):
            print(f"[LEAKINSIGHT] Search failed: {response.get('message')}")
            return []

        results = response.get('results', [])
        print(f"[LEAKINSIGHT] Found {len(results)} results")

        formatted_results = []
        for result in results:
            source_info = result.get('source', {})

            formatted_results.append({
                'email': result.get('email_address', ''),
                'username': result.get('user_name', ''),
                'password': result.get('password', ''),
                'breach_name': source_info.get('name', 'Unknown'),
                'breach_date': source_info.get('breach_date', 'Unknown'),
                'source': 'LeakInsight',
                'source_badge_color': '#ffd700',
                'verified': source_info.get('unverified', 1) == 0,
                'has_password': bool(result.get('password')),
                'is_compilation': source_info.get('compilation', 0) == 1,
                'passwordless': source_info.get('passwordless', 0) == 1
            })

        return formatted_results

    except Exception as e:
        print(f"[LEAKINSIGHT] Error: {e}")
        import traceback
        traceback.print_exc()
        return []
