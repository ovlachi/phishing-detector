import os
import json
import requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def test_safe_browsing_simple():
    """Test Google Safe Browsing API with threatLists endpoint first"""
    
    api_key = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')
    if not api_key:
        raise ValueError("Google Safe Browsing API key not found in environment variables")
    
    print(f"Using API key: {api_key[:10]}...")
    
    # Try the simpler threatLists endpoint first
    url = f"https://safebrowsing.googleapis.com/v4/threatLists?key={api_key}"
    
    try:
        response = requests.get(url)
        print(f"\nThreatLists Test - Status Code: {response.status_code}")
        print("Response:", json.dumps(response.json(), indent=2)[:500])
        
        if response.status_code == 200:
            print("\n✅ API Key is working! Now testing FindThreatMatches...")
            return test_threat_matches(api_key)
        else:
            print("\n❌ API Key issue detected")
            return False
            
    except Exception as e:
        print(f"Error: {e}")
        return False

def test_threat_matches(api_key):
    """Test the FindThreatMatches endpoint"""
    
    url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    
    payload = {
        "client": {
            "clientId": "PhishR",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": ["SOCIAL_ENGINEERING"],  # Only test one threat type
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": "http://www.google.com"}  # Test with just one safe URL
            ]
        }
    }
    
    try:
        response = requests.post(
            url,
            json=payload,
            headers={'Content-Type': 'application/json'},
            timeout=30
        )
        
        print(f"\nFindThreatMatches Test - Status Code: {response.status_code}")
        print("Response:", json.dumps(response.json(), indent=2))
        
        return response.status_code == 200
        
    except Exception as e:
        print(f"Error in FindThreatMatches: {e}")
        return False

if __name__ == "__main__":
    test_safe_browsing_simple()