import os
import json
import requests
from dotenv import load_dotenv

load_dotenv()

def test_web_risk_api():
    """Test Google Web Risk API as alternative to Safe Browsing"""
    
    api_key = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')
    if not api_key:
        raise ValueError("API key not found")
    
    print(f"Testing Web Risk API with key: {api_key[:10]}...")
    
    # Enable Web Risk API first
    url = f"https://webrisk.googleapis.com/v1/uris:search"
    
    params = {
        'uri': 'http://www.google.com',
        'threatTypes': ['SOCIAL_ENGINEERING', 'MALWARE'],
        'key': api_key
    }
    
    try:
        response = requests.get(url, params=params, timeout=30)
        print(f"\nWeb Risk API - Status Code: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print("✅ Web Risk API is working!")
            print("Response:", json.dumps(result, indent=2))
            return True
        else:
            print("❌ Web Risk API failed")
            print("Response:", json.dumps(response.json(), indent=2))
            return False
            
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    test_web_risk_api()