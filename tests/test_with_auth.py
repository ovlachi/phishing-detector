import requests
import json

def login_and_get_token():
    """Login and get authentication token"""
    
    login_url = "http://127.0.0.1:8000/token"
    
    # Try with the test user credentials
    login_data = {
        "username": "testuser",
        "password": "testpass123"
    }
    
    print("🔑 Attempting to login...")
    
    try:
        response = requests.post(login_url, data=login_data, timeout=10)
        
        print(f"Login Status: {response.status_code}")
        
        if response.status_code == 200:
            token_data = response.json()
            access_token = token_data.get('access_token')
            print(f"✅ Login successful! Token received.")
            return access_token
        else:
            print(f"❌ Login failed: {response.text}")
            return None
            
    except Exception as e:
        print(f"❌ Login error: {str(e)}")
        return None

def test_authenticated_classification():
    """Test URL classification with authentication"""
    
    # Get authentication token
    token = login_and_get_token()
    if not token:
        print("❌ Cannot test without authentication token")
        return
    
    # Set up headers with authentication
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    print(f"\n🧪 Testing with Authentication")
    print("=" * 50)
    
    # Test single URL classification
    test_urls = [
        "https://google.com",
        "https://serofertascol.com/",
        "https://acessogerenciador.online/9658965.php",
        "https://suite.en-trezor.cc/"
    ]
    
    for i, url in enumerate(test_urls, 1):
        print(f"\n🌐 Test {i}: {url}")
        print("-" * 30)
        
        try:
            response = requests.post(
                "http://127.0.0.1:8000/classify-url",
                headers=headers,
                json={"url": url},
                timeout=30
            )
            
            print(f"   Status: {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                print(f"   ✅ Class: {result.get('class_name', 'Unknown')}")
                print(f"   🎯 Threat: {result.get('threat_level', 'unknown')}")
                print(f"   📊 Confidence: {result.get('final_confidence', 'N/A')}")
                print(f"   ❌ Error: {result.get('error', 'None')}")
                
                if result.get('probabilities'):
                    print(f"   🤖 ML Probs:")
                    for cls, prob in result['probabilities'].items():
                        print(f"      {cls}: {prob:.3f}")
            else:
                print(f"   ❌ Error: {response.text}")
                
        except Exception as e:
            print(f"   ❌ Failed: {str(e)}")

def test_batch_with_auth():
    """Test batch classification with authentication"""
    
    # Get authentication token
    token = login_and_get_token()
    if not token:
        return
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    print(f"\n🧪 Testing Batch Classification with Auth")
    print("=" * 50)
    
    test_data = {
        "urls": [
            "https://serofertascol.com/",
            "https://acessogerenciador.online/9658965.php",
            "https://suite.en-trezor.cc/"
        ]
    }
    
    try:
        response = requests.post(
            "http://127.0.0.1:8000/classify-batch",
            headers=headers,
            json=test_data,
            timeout=90
        )
        
        print(f"Status: {response.status_code}")
        
        if response.status_code == 200:
            results = response.json()
            print(f"📊 Processing Time: {results.get('processing_time')}s")
            
            for i, result in enumerate(results.get('results', []), 1):
                print(f"\n📊 Result {i}:")
                print(f"   URL: {result.get('url')}")
                print(f"   Class: {result.get('class_name')}")
                print(f"   Threat: {result.get('threat_level')}")
                print(f"   Confidence: {result.get('final_confidence', 0):.3f}")
                print(f"   Error: {result.get('error', 'None')}")
        else:
            print(f"❌ Error: {response.text}")
            
    except Exception as e:
        print(f"❌ Failed: {str(e)}")

if __name__ == "__main__":
    test_authenticated_classification()
    test_batch_with_auth()