import requests
import json

def try_different_credentials():
    """Try different credential combinations"""
    
    login_url = "http://127.0.0.1:8000/token"
    
    # Try different credential combinations
    credential_sets = [
        {"username": "testuser", "password": "testpass123"},
        {"username": "admin", "password": "admin123"},
        {"username": "test", "password": "test"},
        {"username": "user", "password": "password"},
        {"username": "testuser", "password": "password"},
    ]
    
    print("🔑 Trying Different Login Credentials")
    print("=" * 50)
    
    for i, creds in enumerate(credential_sets, 1):
        print(f"\n🧪 Attempt {i}: {creds['username']}/{creds['password']}")
        
        try:
            response = requests.post(
                login_url, 
                data=creds,  # Use form data, not JSON
                timeout=10
            )
            
            print(f"   Status: {response.status_code}")
            
            if response.status_code == 200:
                token_data = response.json()
                access_token = token_data.get('access_token')
                print(f"   ✅ SUCCESS! Token received: {access_token[:20]}...")
                return access_token
            else:
                print(f"   ❌ Failed: {response.text}")
                
        except Exception as e:
            print(f"   ❌ Error: {str(e)}")
    
    return None

def test_without_auth():
    """Test classification endpoints without authentication"""
    
    print(f"\n🧪 Testing Without Authentication")
    print("=" * 50)
    
    # Test single URL with correct endpoint
    test_url = "https://google.com"
    
    try:
        response = requests.post(
            "http://127.0.0.1:8000/classify",  # Correct endpoint
            json={"url": test_url},
            timeout=30
        )
        
        print(f"POST /classify - Status: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ SUCCESS without auth!")
            print(f"   Class: {result.get('class_name')}")
            print(f"   Threat: {result.get('threat_level')}")
            print(f"   Confidence: {result.get('final_confidence')}")
            return True
        else:
            print(f"❌ Failed: {response.text}")
            
    except Exception as e:
        print(f"❌ Error: {str(e)}")
    
    # Test batch classification
    try:
        response = requests.post(
            "http://127.0.0.1:8000/classify-batch",
            json={"urls": ["https://google.com"]},
            timeout=30
        )
        
        print(f"POST /classify-batch - Status: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Batch works without auth!")
            return True
        else:
            print(f"❌ Batch failed: {response.text}")
            
    except Exception as e:
        print(f"❌ Batch error: {str(e)}")
    
    return False

def test_problematic_urls():
    """Test the specific URLs that were showing as Unknown"""
    
    print(f"\n🔍 Testing Problematic URLs")
    print("=" * 60)
    
    problem_urls = [
        "https://acessogerenciador.online/9658965.php",
        "https://suite.en-trezor.cc/",
        "https://serofertascol.com/"  # This one worked before
    ]
    
    for i, url in enumerate(problem_urls, 1):
        print(f"\n🌐 Test {i}: {url}")
        print("-" * 40)
        
        try:
            response = requests.post(
                "http://127.0.0.1:8000/classify",
                json={"url": url},
                timeout=45  # Longer timeout for potentially slow sites
            )
            
            print(f"   Status: {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                
                print(f"   ✅ Class: {result.get('class_name', 'Unknown')}")
                print(f"   🎯 Threat: {result.get('threat_level', 'unknown')}")
                print(f"   📊 Confidence: {result.get('final_confidence', 'N/A')}")
                print(f"   ❌ Error: {result.get('error', 'None')}")
                
                # Check if we have ML probabilities
                if result.get('probabilities'):
                    print(f"   🤖 ML Probabilities:")
                    for cls, prob in result['probabilities'].items():
                        print(f"      {cls}: {prob:.3f} ({prob*100:.1f}%)")
                else:
                    print(f"   ⚠️ No ML probabilities - this might be why it's 'Unknown'")
                
                # Check URL features
                if result.get('url_features'):
                    print(f"   🔧 URL features extracted: {len(result['url_features'])}")
                else:
                    print(f"   ⚠️ No URL features extracted")
                    
            else:
                print(f"   ❌ API Error: {response.text}")
                
        except Exception as e:
            print(f"   ❌ Request failed: {str(e)}")

def test_batch_problematic():
    """Test the problematic URLs in batch mode"""
    
    print(f"\n🧪 Testing Batch Mode - Problematic URLs")
    print("=" * 50)
    
    test_data = {
        "urls": [
            "https://acessogerenciador.online/9658965.php",
            "https://suite.en-trezor.cc/",
            "https://serofertascol.com/"
        ]
    }
    
    try:
        response = requests.post(
            "http://127.0.0.1:8000/classify-batch",
            json=test_data,
            timeout=120  # Longer timeout for batch
        )
        
        print(f"Status: {response.status_code}")
        
        if response.status_code == 200:
            results = response.json()
            
            print(f"📊 Processing Time: {results.get('processing_time')}s")
            print(f"📈 Results Count: {len(results.get('results', []))}")
            
            for i, result in enumerate(results.get('results', []), 1):
                print(f"\n📊 Batch Result {i}:")
                print(f"   URL: {result.get('url')}")
                print(f"   Class: {result.get('class_name')}")
                print(f"   Threat: {result.get('threat_level')}")
                print(f"   Confidence: {result.get('final_confidence', 0):.3f}")
                print(f"   Error: {result.get('error', 'None')}")
                
                # This is the key - check if probabilities exist
                if result.get('probabilities'):
                    print(f"   ✅ Has ML probabilities")
                else:
                    print(f"   ❌ Missing ML probabilities - ROOT CAUSE!")
                    
        else:
            print(f"❌ Batch Error: {response.text}")
            
    except Exception as e:
        print(f"❌ Batch Failed: {str(e)}")

def main():
    """Run all tests to debug the Unknown results"""
    
    print("🎯 DEBUGGING UNKNOWN URL CLASSIFICATIONS")
    print("=" * 60)
    
    # Step 1: Try to login (optional)
    token = try_different_credentials()
    if token:
        print(f"✅ We have authentication if needed")
    
    # Step 2: Test without auth first
    works_without_auth = test_without_auth()
    
    if works_without_auth:
        print(f"\n✅ Endpoints work without auth - proceeding with tests")
        
        # Step 3: Test the specific problematic URLs
        test_problematic_urls()
        
        # Step 4: Test in batch mode
        test_batch_problematic()
    else:
        print(f"\n❌ Endpoints require authentication - need to fix credentials first")

if __name__ == "__main__":
    main()