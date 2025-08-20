import requests
import json
import time

def test_server_and_endpoints():
    """Test server status and endpoints"""
    
    print("🔍 Checking Server and Endpoints")
    print("=" * 50)
    
    # Check server status
    try:
        response = requests.get("http://127.0.0.1:8000/", timeout=5)
        print(f"✅ Server is running! Status: {response.status_code}")
    except Exception as e:
        print(f"❌ Server is not running: {str(e)}")
        return False
    
    # Check API docs
    try:
        response = requests.get("http://127.0.0.1:8000/docs", timeout=5)
        if response.status_code == 200:
            print("✅ API docs available at: http://127.0.0.1:8000/docs")
    except Exception as e:
        print(f"⚠️ API docs not accessible: {str(e)}")
    
    return True

def test_single_urls_detailed():
    """Test single URL classification with detailed output"""
    
    print("\n🔍 Testing Single URL Classification (Detailed)")
    print("=" * 60)
    
    # Test URLs - working one first, then the problematic ones
    test_urls = [
        "https://google.com",  # Should work
        "https://serofertascol.com/",  # This one worked in batch
        "https://acessogerenciador.online/9658965.php",  # Unknown result
        "https://suite.en-trezor.cc/"  # Unknown result
    ]
    
    for i, url in enumerate(test_urls, 1):
        print(f"\n🌐 Test {i}: {url}")
        print("-" * 40)
        
        try:
            response = requests.post(
                "http://127.0.0.1:8000/classify-url",
                json={"url": url},
                timeout=30
            )
            
            print(f"   Status Code: {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                
                print(f"   ✅ Classification: {result.get('class_name', 'Unknown')}")
                print(f"   🎯 Threat Level: {result.get('threat_level', 'unknown')}")
                print(f"   📊 Final Confidence: {result.get('final_confidence', 'N/A')}")
                print(f"   ❌ Error: {result.get('error', 'None')}")
                
                # Show ML probabilities if available
                if result.get('probabilities'):
                    print(f"   🤖 ML Probabilities:")
                    for class_name, prob in result['probabilities'].items():
                        print(f"      {class_name}: {prob:.3f} ({prob*100:.1f}%)")
                else:
                    print(f"   ⚠️ No ML probabilities returned")
                
                # Show URL features if available
                if result.get('url_features'):
                    features = result['url_features']
                    print(f"   🔧 URL Features: {len(features)} features extracted")
                    # Show a few key features
                    key_features = ['domain_length', 'subdomain_count', 'path_length']
                    for feat in key_features:
                        if feat in features:
                            print(f"      {feat}: {features[feat]}")
                else:
                    print(f"   ⚠️ No URL features returned")
                    
            else:
                print(f"   ❌ API Error ({response.status_code}): {response.text}")
                
        except Exception as e:
            print(f"   ❌ Request failed: {str(e)}")
        
        time.sleep(2)  # Small delay between requests

def test_batch_with_comparison():
    """Test the same URLs in batch mode and compare results"""
    
    print("\n\n🧪 Testing Batch Classification")
    print("=" * 50)
    
    test_data = {
        "urls": [
            "https://serofertascol.com/",  # This one worked
            "https://acessogerenciador.online/9658965.php",  # Unknown
            "https://suite.en-trezor.cc/"  # Unknown
        ]
    }
    
    try:
        response = requests.post(
            "http://127.0.0.1:8000/classify-batch",
            json=test_data,
            timeout=90
        )
        
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            results = response.json()
            
            print(f"📊 Processing Time: {results.get('processing_time', 'Unknown')}s")
            print(f"📈 Number of Results: {len(results.get('results', []))}")
            
            for i, result in enumerate(results.get('results', []), 1):
                print(f"\n📊 Batch Result {i}:")
                print(f"   URL: {result.get('url', 'Unknown')}")
                print(f"   Class: {result.get('class_name', 'Unknown')}")
                print(f"   Threat Level: {result.get('threat_level', 'unknown')}")
                print(f"   Final Confidence: {result.get('final_confidence', 0):.3f}")
                print(f"   Error: {result.get('error', 'None')}")
                
                if result.get('probabilities'):
                    print(f"   ML Probabilities:")
                    for class_name, prob in result['probabilities'].items():
                        print(f"     {class_name}: {prob:.3f} ({prob*100:.1f}%)")
                        
        else:
            print(f"❌ Batch API Error ({response.status_code}): {response.text}")
            
    except Exception as e:
        print(f"❌ Batch request failed: {str(e)}")

def main():
    """Run all debugging tests"""
    
    # Step 1: Check if server is running
    if not test_server_and_endpoints():
        print("\n❌ Server is not running. Please start it first:")
        print("   python -m uvicorn src.api.main:app --reload --host 127.0.0.1 --port 8000")
        return
    
    # Step 2: Test individual URLs
    test_single_urls_detailed()
    
    # Step 3: Test batch processing
    test_batch_with_comparison()
    
    print("\n" + "=" * 60)
    print("🎯 DEBUGGING SUMMARY")
    print("=" * 60)
    print("1. Check which URLs return 'Unknown' vs proper classifications")
    print("2. Look for error messages in the responses")
    print("3. Compare ML probabilities - are they missing for 'Unknown' results?")
    print("4. Check if it's a content fetching issue or ML model issue")

if __name__ == "__main__":
    main()