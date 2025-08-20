import requests
import json
import time

def test_single_url_first():
    """Test single URL classification first"""
    
    api_url = "http://127.0.0.1:8000/classify-url"
    
    test_urls = [
        "https://google.com",
        "https://acessogerenciador.online/9658965.php",
        "https://suite.en-trezor.cc/"
    ]
    
    print("🔍 Testing Single URL Classification")
    print("=" * 50)
    
    for url in test_urls:
        print(f"\n🌐 Testing: {url}")
        print("-" * 30)
        
        try:
            response = requests.post(
                api_url, 
                json={"url": url}, 
                timeout=30
            )
            
            print(f"Status Code: {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                
                print(f"✅ Classification: {result.get('class_name', 'Unknown')}")
                print(f"   Threat Level: {result.get('threat_level', 'unknown')}")
                print(f"   Final Confidence: {result.get('final_confidence', 'N/A')}")
                print(f"   Error: {result.get('error', 'None')}")
                
                if result.get('probabilities'):
                    print(f"   ML Probabilities:")
                    for class_name, prob in result['probabilities'].items():
                        print(f"     {class_name}: {prob:.3f}")
                        
            else:
                print(f"❌ API Error: {response.text}")
                
        except Exception as e:
            print(f"❌ Request failed: {str(e)}")
        
        time.sleep(1)  # Small delay between requests

def test_batch_classification():
    """Test batch URL classification"""
    
    api_url = "http://127.0.0.1:8000/classify-batch"
    
    test_data = {
        "urls": [
            "https://acessogerenciador.online/9658965.php",
            "https://serofertascol.com/", 
            "https://suite.en-trezor.cc/"
        ]
    }
    
    print("\n\n🧪 Testing Batch Classification")
    print("=" * 50)
    
    try:
        response = requests.post(api_url, json=test_data, timeout=60)
        
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            results = response.json()
            
            print(f"Processing Time: {results.get('processing_time', 'Unknown')}s")
            print(f"Number of Results: {len(results.get('results', []))}")
            
            for i, result in enumerate(results.get('results', [])):
                print(f"\n📊 Result {i+1}:")
                print(f"   URL: {result.get('url', 'Unknown')}")
                print(f"   Class: {result.get('class_name', 'Unknown')}")
                print(f"   Confidence: {result.get('final_confidence', 0):.2f}")
                print(f"   Threat Level: {result.get('threat_level', 'unknown')}")
                print(f"   Error: {result.get('error', 'None')}")
                
                if result.get('probabilities'):
                    print(f"   ML Probabilities:")
                    for class_name, prob in result['probabilities'].items():
                        print(f"     {class_name}: {prob:.3f}")
                        
        else:
            print(f"❌ API Error: {response.text}")
            
    except Exception as e:
        print(f"❌ Request failed: {str(e)}")

if __name__ == "__main__":
    # First test single URLs to identify issues
    test_single_url_first()
    
    # Then test batch
    test_batch_classification()