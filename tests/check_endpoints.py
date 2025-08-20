import requests

def check_all_endpoints():
    """Check what endpoints are available and their authentication requirements"""
    
    base_url = "http://127.0.0.1:8000"
    
    print("🔍 Checking Available API Endpoints")
    print("=" * 50)
    
    # Check the API docs to see available endpoints
    try:
        response = requests.get(f"{base_url}/openapi.json", timeout=5)
        if response.status_code == 200:
            openapi_spec = response.json()
            paths = openapi_spec.get('paths', {})
            
            print("📋 Available Endpoints:")
            for path, methods in paths.items():
                for method, details in methods.items():
                    summary = details.get('summary', 'No description')
                    print(f"   {method.upper():6} {path:30} - {summary}")
        
    except Exception as e:
        print(f"❌ Could not fetch OpenAPI spec: {e}")
    
    # Test some common endpoints
    test_endpoints = [
        ("GET", "/"),
        ("GET", "/docs"),
        ("GET", "/login"),
        ("POST", "/login"),
        ("POST", "/api/classify-url"),  # Try with /api prefix
        ("POST", "/classify-url"),
        ("POST", "/api/classify-batch"),
        ("POST", "/classify-batch"),
    ]
    
    print(f"\n🧪 Testing Common Endpoints:")
    print("-" * 50)
    
    for method, endpoint in test_endpoints:
        try:
            if method == "GET":
                response = requests.get(f"{base_url}{endpoint}", timeout=3)
            else:
                response = requests.post(f"{base_url}{endpoint}", 
                                       json={"test": "data"}, timeout=3)
            
            print(f"   {method:4} {endpoint:25} - Status: {response.status_code}")
            
        except Exception as e:
            print(f"   {method:4} {endpoint:25} - Error: Connection failed")

if __name__ == "__main__":
    check_all_endpoints()