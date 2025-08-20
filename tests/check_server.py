import requests

def check_server_status():
    """Check if the FastAPI server is running"""
    
    try:
        response = requests.get("http://127.0.0.1:8000/", timeout=5)
        print(f"✅ Server is running! Status: {response.status_code}")
        return True
    except Exception as e:
        print(f"❌ Server is not running: {str(e)}")
        print("\n💡 To start the server, run:")
        print("   cd /Users/georgeovlachi/LEARNING/phishing-detector")
        print("   python -m uvicorn src.api.main:app --reload --host 127.0.0.1 --port 8000")
        return False

def check_endpoints():
    """Check available API endpoints"""
    
    try:
        response = requests.get("http://127.0.0.1:8000/docs", timeout=5)
        if response.status_code == 200:
            print("✅ API docs available at: http://127.0.0.1:8000/docs")
        
        # Check specific endpoints
        endpoints_to_check = [
            "/classify-url",
            "/classify-batch", 
            "/health" if hasattr('main', 'health') else None
        ]
        
        for endpoint in endpoints_to_check:
            if endpoint:
                try:
                    response = requests.get(f"http://127.0.0.1:8000{endpoint}", timeout=3)
                    print(f"   {endpoint}: Status {response.status_code}")
                except:
                    print(f"   {endpoint}: Not accessible with GET")
                    
    except Exception as e:
        print(f"❌ Cannot check endpoints: {str(e)}")

if __name__ == "__main__":
    print("🔍 Checking Server Status")
    print("=" * 30)
    
    if check_server_status():
        check_endpoints()