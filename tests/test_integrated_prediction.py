import sys
import os
# Add the project root to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.api.predict import predict
from src.api.threat_intelligence import VirusTotalAPI

def test_integrated_prediction():
    """Test the integrated ML + VirusTotal prediction system"""
    
    test_urls = [
        "https://www.google.com",
        "https://github.com",
        "http://example.com"
    ]
    
    print("Testing Integrated Prediction System")
    print("=" * 50)
    
    for url in test_urls:
        print(f"\nTesting: {url}")
        try:
            result = predict(url)
            
            print(f"ML Prediction: {result.get('class_name')}")
            print(f"ML Confidence: {result.get('probabilities', {})}")
            print(f"Threat Level: {result.get('threat_level')}")
            print(f"Final Confidence: {result.get('final_confidence', 0):.2f}")
            
            # Check VirusTotal data
            vt_data = result.get('threat_intelligence', {}).get('url_analysis', {})
            if vt_data and vt_data.get('status') == 'success':
                print(f"VirusTotal: {vt_data.get('malicious', 0)} malicious, {vt_data.get('harmless', 0)} harmless")
            else:
                print("VirusTotal: No data or error")
                
            if result.get('error'):
                print(f"Error: {result['error']}")
                
        except Exception as e:
            print(f"Test failed: {e}")

if __name__ == "__main__":
    test_integrated_prediction()