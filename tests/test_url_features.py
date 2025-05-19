"""
Test script for URL structure features
Run this to verify the URL features are working correctly
"""

import sys
from pathlib import Path

# Add project root to Python path
project_root = str(Path(__file__).parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.features.enhanced_url_features import EnhancedURLFeatureExtractor, calculate_url_confidence

def test_url_features():
    """Test URL feature extraction with various URLs"""
    
    test_urls = [
        # Legitimate URLs
        "https://www.google.com/search?q=test",
        "https://www.amazon.com/dp/B08N5M7S6K",
        "https://github.com/username/repository",
        "https://en.wikipedia.org/wiki/Phishing",
        
        # Suspicious patterns
        "http://192.168.1.1/admin/login",
        "https://paypa1-secure-login.com/update",
        "https://secure-account-verification-microsoft.tk",
        "http://login.security-update.free-wifi.com/signin",
        "https://www.g00gle.com/account/login.php",
        "https://amaz0n.com-secure.info/signin",
        
        # Complex URLs
        "https://sub1.sub2.example.com/path/to/resource?param1=value1&param2=value2#section",
    ]
    
    extractor = EnhancedURLFeatureExtractor()
    
    print("URL Feature Extraction Test Results")
    print("="*50)
    
    for url in test_urls:
        print(f"\nURL: {url}")
        print("-" * len(url))
        
        features = extractor.extract_url_structure_features(url)
        confidence = calculate_url_confidence(features)
        
        # Print key features
        print(f"  Length: {features['url_length']}")
        print(f"  Has HTTPS: {'Yes' if features['has_https'] else 'No'}")
        print(f"  Subdomain count: {features['subdomain_count']}")
        print(f"  Has IP address: {'Yes' if features['has_ip_address'] else 'No'}")
        print(f"  Security keywords: {features['has_security_keywords']}")
        print(f"  Login keywords: {features['has_login_keywords']}")
        print(f"  Potential typos: {features['has_common_typos']}")
        print(f"  Special chars: {features['special_chars_count']}")
        print(f"  Domain age (days): {features['domain_age_days']}")
        
        # Display confidence score
        threat_level = "Low"
        if confidence > 0.3:
            threat_level = "Medium" 
        if confidence > 0.6:
            threat_level = "High"
            
        print(f"  Confidence Score: {confidence:.4f} ({threat_level} risk)")

def test_integration():
    """Test integration with dummy content features"""
    test_url = "https://secure-login-paypal-verification.suspicious.com"
    
    # Simulate existing content features
    content_features = {
        'fetch_success': 1,
        'content_length': 5000,
        'form_count': 3,
        'link_count': 20,
        'script_count': 5
    }
    
    # Import integration function
    from src.features.enhanced_url_features import integrate_url_features_with_existing
    
    # Test integration
    combined_features = integrate_url_features_with_existing(test_url, content_features)
    
    print("\nIntegration Test Results")
    print("="*50)
    print(f"Original features: {len(content_features)}")
    print(f"Combined features: {len(combined_features)}")
    print(f"URL features added: {len(combined_features) - len(content_features)}")
    
    # Print some key combined features
    print("\nKey combined features:")
    for key, value in combined_features.items():
        if key in ['url_length', 'has_security_keywords', 'has_common_typos', 'form_count', 'url_confidence_score']:
            print(f"  {key}: {value}")

if __name__ == "__main__":
    print("Testing URL Structure Features...\n")
    test_url_features()
    test_integration()
    print("\nTest completed successfully!")