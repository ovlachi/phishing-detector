import sys
import os
from pathlib import Path
import asyncio

# Add project root to path
project_root = str(Path(__file__).parent.parent)
sys.path.insert(0, project_root)

from src.features.url_features import extract_url_features
from src.features.content_features import fetch_and_extract_content_features

async def debug_feature_extraction():
    """Debug feature extraction for the failing URLs"""
    
    failing_urls = [
        "https://acessogerenciador.online/9658965.php",
        "https://suite.en-trezor.cc/"
    ]
    
    working_url = "https://serofertascol.com/"
    
    print("🔧 Debugging Feature Extraction")
    print("=" * 50)
    
    # Test working URL first
    print(f"\n✅ Testing WORKING URL: {working_url}")
    try:
        url_features = extract_url_features([working_url])
        content_features = await fetch_and_extract_content_features([working_url])
        
        print(f"   URL features: {len(url_features[0]) if url_features else 0}")
        print(f"   Content features: {len(content_features[0]) if content_features else 0}")
        
        if url_features and url_features[0]:
            print(f"   URL feature sample: {list(url_features[0].keys())[:5]}")
        if content_features and content_features[0]:
            print(f"   Content feature sample: {list(content_features[0].keys())[:5]}")
            
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")
    
    # Test failing URLs
    for url in failing_urls:
        print(f"\n❌ Testing FAILING URL: {url}")
        try:
            # Test URL features
            url_features = extract_url_features([url])
            print(f"   URL features: {len(url_features[0]) if url_features else 0}")
            
            if url_features and url_features[0]:
                print(f"   URL feature sample: {list(url_features[0].keys())[:5]}")
            
            # Test content features
            content_features = await fetch_and_extract_content_features([url])
            print(f"   Content features: {len(content_features[0]) if content_features else 0}")
            
            if content_features and content_features[0]:
                print(f"   Content feature sample: {list(content_features[0].keys())[:5]}")
                
                # Check for specific issues
                features = content_features[0]
                if 'status_code' in features:
                    print(f"   HTTP Status: {features['status_code']}")
                if 'error' in features:
                    print(f"   Content Error: {features['error']}")
                    
        except Exception as e:
            print(f"   ❌ Error: {str(e)}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(debug_feature_extraction())