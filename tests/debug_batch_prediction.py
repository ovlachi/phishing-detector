import sys
import os
from pathlib import Path

# Add project root to path
project_root = str(Path(__file__).parent.parent)
sys.path.insert(0, project_root)

from src.api.predict import predict_url_enhanced
import asyncio

async def debug_batch_urls():
    """Debug the specific URLs that are failing"""
    
    test_urls = [
        "https://acessogerenciador.online/9658965.php",
        "https://serofertascol.com/",
        "https://suite.en-trezor.cc/"
    ]
    
    print("🔍 Debugging Batch URL Predictions")
    print("=" * 50)
    
    for url in test_urls:
        print(f"\n🌐 Testing: {url}")
        print("-" * 30)
        
        try:
            result = await predict_url_enhanced(url)
            
            print(f"✅ Prediction successful:")
            print(f"   Class: {result.get('class_name', 'None')}")
            print(f"   Confidence: {result.get('final_confidence', 'None')}")
            print(f"   Threat Level: {result.get('threat_level', 'None')}")
            print(f"   ML Probabilities: {result.get('probabilities', 'None')}")
            print(f"   Error: {result.get('error', 'None')}")
            
            # Check feature extraction
            if 'url_features' in result:
                features = result['url_features']
                print(f"   Features extracted: {len(features) if features else 0}")
                if features:
                    print(f"   Sample features: {list(features.keys())[:5]}")
            
        except Exception as e:
            print(f"❌ Error occurred: {str(e)}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(debug_batch_urls())