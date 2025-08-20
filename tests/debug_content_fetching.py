import requests
import asyncio
import aiohttp
from urllib.parse import urlparse

async def test_manual_content_fetch():
    """Manually test content fetching for the failing URLs"""
    
    failing_urls = [
        "https://acessogerenciador.online/9658965.php",
        "https://suite.en-trezor.cc/"
    ]
    
    working_url = "https://serofertascol.com/"
    
    print("🔧 Manual Content Fetching Test")
    print("=" * 50)
    
    # Test with different approaches
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
    }
    
    # Test working URL first
    print(f"\n✅ Testing WORKING URL: {working_url}")
    await test_url_content(working_url, headers)
    
    # Test failing URLs
    for url in failing_urls:
        print(f"\n❌ Testing FAILING URL: {url}")
        await test_url_content(url, headers)

async def test_url_content(url, headers):
    """Test content fetching for a single URL"""
    
    # Test 1: Direct requests
    try:
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        print(f"   Requests: Status {response.status_code}, Content length: {len(response.content)}")
    except Exception as e:
        print(f"   Requests: ❌ Failed - {str(e)}")
    
    # Test 2: aiohttp (like your API uses)
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            async with session.get(url, headers=headers, ssl=False) as response:
                content = await response.read()
                print(f"   aiohttp: Status {response.status}, Content length: {len(content)}")
    except Exception as e:
        print(f"   aiohttp: ❌ Failed - {str(e)}")
    
    # Test 3: Basic domain check
    try:
        domain = urlparse(url).netloc
        simple_response = requests.get(f"https://{domain}", headers=headers, timeout=5)
        print(f"   Domain check: Status {simple_response.status_code}")
    except Exception as e:
        print(f"   Domain check: ❌ Failed - {str(e)}")

if __name__ == "__main__":
    asyncio.run(test_manual_content_fetch())