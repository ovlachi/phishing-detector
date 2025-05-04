import requests
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
import pandas as pd
import numpy as np
import re
from concurrent.futures import ThreadPoolExecutor
import time
import random
import warnings

# Suppress XML parsed as HTML warnings
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

class ContentFetcher:
    def __init__(self, timeout=5, max_retries=2, delay=0.5):
        """Initialize the content fetcher."""
        self.timeout = timeout
        self.max_retries = max_retries
        self.delay = delay
        
        # User agents for browser spoofing
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0'
        ]
    
    def fetch_content(self, url):
        """Fetch HTML content from a URL."""
        headers = {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml',
            'Accept-Language': 'en-US,en;q=0.9',
        }
        
        result = {
            'url': url,
            'html': None,
            'status_code': None,
            'redirect_count': 0,
            'final_url': url,
            'content_type': None,
            'error': None
        }
        
        # Implement retry logic
        for attempt in range(self.max_retries + 1):
            try:
                response = requests.get(
                    url, 
                    headers=headers, 
                    timeout=self.timeout,
                    allow_redirects=True
                )
                
                # Save status code and redirect info
                result['status_code'] = response.status_code
                result['redirect_count'] = len(response.history)
                result['final_url'] = response.url
                
                # Save content type if available
                if 'Content-Type' in response.headers:
                    result['content_type'] = response.headers['Content-Type']
                
                if response.status_code == 200:
                    result['html'] = response.text
                    break
                else:
                    result['error'] = f"HTTP Error: {response.status_code}"
            
            except requests.exceptions.Timeout:
                result['error'] = "Timeout Error"
            except requests.exceptions.ConnectionError:
                result['error'] = "Connection Error"
            except Exception as e:
                result['error'] = f"Error: {str(e)}"
            
            # Wait before retrying
            if attempt < self.max_retries:
                time.sleep(self.delay)
        
        return result

    def fetch_multiple(self, urls, max_workers=5):
        """Fetch multiple URLs in parallel."""
        results = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(self.fetch_content, url) for url in urls]
            
            for future in futures:
                try:
                    result = future.result()
                    results.append(result)
                    
                    # Add delay between requests
                    if self.delay > 0:
                        time.sleep(self.delay)
                        
                except Exception as e:
                    results.append({
                        'url': None,
                        'html': None,
                        'status_code': None,
                        'redirect_count': 0,
                        'final_url': None,
                        'content_type': None,
                        'error': f"Executor error: {str(e)}"
                    })
        
        return results

def extract_content_features(urls, max_workers=5, timeout=5, delay=0.5):
    """
    Extract content features from a list of URLs.
    
    Parameters:
    -----------
    urls : list or pandas.Series
        List or Series of URLs to analyze
    max_workers : int
        Maximum number of parallel workers
    timeout : int
        Request timeout in seconds
    delay : float
        Delay between requests in seconds
    
    Returns:
    --------
    pandas.DataFrame
        DataFrame containing extracted content features
    """
    if isinstance(urls, pd.Series):
        urls = urls.tolist()
    
    # Initialize fetcher
    fetcher = ContentFetcher(timeout=timeout, delay=delay)
    
    # Fetch content
    print(f"Fetching content for {len(urls)} URLs with {max_workers} workers...")
    content_results = fetcher.fetch_multiple(urls, max_workers=max_workers)
    
    # Initialize feature dataframe
    features_df = pd.DataFrame({
        'url': [result['url'] for result in content_results],
        'fetch_success': [1 if result['html'] else 0 for result in content_results],
        'status_code': [result['status_code'] for result in content_results],
        'redirect_count': [result['redirect_count'] for result in content_results],
        'final_url': [result['final_url'] for result in content_results],
        'content_type': [result['content_type'] for result in content_results]
    })
    
    # Initialize content features
    # Basic binary features
    binary_features = [
        'has_title', 'has_input', 'has_submit', 'has_link', 'has_button', 
        'has_img', 'has_password', 'has_hidden_element', 'has_email_input',
        'has_audio', 'has_video'
    ]
    
    # Basic quantitative features
    quantitative_features = [
        'length_of_title', 'number_of_inputs', 'number_of_script', 
        'number_of_buttons', 'number_of_img', 'number_of_table',
        'number_of_th', 'number_of_tr', 'number_of_href',
        'number_of_paragraph', 'number_of_options'
    ]
    
    # NEW: Malware-specific features
    malware_binary_features = [
        'has_exe_download', 'has_archive_download', 'has_download_button',
        'has_obfuscated_js', 'has_iframe_loader', 'has_random_subdomain',
        'has_numeric_domain', 'has_suspicious_path', 'has_executable_content_type',
        'has_drive_by_loader', 'has_redirect_chains', 'has_eval_js',
        'has_suspicious_domains', 'has_excessive_domains', 'has_base64_script',
        'has_hidden_iframe', 'is_shortened_url'
    ]
    
    malware_quantitative_features = [
        'js_obfuscation_score', 'number_of_iframes', 'number_of_suspicious_elements',
        'external_domain_count', 'suspicious_domain_count', 'script_to_content_ratio'
    ]
    
    # Initialize feature columns with zeros
    all_features = binary_features + quantitative_features + malware_binary_features + malware_quantitative_features
    for feature in all_features:
        features_df[feature] = 0
    
    # Shortened URL services for detection
    shortened_domains = [
        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'tiny.cc',
        'is.gd', 'cli.gs', 'pic.gd', 'DwarfURL.com', 'ow.ly',
        'yfrog.com', 'migre.me', 'ff.im', 'tiny.cc', 'url4.eu'
    ]
    
    # Suspicious file extensions for malware detection
    suspicious_extensions = r'\.(exe|dll|msi|bat|ps1|vbs|scr|hta|cmd|js|jar|sh|py|php|pl)'
    archive_extensions = r'\.(zip|rar|7z|tar|gz|bz2|cab|iso)'
    
    # Suspicious domains often used in malware distribution
    suspicious_domains = [
        'download', 'setup', 'update', 'free', 'crack', 'hack', 'keygen',
        'patch', 'serial', 'warez', 'full', 'pirate', 'nulled', 'torrent'
    ]
    
    # Process each fetched HTML content
    for i, result in enumerate(content_results):
        # Process URL for malware-specific URL patterns
        url = result['url']
        if url:
            # Check for shortened URL
            features_df.at[i, 'is_shortened_url'] = 1 if any(domain in url for domain in shortened_domains) else 0
            
            # Check for random subdomain (common in malware)
            features_df.at[i, 'has_random_subdomain'] = 1 if re.search(r'://[a-z0-9]{8,}\.', url, re.I) else 0
            
            # Check for numeric domain
            features_df.at[i, 'has_numeric_domain'] = 1 if re.search(r'://[0-9]+\.', url) else 0
            
            # Check for suspicious paths
            features_df.at[i, 'has_suspicious_path'] = 1 if re.search(r'/(setup|install|update|download|get|patch|exploit)\.(php|aspx|jsp)', url, re.I) else 0
            
            # Check for domains containing suspicious keywords
            features_df.at[i, 'has_suspicious_domains'] = 1 if any(keyword in url.lower() for keyword in suspicious_domains) else 0
        
        if result['html']:
            try:
                # Parse HTML
                soup = BeautifulSoup(result['html'], 'html.parser')
                html_content = result['html'].lower()
                
                # Extract standard binary features
                features_df.at[i, 'has_title'] = 1 if soup.find('title') else 0
                features_df.at[i, 'has_input'] = 1 if soup.find('input') else 0
                features_df.at[i, 'has_submit'] = 1 if soup.find('input', {'type': 'submit'}) else 0
                features_df.at[i, 'has_link'] = 1 if soup.find('a') else 0
                features_df.at[i, 'has_button'] = 1 if soup.find('button') else 0
                features_df.at[i, 'has_img'] = 1 if soup.find('img') else 0
                features_df.at[i, 'has_password'] = 1 if soup.find('input', {'type': 'password'}) else 0
                features_df.at[i, 'has_hidden_element'] = 1 if soup.find('input', {'type': 'hidden'}) or soup.find(style=re.compile(r'display:\s*none')) else 0
                features_df.at[i, 'has_email_input'] = 1 if soup.find('input', {'type': 'email'}) or soup.find('input', attrs={'name': re.compile(r'email', re.I)}) else 0
                features_df.at[i, 'has_audio'] = 1 if soup.find('audio') else 0
                features_df.at[i, 'has_video'] = 1 if soup.find('video') else 0
                
                # Extract standard quantitative features
                title = soup.find('title')
                features_df.at[i, 'length_of_title'] = len(title.text) if title else 0
                features_df.at[i, 'number_of_inputs'] = len(soup.find_all('input'))
                features_df.at[i, 'number_of_script'] = len(soup.find_all('script'))
                features_df.at[i, 'number_of_buttons'] = len(soup.find_all('button'))
                features_df.at[i, 'number_of_img'] = len(soup.find_all('img'))
                features_df.at[i, 'number_of_table'] = len(soup.find_all('table'))
                features_df.at[i, 'number_of_th'] = len(soup.find_all('th'))
                features_df.at[i, 'number_of_tr'] = len(soup.find_all('tr'))
                features_df.at[i, 'number_of_href'] = len(soup.find_all('a', href=True))
                features_df.at[i, 'number_of_paragraph'] = len(soup.find_all('p'))
                features_df.at[i, 'number_of_options'] = len(soup.find_all('option'))
                
                # MALWARE DETECTION: Check for executable download references
                features_df.at[i, 'has_exe_download'] = 1 if re.search(suspicious_extensions, html_content, re.I) else 0
                
                # MALWARE DETECTION: Check for archive file references
                features_df.at[i, 'has_archive_download'] = 1 if re.search(archive_extensions, html_content, re.I) else 0
                
                # MALWARE DETECTION: Check for download buttons/text
                download_patterns = ['download', 'install', 'update', 'upgrade', 'get it now', 'run now', 'save file']
                features_df.at[i, 'has_download_button'] = 1 if any(pattern in html_content for pattern in download_patterns) else 0
                
                # MALWARE DETECTION: Check for obfuscated JavaScript
                script_tags = soup.find_all('script')
                js_obfuscation_score = 0
                
                for script in script_tags:
                    if script.string:  # Only check scripts with content
                        script_content = script.string.lower()
                        # Check for common obfuscation patterns
                        if re.search(r'eval\(|document\.write\(|String\.fromCharCode|unescape\(|parseInt\(.+,\s*[0-9]+\)', script_content):
                            js_obfuscation_score += 3
                        # Check for hex/unicode encoding
                        if re.search(r'\\x[0-9a-f]{2}|\\u[0-9a-f]{4}', script_content):
                            js_obfuscation_score += 2
                        # Check for base64
                        if re.search(r'base64,|btoa\(|atob\(', script_content) or ';base64,' in script_content:
                            js_obfuscation_score += 2
                            features_df.at[i, 'has_base64_script'] = 1
                        # Check for eval
                        if re.search(r'eval\(', script_content):
                            features_df.at[i, 'has_eval_js'] = 1
                
                features_df.at[i, 'js_obfuscation_score'] = min(js_obfuscation_score, 10)  # Cap at 10
                features_df.at[i, 'has_obfuscated_js'] = 1 if js_obfuscation_score > 2 else 0
                
                # MALWARE DETECTION: Check for hidden iframes (common malware technique)
                iframes = soup.find_all('iframe')
                features_df.at[i, 'number_of_iframes'] = len(iframes)
                
                hidden_iframe = False
                for iframe in iframes:
                    # Check if iframe is hidden via style
                    if iframe.has_attr('style') and re.search(r'display:\s*none|height:\s*0|width:\s*0|opacity:\s*0', iframe['style']):
                        hidden_iframe = True
                    # Check if iframe has very small dimensions
                    elif (iframe.has_attr('height') and iframe.has_attr('width') and 
                          (iframe['height'] in ['0', '1', '1px', '0px'] or iframe['width'] in ['0', '1', '1px', '0px'])):
                        hidden_iframe = True
                    # Check for suspicious iframe sources
                    if iframe.has_attr('src') and not iframe['src'].startswith(('https:', 'http:', '/')):
                        features_df.at[i, 'has_iframe_loader'] = 1
                
                features_df.at[i, 'has_hidden_iframe'] = 1 if hidden_iframe else 0
                
                # MALWARE DETECTION: Check for drive-by download techniques
                if re.search(r'document\.write\(\s*unescape\(', html_content):
                    features_df.at[i, 'has_drive_by_loader'] = 1
                
                # MALWARE DETECTION: Check for redirect chains
                if re.search(r'window\.location|location\.href|location\.replace', html_content) or soup.find('meta', {'http-equiv': 'refresh'}):
                    features_df.at[i, 'has_redirect_chains'] = 1
                
                # MALWARE DETECTION: Check for executable content types
                executable_content_types = ['application/octet-stream', 'application/x-msdownload', 'application/exe', 
                                           'application/x-msdos-program', 'application/java-archive']
                features_df.at[i, 'has_executable_content_type'] = 1 if result['content_type'] and any(ct in result['content_type'] for ct in executable_content_types) else 0
                
                # MALWARE DETECTION: Count external domains
                external_domains = set()
                for link in soup.find_all(['a', 'script', 'iframe', 'img', 'link'], src=True) + soup.find_all(['a', 'link'], href=True):
                    attr = link.get('src') or link.get('href')
                    if attr and attr.startswith(('http://', 'https://')):
                        try:
                            domain = attr.split('/')[2]
                            external_domains.add(domain)
                        except:
                            pass
                
                features_df.at[i, 'external_domain_count'] = len(external_domains)
                features_df.at[i, 'has_excessive_domains'] = 1 if len(external_domains) > 5 else 0
                
                # Count potentially suspicious elements
                suspicious_elements = len(soup.find_all('object')) + len(soup.find_all('embed')) + len(soup.find_all('applet'))
                features_df.at[i, 'number_of_suspicious_elements'] = suspicious_elements
                
                # Calculate script-to-content ratio (high in malware sites)
                text_content_length = len(soup.get_text())
                script_content_length = sum(len(script.string or '') for script in soup.find_all('script'))
                if text_content_length > 0:
                    script_ratio = script_content_length / text_content_length
                    features_df.at[i, 'script_to_content_ratio'] = min(script_ratio, 10)  # Cap at 10
                
            except Exception as e:
                print(f"Error processing HTML for URL {result['url']}: {str(e)}")
    
    return features_df

if __name__ == "__main__":
    # Simple test
    urls = [
        "https://www.google.com",
        "https://www.example.com",
        "https://github.com"
    ]
    
    features = extract_content_features(urls, max_workers=2)
    print(features.head())