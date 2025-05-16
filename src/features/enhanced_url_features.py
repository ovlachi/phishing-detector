"""
Enhanced URL feature extraction for PhishR
This module provides additional URL structure analysis for better phishing detection
"""

import re
import tldextract
from urllib.parse import urlparse, parse_qs
import ipaddress
from datetime import datetime
import whois
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EnhancedURLFeatureExtractor:
    """
    Extract structural features from URLs to improve phishing detection
    These features can be used even when content fetching fails
    """
    
    def __init__(self):
        # Use default initialization without cache_file parameter
        self.tld_extract = tldextract.TLDExtract()
    
    def extract_url_structure_features(self, url):
        """
        Extract structural features from URL
        
        Parameters:
        -----------
        url : str
            URL to analyze
            
        Returns:
        --------
        dict
            Dictionary of URL features
        """
        features = {}
        
        try:
            parsed = urlparse(url)
            extracted = self.tld_extract(url)
            
            # Basic URL structure
            features['url_length'] = len(url)
            features['has_https'] = 1 if url.startswith('https') else 0
            features['has_www'] = 1 if parsed.netloc.startswith('www.') else 0
            
            # Domain analysis
            features['subdomain_count'] = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
            features['domain_length'] = len(extracted.domain) if extracted.domain else 0
            features['tld_length'] = len(extracted.suffix) if extracted.suffix else 0
            
            # Path analysis
            features['path_length'] = len(parsed.path)
            features['query_length'] = len(parsed.query)
            features['fragment_length'] = len(parsed.fragment)
            
            # Character analysis
            features['digits_in_domain'] = len(re.findall(r'\d', extracted.domain)) if extracted.domain else 0
            features['special_chars_count'] = len(re.findall(r'[^a-zA-Z0-9.\-_]', parsed.netloc))
            features['hyphens_in_domain'] = parsed.netloc.count('-')
            features['dots_in_domain'] = parsed.netloc.count('.')
            
            # Suspicious patterns
            features['has_ip_address'] = self._is_ip_address(parsed.netloc)
            features['has_at_symbol'] = 1 if '@' in parsed.netloc else 0
            features['has_double_slash_redirect'] = 1 if '//' in parsed.path else 0
            features['query_param_count'] = len(parse_qs(parsed.query))
            
            # URL encoding
            features['url_encoded_chars'] = len(re.findall(r'%[0-9A-Fa-f]{2}', url))
            
            # Pattern matching for common phishing indicators
            features['has_security_keywords'] = self._check_security_keywords(url)
            features['has_login_keywords'] = self._check_login_keywords(url)
            features['has_common_typos'] = self._check_common_typos(extracted.domain) if extracted.domain else 0
            
            # Domain age (with fallback)
            try:
                features['domain_age_days'] = self._get_domain_age(parsed.netloc)
            except Exception as e:
                logger.warning(f"Error getting domain age for {parsed.netloc}: {e}")
                features['domain_age_days'] = -1  # Unknown age
                
        except Exception as e:
            logger.error(f"Error extracting URL features: {e}")
            # Default values for failed parsing
            for key in ['url_length', 'has_https', 'has_www', 'subdomain_count', 'domain_length', 
                       'tld_length', 'path_length', 'query_length', 'fragment_length', 
                       'digits_in_domain', 'special_chars_count', 'hyphens_in_domain', 
                       'dots_in_domain', 'has_ip_address', 'has_at_symbol', 'has_double_slash_redirect',
                       'query_param_count', 'url_encoded_chars', 'has_security_keywords', 
                       'has_login_keywords', 'has_common_typos', 'domain_age_days']:
                features[key] = 0
            
        return features
    
    def _is_ip_address(self, netloc):
        """Check if netloc is an IP address"""
        try:
            # Remove port if present
            if ":" in netloc:
                netloc = netloc.split(":")[0]
            ipaddress.ip_address(netloc)
            return 1
        except ValueError:
            return 0
    
    def _check_security_keywords(self, url):
        """Check for security-related keywords often used in phishing"""
        keywords = ['secure', 'login', 'signin', 'account', 'verify', 'update', 
                   'confirm', 'security', 'banking', 'password', 'credential']
        url_lower = url.lower()
        return sum(1 for keyword in keywords if keyword in url_lower)
    
    def _check_login_keywords(self, url):
        """Check for login-related keywords"""
        keywords = ['login', 'signin', 'logon', 'signon', 'account', 'auth', 
                   'authentication', 'password', 'credential', 'session']
        url_lower = url.lower()
        return sum(1 for keyword in keywords if keyword in url_lower)
    
    def _check_common_typos(self, domain):
        """Check for common typos of legitimate domains"""
        if not domain:
            return 0
        
        # Common legitimate domains (extend this list as needed)
        legitimate_domains = {
            'google': ['g00gle', 'googel', 'g0ogle', 'gooogle', 'googgle'],
            'microsoft': ['micr0soft', 'microsft', 'micosoft', 'microsfot'],
            'amazon': ['amazn', 'amaz0n', 'anazon', 'amozon'],
            'apple': ['appl', 'appel', 'appl3', 'aple'],
            'facebook': ['faceb00k', 'facebok', 'facedook', 'faceb0ok'],
            'twitter': ['twiter', 'tw1tter', 'twittter', 'tweter'],
            'paypal': ['paypa1', 'pavpal', 'paypaI', 'paypall', 'paypai'],
            'netflix': ['netfl1x', 'netflex', 'netfix', 'net-flix'],
            'yahoo': ['yah00', 'yahho', 'yah0o', 'yaho'],
            'ebay': ['eba1', 'e-bay', 'ebey', 'ebav'],
            'instagram': ['1nstagram', 'lnstagram', 'instagrarn', 'instagam'],
            'linkedin': ['linkedln', 'link3din', 'lnkedin', 'linkedim'],
            'whatsapp': ['whatsap', 'whatsaap', 'watsapp', 'whatsap'],
            'gmail': ['gma1l', 'gmial', 'gmaill', 'gmall'],
            'outlook': ['0utlook', 'outl00k', 'outlok', 'outl0ok'],
            'bank': ['b4nk', 'banc', 'bancking', 'banck'],
            'chase': ['chasse', 'chas3', 'chse', 'cha$e'],
            'wellsfargo': ['wellsfarg0', 'welsfargo', 'wellsfergo', 'wellsfrgo']
        }
        
        domain_lower = domain.lower()
        
        # Check for character replacements (1 for i, 0 for o, etc.)
        suspicious_replacements = {
            'i': '1', 'l': '1', 'o': '0', 'a': '4', 'e': '3', 's': '5', 
            'g': '9', 'b': '8', 't': '7'
        }
        
        has_replacements = False
        for char, replacement in suspicious_replacements.items():
            if replacement in domain_lower:
                has_replacements = True
        
        # Check for typos of legitimate domains
        for legit_domain, typos in legitimate_domains.items():
            # Exact match to typo list
            if domain_lower in typos:
                return 1
            
            # Similar to legitimate domain but not exact
            if self._similar_domain(domain_lower, legit_domain):
                return 1
        
        # If we detected suspicious character replacements
        if has_replacements:
            return 1
            
        return 0
    
    def _similar_domain(self, domain, legitimate):
        """Check if domain is similar to legitimate domain (potential typo)"""
        # Simple similarity check for now
        if legitimate in domain and domain != legitimate:
            # Check character distance
            if len(domain) <= len(legitimate) + 2:  # Allow up to 2 extra chars
                return True
        
        # More advanced checks could be added here (Levenshtein distance, etc.)
        return False
    
    def _get_domain_age(self, domain):
        """Get domain age in days, with fallback"""
        try:
            # Try to get domain registration info
            # Remove port if present
            if ":" in domain:
                domain = domain.split(":")[0]
                
            # Extract just the domain part if needed
            domain_parts = domain.split('.')
            if len(domain_parts) > 2:
                domain = '.'.join(domain_parts[-2:])
                
            w = whois.whois(domain)
            
            # Check if creation date exists and is valid
            if w.creation_date:
                # Handle case where creation_date is a list
                if isinstance(w.creation_date, list):
                    creation_date = w.creation_date[0]
                else:
                    creation_date = w.creation_date
                    
                # Calculate age in days
                age_days = (datetime.now() - creation_date).days
                return max(0, age_days)  # Ensure non-negative
        except Exception as e:
            # Log the error but continue
            logger.warning(f"WHOIS lookup failed for {domain}: {e}")
        
        # Return default value if lookup fails
        return -1  # Use -1 to indicate unknown age

def integrate_url_features_with_existing(url, content_features=None):
    """
    Integrate URL structure features with existing content features
    
    Parameters:
    -----------
    url : str
        URL to analyze
    content_features : dict, optional
        Existing content features
    
    Returns:
    --------
    dict
        Combined features
    """
    # Extract URL features
    extractor = EnhancedURLFeatureExtractor()
    url_features = extractor.extract_url_structure_features(url)
    
    # Add computed URL confidence score based on features
    url_confidence_score = calculate_url_confidence(url_features)
    url_features['url_confidence_score'] = url_confidence_score
    
    # Combine with existing features if provided
    if content_features:
        combined_features = {**content_features, **url_features}
        return combined_features
    else:
        return url_features

def calculate_url_confidence(url_features):
    """
    Calculate a confidence score for URL based on feature analysis
    
    Parameters:
    -----------
    url_features : dict
        URL features from extract_url_structure_features
    
    Returns:
    --------
    float
        Confidence score between 0-1 (higher is more suspicious)
    """
    # Define risk weights for each feature
    risk_weights = {
        'has_ip_address': 0.7,
        'has_at_symbol': 0.6,
        'has_double_slash_redirect': 0.5,
        'has_common_typos': 0.8,
        'special_chars_count': 0.01,  # Per character
        'url_encoded_chars': 0.03,    # Per character
        'has_security_keywords': 0.15, # Per keyword
        'has_login_keywords': 0.1,    # Per keyword
        'subdomain_count': 0.1,       # Per subdomain
        'url_length': 0.001,          # Per character beyond 50
        'digits_in_domain': 0.05,     # Per digit
        'domain_age_days': -0.0005    # Negative weight - older is safer
    }
    
    # Calculate weighted risk score
    risk_score = 0.0
    
    # IP address is a major red flag
    if url_features['has_ip_address']:
        risk_score += risk_weights['has_ip_address']
    
    # At symbol in URL is suspicious
    if url_features['has_at_symbol']:
        risk_score += risk_weights['has_at_symbol']
    
    # Double slash in path can be used for redirection
    if url_features['has_double_slash_redirect']:
        risk_score += risk_weights['has_double_slash_redirect']
    
    # Typosquatting is a common phishing technique
    if url_features['has_common_typos']:
        risk_score += risk_weights['has_common_typos']
    
    # Special characters can be used to disguise URLs
    risk_score += url_features['special_chars_count'] * risk_weights['special_chars_count']
    
    # URL encoded characters can hide the true URL
    risk_score += url_features['url_encoded_chars'] * risk_weights['url_encoded_chars']
    
    # Keywords related to security or login are common in phishing
    risk_score += url_features['has_security_keywords'] * risk_weights['has_security_keywords']
    risk_score += url_features['has_login_keywords'] * risk_weights['has_login_keywords']
    
    # Multiple subdomains can be suspicious
    if url_features['subdomain_count'] > 1:
        risk_score += (url_features['subdomain_count'] - 1) * risk_weights['subdomain_count']
    
    # Very long URLs can be suspicious
    if url_features['url_length'] > 50:
        risk_score += (url_features['url_length'] - 50) * risk_weights['url_length']
    
    # Many digits in domain can be suspicious
    risk_score += url_features['digits_in_domain'] * risk_weights['digits_in_domain']
    
    # Newer domains are more suspicious
    # But only if we have valid domain age data
    if url_features['domain_age_days'] > 0:
        # Cap at 2 years (730 days) for scaling
        domain_age = min(url_features['domain_age_days'], 730)
        risk_score += domain_age * risk_weights['domain_age_days']
    
    # Scale to 0-1 range
    # Cap at 0.95 to avoid absolute certainty
    risk_score = min(0.95, max(0, risk_score))
    
    return risk_score

# Example usage
if __name__ == "__main__":
    test_urls = [
        "https://www.google.com/search?q=test",
        "http://123.456.789.123/login",
        "https://paypa1-secure-login.com/update-account",
        "https://normal-website.com/"
    ]
    
    extractor = EnhancedURLFeatureExtractor()
    
    for url in test_urls:
        print(f"\nURL: {url}")
        features = extractor.extract_url_structure_features(url)
        confidence = calculate_url_confidence(features)
        print(f"Features: {features}")
        print(f"URL Confidence Score: {confidence:.4f}")