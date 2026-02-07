import os
import requests
import base64
import hashlib
from typing import Optional, Dict, Any
from dotenv import load_dotenv

load_dotenv()

class VirusTotalAPI:
    def __init__(self):
        self.api_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.base_url = "https://www.virustotal.com/api/v3"
        
        if not self.api_key:
            raise ValueError("VirusTotal API key not found in environment variables")

    def get_url_report(self, url: str) -> Optional[Dict[str, Any]]:
        """Get VirusTotal report for a URL"""
        try:
            # Encode URL for VirusTotal
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            
            headers = {"x-apikey": self.api_key}
            response = requests.get(
                f"{self.base_url}/urls/{url_id}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                return self._parse_url_response(response.json())
            elif response.status_code == 404:
                # URL not found, submit for analysis
                return self.submit_url(url)
            else:
                return {"error": f"API error: {response.status_code}"}
                
        except Exception as e:
            return {"error": str(e)}

    def submit_url(self, url: str) -> Dict[str, Any]:
        """Submit URL for analysis if not found"""
        try:
            headers = {"x-apikey": self.api_key}
            data = {"url": url}
            
            response = requests.post(
                f"{self.base_url}/urls",
                headers=headers,
                data=data,
                timeout=10
            )
            
            if response.status_code == 200:
                return {
                    "status": "submitted",
                    "message": "URL submitted for analysis",
                    "analysis_id": response.json().get("data", {}).get("id")
                }
            else:
                return {"error": f"Submission failed: {response.status_code}"}
                
        except Exception as e:
            return {"error": str(e)}

    def get_domain_report(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get VirusTotal report for a domain"""
        try:
            headers = {"x-apikey": self.api_key}
            response = requests.get(
                f"{self.base_url}/domains/{domain}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                return self._parse_domain_response(response.json())
            else:
                return {"error": f"API error: {response.status_code}"}
                
        except Exception as e:
            return {"error": str(e)}

    def _parse_url_response(self, data: Dict) -> Dict[str, Any]:
        """Parse VirusTotal URL response"""
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected
        
        # Calculate threat level
        threat_level = "unknown"
        if total > 0:
            risk_ratio = (malicious + suspicious) / total
            if risk_ratio > 0.3:
                threat_level = "high"
            elif risk_ratio > 0.1:
                threat_level = "medium"
            elif malicious == 0 and suspicious == 0:
                threat_level = "low"
            else:
                threat_level = "suspicious"
        
        return {
            "status": "success",
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "total": total,
            "threat_level": threat_level,
            "risk_ratio": (malicious + suspicious) / total if total > 0 else 0,
            "reputation": attributes.get("reputation", 0),
            "categories": attributes.get("categories", {}),
            "raw_data": data
        }

    def _parse_domain_response(self, data: Dict) -> Dict[str, Any]:
        """Parse VirusTotal domain response"""
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected
        
        return {
            "status": "success",
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "total": total,
            "reputation": attributes.get("reputation", 0),
            "creation_date": attributes.get("creation_date"),
            "categories": attributes.get("categories", {}),
            "popularity_ranks": attributes.get("popularity_ranks", {}),
            "raw_data": data
        }


class GoogleSafeBrowsingAPI:
    """Google Safe Browsing API v4 integration"""

    def __init__(self):
        self.api_key = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')
        self.base_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

        if not self.api_key:
            raise ValueError("Google Safe Browsing API key not found in environment variables")

    def check_url(self, url: str) -> Dict[str, Any]:
        """Check a URL against Google Safe Browsing database"""
        try:
            payload = {
                "client": {
                    "clientId": "phishr-detector",
                    "clientVersion": "1.0.0"
                },
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION"
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }

            response = requests.post(
                f"{self.base_url}?key={self.api_key}",
                json=payload,
                timeout=10
            )

            if response.status_code == 200:
                return self._parse_response(response.json(), url)
            else:
                return {
                    "status": "error",
                    "error": f"API error: {response.status_code}",
                    "provider": "google_safe_browsing"
                }

        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "provider": "google_safe_browsing"
            }

    def check_urls_batch(self, urls: list) -> Dict[str, Any]:
        """Check multiple URLs in a single request (up to 500)"""
        try:
            threat_entries = [{"url": url} for url in urls[:500]]

            payload = {
                "client": {
                    "clientId": "phishr-detector",
                    "clientVersion": "1.0.0"
                },
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION"
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": threat_entries
                }
            }

            response = requests.post(
                f"{self.base_url}?key={self.api_key}",
                json=payload,
                timeout=15
            )

            if response.status_code == 200:
                return self._parse_batch_response(response.json(), urls)
            else:
                return {
                    "status": "error",
                    "error": f"API error: {response.status_code}",
                    "provider": "google_safe_browsing"
                }

        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "provider": "google_safe_browsing"
            }

    def _parse_response(self, data: Dict, url: str) -> Dict[str, Any]:
        """Parse Google Safe Browsing response for single URL"""
        matches = data.get("matches", [])

        if not matches:
            # No threats found - URL is safe
            return {
                "status": "success",
                "safe": True,
                "threats_found": 0,
                "threat_types": [],
                "threat_level": "low",
                "provider": "google_safe_browsing"
            }

        # Extract threat information
        threat_types = list(set(match.get("threatType", "UNKNOWN") for match in matches))
        platform_types = list(set(match.get("platformType", "UNKNOWN") for match in matches))

        # Determine threat level based on threat types
        threat_level = self._calculate_threat_level(threat_types)

        return {
            "status": "success",
            "safe": False,
            "threats_found": len(matches),
            "threat_types": threat_types,
            "platform_types": platform_types,
            "threat_level": threat_level,
            "threat_details": self._get_threat_descriptions(threat_types),
            "provider": "google_safe_browsing"
        }

    def _parse_batch_response(self, data: Dict, urls: list) -> Dict[str, Any]:
        """Parse Google Safe Browsing response for batch URLs"""
        matches = data.get("matches", [])

        # Create a mapping of URL to threats
        url_threats = {url: [] for url in urls}

        for match in matches:
            threat_url = match.get("threat", {}).get("url", "")
            if threat_url in url_threats:
                url_threats[threat_url].append({
                    "threat_type": match.get("threatType"),
                    "platform_type": match.get("platformType")
                })

        # Summarize results
        safe_urls = [url for url, threats in url_threats.items() if not threats]
        unsafe_urls = [url for url, threats in url_threats.items() if threats]

        return {
            "status": "success",
            "total_checked": len(urls),
            "safe_count": len(safe_urls),
            "unsafe_count": len(unsafe_urls),
            "safe_urls": safe_urls,
            "unsafe_urls": unsafe_urls,
            "url_details": url_threats,
            "provider": "google_safe_browsing"
        }

    def _calculate_threat_level(self, threat_types: list) -> str:
        """Calculate overall threat level based on threat types"""
        high_severity = ["MALWARE", "SOCIAL_ENGINEERING"]
        medium_severity = ["UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]

        for threat in threat_types:
            if threat in high_severity:
                return "high"

        for threat in threat_types:
            if threat in medium_severity:
                return "medium"

        return "suspicious" if threat_types else "low"

    def _get_threat_descriptions(self, threat_types: list) -> Dict[str, str]:
        """Get human-readable descriptions for threat types"""
        descriptions = {
            "MALWARE": "This site may install malicious software on your device",
            "SOCIAL_ENGINEERING": "This site may trick you into revealing personal information (phishing)",
            "UNWANTED_SOFTWARE": "This site may contain unwanted or deceptive software",
            "POTENTIALLY_HARMFUL_APPLICATION": "This site may contain potentially harmful applications"
        }

        return {
            threat: descriptions.get(threat, "Unknown threat type")
            for threat in threat_types
        }
