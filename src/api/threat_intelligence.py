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
    