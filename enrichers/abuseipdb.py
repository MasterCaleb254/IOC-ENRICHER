from .base import BaseEnricher
from typing import Dict, Optional
import os
from typing import Literal

# Define valid IOC type
IOC_TYPE = Literal["ip"]

class AbuseIPDBEnricher(BaseEnricher):
    """Enrich IPs using AbuseIPDB API"""
    
    def _get_api_key(self) -> str:
        """Get AbuseIPDB API key from environment variable"""
        api_key = os.getenv("ABUSEIPDB_API_KEY")
        if not api_key:
            raise ValueError("AbuseIPDB API key not found. Set ABUSEIPDB_API_KEY environment variable.")
        return api_key
        
    def enrich(self, ioc: str, ioc_type: IOC_TYPE) -> Optional[Dict]:
        """
        Enrich IP using AbuseIPDB API
        
        Args:
            ioc: IP address to check
            ioc_type: Must be "ip"
            
        Returns:
            Optional[Dict]: Enrichment data or None if not found/supported
        """
        if not ioc:
            raise ValueError("IOC cannot be empty")
            
        if ioc_type != "ip":
            return None
            
        base_url = "https://api.abuseipdb.com/api/v2"
        endpoint = f"{base_url}/check"
        headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ioc,
            "maxAgeInDays": 90
        }
        
        data = self._make_request(endpoint, headers=headers, params=params)
        if not data:
            return None
            
        return self._normalize_data(data)
        
    def _normalize_data(self, data: Dict) -> Dict:
        """
        Normalize AbuseIPDB response to common format
        
        Args:
            data: Raw response from AbuseIPDB API
            
        Returns:
            Dict: Normalized data structure
        """
        if not isinstance(data, dict) or "data" not in data:
            return {
                "source": "abuseipdb",
                "error": "Invalid response format"
            }
            
        return {
            "source": "abuseipdb",
            "abuse_confidence_score": data.get("data", {}).get("abuseConfidenceScore"),
            "total_reports": data.get("data", {}).get("totalReports"),
            "isp": data.get("data", {}).get("isp"),
            "usage_type": data.get("data", {}).get("usageType")
        }