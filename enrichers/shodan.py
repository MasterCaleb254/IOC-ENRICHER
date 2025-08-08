from .base import BaseEnricher
from typing import Dict, Optional
import os
from typing import Literal

# Define valid IOC type
IOC_TYPE = Literal["ip"]

class ShodanEnricher(BaseEnricher):
    """Enrich IPs using Shodan API"""
    
    def _get_api_key(self) -> str:
        """Get Shodan API key from environment variable"""
        api_key = os.getenv("SHODAN_API_KEY")
        if not api_key:
            raise ValueError("Shodan API key not found. Set SHODAN_API_KEY environment variable.")
        return api_key
        
    def enrich(self, ioc: str, ioc_type: IOC_TYPE) -> Optional[Dict]:
        if not ioc:
            raise ValueError("IOC cannot be empty")
            
        if ioc_type != "ip":
            return None
            
        base_url = "https://api.shodan.io"
        endpoint = f"{base_url}/shodan/host/{ioc}"
        params = {"key": self.api_key}
        
        data = self._make_request(endpoint, params=params)
        if not data:
            return None
            
        return self._normalize_data(data)
        
    def _normalize_data(self, data: Dict) -> Dict:
        """Normalize Shodan response to common format"""
        if not isinstance(data, dict):
            return {
                "source": "shodan",
                "error": "Invalid response format"
            }
            
        return {
            "source": "shodan",
            "ports": data.get("ports", []),
            "hostnames": data.get("hostnames", []),
            "org": data.get("org"),
            "asn": data.get("asn"),
            "isp": data.get("isp")
        }