from .base import BaseEnricher
from typing import Dict, Optional
import os
from typing import Literal

# Define valid IOC types
IOC_TYPE = Literal["domain", "hash"]

class OTXEnricher(BaseEnricher):
    """Enrich domains and hashes using AlienVault OTX"""
    
    def _get_api_key(self) -> str:
        """Get OTX API key from environment variable"""
        api_key = os.getenv("OTX_API_KEY")
        if not api_key:
            raise ValueError("OTX API key not found. Set OTX_API_KEY environment variable.")
        return api_key
        
    def enrich(self, ioc: str, ioc_type: IOC_TYPE) -> Optional[Dict]:
        """
        Enrich IOC using OTX API
        
        Args:
            ioc: Indicator to enrich
            ioc_type: Type of indicator (domain or hash)
            
        Returns:
            Optional[Dict]: Enrichment data or None if not found/supported
        """
        if not ioc:
            raise ValueError("IOC cannot be empty")
            
        if ioc_type not in ["domain", "hash"]:
            return None
            
        base_url = "https://otx.alienvault.com/api/v1"
        
        if ioc_type == "domain":
            endpoint = f"{base_url}/indicators/domain/{ioc}/general"
        else:  # hash
            endpoint = f"{base_url}/indicators/file/{ioc}/general"
            
        headers = {"X-OTX-API-KEY": self.api_key}
        
        data = self._make_request(endpoint, headers=headers)
        if not data:
            return None
            
        return self._normalize_data(data, ioc_type)
        
    def _normalize_data(self, data: Dict, ioc_type: str) -> Dict:
        """
        Normalize OTX response to common format
        
        Args:
            data: Raw response from OTX API
            ioc_type: Type of indicator
            
        Returns:
            Dict: Normalized data structure
        """
        if not isinstance(data, dict):
            return {
                "source": "otx",
                "error": "Invalid response format"
            }
            
        result = {
            "source": "otx",
            "pulse_info": {
                "count": data.get("pulse_info", {}).get("count", 0),
                "pulses": [p["name"] for p in data.get("pulse_info", {}).get("pulses", [])]
            }
        }
        
        if ioc_type == "domain":
            result.update({
                "whois": data.get("whois"),
                "passive_dns": data.get("passive_dns", [])
            })
            
        return result