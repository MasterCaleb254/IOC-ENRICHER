from .base import BaseEnricher
from typing import Dict, Optional
import os
from typing import Literal

# Define valid IOC types
IOC_TYPE = Literal["ip", "domain", "hash"]

class VirusTotalEnricher(BaseEnricher):
    """Enrich IOCs using VirusTotal API"""
    
    def _get_api_key(self) -> str:
        """Get VirusTotal API key from environment variable"""
        api_key = os.getenv("VT_API_KEY")
        if not api_key:
            raise ValueError("VirusTotal API key not found. Set VT_API_KEY environment variable.")
        return api_key
        
    def enrich(self, ioc: str, ioc_type: str) -> Optional[Dict]:
        if not ioc:
            raise ValueError("IOC cannot be empty")
            
        base_url = "https://www.virustotal.com/api/v3"
        headers = {"x-apikey": self.api_key}
        
        # Validate IOC type
        if ioc_type not in ("ip", "domain", "hash"):
            return None
            
        endpoints = {
            "ip": f"{base_url}/ip_addresses/{ioc}",
            "domain": f"{base_url}/domains/{ioc}",
            "hash": f"{base_url}/files/{ioc}"
        }
        
        endpoint = endpoints[ioc_type]
        data = self._make_request(endpoint, headers=headers)
        if not data:
            return None
            
        return self._normalize_data(data, ioc_type)
        
    def _normalize_data(self, data: Dict, ioc_type: str) -> Dict:
        """Normalize VT response to common format"""
        if not data.get("data", {}).get("attributes"):
            return {"source": "virustotal", "error": "No attributes found in response"}
            
        result = {"source": "virustotal"}
        attributes = data["data"]["attributes"]
        
        common_fields = {
            "last_analysis_stats": attributes.get("last_analysis_stats"),
        }
        
        type_specific_fields = {
            "ip": {
                "country": attributes.get("country"),
                "reputation": attributes.get("reputation"),
                "tags": attributes.get("tags", [])
            },
            "domain": {
                "country": attributes.get("country"),
                "reputation": attributes.get("reputation"),
                "tags": attributes.get("tags", [])
            },
            "hash": {
                "type_description": attributes.get("type_description"),
                "names": attributes.get("names", []),
                "size": attributes.get("size")
            }
        }
        
        result.update(common_fields)
        result.update(type_specific_fields.get(ioc_type, {}))
        return result