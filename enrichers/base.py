from abc import ABC, abstractmethod
from typing import Dict, Optional
import requests
from config import settings

class BaseEnricher(ABC):
    """Abstract base class for all enrichment plugins"""
    
    def __init__(self):
        self.api_key = self._get_api_key()
        self.cache_enabled = settings.CACHE_ENABLED
        self.timeout = 10  # seconds
        
    @abstractmethod
    def _get_api_key(self) -> str:
        """Get API key from settings"""
        pass
        
    @abstractmethod
    def enrich(self, ioc: str, ioc_type: str) -> Optional[Dict]:
        """Enrich an IOC with data from this source"""
        pass
        
    def _make_request(self, url: str, headers: Dict = None, params: Dict = None) -> Dict:
        """Helper method for API requests"""
        try:
            response = requests.get(
                url,
                headers=headers,
                params=params,
                timeout=self.timeout
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"API request failed: {e}")
            return None