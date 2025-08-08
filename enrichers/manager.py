import time
from typing import Dict, List, Optional, Any
from config import settings
from cache.db import CacheDB
from mitre.correlator import MITRECorrelator

class EnrichmentManager:
    """Orchestrate enrichment across all available plugins with MITRE correlation"""
    
    def __init__(self):
        self.enrichers = self._load_enrichers()
        self.cache = CacheDB() if settings.CACHE_ENABLED else None
        self.rate_limits = self._init_rate_limits()
        self.correlator = MITRECorrelator()
        
    def _load_enrichers(self) -> Dict[str, List[Any]]:
        """Initialize all available enrichers with their rate limits"""
        from .virustotal import VirusTotalEnricher
        from .shodan import ShodanEnricher
        from .abuseipdb import AbuseIPDBEnricher
        from .otx import OTXEnricher
        
        return {
            "ip": [
                VirusTotalEnricher(),
                ShodanEnricher(), 
                AbuseIPDBEnricher()
            ],
            "domain": [
                VirusTotalEnricher(),
                OTXEnricher()
            ],
            "hash": [
                VirusTotalEnricher(),
                OTXEnricher()
            ]
        }
        
    def _init_rate_limits(self) -> Dict[str, Dict[str, float]]:
        """Initialize rate limit tracking for each enricher"""
        return {
            'virustotal': {'last_call': 0.0, 'interval': 15.0},  # VT public API: 4 req/min
            'shodan': {'last_call': 0.0, 'interval': 1.0},       # Shodan: 1 req/sec
            'abuseipdb': {'last_call': 0.0, 'interval': 1.0},    # AbuseIPDB: 1 req/sec
            'otx': {'last_call': 0.0, 'interval': 0.0}           # OTX: no rate limit
        }
        
    def _enforce_rate_limit(self, enricher_name: str) -> None:
        """Enforce rate limiting for API calls"""
        if not enricher_name:
            return
            
        limit = self.rate_limits.get(enricher_name.lower())
        if not limit or limit['interval'] <= 0:
            return
            
        current_time = time.time()
        elapsed = current_time - limit['last_call']
        if elapsed < limit['interval']:
            sleep_time = limit['interval'] - elapsed
            time.sleep(sleep_time)
            
        self.rate_limits[enricher_name.lower()]['last_call'] = current_time
        
    def enrich_ioc(self, ioc: str, ioc_type: str) -> Dict[str, Any]:
        """
        Enrich a single IOC with all relevant sources and MITRE correlation
        
        Args:
            ioc: The IOC to enrich (IP, domain, or hash)
            ioc_type: Type of IOC ('ip', 'domain', or 'hash')
            
        Returns:
            Dictionary containing all enrichment results and MITRE correlation
        """
        if not ioc or not ioc_type:
            return {}
            
        results: Dict[str, Any] = {}
        
        # Check cache first
        if self.cache:
            cached = self.cache.get(ioc)
            if cached and isinstance(cached, dict):
                return cached
                
        # Run through all relevant enrichers
        for enricher in self.enrichers.get(ioc_type, []):
            try:
                # Enforce rate limiting
                self._enforce_rate_limit(enricher.__class__.__name__.lower())
                
                # Perform enrichment
                enriched_data = enricher.enrich(ioc, ioc_type)
                if enriched_data and isinstance(enriched_data, dict):
                    source = enriched_data.pop("source", None)
                    if source:
                        results[source] = enriched_data
            except Exception as e:
                print(f"Error enriching {ioc} with {enricher.__class__.__name__}: {str(e)}")
                continue
                
        # Add MITRE correlation if we got results
        if results:
            try:
                mitre_data = self.correlator.correlate(results)
                if mitre_data:
                    results['mitre'] = mitre_data
            except Exception as e:
                print(f"Error performing MITRE correlation: {str(e)}")
            
            # Update cache
            if self.cache:
                try:
                    self.cache.set(ioc, results)
                except Exception as e:
                    print(f"Error caching results: {str(e)}")
            
        return results
        
    def enrich_batch(self, iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Enrich a batch of IOCs with MITRE correlation
        
        Args:
            iocs: List of IOC dictionaries with 'ioc' and 'type' keys
            
        Returns:
            List of enriched IOC results
        """
        if not iocs:
            return []
            
        return [{
            **ioc,
            'enrichment': self.enrich_ioc(ioc.get('ioc', ''), ioc.get('type', ''))
        } for ioc in iocs if isinstance(ioc, dict)]