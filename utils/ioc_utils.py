import re
from typing import Dict, Optional, Tuple

class IOCClassifier:
    """Classify and normalize IOCs (IP, domain, hash)"""
    
    @staticmethod
    def classify(ioc: str) -> Optional[Tuple[str, str]]:
        """
        Classify an IOC into type and normalized form
        Returns: (type, normalized_ioc) or None if invalid
        """
        ioc = ioc.strip()
        
        # Check for IP address (IPv4 or IPv6)
        if ip_type := IOCClassifier._classify_ip(ioc):
            return ip_type
        
        # Check for domain
        if domain := IOCClassifier._classify_domain(ioc):
            return ('domain', domain.lower())
        
        # Check for hash
        if hash_type := IOCClassifier._classify_hash(ioc):
            return hash_type
        
        return None

    @staticmethod
    def _classify_ip(ioc: str) -> Optional[Tuple[str, str]]:
        """Classify IPv4 or IPv6 address"""
        # IPv4 regex
        ipv4_re = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        if re.fullmatch(ipv4_re, ioc):
            return ('ip', ioc)
        
        # IPv6 regex (simplified)
        ipv6_re = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
        if re.fullmatch(ipv6_re, ioc):
            return ('ip', ioc.lower())
        
        return None

    @staticmethod
    def _classify_domain(ioc: str) -> Optional[str]:
        """Validate and normalize domain"""
        # Simple domain regex - adjust as needed
        domain_re = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        if re.fullmatch(domain_re, ioc):
            return ioc.lower()
        return None

    @staticmethod
    def _classify_hash(ioc: str) -> Optional[Tuple[str, str]]:
        """Classify hash type (MD5, SHA1, SHA256)"""
        ioc = ioc.lower()
        
        # MD5 (32 hex chars)
        if re.fullmatch(r'^[a-f0-9]{32}$', ioc):
            return ('hash', ioc)
        
        # SHA1 (40 hex chars)
        if re.fullmatch(r'^[a-f0-9]{40}$', ioc):
            return ('hash', ioc)
        
        # SHA256 (64 hex chars)
        if re.fullmatch(r'^[a-f0-9]{64}$', ioc):
            return ('hash', ioc)
        
        return None