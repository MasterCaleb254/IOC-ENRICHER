import json
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from config import settings

class CacheDB:
    """Simple cache implementation using TinyDB"""
    
    def __init__(self):
        self.db_path = settings.CACHE_PATH
        self._ensure_db_dir()
        
        # Initialize database
        from tinydb import TinyDB, Query
        self.db = TinyDB(self.db_path)
        self.query = Query()
        self.ttl = settings.CACHE_TTL
        
    def _ensure_db_dir(self):
        """Create cache directory if it doesn't exist"""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
    def get(self, ioc: str) -> Optional[Dict[str, Any]]:
        """Get cached results for an IOC if not expired"""
        result = self.db.search(self.query.ioc == ioc)
        if not result:
            return None
            
        record = result[0]
        if self._is_expired(record['timestamp']):
            self.db.remove(self.query.ioc == ioc)
            return None
            
        return record['data']
        
    def set(self, ioc: str, data: Dict[str, Any]):
        """Cache enrichment results for an IOC"""
        self.db.upsert({
            'ioc': ioc,
            'data': data,
            'timestamp': datetime.utcnow().isoformat()
        }, self.query.ioc == ioc)
        
    def _is_expired(self, timestamp: str) -> bool:
        """Check if cached record is expired"""
        if self.ttl <= 0:
            return False
            
        record_time = datetime.fromisoformat(timestamp)
        return datetime.utcnow() > record_time + timedelta(seconds=self.ttl)
        
    def clear_expired(self):
        """Remove all expired cache entries"""
        expired = self.db.search(
            self._is_expired(self.query.timestamp)
        )
        for entry in expired:
            self.db.remove(doc_ids=[entry.doc_id])