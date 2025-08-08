import json
from pathlib import Path
from typing import Dict, List
from config import settings

class MITREAttack:
    """Handle MITRE ATT&CK data loading and lookup"""
    
    def __init__(self):
        self.dataset = self._load_dataset()
        self.techniques = self._index_techniques()
        self.actors = self._load_threat_actors()
        
    def _load_dataset(self) -> Dict:
        """Load MITRE ATT&CK dataset"""
        attack_file = Path(__file__).parent / 'data' / 'enterprise-attack.json'
        with open(attack_file, 'r', encoding='utf-8') as f:
            return json.load(f)
            
    def _index_techniques(self) -> Dict[str, Dict]:
        """Create lookup index for techniques"""
        techniques = {}
        for item in self.dataset['objects']:
            if item['type'] == 'attack-pattern':
                for ref in item.get('external_references', []):
                    if ref.get('source_name') == 'mitre-attack':
                        techniques[ref['external_id']] = {
                            'name': item['name'],
                            'tactic': [phase['phase_name'] for phase in item.get('kill_chain_phases', [])],
                            'url': ref['url'],
                            'platforms': item.get('x_mitre_platforms', [])
                        }
        return techniques
        
    def _load_threat_actors(self) -> Dict[str, Dict]:
        """Load custom threat actor mappings"""
        actors_file = Path(__file__).parent / 'data' / 'threat_actors.json'
        if actors_file.exists():
            with open(actors_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {}
        
    def get_technique(self, technique_id: str) -> Dict:
        """Get technique details by ID (e.g., T1059)"""
        return self.techniques.get(technique_id.upper())
        
    def get_actor_techniques(self, actor_name: str) -> List[str]:
        """Get techniques associated with a threat actor"""
        return self.actors.get(actor_name.lower(), {}).get('techniques', [])