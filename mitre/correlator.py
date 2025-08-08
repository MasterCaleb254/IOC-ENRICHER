from typing import Dict, List, Optional
from mitre.attack import MITREAttack

class MITRECorrelator:
    """Correlate enriched IOCs with MITRE ATT&CK framework"""
    
    def __init__(self):
        self.mitre = MITREAttack()
        
    def correlate(self, enriched_data: Dict) -> Dict:
        """Correlate enriched IOC data with MITRE ATT&CK"""
        correlations = {
            'techniques': [],
            'tactics': set(),
            'actors': set()
        }
        
        if not enriched_data:
            return {
                'techniques': [],
                'tactics': [],
                'actors': []
            }
        
        # Check VirusTotal for MITRE references
        if 'virustotal' in enriched_data:
            self._process_virustotal(enriched_data['virustotal'], correlations)
            
        # Check OTX for threat actor references
        if 'otx' in enriched_data:
            self._process_otx(enriched_data['otx'], correlations)
            
        # Convert sets to lists for JSON serialization
        correlations['tactics'] = sorted(correlations['tactics'])
        correlations['actors'] = sorted(correlations['actors'])
        
        return correlations
        
    def _process_virustotal(self, vt_data: Dict, correlations: Dict):
        """Extract MITRE references from VirusTotal data"""
        for tag in vt_data.get('tags', []):
            if tag.startswith('T') and tag[1:].isdigit():
                technique = self.mitre.get_technique(tag)
                if technique:
                    correlations['techniques'].append({
                        'id': tag,
                        'name': technique['name'],
                        'tactics': technique['tactic'],
                        'url': technique['url']
                    })
                    correlations['tactics'].update(technique['tactic'])
                    
    def _process_otx(self, otx_data: Dict, correlations: Dict):
        """Extract threat actor info from OTX data"""
        for pulse in otx_data.get('pulse_info', {}).get('pulses', []):
            for actor in pulse.get('adversary', '').split(','):
                actor = actor.strip().lower()
                if actor in self.mitre.actors:
                    correlations['actors'].add(actor)
                    # Add actor's known techniques
                    for tech_id in self.mitre.get_actor_techniques(actor):
                        technique = self.mitre.get_technique(tech_id)
                        if technique:
                            correlations['techniques'].append({
                                'id': tech_id,
                                'name': technique['name'],
                                'tactics': technique['tactic'],
                                'url': technique['url'],
                                'source': 'actor_profile'
                            })
                            correlations['tactics'].update(technique['tactic'])