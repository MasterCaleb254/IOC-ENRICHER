import json
from typing import List, Dict
from datetime import datetime

def format_splunk(results: List[Dict], output_file: str = None) -> str:
    """
    Format results as Splunk-compatible JSON
    Args:
        results: List of enriched IOC dictionaries
        output_file: Optional file path to write output
    Returns:
        JSON string in Splunk format
    """
    splunk_results = []
    for result in results:
        splunk_result = {
            'ioc': result['ioc'],
            'type': result['type'],
            'timestamp': datetime.utcnow().isoformat()
        }
        
        if 'enrichment' in result:
            for source, data in result['enrichment'].items():
                for key, value in data.items():
                    splunk_result[f"{source}.{key}"] = value
        
        if 'mitre' in result:
            splunk_result['mitre.techniques'] = [t['id'] for t in result['mitre']['techniques']]
            splunk_result['mitre.actors'] = result['mitre']['actors']
        
        splunk_results.append(splunk_result)
    
    output = json.dumps(splunk_results, indent=2)
    if output_file:
        with open(output_file, 'w') as f:
            f.write(output)
    return output