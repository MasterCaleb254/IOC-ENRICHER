import json
from typing import List, Dict

def format_json(results: List[Dict], output_file: str = None) -> str:
    """
    Format results as JSON
    Args:
        results: List of enriched IOC dictionaries
        output_file: Optional file path to write output
    Returns:
        JSON string of results
    """
    output = json.dumps(results, indent=2)
    if output_file:
        with open(output_file, 'w') as f:
            f.write(output)
    return output