import csv
from typing import List, Dict, Optional, TextIO
from io import StringIO

def format_csv(results: List[Dict], output_file: Optional[str] = None) -> str:
    """
    Format results as CSV
    
    Args:
        results: List of enriched IOC dictionaries
        output_file: Optional file path to write output
        
    Returns:
        CSV string of results
    """
    if not results:
        return ""

    # Get all possible field names
    fieldnames = set()
    for result in results:
        fieldnames.update(result.keys())
        if 'enrichment' in result and isinstance(result['enrichment'], dict):
            for source, data in result['enrichment'].items():
                if isinstance(data, dict):
                    for key in data.keys():
                        fieldnames.add(f"{source}_{key}")

    fieldnames = sorted(fieldnames)
    
    # Use StringIO for in-memory CSV writing
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    
    for result in results:
        row = result.copy()
        if 'enrichment' in result and isinstance(result['enrichment'], dict):
            for source, data in result['enrichment'].items():
                if isinstance(data, dict):
                    for key, value in data.items():
                        row[f"{source}_{key}"] = str(value)
        writer.writerow(row)
    
    csv_content = output.getvalue()
    output.close()
    
    # Write to file if specified
    if output_file:
        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                f.write(csv_content)
        except IOError as e:
            raise IOError(f"Failed to write CSV file: {str(e)}")
    
    return csv_content