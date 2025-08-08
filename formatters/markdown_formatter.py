from typing import List, Dict

def format_markdown(results: List[Dict], output_file: str = None) -> str:
    """
    Format results as Markdown
    Args:
        results: List of enriched IOC dictionaries
        output_file: Optional file path to write output
    Returns:
        Markdown string of results
    """
    output = []
    for result in results:
        output.append(f"### {result['ioc']} ({result['type']})")
        output.append("")
        
        if not result.get('enrichment'):
            output.append("No enrichment data available")
            output.append("")
            continue
            
        for source, data in result['enrichment'].items():
            output.append(f"#### {source.upper()}")
            for key, value in data.items():
                output.append(f"- **{key}**: {value}")
            output.append("")
        
        if 'mitre' in result:
            mitre = result['mitre']
            output.append("#### MITRE ATT&CK")
            if mitre['techniques']:
                output.append("**Techniques:**")
                for tech in mitre['techniques']:
                    output.append(f"- {tech['id']}: {tech['name']}")
                    output.append(f"  - Tactics: {', '.join(tech['tactics'])}")
            if mitre['actors']:
                output.append("**Associated Actors:**")
                output.append("- " + ", ".join(mitre['actors']))
            output.append("")
    
    md_output = "\n".join(output)
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(md_output)
    return md_output
