#!/usr/bin/env python
import click
import json
from pathlib import Path
from typing import List, Dict
from datetime import datetime
from config import settings
from utils.file_parser import FileParser
from enrichers.manager import EnrichmentManager
from formatters import (
    format_json,
    format_csv,
    format_markdown,
    format_splunk
)
import sys

# Add these two lines at the top of your script to force UTF-8 encoding
sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')

@click.group()
def cli():
    """IOC Enrichment & Correlation Tool"""
    pass

def _get_output_formatter(format_type: str):
    """Select the appropriate output formatter"""
    formatters = {
        'json': format_json,
        'csv': format_csv,
        'markdown': format_markdown,
        'splunk': format_splunk
    }
    return formatters.get(format_type.lower(), format_json)

def _validate_output_dir(output_file: str):
    """Ensure output directory exists"""
    if output_file:
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

@cli.command()
@click.argument('input_file', type=click.Path(exists=True))
@click.option('--output-format', default=settings.DEFAULT_OUTPUT_FORMAT,
              type=click.Choice(['json', 'csv', 'markdown', 'splunk']),
              help='Output format')
@click.option('--output-file', type=click.Path(),
              help='Output file path')
def enrich(input_file, output_format, output_file):
    """Enrich IOCs from input file"""
    try:
        # Parse input file
        click.secho(f"🔍 Parsing input file: {input_file}", fg='blue')
        iocs = FileParser.parse_file(input_file)
        
        if not iocs:
            click.secho("❌ No valid IOCs found in input file", fg='red', err=True)
            return
        
        click.secho(f"✅ Found {len(iocs)} valid IOCs to process", fg='green')
        
        # Initialize enrichment pipeline
        manager = EnrichmentManager()
        enriched_results = []
        
        # Process IOCs
        for ioc in iocs:
            enriched_data = manager.enrich_ioc(ioc['ioc'], ioc['type'])
            enriched_results.append({
                'original': ioc['original'],
                'ioc': ioc['ioc'],
                'type': ioc['type'],
                'enrichment': enriched_data
            })
        
        # Format output
        formatter = _get_output_formatter(output_format)
        try:
            output = formatter(enriched_results, output_file)
            
            # Print to console if no output file specified
            if not output_file:
                click.echo(output)
            
            click.secho("\n🎉 Enrichment Complete!", fg='green', bold=True)
            click.echo(f"┣ Processed: {len(enriched_results)} IOCs")
            click.echo(f"┣ Output Format: {output_format.upper()}")
            click.echo(f"┗ Output: {output_file if output_file else 'Console'}")
            
        except IOError as e:
            click.secho(f"\n❌ Error writing output: {str(e)}", fg='red', err=True)
        
    except Exception as e:
        click.secho(f"\n❌ Error: {str(e)}", fg='red', err=True)
        raise click.Abort()

if __name__ == '__main__':
    cli()