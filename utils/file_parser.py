import csv
import json
from pathlib import Path
from typing import List, Dict, Union, Any
from .ioc_utils import IOCClassifier

class FileParser:
    """Parse input files (CSV/JSON) and extract IOCs"""
    
    @staticmethod
    def parse_file(file_path: Union[str, Path]) -> List[Dict[str, Any]]:
        """Parse input file and return normalized IOCs with types"""
        path = Path(file_path)
        
        if not path.exists():
            raise FileNotFoundError(f"Input file not found: {file_path}")
        
        suffix = path.suffix.lower()
        if suffix == '.json':
            return FileParser._parse_json(path)
        elif suffix == '.csv':
            return FileParser._parse_csv(path)
        else:
            raise ValueError("Unsupported file format. Only JSON and CSV are supported.")

    @staticmethod
    def _parse_json(file_path: Path) -> List[Dict[str, Any]]:
        """Parse JSON input file"""
        with open(file_path, 'r') as f:
            try:
                data = json.load(f)
                if isinstance(data, dict):
                    if 'iocs' in data:
                        iocs = data['iocs']
                    else:
                        raise ValueError("JSON must contain array of IOCs or object with 'iocs' field")
                elif isinstance(data, list):
                    iocs = data
                else:
                    raise ValueError("JSON must contain array of IOCs or object with 'iocs' field")
                
                if not isinstance(iocs, list):
                    raise ValueError("IOCs must be provided as a list")
                
                return FileParser._normalize_iocs(iocs)
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON file: {e}")

    @staticmethod
    def _parse_csv(file_path: Path) -> List[Dict[str, Any]]:
        """Parse CSV input file"""
        with open(file_path, 'r') as f:
            reader = csv.reader(f)
            try:
                # Skip header row if it exists
                first_row = next(reader)
                try:
                    # Check if first row contains an IOC
                    IOCClassifier.classify(first_row[0])
                    iocs = [first_row[0]] + [row[0] for row in reader if row and row[0].strip()]
                except:
                    # Assume first row was header
                    iocs = [row[0] for row in reader if row and row[0].strip()]
            except StopIteration:
                iocs = []
            except IndexError as e:
                raise ValueError(f"Invalid CSV format: {e}")
        
        return FileParser._normalize_iocs(iocs)

    @staticmethod
    def _normalize_iocs(raw_iocs: List[str]) -> List[Dict[str, Any]]:
        """Normalize and classify IOCs"""
        normalized = []
        seen = set()
        
        for ioc in raw_iocs:
            if not ioc or not isinstance(ioc, str):
                continue
            
            # Classify and normalize the IOC
            classified = IOCClassifier.classify(ioc.strip())
            if not classified:
                continue
            
            ioc_type, normalized_ioc = classified
            
            # Deduplicate
            if normalized_ioc in seen:
                continue
            seen.add(normalized_ioc)
            
            normalized.append({
                'original': ioc,
                'ioc': normalized_ioc,
                'type': ioc_type
            })
        
        return normalized