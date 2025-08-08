import json
import pytest
from pathlib import Path
from utils.file_parser import FileParser

def test_parse_json(tmp_path):
    # Create temp JSON file
    test_file = tmp_path / "test.json"
    test_file.write_text(json.dumps({"iocs": ["8.8.8.8", "example.com", "invalid"]}))
    
    result = FileParser.parse_file(test_file)
    assert len(result) == 2  # Should skip invalid
    assert result[0]['type'] == 'ip'
    assert result[1]['type'] == 'domain'

def test_parse_csv(tmp_path):
    # Create temp CSV file
    test_file = tmp_path / "test.csv"
    test_file.write_text("8.8.8.8\nexample.com\ninvalid\n")
    
    result = FileParser.parse_file(test_file)
    assert len(result) == 2  # Should skip invalid
    assert result[0]['type'] == 'ip'
    assert result[1]['type'] == 'domain'

def test_invalid_file():
    with pytest.raises(FileNotFoundError):
        FileParser.parse_file("nonexistent.txt")

def test_unsupported_format(tmp_path):
    test_file = tmp_path / "test.txt"
    test_file.write_text("dummy content")
    with pytest.raises(ValueError, match="Unsupported file format"):
        FileParser.parse_file(test_file)