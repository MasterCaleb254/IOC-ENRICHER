import pytest
from unittest.mock import patch, MagicMock
from enrichers.virustotal import VirusTotalEnricher

@pytest.fixture
def vt_enricher():
    with patch.dict('os.environ', {'VT_API_KEY': 'test_key'}):
        return VirusTotalEnricher()

@patch('requests.get')
def test_enrich_ip(mock_get, vt_enricher):
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 5},
                "country": "US",
                "reputation": 90,
                "tags": ["dns-server"]
            }
        }
    }
    mock_get.return_value = mock_response
    
    result = vt_enricher.enrich("8.8.8.8", "ip")
    assert result['source'] == 'virustotal'
    assert result['country'] == 'US'
    assert result['reputation'] == 90
    assert 'dns-server' in result['tags']

@patch('requests.get')
def test_enrich_domain(mock_get, vt_enricher):
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 2},
                "last_dns_records": [{"type": "A", "value": "1.2.3.4"}]
            }
        }
    }
    mock_get.return_value = mock_response
    
    result = vt_enricher.enrich("example.com", "domain")
    assert result['source'] == 'virustotal'
    assert result['last_analysis_stats']['malicious'] == 2

@patch('requests.get')
def test_enrich_hash(mock_get, vt_enricher):
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 10},
                "type_description": "PE32",
                "names": ["malware.exe"]
            }
        }
    }
    mock_get.return_value = mock_response
    
    result = vt_enricher.enrich("a"*64, "hash")
    assert result['source'] == 'virustotal'
    assert result['type_description'] == 'PE32'
    assert 'malware.exe' in result['names']