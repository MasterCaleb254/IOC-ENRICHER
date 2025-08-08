import pytest
from unittest.mock import patch, MagicMock
from enrichers.otx import OTXEnricher

@pytest.fixture
def otx_enricher():
    with patch.dict('os.environ', {'OTX_API_KEY': 'test_key'}):
        return OTXEnricher()

@patch('requests.get')
def test_enrich_domain(mock_get, otx_enricher):
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "pulse_info": {
            "count": 3,
            "pulses": [{"name": "Malicious Domain", "adversary": ""}]
        },
        "whois": "Example Registrar",
        "passive_dns": []
    }
    mock_get.return_value = mock_response
    
    result = otx_enricher.enrich("example.com", "domain")
    assert result['source'] == 'otx'
    assert isinstance(result['pulse_info'], dict)  # Ensure it's a dict
    assert result['pulse_info']['count'] == 3
    assert isinstance(result['pulse_info']['pulses'], list)  # Ensure pulses is a list

@patch('requests.get')
def test_enrich_hash(mock_get, otx_enricher):
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "pulse_info": {
            "count": 5,
            "pulses": [{"name": "MALWARE", "adversary": "APT29"}]
        },
        "analysis": {}
    }
    mock_get.return_value = mock_response
    
    result = otx_enricher.enrich("a"*64, "hash")
    assert result['source'] == 'otx'
    assert isinstance(result['pulse_info'], dict)
    assert result['pulse_info']['count'] == 5
    assert isinstance(result['pulse_info']['pulses'], list)

def test_skip_non_domain_or_hash(otx_enricher):
    result = otx_enricher.enrich("8.8.8.8", "ip")
    assert result is None