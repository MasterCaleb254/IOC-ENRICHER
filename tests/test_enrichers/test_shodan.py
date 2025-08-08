import pytest
from unittest.mock import patch, MagicMock
from enrichers.shodan import ShodanEnricher

@pytest.fixture
def shodan_enricher():
    with patch.dict('os.environ', {'SHODAN_API_KEY': 'test_key'}):
        return ShodanEnricher()

@patch('requests.get')
def test_enrich_ip(mock_get, shodan_enricher):
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "ports": [80, 443],
        "org": "Google LLC",
        "asn": "AS15169",
        "hostnames": ["dns.google"]
    }
    mock_get.return_value = mock_response
    
    result = shodan_enricher.enrich("8.8.8.8", "ip")
    assert result['source'] == 'shodan'
    assert 80 in result['ports']
    assert result['org'] == 'Google LLC'
    assert 'dns.google' in result['hostnames']

def test_skip_non_ip(shodan_enricher):
    result = shodan_enricher.enrich("example.com", "domain")
    assert result is None