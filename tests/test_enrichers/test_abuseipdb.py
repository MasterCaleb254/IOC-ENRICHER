import pytest
from unittest.mock import patch, MagicMock
from enrichers.abuseipdb import AbuseIPDBEnricher

@pytest.fixture
def abuse_enricher():
    with patch.dict('os.environ', {'ABUSEIPDB_API_KEY': 'test_key'}):
        return AbuseIPDBEnricher()

@patch('requests.get')
def test_enrich_ip(mock_get, abuse_enricher):
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "data": {
            "abuseConfidenceScore": 95,
            "totalReports": 42,
            "isp": "Bad ISP",
            "usageType": "Data Center"
        }
    }
    mock_get.return_value = mock_response
    
    result = abuse_enricher.enrich("1.2.3.4", "ip")
    assert result['source'] == 'abuseipdb'
    assert result['abuse_confidence_score'] == 95  # Fixed key name
    assert result['total_reports'] == 42
    assert result['isp'] == 'Bad ISP'

def test_skip_non_ip(abuse_enricher):
    result = abuse_enricher.enrich("example.com", "domain")
    assert result is None