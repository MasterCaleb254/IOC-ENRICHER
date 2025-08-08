import pytest
from unittest.mock import patch, MagicMock, PropertyMock
from mitre.attack import MITREAttack
from mitre.correlator import MITRECorrelator

# Mock data
MOCK_ACTORS = {
    "apt28": {
        "name": "APT28",
        "techniques": ["T1059"],
        "country": "Russia"
    }
}

@pytest.fixture
def mock_mitre_attack():
    # Create a properly configured mock of MITREAttack
    mitre = MagicMock(spec=MITREAttack)
    
    # Mock get_technique
    mitre.get_technique.return_value = {
        'name': 'Command-Line Interface',
        'tactic': ['execution'],
        'url': 'https://attack.mitre.org/techniques/T1059'
    }
    
    # Mock get_actor_techniques
    mitre.get_actor_techniques.return_value = ["T1059"]
    
    # Mock the actors property
    type(mitre).actors = PropertyMock(return_value=MOCK_ACTORS)
    
    return mitre

@pytest.fixture
def correlator(mock_mitre_attack):
    correlator = MITRECorrelator()
    correlator.mitre = mock_mitre_attack
    return correlator

def test_technique_lookup(mock_mitre_attack):
    technique = mock_mitre_attack.get_technique('T1059')
    assert technique['name'] == "Command-Line Interface"
    assert 'execution' in technique['tactic']

def test_actor_lookup(mock_mitre_attack):
    techniques = mock_mitre_attack.get_actor_techniques('apt28')
    assert 'T1059' in techniques

def test_correlation_virustotal(correlator):
    test_data = {'virustotal': {'tags': ['T1059']}}
    result = correlator.correlate(test_data)
    assert len(result['techniques']) == 1
    assert result['techniques'][0]['id'] == 'T1059'

def test_correlation_otx(correlator):
    test_data = {
        'otx': {
            'pulse_info': {
                'pulses': [{'adversary': 'APT28'}]
            }
        }
    }
    result = correlator.correlate(test_data)
    assert 'apt28' in result['actors']
    assert len(result['techniques']) > 0

def test_correlation_combined(correlator):
    test_data = {
        'virustotal': {'tags': ['T1059']},
        'otx': {
            'pulse_info': {
                'pulses': [{'adversary': 'APT28'}]
            }
        }
    }
    result = correlator.correlate(test_data)
    assert len(result['techniques']) > 0
    assert 'apt28' in result['actors']

def test_empty_correlation(correlator):
    result = correlator.correlate({})
    assert result == {
        'techniques': [],
        'tactics': [],
        'actors': []
    }