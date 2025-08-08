import pytest
from formatters import format_json, format_csv, format_markdown, format_splunk

@pytest.fixture
def sample_results():
    return [
        {
            'ioc': '8.8.8.8',
            'type': 'ip',
            'enrichment': {
                'virustotal': {
                    'malicious': True,
                    'country': 'US'
                },
                'shodan': {
                    'ports': [53, 80]
                }
            },
            'mitre': {
                'techniques': [
                    {
                        'id': 'T1071',
                        'name': 'Application Layer Protocol',
                        'tactics': ['command-and-control']
                    }
                ],
                'actors': ['apt28']
            }
        }
    ]

def test_format_json(sample_results, tmp_path):
    output_file = tmp_path / "output.json"
    result = format_json(sample_results, output_file)
    assert '"ioc": "8.8.8.8"' in result
    assert output_file.exists()

def test_format_csv(sample_results, tmp_path):
    output_file = tmp_path / "output.csv"
    result = format_csv(sample_results, output_file)
    assert '8.8.8.8' in result
    assert 'virustotal_malicious' in result
    assert output_file.exists()

def test_format_markdown(sample_results, tmp_path):
    output_file = tmp_path / "output.md"
    result = format_markdown(sample_results, output_file)
    assert '### 8.8.8.8 (ip)' in result
    assert '#### VIRUSTOTAL' in result
    assert '#### MITRE ATT&CK' in result
    assert output_file.exists()

def test_format_splunk(sample_results, tmp_path):
    output_file = tmp_path / "output.json"
    result = format_splunk(sample_results, output_file)
    assert 'virustotal.malicious' in result
    assert 'mitre.techniques' in result
    assert output_file.exists()