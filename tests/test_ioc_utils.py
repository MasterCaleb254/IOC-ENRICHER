import pytest
from utils.ioc_utils import IOCClassifier

@pytest.mark.parametrize("ioc,expected", [
    ("8.8.8.8", ("ip", "8.8.8.8")),
    ("2001:0db8:85a3:0000:0000:8a2e:0370:7334", ("ip", "2001:0db8:85a3:0000:0000:8a2e:0370:7334")),
    ("example.com", ("domain", "example.com")),
    ("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9", ("hash", "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")),
    ("invalid", None),
    ("", None)
])
def test_classify_ioc(ioc, expected):
    assert IOCClassifier.classify(ioc) == expected