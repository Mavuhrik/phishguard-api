from analyzer.url_validator import validate_url

def test_valid_https_url():
    assert validate_url("https://example.com") is True

def test_valid_http_url():
    assert validate_url("http://example.com") is True


def test_missing_hostname():
    assert validate_url("https://") is False


def test_missing_scheme():
    assert validate_url("example.com") is False


def test_unsupported_scheme():
    assert validate_url("ftp://example.com") is False


def test_empty_url():
    assert validate_url("") is False