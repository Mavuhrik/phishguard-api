from urllib.parse import urlparse

def validate_url(url):
    if not isinstance(url, str):
        return False
    url = url.strip()
    if not url:
        return False
    parsed_url = urlparse(url)

    if parsed_url.scheme not in ("http", "https"):
        return False
    if not parsed_url.hostname:
        return False
    return True
    