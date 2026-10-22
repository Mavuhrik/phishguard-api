from ipaddress import ip_address
from urllib.parse import unquote, urlparse, parse_qs
from analyzer.risk_scorer import calculate_risk_score
import tldextract

def is_ip_address(hostname):
    try:
        ip_address(hostname)
        return True
    except ValueError:
        return False

def get_hostname_idna(hostname):
    try:
       return hostname.encode("idna").decode("ascii")
    except UnicodeError:
        return hostname
    
SUSPICIOUS_KEYWORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "confirm",
    "password",
    "credential",
    "payment",
    "wallet"
}
    
def analyze_url(url):
    parsed_url = urlparse(url)
    domain_features = analyze_domain(parsed_url.hostname)
    path_features = analyze_path(parsed_url)
    keyword_features = analyze_keywords(url)
    encoding_features = analyze_encoding(url)
    query_features = analyze_query(parsed_url)

    uses_https = parsed_url.scheme.lower() == "https"
    uses_at_symbol = "@" in url
    features = { "url" : url,
           **domain_features,
           **path_features,
           **keyword_features,
           **encoding_features,
           **query_features,
           "uses_https" : uses_https,
           "uses_at_symbol" : uses_at_symbol
           }
    risk_results = calculate_risk_score(features)

    features["risk_score"] = risk_results["score"]
    features["risk_reasons"] = risk_results["reasons"]
    features["risk_level"] = risk_results["risk_level"]
    return features
def analyze_domain(hostname):
    uses_ip = is_ip_address(hostname)
    if uses_ip:
        subdomain_count = 0
    else:
        extracted = tldextract.extract(hostname)
        subdomain_count = len(extracted.subdomain.split(".")) if extracted.subdomain else 0
    contains_unicode = any(ord(chr) > 127 for chr in hostname)
    idna_hostname = get_hostname_idna(hostname)
    has_punycode = "xn--" in idna_hostname.lower()

    return {"domain": hostname,
             "uses_ip": uses_ip,
             "subdomain_count" : subdomain_count,
             "contains_unicode" : contains_unicode,
             "has_punycode" : has_punycode
             }
def analyze_path(parsed_url):
    path = parsed_url.path
    return{"path" : path,
           "path_length" : len(path),
           "slash_count" : path.count("/")
           }
def analyze_keywords(url):
    url_lower = url.lower()
    found_keywords = [keyword for keyword in SUSPICIOUS_KEYWORDS
                      if keyword in url_lower
                           ]
    return{"suspicious_keywords" : found_keywords,
           "keyword_count" : len(found_keywords)
           }
def analyze_encoding(url):
    decode_url = unquote(url)
    return {"decoded_url" : decode_url,
            "has_encoded_characters" : decode_url != url 
            }
def analyze_query(parsed_url):
    query = parsed_url.query
    parameters = parse_qs(query)
    return{"query" : query,
           "query_length" : len(query),
           "parameter_count" : len(parameters)
           }

