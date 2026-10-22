def calculate_risk_score(features):
    score = 0
    reasons = []
    if features["uses_ip"]:
        score += 25
        reasons.append("URl uses an ip address")
    if features["uses_at_symbol"]:
        score += 25
        reasons.append("URL contains @ symbol")
    if features["contains_unicode"]:
        score += 15
        reasons.append("Domain contains unicode")
    if features["has_punycode"]:
        score += 20
        reasons.append("Domain contains punycode")
    if features["has_encoded_characters"]:
        score += 10
        reasons.append("URL contains encoded character(s)")
    if not features["uses_https"]:
       score += 5
       reasons.append("URL does not use https")
    if features["keyword_count"]:
        score += features["keyword_count"]*5
        reasons.append(f"URL contains {features['keyword_count']} suspicious keyword(s)")
    if features["subdomain_count"] > 2:
        score += 10
        reasons.append("Hostname has multiple subdomains")
    return {"score" : score,
            "reasons" : reasons,
            "risk_level" : get_risk_level(score)}

def get_risk_level(score):
    if score >= 60:
       return "high"
    elif score >= 30:
        return "medium"
    else:
        return "low"