# DETECTION_ENGINE.PY
import re
import math
import socket
import pandas as pd
from urllib.parse import urlparse
import whois
from datetime import datetime, timezone

SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "password",
    "bank",
    "paypal",
    "signin",
    "confirm"
]

SUSPICIOUS_TLDS = [
    ".ru",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".top",
    ".xyz",
    ".click"
]

SHORTENED_DOMAINS = [
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "ow.ly",
    "cutt.ly",
    "forms.gle",
    "t.co",
    "is.gd"
]

DEFAULT_THRESHOLD = 0.6


def calculate_entropy(text):
    if len(text) == 0:
        return 0

    probabilities = [
        float(text.count(c)) / len(text)
        for c in dict.fromkeys(text)
    ]

    return -sum(
        p * math.log2(p)
        for p in probabilities
    )


def extract_features(url):
    url = str(url).strip().rstrip("/")
    url = str(url)
    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    # Domain Length
    domain_length = len(domain)

    # Path Length
    path_length = len(parsed.path)

    # Query Count
    query_count = len(parsed.query.split("&")) if parsed.query else 0

    # Special Character Count
    special_char_count = len(
        re.findall(r'[^a-zA-Z0-9]', url)
    )

    # TLD Length
    parts = domain.split(".")
    tld_length = len(parts[-1]) if len(parts) > 1 else 0

    # Suspicious Keyword Count
    keyword_count = sum(
        1 for keyword in SUSPICIOUS_KEYWORDS
        if keyword in url.lower()
    )

    # URL Length
    url_length = len(url)

    # URL Depth
    url_depth = len([x for x in parsed.path.split("/") if x])

    # Have IP Address
    has_ip = 1 if re.search(r'(\d{1,3}\.){3}\d{1,3}', domain) else 0

    # Have @ Symbol
    has_at = 1 if "@" in url else 0

    # Double Slash Redirect
    double_slash_redirect = 1 if url.rfind("//") > 7 else 0

    # Is URL scheme HTTPS
    is_https = 1 if parsed.scheme == "https" else 0

    # Port
    port = parsed.port if parsed.port else 0

    # Fragment Length
    fragment_length = len(parsed.fragment)

    # Hyphen in Domain
    has_hyphen = 1 if "-" in domain else 0

    # Subdomain Count
    subdomain_count = domain.count(".")

    # Digit Count
    digit_count = sum(
        c.isdigit() for c in url
    )

    # URL Entropy
    url_entropy = calculate_entropy(url)

    feature_df = pd.DataFrame(
        [[
            url_length,
            url_depth,
            has_ip,
            has_at,
            double_slash_redirect,
            has_hyphen,
            subdomain_count,
            digit_count,
            round(url_entropy, 6),
            domain_length,
            path_length,
            query_count,
            special_char_count,
            tld_length,
            keyword_count,
            port,
            fragment_length,
            is_https
        ]],
        columns=[
            "url_length",
            "url_depth",
            "has_ip",
            "has_at",
            "double_slash_redirect",
            "has_hyphen",
            "subdomain_count",
            "digit_count",
            "url_entropy",
            "domain_length",
            "path_length",
            "query_count",
            "special_char_count",
            "tld_length",
            "keyword_count",
            "port",
            "fragment_length",
            "is_https"
        ]
    )

    feature_info = {
        "URL Length": url_length,
        "URL Depth": url_depth,
        "Has IP": has_ip,
        "Has @": has_at,
        "Double Slash Redirect": double_slash_redirect,
        "Is HTTPS": is_https,
        "Has Hyphen": has_hyphen,
        "Subdomain Count": subdomain_count,
        "Digit Count": digit_count,
        "URL Entropy": round(url_entropy, 6),
        "Domain Length": domain_length,
        "Path Length": path_length,
        "Query Count": query_count,
        "Special Char Count": special_char_count,
        "TLD Length": tld_length,
        "Keyword Count": keyword_count,
        "Port": port,
        "Fragment Length": fragment_length
    }

    return feature_df, feature_info


def dns_check(domain):
    try:
        domain = str(domain).split(":")[0]
        socket.gethostbyname(domain)
        return True
    except Exception:
        return False


def get_domain_metadata(url):

    try:

        parsed = urlparse(url)

        domain = parsed.netloc.lower()

        ip_address = socket.gethostbyname(domain)

        w = whois.whois(domain)

        created = w.creation_date
        updated = w.updated_date
        expired = w.expiration_date

        if isinstance(created, list):
            created = created[0]

        if isinstance(updated, list):
            updated = updated[0]

        if isinstance(expired, list):
            expired = expired[0]

        age = 0

        #if created:
            #age = (datetime.now() - created).days

        if created:
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
                age = (
                    datetime.now(timezone.utc) - created
                    ).days

        return {
            "ipAddress": ip_address,
            "urlRegistrar": str(w.registrar or ""),
            "urlCreated": created,
            "urlUpdated": updated,
            "urlExpired": expired,
            "urlAge": age
        }

    except Exception as e:

        print("WHOIS ERROR:", e)

        return {
            "ipAddress": "",
            "urlRegistrar": "",
            "urlCreated": None,
            "urlUpdated": None,
            "urlExpired": None,
            "urlAge": 0
        }


def suspicious_pattern_check(url, domain):
    reasons = []
    url_lower = url.lower()

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url_lower:
            reasons.append(f"Keyword Detected ({keyword})")

    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            reasons.append(f"Suspicious TLD ({tld})")

    if re.search(r"g00gle|goog1e|paypa1|faceb00k|micr0soft", domain):
        reasons.append("Brand Impersonation Detected")

    return reasons


def predict_url(model, url):
    print("TYPE =", type(url))
    print("VALUE =", repr(url))

    features, feature_info = extract_features(url)
    if hasattr(model, 'feature_names_in_'):
        features = features.reindex(columns=model.feature_names_in_)

    probability = model.predict_proba(features)[0]
    class_order = list(model.classes_)

    phishing_index = class_order.index(0) if 0 in class_order else 0
    safe_index = class_order.index(1) if 1 in class_order else (1 if len(probability) > 1 else phishing_index)

    phishing_prob = float(probability[phishing_index])
    safe_prob = float(probability[safe_index]) if safe_index < len(probability) else 0.0

    prediction = int(model.predict(features)[0])
    ml_result = "PHISHING" if prediction == 0 else "SAFE"
    confidence = phishing_prob if prediction == 0 else safe_prob

    # threshold = DEFAULT_THRESHOLD
    # ml_result = "PHISHING" if phishing_prob >= threshold else "SAFE"
    # confidence = phishing_prob if ml_result == "PHISHING" else safe_prob

    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    metadata = get_domain_metadata(url)
    https_valid = parsed.scheme == "https"
    dns_valid = dns_check(domain)
    suspicious_reasons = suspicious_pattern_check(url, domain)

    # Rule-base final status
    final_status = "SAFE" if (https_valid and dns_valid and not suspicious_reasons) else "SUSPICIOUS"
    # final_status = "SUSPICIOUS" if ml_result == "PHISHING" or suspicious_reasons else "SAFE"

    return {
        "url": url,

        "ml_result": ml_result,
        "final_status": final_status,

        "confidence": round(confidence * 100, 2),

        "https": https_valid,
        "dns": dns_valid,

        "ipAddress": metadata["ipAddress"],

        "urlLength": len(url),
        "urlProtocol": parsed.scheme,
        "urlDomain": domain,

        "urlRegistrar": metadata["urlRegistrar"],
        "urlCreated": metadata["urlCreated"],
        "urlUpdated": metadata["urlUpdated"],
        "urlExpired": metadata["urlExpired"],
        "urlAge": metadata["urlAge"],

        "probability": {
            "phishing": phishing_prob,
            "safe": safe_prob
        },

        "feature_info": feature_info,
        "suspicious_reasons": suspicious_reasons
    }
