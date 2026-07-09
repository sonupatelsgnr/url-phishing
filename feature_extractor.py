import re
from urllib.parse import urlparse

# Suspicious TLDs commonly used for phishing
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq",
    "xyz", "top", "work", "click",
    "country", "stream", "download", "zip", "link", "buzz", "monster"
}

# Common URL shortening domains
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl",
    "t.co", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rb.gy"
}


def has_ip(domain):
    """Check if domain is an IP address."""
    if not domain:
        return 0
    pattern = r"^\d+\.\d+\.\d+\.\d+$"
    return 1 if re.match(pattern, domain) else 0


def is_shortener(domain):
    """Check if domain is a URL shortener."""
    if not domain:
        return 0
    return 1 if domain.lower() in URL_SHORTENERS else 0


def extract_features(url):
    """
    Safely extract 19 lexical and structural features from a URL.
    Handles malformed or empty URLs without crashing.
    """
    # Safe string conversion
    if not isinstance(url, str):
        url = str(url) if url is not None else ""

    url = url.strip()

    try:
        # Prepend protocol if missing to allow proper urlparse detection
        if url and not url.startswith(("http://", "https://")):
            url_to_parse = "http://" + url
        else:
            url_to_parse = url

        parsed = urlparse(url_to_parse)
        domain = parsed.netloc.lower()

        # Remove www. prefix if present for domain analysis
        if domain.startswith("www."):
            domain = domain[4:]

        path = parsed.path
        query = parsed.query
        scheme = parsed.scheme
    except Exception:
        domain = ""
        path = ""
        query = ""
        scheme = ""

    # Feature 1-3: Lengths
    url_len = len(url)
    domain_len = len(domain)
    path_len = len(path)

    # Feature 4-12: Character counts in the URL
    dots = url.count(".")
    hyphens = url.count("-")
    underscores = url.count("_")
    slashes = url.count("/")
    question_marks = url.count("?")
    equal_signs = url.count("=")
    ats = url.count("@")
    ampersands = url.count("&")
    percent = url.count("%")

    # Feature 13: Digits in the URL
    digits = sum(c.isdigit() for c in url)

    # Feature 14-16: Binary Flags (HTTPS, IP, Shortener)
    https_flag = 1 if scheme == "https" else 0
    ip_flag = has_ip(domain)
    shortener_flag = is_shortener(domain)

    # Feature 17: Subdomain count
    subdomains = max(0, len(domain.split(".")) - 2) if domain else 0

    # Feature 18: Suspicious TLD check
    tld = domain.split(".")[-1] if "." in domain else ""
    suspicious_tld_flag = 1 if tld in SUSPICIOUS_TLDS else 0

    # Feature 19: Query Length
    query_len = len(query)

    features = [
        url_len,
        domain_len,
        path_len,
        dots,
        hyphens,
        underscores,
        slashes,
        question_marks,
        equal_signs,
        ats,
        ampersands,
        percent,
        digits,
        https_flag,
        ip_flag,
        shortener_flag,
        subdomains,
        suspicious_tld_flag,
        query_len
    ]

    return features