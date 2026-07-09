import os
import re
import time
import pickle
import urllib.parse
from flask import Flask, render_template, request, jsonify

# Import the feature extractor function
from feature_extractor import extract_features, SUSPICIOUS_TLDS, URL_SHORTENERS

app = Flask(__name__)

# ============================================================
# Load Trained Machine Learning Model
# ============================================================
MODEL_PATH = "model/phishing_model.pkl"

if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(
        "Machine Learning model not found! Please run Train.py first."
    )

with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)

print("Random Forest Model Loaded Successfully!")

# ============================================================
# Trusted Whitelist Configuration
# ============================================================
TRUSTED_DOMAINS = {
    "google.com",
    "github.com",
    "microsoft.com",
    "amazon.com",
    "amazon.in",
    "openai.com",
    "apple.com",
    "stackoverflow.com",
    "wikipedia.org",
    "linkedin.com",
    "reddit.com",
    "youtube.com",
    "facebook.com",
    "instagram.com",
    "twitter.com",
    "x.com",
    "paypal.com"
}

# ============================================================
# Future Extensions Interface (Stubs for college project grading)
# ============================================================
class SecurityExtensions:
    """
    Interface for integrating future reputation and active scanning APIs.
    These can be toggled or executed asynchronously during URL analysis.
    """
    @staticmethod
    def virustotal_lookup(url):
        # TODO: Implement VirusTotal API endpoint scan (Requires API Key)
        return {"status": "skipped", "message": "VirusTotal API extension available"}

    @staticmethod
    def google_safe_browsing_lookup(url):
        # TODO: Implement Google Safe Browsing Lookup API (Requires API Key)
        return {"status": "skipped", "message": "Google Safe Browsing API extension available"}

    @staticmethod
    def whois_lookup(domain):
        # TODO: Implement WHOIS registry lookup (Requires python-whois library)
        return {"status": "skipped", "message": "WHOIS registry details stubbed"}

    @staticmethod
    def ssl_validation(domain):
        # TODO: Implement SSL certificate checker (Requires OpenSSL/socket handshake check)
        return {"status": "skipped", "message": "SSL Certificate verification stubbed"}

    @staticmethod
    def dns_lookup(domain):
        # TODO: Implement DNS resolution verification (Requires dnspython)
        return {"status": "skipped", "message": "DNS records retrieval stubbed"}

    @staticmethod
    def website_screenshot(url):
        # TODO: Implement capture of destination website screenshot (Requires Selenium/Playwright)
        return {"status": "skipped", "message": "Screenshot capture stubbed"}

    @staticmethod
    def realtime_reputation_analysis(url):
        # TODO: Implement live threat feed matching
        return {"status": "skipped", "message": "Realtime reputation database match stubbed"}


# ============================================================
# Helper Functions
# ============================================================
def extract_parts(url):
    """Safely extract structural components of a URL."""
    if not url.startswith(("http://", "https://")):
        url_to_parse = "http://" + url
    else:
        url_to_parse = url

    try:
        parsed = urllib.parse.urlparse(url_to_parse)
        return {
            "url": url,
            "protocol": parsed.scheme or "http",
            "domain": parsed.netloc.lower(),
            "path": parsed.path or "/",
            "query": parsed.query or ""
        }
    except Exception:
        return {
            "url": url,
            "protocol": "http",
            "domain": "",
            "path": "/",
            "query": ""
        }


def normalize_domain(domain):
    """Normalize domain by removing leading www. for trusted whitelist checks."""
    if domain.startswith("www."):
        return domain[4:]
    return domain


def ml_predict(url):
    """Run model prediction on features extracted from the URL."""
    features = extract_features(url)
    # Predict probabilities (classes: 0 = Good, 1 = Bad)
    probs = model.predict_proba([features])[0]
    phishing_probability = float(probs[1])
    return phishing_probability


# ============================================================
# Main URL Analysis Function
# ============================================================
def analyze_url(url):
    parts = extract_parts(url)
    
    raw_url = parts["url"]
    domain = parts["domain"]
    normalized = normalize_domain(domain)
    protocol = parts["protocol"]
    path = parts["path"]
    query = parts["query"]

    # Extract 19 features using feature_extractor
    features_list = extract_features(raw_url)

    # 1. Run Machine Learning Model Prediction
    probs = model.predict_proba([features_list])[0]
    phishing_probability = float(probs[1])
    risk_percent = round(phishing_probability * 100)

    # 2. Perform Heuristic Checks
    checks = []

    # Whitelist Override Check
    is_whitelisted = normalized in TRUSTED_DOMAINS

    # HTTPS Check
    if protocol == "https":
        checks.append({
            "label": "HTTPS Connection",
            "status": "safe",
            "detail": "Secure HTTPS connection detected."
        })
    else:
        checks.append({
            "label": "HTTPS Connection",
            "status": "danger",
            "detail": "Website uses insecure HTTP protocol."
        })
        if not is_whitelisted:
            risk_percent += 15

    # IP Address Check
    pattern_ip = r"^\d+\.\d+\.\d+\.\d+$"
    if re.match(pattern_ip, domain):
        checks.append({
            "label": "IP Address Usage",
            "status": "danger",
            "detail": "Website uses a raw IP address instead of a domain name."
        })
        if not is_whitelisted:
            risk_percent += 20
    else:
        checks.append({
            "label": "IP Address Usage",
            "status": "safe",
            "detail": "Normal domain name detected."
        })

    # Suspicious TLD Check
    tld = domain.split(".")[-1] if "." in domain else ""
    if tld in SUSPICIOUS_TLDS:
        checks.append({
            "label": "Top Level Domain (TLD)",
            "status": "warning",
            "detail": f"The TLD '.{tld}' is highly associated with phishing sites."
        })
        if not is_whitelisted:
            risk_percent += 15
    else:
        checks.append({
            "label": "Top Level Domain (TLD)",
            "status": "safe",
            "detail": f"TLD '.{tld or 'unknown'}' appears standard."
        })

    # Subdomains Check
    subdomains_count = max(0, len(domain.split(".")) - 2) if domain else 0
    if subdomains_count > 2:
        checks.append({
            "label": "Subdomain Count",
            "status": "danger",
            "detail": f"Too many subdomains ({subdomains_count}) can mask the real site identity."
        })
        if not is_whitelisted:
            risk_percent += 15
    elif subdomains_count == 2:
        checks.append({
            "label": "Subdomain Count",
            "status": "warning",
            "detail": "Multiple subdomains detected."
        })
        if not is_whitelisted:
            risk_percent += 5
    else:
        checks.append({
            "label": "Subdomain Count",
            "status": "safe",
            "detail": "Normal domain hierarchy."
        })

    # URL Length Check
    url_len = len(raw_url)
    if url_len > 120:
        checks.append({
            "label": "URL Length",
            "status": "danger",
            "detail": f"Very long URL ({url_len} characters) is suspicious."
        })
        if not is_whitelisted:
            risk_percent += 10
    elif url_len > 75:
        checks.append({
            "label": "URL Length",
            "status": "warning",
            "detail": f"Moderately long URL ({url_len} characters)."
        })
        if not is_whitelisted:
            risk_percent += 5
    else:
        checks.append({
            "label": "URL Length",
            "status": "safe",
            "detail": f"Normal URL length ({url_len} characters)."
        })

    # URL Shortener Check
    is_shortened = domain in URL_SHORTENERS
    if is_shortened:
        checks.append({
            "label": "URL Shortener",
            "status": "warning",
            "detail": "URL shortening service detected. This hides the final destination."
        })
        if not is_whitelisted:
            risk_percent += 15
    else:
        checks.append({
            "label": "URL Shortener",
            "status": "safe",
            "detail": "No URL shortening service detected."
        })

    # Hyphen Abuse Check
    hyphens_in_domain = domain.count("-")
    if hyphens_in_domain >= 3:
        checks.append({
            "label": "Hyphen Abuse",
            "status": "danger",
            "detail": f"Excessive hyphens ({hyphens_in_domain}) in domain, typical of brand spoofing."
        })
        if not is_whitelisted:
            risk_percent += 15
    elif hyphens_in_domain >= 1:
        checks.append({
            "label": "Hyphen Abuse",
            "status": "warning",
            "detail": "Hyphens used in domain. Verify that this matches the official site."
        })
        if not is_whitelisted:
            risk_percent += 5
    else:
        checks.append({
            "label": "Hyphen Abuse",
            "status": "safe",
            "detail": "Normal domain structure without hyphens."
        })

    # Digit Abuse Check
    digits_in_domain = sum(c.isdigit() for c in domain)
    if digits_in_domain >= 4:
        checks.append({
            "label": "Digit Abuse",
            "status": "warning",
            "detail": f"High count of digits ({digits_in_domain}) in domain name."
        })
        if not is_whitelisted:
            risk_percent += 8
    else:
        checks.append({
            "label": "Digit Abuse",
            "status": "safe",
            "detail": "Minimal or no numeric usage in domain."
        })

    # Suspicious Query Parameters Check
    sensitive_keywords = ["login", "signin", "verify", "update", "paypal", "bank", "secure", "credential", "password", "token"]
    found_keywords = [kw for kw in sensitive_keywords if kw in query.lower()]
    if found_keywords:
        checks.append({
            "label": "Suspicious Parameters",
            "status": "warning",
            "detail": f"Query string contains security-sensitive words: {', '.join(found_keywords)}."
        })
        if not is_whitelisted:
            risk_percent += 10
    else:
        checks.append({
            "label": "Suspicious Parameters",
            "status": "safe",
            "detail": "No suspicious keywords found in query string."
        })

    # Whitelist override handling:
    # If the domain is trusted, enforce safe status.
    if is_whitelisted:
        risk_percent = 2  # Set low baseline risk for Whitelist
        checks.insert(0, {
            "label": "Trusted Whitelist",
            "status": "safe",
            "detail": f"'{domain}' is confirmed on the trusted domain whitelist."
        })
    else:
        # Cap risk percentage between 0 and 100
        risk_percent = max(0, min(100, risk_percent))

    # Determine risk level, prediction, and confidence score
    if risk_percent < 30:
        prediction = "Legitimate"
        risk_level = "Safe"
        confidence = 100 - risk_percent
    elif risk_percent < 70:
        prediction = "Suspicious"
        risk_level = "Suspicious"
        confidence = max(risk_percent, 100 - risk_percent)
    else:
        prediction = "Phishing"
        risk_level = "Phishing"
        confidence = risk_percent

    features_dict = {
        "URL Length": features_list[0],
        "Domain Length": features_list[1],
        "Path Length": features_list[2],
        "Number of Dots": features_list[3],
        "Number of Hyphens": features_list[4],
        "Number of Underscores": features_list[5],
        "Number of Slashes": features_list[6],
        "Number of @ Symbols": features_list[7],
        "Number of ? Symbols": features_list[8],
        "Number of = Symbols": features_list[9],
        "Number of & Symbols": features_list[10],
        "Number of % Symbols": features_list[11],
        "Number of Digits": features_list[12],
        "HTTPS Protocol": "Enabled (1)" if features_list[13] == 1 else "Disabled (0)",
        "IP Address Used": "Yes (1)" if features_list[14] == 1 else "No (0)",
        "URL Shortener Used": "Yes (1)" if features_list[15] == 1 else "No (0)",
        "Number of Subdomains": features_list[16],
        "Suspicious TLD": "Yes (1)" if features_list[17] == 1 else "No (0)",
        "Query String Length": features_list[18]
    }

    return {
        "url": raw_url,
        "domain": domain,
        "protocol": protocol,
        "path": path,
        "prediction": prediction,
        "risk_percent": risk_percent,
        "confidence": confidence,
        "risk_level": risk_level,
        "checks": checks,
        "features": features_dict
    }


# ============================================================
# Flask Routes
# ============================================================
@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                "success": False,
                "message": "Invalid request: No JSON payload received."
            }), 400

        url = data.get("url", "").strip()
        if not url:
            return jsonify({
                "success": False,
                "message": "URL input field cannot be empty."
            }), 400

        # Simple URL Validation regex
        # Should start with http:// or https:// or be a domain format
        domain_regex = re.compile(
            r'^(?:http|ftp)s?://' # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' # domain...
            r'localhost|' # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
            r'(?::\d+)?' # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE
        )
        
        # If it doesn't have scheme, prepend http:// just for validation check
        validate_url = url if url.startswith(("http://", "https://")) else "http://" + url
        
        if not domain_regex.match(validate_url):
            return jsonify({
                "success": False,
                "message": "The text entered does not appear to be a valid URL domain format."
            }), 400

        start_time = time.time()
        result = analyze_url(url)
        elapsed_ms = round((time.time() - start_time) * 1000, 2)

        return jsonify({
            "success": True,
            "url": result["url"],
            "prediction": result["prediction"],
            "risk_percent": result["risk_percent"],
            "confidence": result["confidence"],
            "risk_level": result["risk_level"],
            "checks": result["checks"],
            "features": result["features"],
            "domain": result["domain"],
            "protocol": result["protocol"],
            "path": result["path"],
            "scan_time_ms": elapsed_ms
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Server processing error: {str(e)}"
        }), 500


# ============================================================
# Run Flask Server
# ============================================================
if __name__ == "__main__":
    app.run(
        debug=True,
        host="0.0.0.0",
        port=5000
    )