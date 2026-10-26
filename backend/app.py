from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle, os, sys, re, requests, base64
from datetime import datetime
import pandas as pd
from urllib.parse import urlparse, quote

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

sys.path.insert(0, os.path.dirname(__file__))
from utils.feature_extractor import extract_features
from utils.qr_decoder import decode_qr_from_image

app = Flask(__name__)
CORS(app)

model_path = os.path.join(os.path.dirname(__file__), 'model', 'model.pkl')
model = pickle.load(open(model_path, 'rb'))

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ── PASTE YOUR API KEYS HERE ──────────────────────────────────────────────────
VIRUSTOTAL_API_KEY       = os.getenv("VIRUSTOTAL_API_KEY", "")
GOOGLE_SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "")
IPQS_API_KEY             = os.getenv("IPQS_API_KEY", "")
# ─────────────────────────────────────────────────────────────────────────────

TRUSTED_DOMAINS = {
    'google.com','google.co.in','youtube.com','facebook.com','instagram.com',
    'twitter.com','x.com','linkedin.com','whatsapp.com','amazon.in','amazon.com',
    'flipkart.com','myntra.com','paytm.com','phonepe.com','gpay.app',
    'hdfcbank.com','sbi.co.in','icicibank.com','axisbank.com','kotakbank.com',
    'irctc.co.in','naukri.com','zomato.com','swiggy.com','ola.com',
    'makemytrip.com','bookmyshow.com','bigbasket.com','meesho.com',
    'razorpay.com','billdesk.com','npci.org.in','wikipedia.org','wikimedia.org',
    'microsoft.com','apple.com','github.com','stackoverflow.com',
    'reddit.com','netflix.com','spotify.com','dropbox.com','zoom.us',
    'slack.com','notion.so','figma.com','bbc.com','cnn.com',
    'nytimes.com','timesofindia.com','ndtv.com','indianexpress.com',
    'maps.google.com','play.google.com','docs.google.com','drive.google.com',
    'accounts.google.com','mail.google.com','meet.google.com',
}

PHISHING_KEYWORDS = [
    'login','verify','secure','update','bank','paypal','confirm','account',
    'password','signin','alert','urgent','suspended','unlock','claim',
    'winner','prize','reward','free-gift','verify-now','act-now',
    'limited-time','account-suspended','billing-update','security-alert',
    'unusual-activity','validate','reactivate','credential','ebayisapi',
    'webscr','reset-password','recover-account',
]

SUSPICIOUS_TLDS = {
    '.xyz','.info','.online','.biz','.click','.link',
    '.tk','.ga','.ml','.cf','.gq','.top','.work','.party',
    '.loan','.download','.cricket','.racing','.win','.bid',
    '.stream','.gdn','.accountant','.science','.faith',
}


# ─────────────────────────────────────────────────────────────────────────────
#  QR CONTENT TYPE DETECTOR — handles non-URL QR codes correctly
# ─────────────────────────────────────────────────────────────────────────────

def detect_qr_content_type(raw):
    """
    Returns dict:
      type    : 'upi' | 'url' | 'tel' | 'mailto' | 'wifi' | 'sms' | 'text'
      safe    : True/False/None
      reason  : explanation string
      display : clean display string for frontend
    """
    raw = raw.strip()
    low = raw.lower()

    # ── UPI Payment QR ───────────────────────────────────────────────────────
    if low.startswith('upi://'):
        # Parse UPI fields
        upi_id   = ''
        name     = ''
        amount   = ''
        try:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(raw)
            params = parse_qs(parsed.query)
            upi_id = params.get('pa', [''])[0]
            name   = params.get('pn', [''])[0].replace('%20', ' ')
            amount = params.get('am', [''])[0]
        except Exception:
            pass

        # Validate UPI ID format: localpart@provider
        import re
        valid_upi = bool(re.match(r'^[\w.\-]+@[\w]+$', upi_id)) if upi_id else False

        # Known legitimate UPI handles (bank/wallet suffixes)
        LEGIT_UPI_HANDLES = {
            'oksbi','okaxis','okicici','okhdfcbank','ybl','ibl','axl',
            'paytm','upi','apl','barodampay','cboi','centralbank','dbs',
            'equitas','federal','freecharge','hsbc','idbi','idfcbank',
            'indus','jsb','kotak','mahb','myicici','obc','okbizaxis',
            'pnb','postpay','psb','ptsbi','ptyes','rbl','sc','scmobile',
            'sib','syndicate','tjsb','ubi','uboi','ucb','unionbank',
            'united','utbi','utiitsl','vijb','waaxis','wahdfcbank',
            'waicici','wasbi','yesbankltd','oksbi','okaxis',
            'bhim','gpay','phonepe','amazonpay',
        }
        handle = upi_id.split('@')[-1].lower() if '@' in upi_id else ''
        known_handle = handle in LEGIT_UPI_HANDLES

        return {
            'type':       'upi',
            'safe':       True,           # UPI QR cannot steal data
            'reason':     'UPI Payment QR code — safe by design. UPI requires PIN to complete payment.',
            'display':    raw,
            'upi_id':     upi_id,
            'name':       name,
            'amount':     amount,
            'valid_format': valid_upi,
            'known_handle': known_handle,
        }

    # ── Phone number ─────────────────────────────────────────────────────────
    if low.startswith('tel:'):
        number = raw[4:].strip()
        return {
            'type': 'tel', 'safe': True,
            'reason': 'Phone number QR — safe',
            'display': number
        }

    # ── SMS ──────────────────────────────────────────────────────────────────
    if low.startswith('sms:'):
        return {
            'type': 'sms', 'safe': True,
            'reason': 'SMS QR code — safe',
            'display': raw[4:]
        }

    # ── Email ────────────────────────────────────────────────────────────────
    if low.startswith('mailto:'):
        return {
            'type': 'mailto', 'safe': True,
            'reason': 'Email QR code — safe',
            'display': raw[7:]
        }

    # ── WiFi ─────────────────────────────────────────────────────────────────
    if low.startswith('wifi:'):
        return {
            'type': 'wifi', 'safe': True,
            'reason': 'WiFi credentials QR — safe',
            'display': raw
        }

    # ── Plain text ───────────────────────────────────────────────────────────
    if not low.startswith('http') and '.' not in raw[:50]:
        return {
            'type': 'text', 'safe': True,
            'reason': 'Plain text QR — no URL detected',
            'display': raw
        }

    # ── URL — needs full scanning ─────────────────────────────────────────────
    return {
        'type': 'url', 'safe': None,
        'reason': 'URL detected — running full phishing analysis',
        'display': raw
    }



# ─────────────────────────────────────────────────────────────────────────────
#  RULE-BASED URL RISK SCORER
# ─────────────────────────────────────────────────────────────────────────────
def compute_url_risk(url):
    score = 0
    reasons = []
    try:
        parsed = urlparse(url)
    except Exception:
        return 85, ["Could not parse URL"]

    domain      = (parsed.netloc or '').lower()
    domain_clean = re.sub(r'^www\.', '', domain).split(':')[0]
    scheme      = (parsed.scheme or '').lower()
    path        = (parsed.path or '').lower()
    query       = (parsed.query or '').lower()
    full_url    = url.lower()
    root_domain = '.'.join(domain_clean.split('.')[-2:]) if '.' in domain_clean else domain_clean

    # Trust signals
    if root_domain in TRUSTED_DOMAINS or domain_clean in TRUSTED_DOMAINS:
        score -= 55
        reasons.append(f"Trusted domain ({root_domain}) -55")
    if scheme == 'https':
        score -= 8
        reasons.append("HTTPS -8")
    if len(url) < 50 and scheme == 'https' and domain_clean.count('.') <= 2:
        score -= 5
        reasons.append("Short clean URL -5")

    # Risk signals
    if scheme == 'http':
        score += 20
        reasons.append("HTTP not HTTPS +20")
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain_clean):
        score += 45
        reasons.append("IP address as domain +45")
    tld = '.' + domain_clean.split('.')[-1] if '.' in domain_clean else ''
    if tld in SUSPICIOUS_TLDS:
        score += 32
        reasons.append(f"Suspicious TLD ({tld}) +32")
    hits = [kw for kw in PHISHING_KEYWORDS if kw in full_url]
    if hits:
        kw_score = min(len(hits) * 12, 40)
        score += kw_score
        reasons.append(f"Phishing keywords: {', '.join(hits[:4])} +{kw_score}")
    hyphens = domain_clean.count('-')
    if hyphens >= 3:
        score += hyphens * 12
        reasons.append(f"{hyphens} hyphens in domain +{hyphens*12}")
    elif hyphens == 2:
        score += 18
        reasons.append("2 hyphens in domain +18")
    elif hyphens == 1:
        score += 8
        reasons.append("Hyphen in domain +8")
    dots = domain_clean.count('.')
    if dots >= 3:
        add = (dots - 2) * 15
        score += add
        reasons.append(f"Excessive subdomains ({dots} dots) +{add}")
    if '@' in url:
        score += 35
        reasons.append("@ symbol in URL +35")
    if re.search(r'(?<!:)//', path):
        score += 25
        reasons.append("Double slash in path +25")
    if len(url) > 120:
        score += 22
        reasons.append(f"Very long URL ({len(url)}) +22")
    elif len(url) > 80:
        score += 12
        reasons.append(f"Long URL ({len(url)}) +12")
    digit_count = sum(c.isdigit() for c in domain_clean)
    if digit_count >= 5:
        score += 18
        reasons.append(f"Many digits in domain ({digit_count}) +18")
    elif digit_count >= 3:
        score += 9
        reasons.append(f"Digits in domain ({digit_count}) +9")
    if parsed.port and parsed.port not in (80, 443):
        score += 28
        reasons.append(f"Non-standard port ({parsed.port}) +28")
    pct = url.count('%')
    if pct >= 3:
        score += 18
        reasons.append("Heavy URL encoding +18")
    elif pct >= 1:
        score += 6
        reasons.append("URL encoding present +6")
    consonants  = sum(1 for c in root_domain.replace('.','') if c in 'bcdfghjklmnpqrstvwxyz')
    total_alpha = sum(1 for c in root_domain.replace('.','') if c.isalpha())
    if total_alpha > 5 and consonants / max(total_alpha, 1) > 0.75:
        score += 15
        reasons.append("Random-looking domain name +15")

    # If no risk signals fired, explain why it's clean
    if score <= 0 and not reasons:
        reasons.append("No suspicious signals detected in URL structure")
    if scheme == 'https' and root_domain in TRUSTED_DOMAINS:
        reasons = [r for r in reasons if r]  # keep existing
        if not any('Trusted' in r for r in reasons):
            reasons.insert(0, f"Trusted domain ({root_domain}) — verified safe")
    return max(0, min(100, score)), reasons


# ─────────────────────────────────────────────────────────────────────────────
#  LIVE DATABASE 1: URLhaus (abuse.ch) — free, no key
# ─────────────────────────────────────────────────────────────────────────────
def check_urlhaus(url):
    try:
        r = requests.post("https://urlhaus-api.abuse.ch/v1/url/",
                          data={"url": url}, timeout=7)
        if r.status_code == 200:
            d = r.json()
            if d.get("query_status") == "is_listed":
                tags   = d.get("tags") or []
                threat = d.get("threat", "malware")
                return {"flagged": True,
                        "detail": f"Listed as '{threat}'. Tags: {', '.join(tags) if tags else 'none'}"}
            return {"flagged": False, "detail": "Not in URLhaus malware database"}
    except Exception:
        pass
    return {"flagged": None, "detail": "Unavailable"}


# ─────────────────────────────────────────────────────────────────────────────
#  LIVE DATABASE 2: PhishTank — free, no key
# ─────────────────────────────────────────────────────────────────────────────
def check_phishtank(url):
    try:
        r = requests.post(
            "https://checkurl.phishtank.com/checkurl/",
            data={"url": quote(url, safe=''), "format": "json", "app_key": ""},
            headers={"User-Agent": "phishtank/QRGuard"}, timeout=7)
        if r.status_code == 200:
            res = r.json().get("results", {})
            if res.get("in_database"):
                if res.get("valid"):
                    return {"flagged": True,
                            "detail": "Confirmed phishing URL in PhishTank database"}
                return {"flagged": False, "detail": "In database, not confirmed phish"}
            return {"flagged": False, "detail": "Not in PhishTank database"}
    except Exception:
        pass
    return {"flagged": None, "detail": "Unavailable"}


# ─────────────────────────────────────────────────────────────────────────────
#  LIVE DATABASE 3: Google Safe Browsing — free with key
# ─────────────────────────────────────────────────────────────────────────────
def check_google_safe_browsing(url):
    try:
        if GOOGLE_SAFE_BROWSING_KEY and "PASTE" not in GOOGLE_SAFE_BROWSING_KEY:
            payload = {
                "client": {"clientId": "QRGuard", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE","SOCIAL_ENGINEERING",
                                    "UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            r = requests.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_KEY}",
                json=payload, timeout=6)
            if r.status_code == 200:
                data = r.json()
                if data.get("matches"):
                    threat = data["matches"][0].get("threatType", "THREAT")
                    return {"flagged": True, "detail": f"Google flagged as {threat}"}
                return {"flagged": False, "detail": "Not flagged by Google Safe Browsing"}
            return {"flagged": None, "detail": f"API error {r.status_code}"}
        else:
            domain = urlparse(url).netloc
            r = requests.get(
                f"https://transparencyreport.google.com/transparencyreport/api/v3/safebrowsing/status?site={domain}",
                timeout=6, headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code == 200:
                if any(x in r.text for x in ['"SOCIAL_ENGINEERING"','"MALWARE"','"UNWANTED_SOFTWARE"']):
                    return {"flagged": True, "detail": "Flagged as dangerous by Google"}
                return {"flagged": False, "detail": "Not flagged by Google"}
    except Exception:
        pass
    return {"flagged": None, "detail": "Unavailable"}


# ─────────────────────────────────────────────────────────────────────────────
#  LIVE DATABASE 4: VirusTotal — free with key (500/day)
# ─────────────────────────────────────────────────────────────────────────────
def check_virustotal(url):
    try:
        if VIRUSTOTAL_API_KEY and "PASTE" not in VIRUSTOTAL_API_KEY:
            headers = {"x-apikey": VIRUSTOTAL_API_KEY,
                       "Content-Type": "application/x-www-form-urlencoded"}
            requests.post("https://www.virustotal.com/api/v3/urls",
                          data=f"url={quote(url, safe='')}",
                          headers=headers, timeout=8)
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            r = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}",
                             headers={"x-apikey": VIRUSTOTAL_API_KEY}, timeout=8)
            if r.status_code == 200:
                stats = r.json().get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
                mal = stats.get("malicious", 0)
                sus = stats.get("suspicious", 0)
                har = stats.get("harmless", 0)
                uns = stats.get("undetected", 0)
                tot = mal + sus + har + uns
                return {"flagged": mal > 0 or sus > 0,
                        "malicious": mal, "suspicious_count": sus,
                        "harmless": har, "total_engines": tot,
                        "detail": f"{mal} malicious, {sus} suspicious / {tot} engines"}
    except Exception:
        pass
    return {"flagged": None, "detail": "Unavailable"}


# ─────────────────────────────────────────────────────────────────────────────
#  LIVE DATABASE 5: PhishStats — free, no key (live phishing feed)
# ─────────────────────────────────────────────────────────────────────────────
def check_phishstats(url):
    try:
        encoded = quote(url, safe='')
        r = requests.get(
            f"https://phishstats.info:2096/api/phishing?_where=(url,like,~{encoded}~)&_size=1",
            timeout=7,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if r.status_code == 200:
            data = r.json()
            if isinstance(data, list) and len(data) > 0:
                score = data[0].get("score", 0)
                return {
                    "flagged": True,
                    "detail": f"Found in PhishStats database. Risk score: {score}/10"
                }
            return {"flagged": False, "detail": "Not found in PhishStats database"}
    except Exception:
        pass
    return {"flagged": None, "detail": "Unavailable"}


# ─────────────────────────────────────────────────────────────────────────────
#  LIVE DATABASE 6: IPQualityScore — free (5000/month with key)
# ─────────────────────────────────────────────────────────────────────────────
def check_ipqualityscore(url):
    try:
        if IPQS_API_KEY and "PASTE" not in IPQS_API_KEY and IPQS_API_KEY != "":
            encoded = quote(url, safe='')
            r = requests.get(
                f"https://www.ipqualityscore.com/api/json/url/{IPQS_API_KEY}/{encoded}",
                timeout=7
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("success"):
                    phishing   = data.get("phishing", False)
                    malware    = data.get("malware", False)
                    suspicious = data.get("suspicious", False)
                    risk_score = data.get("risk_score", 0)
                    flagged    = phishing or malware or suspicious or risk_score >= 75
                    detail_parts = []
                    if phishing:   detail_parts.append("phishing")
                    if malware:    detail_parts.append("malware")
                    if suspicious: detail_parts.append("suspicious")
                    detail = f"Risk score: {risk_score}/100"
                    if detail_parts:
                        detail += f". Flagged as: {', '.join(detail_parts)}"
                    return {"flagged": flagged, "detail": detail,
                            "risk_score": risk_score}
    except Exception:
        pass
    return {"flagged": None, "detail": "Add free key at ipqualityscore.com (5000/month free)"}


# ─────────────────────────────────────────────────────────────────────────────
#  LIVE DATABASE 7: Scamalytics — free tier
# ─────────────────────────────────────────────────────────────────────────────
def check_scamalytics(url):
    try:
        domain = re.sub(r'^www\.', '', urlparse(url).netloc).split(':')[0]
        if not domain:
            return {"flagged": None, "detail": "Could not extract domain"}
        r = requests.get(
            f"https://scamalytics.com/ip/{domain}",
            timeout=6,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if r.status_code == 200:
            text = r.text.lower()
            if 'fraud score: 100' in text or 'very high risk' in text:
                return {"flagged": True, "detail": "Very high fraud risk on Scamalytics"}
            elif 'high risk' in text:
                return {"flagged": True, "detail": "High fraud risk on Scamalytics"}
            elif 'low risk' in text or 'very low' in text:
                return {"flagged": False, "detail": "Low risk on Scamalytics"}
            return {"flagged": None, "detail": "Checked Scamalytics — inconclusive"}
    except Exception:
        pass
    return {"flagged": None, "detail": "Unavailable"}


# ─────────────────────────────────────────────────────────────────────────────
#  LIVE DATABASE 8: WHOIS / RDAP domain age
# ─────────────────────────────────────────────────────────────────────────────
def check_domain_age(url):
    try:
        domain = re.sub(r'^www\.', '', urlparse(url).netloc).split(':')[0]
        if not domain or re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
            return {"domain": domain or "N/A", "created": "N/A",
                    "registrar": "N/A", "age_days": None, "suspicious": False}
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=6)
        if r.status_code == 200:
            data     = r.json()
            events   = data.get("events", [])
            created  = next((e["eventDate"] for e in events
                             if e.get("eventAction") == "registration"), None)
            age_days = None
            if created:
                try:
                    age_days = (datetime.now() - datetime.fromisoformat(created[:10])).days
                except Exception:
                    pass
            registrar = "Unknown"
            for e in data.get("entities", []):
                if "registrar" in e.get("roles", []):
                    vc = e.get("vcardArray") or []
                    if len(vc) > 1:
                        for item in vc[1]:
                            if item[0] == "fn":
                                registrar = item[3]; break
            return {"domain": domain,
                    "created": created[:10] if created else "Unknown",
                    "registrar": registrar,
                    "age_days": age_days,
                    "suspicious": age_days is not None and age_days < 30}
    except Exception:
        pass
    try:
        domain = re.sub(r'^www\.', '', urlparse(url).netloc).split(':')[0]
        return {"domain": domain, "created": "Unknown", "registrar": "Unknown",
                "age_days": None, "suspicious": False}
    except Exception:
        pass
    return {"domain": "", "created": "Unknown", "registrar": "Unknown",
            "age_days": None, "suspicious": False}


# ─────────────────────────────────────────────────────────────────────────────
#  ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────
# In-memory scan history (persists while Flask is running)
scan_history = []

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "running"})

@app.route('/history', methods=['GET'])
def get_history():
    return jsonify({"history": scan_history[-50:][::-1]})  # last 50, newest first

@app.route('/history/clear', methods=['DELETE'])
def clear_history():
    scan_history.clear()
    return jsonify({"message": "History cleared"})


@app.route('/scan', methods=['POST'])
def scan():
    if 'image' not in request.files:
        return jsonify({"error": "No image uploaded"}), 400
    file = request.files['image']
    if not file.filename:
        return jsonify({"error": "Empty filename"}), 400

    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)

    # 1 ── Decode QR
    raw = decode_qr_from_image(filepath)
    if not raw:
        return jsonify({"error": "No QR code found in image"}), 400

    # Clean URL string
    if isinstance(raw, pd.Series):
        url = str(raw.iloc[0]).strip()
    else:
        url = str(raw).strip()
    url = re.sub(r'^\d+\s+', '', url)
    url = re.sub(r'\s+Name:.*$', '', url)
    url = url.strip()

    # 2 ── Detect QR content type FIRST
    qr_info = detect_qr_content_type(url)

    # ── Handle non-URL QR types immediately (no phishing scan needed) ────────
    if qr_info['type'] == 'upi':
        upi_id = qr_info.get('upi_id', '')
        name   = qr_info.get('name', '')
        known  = qr_info.get('known_handle', False)
        valid  = qr_info.get('valid_format', False)
        risk   = 5 if known else 15   # known bank handle = very low risk
        # Save UPI to history
        scan_history.append({
            "id":          len(scan_history) + 1,
            "timestamp":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "url":         upi_id,
            "result":      "LEGITIMATE",
            "is_phishing": False,
            "confidence":  risk,
            "qr_type":     "upi",
            "flags_count": 0,
        })

        return jsonify({
            "url":          url,
            "result":       "LEGITIMATE",
            "is_phishing":  False,
            "confidence":   risk,
            "qr_type":      "upi",
            "risk_reasons": ["UPI Payment QR — safe by design",
                             f"UPI ID: {upi_id}",
                             f"Recipient: {name}",
                             f"Known bank handle: {'Yes' if known else 'Unknown'}"],
            "ml":           {"prediction": "LEGITIMATE", "phishing_probability": risk, "confidence": 100 - risk},
            "live_checks": {
                "urlhaus":             {"flagged": False, "detail": "UPI QR — not a web URL"},
                "phishtank":           {"flagged": False, "detail": "UPI QR — not a web URL"},
                "google_safebrowsing": {"flagged": False, "detail": "UPI QR — not a web URL"},
                "virustotal":          {"flagged": False, "detail": "UPI QR — not a web URL"},
                "phishstats":          {"flagged": False, "detail": "UPI QR — not a web URL"},
                "ipqualityscore":      {"flagged": False, "detail": "UPI QR — not a web URL"},
                "scamalytics":         {"flagged": False, "detail": "UPI QR — not a web URL"},
            },
            "domain_info":  {"domain": "UPI Payment", "created": "N/A",
                             "registrar": "NPCI (National Payments Corporation of India)",
                             "age_days": None, "suspicious": False},
            "flags_count":  0,
            "upi_details":  {"upi_id": upi_id, "name": name,
                             "amount": qr_info.get('amount',''),
                             "known_handle": known, "valid_format": valid}
        })

    if qr_info['type'] in ('tel', 'sms', 'mailto', 'wifi', 'text'):
        return jsonify({
            "url":          url,
            "result":       "LEGITIMATE",
            "is_phishing":  False,
            "confidence":   2,
            "qr_type":      qr_info['type'],
            "risk_reasons": [qr_info['reason']],
            "ml":           {"prediction": "LEGITIMATE", "phishing_probability": 2, "confidence": 98},
            "live_checks": {k: {"flagged": False, "detail": f"{qr_info['type'].upper()} QR — not a web URL"}
                            for k in ["urlhaus","phishtank","google_safebrowsing",
                                      "virustotal","phishstats","ipqualityscore","scamalytics"]},
            "domain_info":  {"domain": qr_info['type'], "created": "N/A",
                             "registrar": "N/A", "age_days": None, "suspicious": False},
            "flags_count":  0
        })

    # ── URL QR — run full phishing analysis ──────────────────────────────────

    # 3 ── ML model
    features_df       = pd.DataFrame([extract_features(url)])
    ml_prediction     = int(model.predict(features_df)[0])
    ml_proba          = model.predict_proba(features_df)[0]
    ml_proba_phishing = round(float(ml_proba[1]) * 100, 2)
    ml_confidence     = round(float(ml_proba.max()) * 100, 2)

    # 4 ── Rule-based URL risk
    url_risk_score, risk_reasons = compute_url_risk(url)

    # 5 ── All 7 live database checks
    urlhaus_result     = check_urlhaus(url)
    phishtank_result   = check_phishtank(url)
    gsb_result         = check_google_safe_browsing(url)
    vt_result          = check_virustotal(url)
    phishstats_result  = check_phishstats(url)
    ipqs_result        = check_ipqualityscore(url)
    scamalytics_result = check_scamalytics(url)
    domain_info        = check_domain_age(url)

    all_checks = [urlhaus_result, phishtank_result, gsb_result,
                  vt_result, phishstats_result, ipqs_result, scamalytics_result]

    live_flags = [r for r in all_checks if r.get("flagged") is True]
    live_clean = [r for r in all_checks if r.get("flagged") is False]

    # 6 ── Final verdict
    # url_risk > 50 OR ML confident (>65%) OR any live DB flags
    final_is_phishing = (
        url_risk_score > 50
        or ml_proba_phishing > 65
        or len(live_flags) > 0
    )

    # 7 ── Genuine dynamic risk score
    #
    # Formula breakdown:
    #   url_risk_score  = 0-100 from rule engine (primary driver, 75% weight)
    #   ml_proba        = 0-100 ML phishing probability   (20% weight)
    #   live_flags      = each confirmed DB flag adds +8   (capped at 24)
    #   live_clean      = each DB saying CLEAN subtracts -3 (capped at -15)
    #   domain_bonus    = new domain < 30 days adds +8
    #   ipqs_boost      = IPQS risk score >= 75 adds +12
    #
    live_flag_score  = min(len(live_flags) * 8,  24)
    live_clean_score = min(len(live_clean) * 3,  15)
    domain_bonus     = 8  if domain_info.get("suspicious") else 0
    ipqs_boost       = 12 if ipqs_result.get("risk_score", 0) >= 75 else 0

    raw_score = (
        url_risk_score    * 0.75   # URL characteristics are primary judge
        + ml_proba_phishing * 0.20  # ML adds realistic probability
        + live_flag_score           # live DB flags boost score
        - live_clean_score          # live DB cleans reduce score
        + domain_bonus
        + ipqs_boost
    )
    final_risk = int(max(0, min(100, raw_score)))

    # NO fixed floor or ceiling — score is purely based on URL signals
    # Only hard override: if many VT engines flag → boost score
    if vt_result.get("malicious", 0) >= 5:
        final_risk = max(final_risk, 80)
    if vt_result.get("malicious", 0) >= 15:
        final_risk = max(final_risk, 92)

    # Save to history
    scan_record = {
        "id":         len(scan_history) + 1,
        "timestamp":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "url":        url,
        "result":     "PHISHING" if final_is_phishing else "LEGITIMATE",
        "is_phishing": final_is_phishing,
        "confidence": final_risk,
        "qr_type":    "url",
        "flags_count": len(live_flags),
    }
    scan_history.append(scan_record)

    return jsonify({
        "url":          url,
        "result":       "PHISHING" if final_is_phishing else "LEGITIMATE",
        "is_phishing":  final_is_phishing,
        "confidence":   final_risk,
        "qr_type":      "url",
        "risk_reasons": risk_reasons,
        "ml": {
            "prediction":           "PHISHING" if ml_prediction == 1 else "LEGITIMATE",
            "phishing_probability": ml_proba_phishing,
            "confidence":           ml_confidence
        },
        "live_checks": {
            "urlhaus":             urlhaus_result,
            "phishtank":           phishtank_result,
            "google_safebrowsing": gsb_result,
            "virustotal":          vt_result,
            "phishstats":          phishstats_result,
            "ipqualityscore":      ipqs_result,
            "scamalytics":         scamalytics_result,
        },
        "domain_info":  domain_info,
        "flags_count":  len(live_flags)
    })


if __name__ == '__main__':
    app.run(debug=True, port=5000, host='0.0.0.0')