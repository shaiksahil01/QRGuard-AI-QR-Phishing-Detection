"""
Real Dataset Fetcher for QR Phishing Detection
Fetches from:
  1. OpenPhish       — live phishing feed (no key needed)
  2. PhishTank       — verified phishing URLs (no key needed)
  3. URLhaus         — malware URLs (no key needed)
  4. Majestic Million— top legitimate websites (no key needed)
  5. Tranco List     — top legitimate websites (no key needed)
"""

import csv
import os
import random
import re
import requests
import json
import time
from urllib.parse import urlparse

OUTPUT_FILE = "dataset.csv"
TOTAL_TARGET = 2000   # total URLs to collect (1000 phishing + 1000 legit)

print("=" * 60)
print("  REAL DATASET FETCHER — QR Phishing Detection System")
print("=" * 60)

phishing_urls = []
legit_urls    = []


# ─────────────────────────────────────────────────────────────────
#  SOURCE 1: OpenPhish (free live phishing feed)
# ─────────────────────────────────────────────────────────────────
def fetch_openphish():
    print("\n[1/5] Fetching from OpenPhish...")
    try:
        r = requests.get(
            "https://openphish.com/feed.txt",
            timeout=15,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if r.status_code == 200:
            urls = [line.strip() for line in r.text.splitlines()
                    if line.strip().startswith("http")]
            print(f"     ✅ Got {len(urls)} phishing URLs from OpenPhish")
            return urls[:500]
        else:
            print(f"     ⚠ OpenPhish returned {r.status_code}")
    except Exception as e:
        print(f"     ❌ OpenPhish failed: {e}")
    return []


# ─────────────────────────────────────────────────────────────────
#  SOURCE 2: URLhaus (malware/phishing URLs)
# ─────────────────────────────────────────────────────────────────
def fetch_urlhaus():
    print("\n[2/5] Fetching from URLhaus (abuse.ch)...")
    try:
        r = requests.get(
            "https://urlhaus.abuse.ch/downloads/csv_recent/",
            timeout=20,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if r.status_code == 200:
            urls = []
            lines = r.text.splitlines()
            for line in lines:
                if line.startswith('#') or not line.strip():
                    continue
                parts = line.split(',')
                if len(parts) >= 3:
                    url = parts[2].strip().strip('"')
                    if url.startswith('http'):
                        urls.append(url)
            print(f"     ✅ Got {len(urls)} malware URLs from URLhaus")
            return urls[:500]
        else:
            print(f"     ⚠ URLhaus returned {r.status_code}")
    except Exception as e:
        print(f"     ❌ URLhaus failed: {e}")
    return []


# ─────────────────────────────────────────────────────────────────
#  SOURCE 3: PhishTank (verified phishing database)
# ─────────────────────────────────────────────────────────────────
def fetch_phishtank():
    print("\n[3/5] Fetching from PhishTank...")
    try:
        # PhishTank online_valid feed (no auth needed for basic)
        r = requests.get(
            "http://data.phishtank.com/data/online-valid.csv",
            timeout=30,
            headers={"User-Agent": "phishtank/QRGuard"}
        )
        if r.status_code == 200:
            urls = []
            reader = csv.DictReader(r.text.splitlines())
            for row in reader:
                url = row.get("url", "").strip()
                if url.startswith("http"):
                    urls.append(url)
            print(f"     ✅ Got {len(urls)} verified phishing URLs from PhishTank")
            return urls[:500]
        else:
            print(f"     ⚠ PhishTank returned {r.status_code} — trying alternate...")
            # alternate: JSON feed
            r2 = requests.get(
                "https://data.phishtank.com/data/online-valid.json",
                timeout=30,
                headers={"User-Agent": "phishtank/QRGuard"}
            )
            if r2.status_code == 200:
                data = r2.json()
                urls = [entry["url"] for entry in data
                        if entry.get("url", "").startswith("http")]
                print(f"     ✅ Got {len(urls)} URLs from PhishTank JSON feed")
                return urls[:500]
    except Exception as e:
        print(f"     ❌ PhishTank failed: {e}")
    return []


# ─────────────────────────────────────────────────────────────────
#  SOURCE 4: Tranco List (top legitimate websites)
# ─────────────────────────────────────────────────────────────────
def fetch_tranco():
    print("\n[4/5] Fetching from Tranco List (legitimate sites)...")
    try:
        # Get latest Tranco list ID
        r = requests.get(
            "https://tranco-list.eu/top-1m.csv.zip",
            timeout=30,
            headers={"User-Agent": "Mozilla/5.0"},
            stream=True
        )
        if r.status_code == 200:
            import zipfile, io
            z = zipfile.ZipFile(io.BytesIO(r.content))
            with z.open(z.namelist()[0]) as f:
                lines = f.read().decode('utf-8').splitlines()
            urls = []
            for line in lines[:2000]:
                parts = line.strip().split(',')
                if len(parts) >= 2:
                    domain = parts[1].strip()
                    if domain and '.' in domain:
                        urls.append(f"https://{domain}")
            print(f"     ✅ Got {len(urls)} legitimate URLs from Tranco")
            return urls[:600]
        else:
            print(f"     ⚠ Tranco returned {r.status_code}")
    except Exception as e:
        print(f"     ❌ Tranco failed: {e}")
    return []


# ─────────────────────────────────────────────────────────────────
#  SOURCE 5: Majestic Million (backup legitimate sites)
# ─────────────────────────────────────────────────────────────────
def fetch_majestic():
    print("\n[5/5] Fetching from Majestic Million (legitimate sites)...")
    try:
        r = requests.get(
            "https://downloads.majestic.com/majestic_million.csv",
            timeout=30,
            headers={"User-Agent": "Mozilla/5.0"},
            stream=True
        )
        if r.status_code == 200:
            urls = []
            lines = r.text.splitlines()
            reader = csv.DictReader(lines)
            for i, row in enumerate(reader):
                if i >= 2000:
                    break
                domain = row.get("Domain", "").strip()
                if domain and '.' in domain:
                    urls.append(f"https://{domain}")
            print(f"     ✅ Got {len(urls)} legitimate URLs from Majestic Million")
            return urls[:600]
        else:
            print(f"     ⚠ Majestic returned {r.status_code}")
    except Exception as e:
        print(f"     ❌ Majestic failed: {e}")
    return []


# ─────────────────────────────────────────────────────────────────
#  BUILT-IN BACKUP DATASET (if internet sources fail)
# ─────────────────────────────────────────────────────────────────
BACKUP_PHISHING = [
    "http://paypal-login-verify.xyz/secure/account",
    "http://amazon-security-alert.com/update/billing",
    "http://appleid-confirm.xyz/signin/verify",
    "http://secure-login.paypall.com/webscr?cmd=login",
    "http://netflix-billing-update.com/account/fix",
    "http://microsoft-alert.security-check.net/verify",
    "http://login.bank-secure-update.com/auth",
    "http://verify-your-account.info/login/confirm",
    "http://ebay-account-suspended.com/restore/now",
    "http://citibank-login.phishing-site.xyz/secure",
    "http://dhl-parcel-notification.com/track/package",
    "http://fedex-delivery-alert.net/confirm/delivery",
    "http://irs-tax-refund.gov-alert.com/claim",
    "http://prize-winner-claim.xyz/redeem/now",
    "http://crypto-invest-now.scam.net/buy/bitcoin",
    "http://update-your-password.alert-service.com/reset",
    "http://your-account-locked.phish.net/unlock/verify",
    "http://security-breach-alert.com/fix/account",
    "http://confirm-identity.fake-paypal.com/webscr",
    "http://hdfc-bank-alert.update-now.xyz/login",
    "http://sbi-netbanking-secure.phish.com/signin",
    "http://icici-account-verify.fraud.net/confirm",
    "http://upi-payment-failed.retry-now.xyz/pay",
    "http://gpay-transaction-alert.scam.info/verify",
    "http://paytm-wallet-blocked.update.xyz/unblock",
    "http://flipkart-order-cancel.fake.com/reorder",
    "http://amazon-refund-pending.claim.xyz/submit",
    "http://irctc-ticket-cancel.phish.net/rebook",
    "http://covid-relief-payment.gov-form.net/apply",
    "http://income-tax-refund-2024.gov-fake.xyz/claim",
    "http://192.168.1.1/admin/login",
    "http://10.0.0.1/router/setup",
    "http://account-suspended.bankofamerica-secure.xyz",
    "http://signin.google-security-notice.com/verify",
    "http://unusual-activity.facebook-secure.xyz/login",
    "http://instagram-account-disabled.fake.net/appeal",
    "http://whatsapp-verification.scam.xyz/confirm",
    "http://twitter-suspended.appeal-now.xyz/restore",
    "http://linkedin-account-hack.alert.xyz/secure",
    "http://zoom-meeting-invite.phish.xyz/join/secure",
    "http://microsoft365-expire.alert.xyz/renew",
    "http://apple-id-locked.support-fake.xyz/unlock",
    "http://samsung-prize-winner.claim.xyz/redeem",
    "http://jio-sim-blocked.verify.xyz/unblock",
    "http://airtel-recharge-offer.fake.xyz/claim",
    "http://vodafone-data-bonus.scam.xyz/activate",
    "http://bsnl-broadband-alert.phish.xyz/update",
    "http://ola-ride-cancelled.refund.xyz/claim",
    "http://uber-account-suspended.fake.xyz/restore",
    "http://swiggy-order-fraud.alert.xyz/verify",
    "http://zomato-refund-pending.claim.xyz/submit",
    "http://meesho-account-hack.alert.xyz/secure",
    "http://myntra-order-cancel.fake.xyz/rebook",
    "http://snapdeal-prize.winner.xyz/claim",
    "http://bigbasket-delivery-failed.phish.xyz/retry",
    "http://bookmyshow-ticket-cancel.fake.xyz/rebook",
    "http://makemytrip-booking-cancel.scam.xyz/rebook",
    "http://yatra-flight-cancel.phish.xyz/rebook",
    "http://cleartrip-hotel-cancel.fake.xyz/rebook",
    "http://policybazaar-policy-expire.scam.xyz/renew",
    "http://phonepe-upi-blocked.verify.xyz/unblock",
    "http://googlepay-transaction-fail.scam.xyz/retry",
    "http://bhim-payment-pending.phish.xyz/confirm",
    "http://neft-transfer-failed.bank-alert.xyz/retry",
    "http://imps-transaction-hold.bank-secure.xyz/verify",
    "http://rtgs-payment-pending.bank-phish.xyz/confirm",
    "http://kyc-expiry-alert.bank-fake.xyz/update",
    "http://pan-verification-pending.gov-fake.xyz/submit",
    "http://aadhaar-link-expire.gov-phish.xyz/update",
    "http://epf-claim-pending.pf-fake.xyz/submit",
    "http://nps-account-expire.pension-scam.xyz/renew",
    "http://mutual-fund-alert.invest-fake.xyz/verify",
    "http://share-market-alert.zerodha-fake.xyz/login",
    "http://groww-account-alert.scam.xyz/verify",
    "http://upstox-security-alert.phish.xyz/login",
    "http://angelbroking-alert.fake.xyz/secure",
    "http://demat-account-hack.alert.xyz/secure",
]

BACKUP_LEGIT = [
    "https://www.google.com",
    "https://www.youtube.com",
    "https://www.facebook.com",
    "https://www.amazon.in",
    "https://www.wikipedia.org",
    "https://www.twitter.com",
    "https://www.instagram.com",
    "https://www.linkedin.com",
    "https://www.microsoft.com",
    "https://www.apple.com",
    "https://www.github.com",
    "https://www.stackoverflow.com",
    "https://www.reddit.com",
    "https://www.netflix.com",
    "https://www.hdfcbank.com",
    "https://www.sbi.co.in",
    "https://www.icicibank.com",
    "https://www.axisbank.com",
    "https://www.kotakbank.com",
    "https://www.flipkart.com",
    "https://www.myntra.com",
    "https://www.zomato.com",
    "https://www.swiggy.com",
    "https://www.paytm.com",
    "https://www.irctc.co.in",
    "https://www.naukri.com",
    "https://www.makemytrip.com",
    "https://www.timesofindia.com",
    "https://www.ndtv.com",
    "https://www.bbc.com",
    "https://www.cnn.com",
    "https://www.nytimes.com",
    "https://www.bookmyshow.com",
    "https://www.bigbasket.com",
    "https://www.meesho.com",
    "https://www.razorpay.com",
    "https://www.phonepe.com",
    "https://www.ola.com",
    "https://www.airbnb.com",
    "https://www.booking.com",
    "https://www.tripadvisor.com",
    "https://www.spotify.com",
    "https://www.zoom.us",
    "https://www.slack.com",
    "https://www.notion.so",
    "https://www.figma.com",
    "https://www.canva.com",
    "https://www.dropbox.com",
    "https://www.adobe.com",
    "https://www.salesforce.com",
    "https://www.shopify.com",
    "https://www.wordpress.com",
    "https://www.medium.com",
    "https://www.quora.com",
    "https://www.pinterest.com",
    "https://www.twitch.tv",
    "https://www.discord.com",
    "https://www.telegram.org",
    "https://www.whatsapp.com",
    "https://www.snapchat.com",
    "https://www.tiktok.com",
    "https://accounts.google.com",
    "https://mail.google.com",
    "https://drive.google.com",
    "https://docs.google.com",
    "https://maps.google.com",
    "https://play.google.com",
    "https://meet.google.com",
    "https://calendar.google.com",
    "https://news.google.com",
    "https://translate.google.com",
    "https://www.indiatoday.in",
    "https://www.hindustantimes.com",
    "https://www.thehindu.com",
    "https://www.livemint.com",
    "https://www.moneycontrol.com",
    "https://www.economictimes.com",
    "https://www.businesstoday.in",
    "https://zerodha.com",
    "https://www.groww.in",
    "https://www.upstox.com",
    "https://www.angelbroking.com",
    "https://www.policybazaar.com",
    "https://www.healthkart.com",
    "https://www.1mg.com",
    "https://www.netmeds.com",
    "https://www.lenskart.com",
    "https://www.nykaa.com",
    "https://www.ajio.com",
    "https://www.jabong.com",
    "https://www.pepperfry.com",
    "https://www.urban-company.com",
    "https://www.practo.com",
    "https://www.cult.fit",
    "https://www.byju.com",
    "https://www.unacademy.com",
    "https://www.vedantu.com",
    "https://www.coursera.org",
    "https://www.udemy.com",
    "https://www.edx.org",
    "https://www.khanacademy.org",
]


# ─────────────────────────────────────────────────────────────────
#  CLEAN & DEDUPLICATE URLs
# ─────────────────────────────────────────────────────────────────
def clean_url(url):
    url = url.strip().strip('"').strip("'")
    if not url.startswith('http'):
        return None
    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            return None
        # remove obviously broken URLs
        if len(url) > 500:
            return None
        return url
    except Exception:
        return None


def deduplicate(urls):
    seen_domains = set()
    result = []
    for url in urls:
        try:
            domain = urlparse(url).netloc.lower()
            if domain not in seen_domains:
                seen_domains.add(domain)
                result.append(url)
        except Exception:
            pass
    return result


# ─────────────────────────────────────────────────────────────────
#  MAIN — FETCH AND BUILD DATASET
# ─────────────────────────────────────────────────────────────────
print("\nStarting data collection from real databases...")
print("This may take 1-2 minutes depending on your internet speed.\n")

# Fetch phishing URLs
phishing_raw = []
phishing_raw += fetch_openphish()
time.sleep(1)
phishing_raw += fetch_urlhaus()
time.sleep(1)
phishing_raw += fetch_phishtank()

# Fetch legitimate URLs
legit_raw = []
legit_raw += fetch_tranco()
time.sleep(1)
legit_raw += fetch_majestic()

# Clean and deduplicate
print("\n📊 Processing collected data...")
phishing_clean = [u for u in (clean_url(u) for u in phishing_raw) if u]
legit_clean    = [u for u in (clean_url(u) for u in legit_raw) if u]

phishing_clean = deduplicate(phishing_clean)
legit_clean    = deduplicate(legit_clean)

print(f"   Phishing URLs collected: {len(phishing_clean)}")
print(f"   Legitimate URLs collected: {len(legit_clean)}")

# If internet sources failed, use backup
if len(phishing_clean) < 50:
    print("\n   ⚠ Internet sources limited — adding built-in backup phishing URLs")
    phishing_clean += BACKUP_PHISHING
    phishing_clean = deduplicate(phishing_clean)

if len(legit_clean) < 50:
    print("   ⚠ Internet sources limited — adding built-in backup legitimate URLs")
    legit_clean += BACKUP_LEGIT
    legit_clean = deduplicate(legit_clean)

# Always add backup to ensure diversity
phishing_clean += BACKUP_PHISHING
legit_clean    += BACKUP_LEGIT
phishing_clean  = list(dict.fromkeys(phishing_clean))  # preserve order dedup
legit_clean     = list(dict.fromkeys(legit_clean))

# Balance dataset
target_each = min(len(phishing_clean), len(legit_clean), TOTAL_TARGET // 2)
target_each = max(target_each, 50)  # at least 50 each

random.shuffle(phishing_clean)
random.shuffle(legit_clean)

phishing_final = phishing_clean[:target_each]
legit_final    = legit_clean[:target_each]

# Build final rows
rows = []
for url in phishing_final:
    rows.append({"url": url, "label": 1})
for url in legit_final:
    rows.append({"url": url, "label": 0})

random.shuffle(rows)

# Write CSV
with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=["url", "label"])
    writer.writeheader()
    writer.writerows(rows)

print("\n" + "=" * 60)
print("✅ DATASET CREATED SUCCESSFULLY!")
print("=" * 60)
print(f"   📁 File:       {OUTPUT_FILE}")
print(f"   🔴 Phishing:   {len(phishing_final)} URLs")
print(f"   🟢 Legitimate: {len(legit_final)} URLs")
print(f"   📊 Total:      {len(rows)} URLs")
print("\n   Sources used:")
print("   • OpenPhish  — live phishing feed")
print("   • URLhaus    — abuse.ch malware database")
print("   • PhishTank  — verified phishing database")
print("   • Tranco     — top 1M legitimate sites")
print("   • Majestic   — Million legitimate sites")
print("   • Built-in   — curated Indian phishing/legit URLs")
print("\n   Next step: Run train_model.py to retrain with new data!")
print("=" * 60)