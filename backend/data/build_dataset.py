import csv
import random

phishing_urls = [
    "http://paypal-login-verify.xyz/secure",
    "http://192.168.1.1/admin/login",
    "http://bankofamerica-update.com/verify",
    "http://facebook-login.suspicious.net/auth",
    "http://amazon-security-alert.com/update",
    "http://appleid-confirm.xyz/signin",
    "http://secure-login.paypall.com/webscr",
    "http://netflix-billing-update.com/account",
    "http://verify-your-account.info/login",
    "http://ebay-account-suspended.com/restore",
    "http://microsoft-alert.security-check.net",
    "http://login.bank-secure-update.com",
    "http://user-verification.suspicious.org/form",
    "http://signin.google-security-notice.com",
    "http://urgent-account-update.net/verify",
    "http://wellsfargo-online.verify-now.com",
    "http://chase-secure.update-info.com/login",
    "http://citibank-login.phishing-site.xyz",
    "http://dhl-parcel-notification.com/track",
    "http://fedex-delivery-alert.net/confirm",
    "http://irs-tax-refund.gov-alert.com",
    "http://covid-relief-payment.gov-form.net",
    "http://prize-winner-claim.xyz/redeem",
    "http://free-gift-card.suspicious.com/get",
    "http://crypto-invest-now.scam.net/buy",
    "http://update-your-password.alert-service.com",
    "http://login-required.fake-bank.com/auth",
    "http://your-account-locked.phish.net/unlock",
    "http://security-breach-alert.com/fix",
    "http://confirm-identity.fake-paypal.com",
]

legitimate_urls = [
    "https://www.google.com",
    "https://www.youtube.com",
    "https://www.facebook.com",
    "https://www.amazon.com",
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
]

rows = []
for url in phishing_urls:
    rows.append({"url": url, "label": 1})
for url in legitimate_urls:
    rows.append({"url": url, "label": 0})

random.shuffle(rows)

with open("dataset.csv", "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["url", "label"])
    writer.writeheader()
    writer.writerows(rows)

print(f"Dataset created with {len(rows)} URLs")
print(f"Phishing: {sum(1 for r in rows if r['label']==1)}")
print(f"Legitimate: {sum(1 for r in rows if r['label']==0)}")