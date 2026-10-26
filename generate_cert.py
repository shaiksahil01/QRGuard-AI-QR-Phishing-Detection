"""
Run this ONCE to generate a self-signed SSL certificate for Flask.
Place this file in D:\QR phishind detection\ and run:
    python generate_cert.py
"""
from OpenSSL import crypto
import os

cert_file = "cert.pem"
key_file  = "key.pem"

# Generate key
k = crypto.PKey()
k.generate_key(crypto.TYPE_RSA, 2048)

# Generate cert
cert = crypto.X509()
cert.get_subject().C  = "IN"
cert.get_subject().ST = "Karnataka"
cert.get_subject().L  = "Bengaluru"
cert.get_subject().O  = "QRGuard"
cert.get_subject().CN = "192.168.1.5"   # ← your PC WiFi IP
cert.set_serial_number(1000)
cert.gmtime_adj_notBefore(0)
cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)  # 1 year
cert.set_issuer(cert.get_subject())
cert.set_pubkey(k)
cert.sign(k, 'sha256')

with open(cert_file, "wb") as f:
    f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
with open(key_file, "wb") as f:
    f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))

print(f"✅ cert.pem and key.pem generated!")
print(f"   Flask will now run on https://192.168.1.5:5000")
print(f"   React will run on  https://192.168.1.5:3000")