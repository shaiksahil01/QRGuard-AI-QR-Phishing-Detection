import re
from urllib.parse import urlparse

def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    query = parsed.query

    suspicious_words = ['login', 'verify', 'secure', 'update', 'bank',
                        'paypal', 'confirm', 'account', 'password', 'signin',
                        'alert', 'urgent', 'suspended', 'unlock', 'claim']

    features = {
        'url_length':           len(url),
        'domain_length':        len(domain),
        'path_length':          len(path),
        'num_dots':             url.count('.'),
        'num_hyphens':          url.count('-'),
        'num_slashes':          url.count('/'),
        'num_at':               url.count('@'),
        'num_underscores':      url.count('_'),
        'num_digits':           sum(c.isdigit() for c in url),
        'num_params':           len(query.split('&')) if query else 0,
        'num_subdomains':       len(domain.split('.')) - 2,
        'has_ip':               1 if re.match(r'\d+\.\d+\.\d+\.\d+', domain) else 0,
        'has_https':            1 if parsed.scheme == 'https' else 0,
        'has_port':             1 if parsed.port else 0,
        'has_suspicious_words': 1 if any(w in url.lower() for w in suspicious_words) else 0,
        'has_at_symbol':        1 if '@' in url else 0,
        'has_double_slash':     1 if '//' in path else 0,
        'domain_has_hyphen':    1 if '-' in domain else 0,
        'domain_has_digits':    1 if any(c.isdigit() for c in domain) else 0,
        'url_is_short':         1 if len(url) < 30 else 0,
        'url_is_long':          1 if len(url) > 75 else 0,
        'tld_is_suspicious':    1 if any(domain.endswith(t) for t in
                                    ['.xyz','.info','.net','.org','.biz','.online']) else 0,
    }
    return features