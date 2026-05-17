import joblib
import os
import logging
import re
import math
from urllib.parse import urlparse, unquote
import pandas as pd
import tldextract

# Pre-compile regex for speed
IP_REGEX = re.compile(r'\d+\.\d+\.\d+\.\d+')

# Must mirror the exact same constants from data_prep.py
HIGH_RISK_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'buzz', 'club', 'work',
    'info', 'online', 'site', 'live', 'icu', 'su', 'cc', 'pw', 'ws',
    'click', 'link', 'download', 'win', 'bid', 'stream', 'racing',
    'review', 'science', 'party', 'cricket', 'date', 'faith', 'accountant'
}

TARGET_BRANDS = [
    'paypal', 'google', 'apple', 'microsoft', 'amazon', 'netflix', 'facebook',
    'instagram', 'whatsapp', 'linkedin', 'twitter', 'chase', 'wellsfargo',
    'bankofamerica', 'citibank', 'dropbox', 'icloud', 'outlook', 'office365',
    'dhl', 'fedex', 'usps', 'ups', 'adobe', 'yahoo', 'aol', 'ebay',
    'coinbase', 'binance', 'blockchain', 'steam', 'epic', 'roblox',
    'spotify', 'discord', 'telegram', 'signal', 'zoom', 'docusign',
    'salesforce', 'shopify', 'stripe', 'square', 'venmo', 'zelle'
]

SUSPICIOUS_PATH_KEYWORDS = {
    'login', 'signin', 'sign-in', 'verify', 'verification', 'secure',
    'update', 'account', 'confirm', 'suspend', 'unlock', 'restore',
    'password', 'credential', 'authenticate', 'webscr', 'billing',
    'payment', 'wallet', 'bank', 'security', 'alert', 'unusual',
    'activity', 'expire', 'renew', 'validate', 'identity'
}


class MLModelService:
    def __init__(self):
        current_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.abspath(os.path.join(current_dir, "..", "..", ".."))
        model_path = os.path.join(project_root, "ml_pipeline", "models", "phishguard_model.joblib")
        
        if not os.path.exists(model_path):
            logging.error(f"Model not found at {model_path}")
            self.model = None
        else:
            self.model = joblib.load(model_path)
            logging.info(f"Loaded ML model from {model_path}")
        
        # Pre-warm tldextract cache
        tldextract.extract("https://example.com")
            
    def extract_features(self, url: str) -> pd.DataFrame:
        """Extract 20 features — must exactly mirror data_prep.py"""
        decoded_url = unquote(unquote(url))
        
        parsed = urlparse(decoded_url)
        hostname = parsed.netloc or ""
        path = parsed.path or ""
        ext = tldextract.extract(decoded_url)
        
        registered_domain = ext.domain or ""
        suffix = ext.suffix or ""
        subdomain = ext.subdomain or ""
        
        # Original features
        features = {
            'url_length': len(decoded_url),
            'hostname_length': len(hostname),
            'path_length': len(path),
            'num_dots': decoded_url.count('.'),
            'num_hyphens': decoded_url.count('-'),
            'num_at': decoded_url.count('@'),
            'num_query_params': len(parsed.query.split('&')) if parsed.query else 0,
            'is_https': 1 if parsed.scheme == 'https' else 0,
            'has_ip_in_domain': 1 if IP_REGEX.search(hostname) else 0,
            'has_obfuscation': 1 if '%' in url or 'bit.ly' in hostname or 'tinyurl' in hostname else 0,
            'subdomain_count': len(subdomain.split('.')) if subdomain else 0,
            'num_digits_in_hostname': sum(c.isdigit() for c in hostname),
        }
        
        # New high-signal features
        
        # 1. Hostname entropy
        if hostname:
            prob = [hostname.lower().count(c) / len(hostname) for c in set(hostname.lower())]
            features['hostname_entropy'] = -sum(p * math.log2(p) for p in prob if p > 0)
        else:
            features['hostname_entropy'] = 0.0
        
        # 2. TLD risk score
        features['tld_risk_score'] = 1 if suffix.lower() in HIGH_RISK_TLDS else 0
        
        # 3. Domain length
        features['domain_length'] = len(registered_domain)
        
        # 4. Brand impersonation
        domain_lower = registered_domain.lower()
        has_brand = 0
        for brand in TARGET_BRANDS:
            if brand in domain_lower and domain_lower != brand:
                has_brand = 1
                break
        features['has_brand_impersonation'] = has_brand
        
        # 5. Special character ratio
        special_chars = sum(1 for c in decoded_url if not c.isalnum() and c not in './-_:?=&')
        features['special_char_ratio'] = special_chars / max(len(decoded_url), 1)
        
        # 6. Path depth
        features['path_depth'] = len([s for s in path.split('/') if s])
        
        # 7. Suspicious keywords
        path_lower = path.lower()
        features['has_suspicious_keywords'] = 1 if any(kw in path_lower for kw in SUSPICIOUS_PATH_KEYWORDS) else 0
        
        # 8. Digit-to-letter ratio in domain
        digits = sum(c.isdigit() for c in registered_domain)
        letters = sum(c.isalpha() for c in registered_domain)
        features['digit_letter_ratio_in_domain'] = digits / max(letters, 1)
        
        return pd.DataFrame([features])

    def predict(self, url: str) -> dict:
        if not self.model:
            return {"is_phishing": False, "probability": 0.0}
            
        features_df = self.extract_features(url)
        prediction = self.model.predict(features_df)[0]
        
        prob = 0.0
        if hasattr(self.model, "predict_proba"):
            prob = self.model.predict_proba(features_df)[0][1]
            
        return {
            "is_phishing": bool(prediction == 1),
            "probability": float(prob)
        }
