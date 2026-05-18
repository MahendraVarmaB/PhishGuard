import pandas as pd
import re
from urllib.parse import urlparse, unquote
import logging
from pathlib import Path
import os
import math
import requests
from dotenv import load_dotenv
import tldextract

load_dotenv()
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# High-risk TLDs overwhelmingly used for phishing
HIGH_RISK_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'buzz', 'club', 'work',
    'info', 'online', 'site', 'live', 'icu', 'su', 'cc', 'pw', 'ws',
    'click', 'link', 'download', 'win', 'bid', 'stream', 'racing',
    'review', 'science', 'party', 'cricket', 'date', 'faith', 'accountant'
}

# Top brands targeted by phishing
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


class DataPrepPipeline:
    def __init__(self, data_dir="data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.urlhaus_api_key = os.getenv("URLHAUS_API_KEY")
        
    def extract_lexical_features(self, url):
        """Extract 20 statistical, lexical, and domain-reputation features from a URL."""
        if not isinstance(url, str):
            return None
            
        try:
            # Decode any obfuscation first
            decoded_url = unquote(unquote(url))
            
            parsed = urlparse(decoded_url)
            hostname = parsed.netloc or ""
            path = parsed.path or ""
            ext = tldextract.extract(decoded_url)
            
            registered_domain = ext.domain or ""
            suffix = ext.suffix or ""
            subdomain = ext.subdomain or ""
            
            # --- Original features (refined) ---
            features: dict[str, float] = {
                'url_length': len(decoded_url),
                'hostname_length': len(hostname),
                'path_length': len(path),
                'num_dots': decoded_url.count('.'),
                'num_hyphens': decoded_url.count('-'),
                'num_at': decoded_url.count('@'),
                'num_query_params': len(parsed.query.split('&')) if parsed.query else 0,
                'is_https': 1 if parsed.scheme == 'https' else 0,
                'has_ip_in_domain': 1 if re.search(r'\d+\.\d+\.\d+\.\d+', hostname) else 0,
                'has_obfuscation': 1 if '%' in url or 'bit.ly' in hostname or 'tinyurl' in hostname else 0,
                'subdomain_count': len(subdomain.split('.')) if subdomain else 0,
                'num_digits_in_hostname': sum(c.isdigit() for c in hostname),
            }
            
            # --- New high-signal features ---
            
            # 1. Hostname entropy (randomness detection)
            if hostname:
                prob = [hostname.lower().count(c) / len(hostname) for c in set(hostname.lower())]
                features['hostname_entropy'] = -sum(p * math.log2(p) for p in prob if p > 0)
            else:
                features['hostname_entropy'] = 0.0
            
            # 2. TLD risk score
            features['tld_risk_score'] = 1 if suffix.lower() in HIGH_RISK_TLDS else 0
            
            # 3. Domain length (just the registered domain, not subdomains)
            features['domain_length'] = len(registered_domain)
            
            # 4. Brand impersonation detection
            domain_lower = registered_domain.lower()
            has_brand = 0
            for brand in TARGET_BRANDS:
                if brand in domain_lower and domain_lower != brand:
                    has_brand = 1
                    break
            features['has_brand_impersonation'] = has_brand
            
            # 5. Special character ratio in URL
            special_chars = sum(1 for c in decoded_url if not c.isalnum() and c not in './-_:?=&')
            features['special_char_ratio'] = special_chars / max(len(decoded_url), 1)
            
            # 6. Path depth
            features['path_depth'] = len([s for s in path.split('/') if s])
            
            # 7. Suspicious keywords in path
            path_lower = path.lower()
            features['has_suspicious_keywords'] = 1 if any(kw in path_lower for kw in SUSPICIOUS_PATH_KEYWORDS) else 0
            
            # 8. Digit-to-letter ratio in domain
            digits = sum(c.isdigit() for c in registered_domain)
            letters = sum(c.isalpha() for c in registered_domain)
            features['digit_letter_ratio_in_domain'] = digits / max(letters, 1)
            
            return features
        except Exception as e:
            logging.debug(f"Error parsing URL {url}: {e}")
            return None

    def fetch_urlhaus_api(self):
        """Fetch malicious URLs from URLhaus API."""
        logging.info("Fetching recent URLs from URLhaus API...")
        url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
        headers = {}
        if self.urlhaus_api_key and self.urlhaus_api_key != "your_urlhaus_api_key_here":
            headers['Auth-Key'] = self.urlhaus_api_key
        
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            if data.get("query_status") == "ok":
                urls = [item['url'] for item in data.get('urls', [])]
                df = pd.DataFrame({'url': urls})
                df['label'] = 1
                logging.info(f"Fetched {len(df)} URLs from URLhaus API.")
                return df
            else:
                logging.warning("URLhaus API query did not return 'ok' status.")
        except Exception as e:
            logging.error(f"Error fetching URLhaus API: {e}")
            
        return pd.DataFrame(columns=['url', 'label'])

    def load_and_blend_datasets(self):
        """Load datasets, apply labels, and blend into a balanced dataframe."""
        try:
            logging.info("Loading PhishTank dataset...")
            phishtank_df = pd.read_csv(self.data_dir / "PhishTank.csv")
            
            logging.debug(f"Phishtank columns: {phishtank_df.columns}")
            url_col = 'url' if 'url' in phishtank_df.columns else str(phishtank_df.columns[1])
            phishtank_df = phishtank_df[[url_col]].rename(columns={url_col: 'url'}).copy()
            phishtank_df['label'] = 1
            
            logging.info("Loading Tranco dataset and applying long path augmentation...")
            tranco_df = pd.read_csv(self.data_dir / "tranco_43KLX.csv", names=['rank', 'domain'])
            
            import random
            long_paths = [
                "/search?q=google.dr&oq=google.dr&gs_lcrp=EgZjaHJvbWUyBggAEEUYOTIMCAEQABgUGIcCGIAEMgcIAhAAGIAEMgcIAxAAGIAEMgcIBBAAGIAEMgcIBRAAGIAEMgcIBhAAGIAEMgYIBxBFGDzSAQg3NzY0ajBqNKgCALACAQ&sourceid=chrome&ie=UTF-8",
                "/watch?v=dQw4w9WgXcQ&list=PL4l1O8Xo&index=4&t=1240s&ab_channel=RickAstley",
                "/dp/B08J5F3G18/ref=sr_1_1?crid=2P5N9M4R4&dchild=1&keywords=laptop&qid=1602188448&s=electronics&sprefix=laptop%2Celectronics%2C208&sr=1-1",
                "/index.php?option=com_content&view=article&id=123:long-article-name-here-with-many-words-and-seo-optimization&catid=45:technology&Itemid=67",
                "/products/category/electronics/smartphones/iphone-14-pro-max-256gb-space-black?variant=123456789&currency=USD&utm_source=google&utm_medium=cpc",
                "/wiki/Special:Search?search=Cybersecurity+threat+intelligence+machine+learning&go=Go&ns0=1",
                "/en-us/windows/security/threat-protection/microsoft-defender-antivirus/microsoft-defender-antivirus-in-windows-10",
                "/news/world/europe/ukraine-russia-war-latest-updates-putin-zelensky-kyiv-12345678",
                "/api/v2/users/12345/profile?include_history=true&limit=100&offset=20&sort=desc",
                "/login?redirect_url=https%3A%2F%2Fexample.com%2Fdashboard%3Fuser%3D12345",
                "/dashboard/settings/account/security?tab=2fa&ref=email",
                "/r/cybersecurity/comments/abc123/phishguard_ml_powered_phishing_detection",
                ""
            ]
            
            def augment_url(domain):
                base = 'https://' + str(domain)
                if random.random() < 0.85:
                    return base + random.choice(long_paths)
                return base
                
            tranco_df['url'] = tranco_df['domain'].apply(augment_url)
            tranco_df = tranco_df[['url']].copy()
            tranco_df['label'] = 0
            
            logging.info("Loading ISCX dataset...")
            try:
                iscx_df = pd.read_csv(self.data_dir / "ISCX-URL-2016.csv", low_memory=False)
                url_col_iscx = 'URL' if 'URL' in iscx_df.columns else ('url' if 'url' in iscx_df.columns else str(iscx_df.columns[0]))
                
                label_col_iscx = 'URL_Type_obf_Type' if 'URL_Type_obf_Type' in iscx_df.columns else None
                
                if label_col_iscx:
                    iscx_subset = iscx_df[[url_col_iscx, label_col_iscx]].copy()
                    iscx_subset.rename(columns={url_col_iscx: 'url'}, inplace=True)
                    iscx_subset['label'] = iscx_subset[label_col_iscx].apply(lambda x: 0 if str(x).lower().strip() == 'benign' else 1)
                    iscx_subset.drop(columns=[label_col_iscx], inplace=True)
                    iscx_df = iscx_subset
                else:
                    iscx_df = iscx_df[[url_col_iscx]].rename(columns={url_col_iscx: 'url'}).copy()
                    iscx_df['label'] = 0
            except Exception as e:
                logging.warning(f"Could not parse ISCX perfectly, using empty dataframe: {e}")
                iscx_df = pd.DataFrame(columns=['url', 'label'])
            
            urlhaus_df = self.fetch_urlhaus_api()
            
            # Combine all
            combined_df = pd.concat([phishtank_df, urlhaus_df, tranco_df, iscx_df], ignore_index=True)
            combined_df.dropna(subset=['url'], inplace=True)
            combined_df.drop_duplicates(subset=['url'], inplace=True)
            
            combined_df['label'] = pd.to_numeric(combined_df['label'], errors='coerce')
            combined_df.dropna(subset=['label'], inplace=True)
            
            malicious = combined_df[combined_df['label'] == 1]
            benign = combined_df[combined_df['label'] == 0]
            
            min_len = min(len(malicious), len(benign))
            sample_size = min(min_len, 15000)
            
            balanced_df = pd.concat([
                malicious.sample(n=sample_size, random_state=42),
                benign.sample(n=sample_size, random_state=42)
            ]).sample(frac=1, random_state=42).reset_index(drop=True)
            
            logging.info(f"Balanced Dataset created with {len(balanced_df)} samples.")
            return balanced_df
            
        except Exception as e:
            logging.error(f"Error loading datasets: {e}")
            return None

    def process(self):
        output_file = self.data_dir / "processed_features.csv"
        df = self.load_and_blend_datasets()
        if df is not None:
            logging.info("Extracting features (this may take a while)...")
            features_df = df['url'].apply(self.extract_lexical_features).apply(pd.Series)
            
            final_df = pd.concat([features_df, df['label']], axis=1)
            final_df.dropna(inplace=True)
            
            final_df.to_csv(output_file, index=False)
            logging.info(f"Successfully saved engineered features to {output_file}")
            logging.info(f"Feature columns: {list(features_df.columns)}")
            return final_df

if __name__ == "__main__":
    pipeline = DataPrepPipeline(data_dir="c:/Users/pvmvb/Desktop/Projects/PhishGuard/ml_pipeline/data")
    pipeline.process()
