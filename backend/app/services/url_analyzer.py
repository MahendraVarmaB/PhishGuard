import re
import math
from urllib.parse import urlparse, unquote
import tldextract
import logging
import asyncio

# Top brands targeted by phishing
TARGET_BRANDS = [
    'paypal', 'google', 'apple', 'microsoft', 'amazon', 'netflix', 'facebook',
    'instagram', 'whatsapp', 'linkedin', 'twitter', 'chase', 'wellsfargo',
    'bankofamerica', 'citibank', 'dropbox', 'icloud', 'outlook', 'office365',
    'dhl', 'fedex', 'usps', 'ups', 'adobe', 'yahoo', 'aol', 'ebay',
    'coinbase', 'binance', 'blockchain', 'steam', 'epic', 'roblox',
    'spotify', 'discord', 'telegram', 'signal', 'zoom', 'docusign'
]

# URL shortener domains
SHORTENER_DOMAINS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'short.io', 'rb.gy', 'cutt.ly', 'v.gd'
}

class URLAnalyzerService:
    """Active threat intelligence: obfuscation decoding, typosquatting, and WHOIS checks."""
    
    # --- 1. URL Obfuscation Decoding ---
    
    def decode_url(self, url: str) -> dict:
        """Recursively decode URL obfuscation and return analysis."""
        decoded = url
        layers = 0
        
        # Recursively decode percent-encoding
        while '%' in decoded:
            new_decoded = unquote(decoded)
            if new_decoded == decoded:
                break
            decoded = new_decoded
            layers += 1
        
        # Detect Unicode homoglyphs (Cyrillic/Greek lookalikes)
        homoglyph_map = {
            '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
            '\u0441': 'c', '\u0443': 'y', '\u0445': 'x', '\u0456': 'i',
            '\u0458': 'j', '\u04bb': 'h', '\u0455': 's', '\u0442': 't',
            '\u043d': 'n', '\u043a': 'k', '\u043c': 'm', '\u0432': 'v',
        }
        
        has_homoglyphs = any(c in homoglyph_map for c in decoded)
        if has_homoglyphs:
            for cyrillic, latin in homoglyph_map.items():
                decoded = decoded.replace(cyrillic, latin)
        
        # Check for URL shorteners
        try:
            hostname = urlparse(decoded).netloc.lower()
        except:
            hostname = ""
        is_shortened = hostname in SHORTENER_DOMAINS
        
        return {
            'decoded_url': decoded,
            'is_obfuscated': layers > 1 or has_homoglyphs,
            'encoding_layers': layers,
            'has_homoglyphs': has_homoglyphs,
            'is_shortened': is_shortened
        }
    
    # --- 2. Typosquatting Detection ---
    
    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate edit distance between two strings."""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        
        prev_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row
        
        return prev_row[-1]
    
    def _check_char_substitution(self, domain: str) -> str | None:
        """Check for common character substitution attacks."""
        # Map of common substitutions
        substitutions = {
            '0': 'o', '1': 'l', '3': 'e', '5': 's',
            'vv': 'w', 'rn': 'm', 'cl': 'd', 'nn': 'm'
        }
        
        normalized = domain.lower()
        for fake, real in substitutions.items():
            normalized = normalized.replace(fake, real)
        
        if normalized != domain.lower():
            for brand in TARGET_BRANDS:
                if self._levenshtein_distance(normalized, brand) <= 1:
                    return brand
        return None
    
    def detect_typosquatting(self, url: str) -> dict:
        """Check if the domain is typosquatting a known brand."""
        ext = tldextract.extract(url)
        domain = ext.domain.lower()
        
        # Direct edit distance check
        for brand in TARGET_BRANDS:
            distance = self._levenshtein_distance(domain, brand)
            if 0 < distance <= 2:  # Within 2 edits but not exact match
                return {
                    'is_typosquatting': True,
                    'target_brand': brand,
                    'edit_distance': distance,
                    'method': 'levenshtein'
                }
        
        # Character substitution check
        sub_brand = self._check_char_substitution(domain)
        if sub_brand:
            return {
                'is_typosquatting': True,
                'target_brand': sub_brand,
                'edit_distance': -1,
                'method': 'char_substitution'
            }
        
        return {
            'is_typosquatting': False,
            'target_brand': None,
            'edit_distance': -1,
            'method': None
        }
    
    # --- 3. WHOIS Domain Age Check ---
    
    async def check_domain_age(self, url: str) -> dict:
        """Async WHOIS lookup to get domain creation date."""
        try:
            ext = tldextract.extract(url)
            domain = f"{ext.domain}.{ext.suffix}"
            
            # Run python-whois in a thread to keep it non-blocking
            import whois
            from datetime import datetime
            
            w = await asyncio.wait_for(
                asyncio.to_thread(whois.whois, domain),
                timeout=2.0  # Hard 2s timeout
            )
            
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date:
                age_days = (datetime.now() - creation_date).days
                return {
                    'domain_age_days': age_days,
                    'is_newly_registered': age_days < 30
                }
        except asyncio.TimeoutError:
            logging.debug(f"WHOIS timeout for {url}")
        except Exception as e:
            logging.debug(f"WHOIS error for {url}: {e}")
        
        return {
            'domain_age_days': None,
            'is_newly_registered': False
        }
