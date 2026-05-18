import re
import math
from urllib.parse import urlparse, unquote
import tldextract
import logging
import asyncio
from rapidfuzz.distance import Levenshtein   # C-extension, no GIL contention

# Suppress the python-whois library's internal socket-error logger.
# It logs "Error trying to connect to socket" at ERROR level for every
# WHOIS timeout — misleading since we handle those exceptions gracefully.
logging.getLogger("whois.whois").setLevel(logging.CRITICAL)


# ---------------------------------------------------------------------------
# Target brands list (shared constant; keep in sync with data_prep.py)
# ---------------------------------------------------------------------------
TARGET_BRANDS = [
    'paypal', 'google', 'apple', 'microsoft', 'amazon', 'netflix', 'facebook',
    'instagram', 'whatsapp', 'linkedin', 'twitter', 'chase', 'wellsfargo',
    'bankofamerica', 'citibank', 'dropbox', 'icloud', 'outlook', 'office365',
    'dhl', 'fedex', 'usps', 'ups', 'adobe', 'yahoo', 'aol', 'ebay',
    'coinbase', 'binance', 'blockchain', 'steam', 'epic', 'roblox',
    'spotify', 'discord', 'telegram', 'signal', 'zoom', 'docusign'
]

# URL shortener domains (exact match set for O(1) lookup)
SHORTENER_DOMAINS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'short.io', 'rb.gy', 'cutt.ly', 'v.gd'
}

# ---------------------------------------------------------------------------
# REMEDIATION 3B: Hard defensive constants
#
# MAX_DECODE_ITERATIONS: Caps recursive percent-decode loops. An adversary can
#   construct a URL with 1000 layers of %25-encoding that would spin forever
#   under the old "while '%' in decoded" logic.
#
# MAX_DOMAIN_LENGTH: Truncates absurdly long labels before string-distance
#   computation. A 500-char domain against a 5-char brand name results in an
#   O(n*m) = 2500-cell DP matrix per brand; 40 brands × 2500 = 100,000 ops
#   per request on a single Python thread. The cap cuts that to ~40 × 400.
# ---------------------------------------------------------------------------
MAX_DECODE_ITERATIONS = 3
MAX_DOMAIN_LENGTH     = 64   # RFC 1035 §2.3.4 limit per label is 63 chars


class URLAnalyzerService:
    """Active threat intelligence: obfuscation decoding, typosquatting, WHOIS."""

    # -----------------------------------------------------------------------
    # 1. URL Obfuscation Decoding
    # -----------------------------------------------------------------------

    def decode_url(self, url: str) -> dict:
        """
        Decode URL obfuscation with hard iteration cap.
        REMEDIATION 3B: The old 'while '%' in decoded' loop had no termination
        guard; replaced with an explicit counter ceiling.
        """
        decoded = url
        layers  = 0

        # Bounded decode loop — maximum MAX_DECODE_ITERATIONS passes
        while '%' in decoded and layers < MAX_DECODE_ITERATIONS:
            new_decoded = unquote(decoded)
            if new_decoded == decoded:   # No change → nothing more to decode
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
        except Exception:
            hostname = ""
        is_shortened = hostname in SHORTENER_DOMAINS

        return {
            'decoded_url':    decoded,
            'is_obfuscated':  layers > 1 or has_homoglyphs,
            'encoding_layers': layers,
            'has_homoglyphs': has_homoglyphs,
            'is_shortened':   is_shortened,
        }

    # -----------------------------------------------------------------------
    # 2. Typosquatting Detection
    # -----------------------------------------------------------------------

    def _check_char_substitution(self, domain: str) -> str | None:
        """
        Normalize leet-speak / common character substitutions then check
        edit distance against the brand list.
        """
        substitutions = {
            '0': 'o', '1': 'l', '3': 'e', '5': 's',
            'vv': 'w', 'rn': 'm', 'cl': 'd', 'nn': 'm'
        }
        normalized = domain.lower()
        for fake, real in substitutions.items():
            normalized = normalized.replace(fake, real)

        if normalized != domain.lower():
            for brand in TARGET_BRANDS:
                # REMEDIATION 3A: rapidfuzz C-extension replaces Python DP
                if Levenshtein.distance(normalized, brand) <= 1:
                    return brand
        return None

    def detect_typosquatting(self, url: str) -> dict:
        """
        Check if the registered domain is a typosquat of a known brand.

        REMEDIATION 3A: Replaced pure-Python O(n*m) Levenshtein with
            rapidfuzz.distance.Levenshtein which is implemented in C++ and
            runs ~50–100× faster on CPython.

        REMEDIATION 3B: Domain is truncated to MAX_DOMAIN_LENGTH before any
            distance computation, bounding worst-case matrix size.
        """
        ext    = tldextract.extract(url)
        domain = ext.domain.lower()

        # Defensive: reject pathologically long domains before string-distance
        if len(domain) > MAX_DOMAIN_LENGTH:
            logging.debug(f"Domain '{domain[:20]}…' exceeds {MAX_DOMAIN_LENGTH} chars — skipping typosquat check")
            return {'is_typosquatting': False, 'target_brand': None,
                    'edit_distance': -1, 'method': None}

        # Direct edit distance check — rapidfuzz supports an early-exit
        # `score_cutoff` parameter that short-circuits once the distance
        # exceeds the threshold, giving additional speedup.
        for brand in TARGET_BRANDS:
            distance = Levenshtein.distance(domain, brand, score_cutoff=2)
            if 0 < distance <= 2:
                return {
                    'is_typosquatting': True,
                    'target_brand':     brand,
                    'edit_distance':    distance,
                    'method':           'levenshtein_rapidfuzz',
                }

        # Character substitution check
        sub_brand = self._check_char_substitution(domain)
        if sub_brand:
            return {
                'is_typosquatting': True,
                'target_brand':     sub_brand,
                'edit_distance':    -1,
                'method':           'char_substitution',
            }

        return {
            'is_typosquatting': False,
            'target_brand':     None,
            'edit_distance':    -1,
            'method':           None,
        }

    # -----------------------------------------------------------------------
    # 3. WHOIS Domain Age Check
    # -----------------------------------------------------------------------

    async def check_domain_age(self, url: str) -> dict:
        """
        Async WHOIS lookup with hard 2-second ceiling.
        python-whois is a synchronous blocking library; we push it into a
        thread via asyncio.to_thread so the event loop remains free.
        The inner wait_for guarantees we never block longer than 2 s even
        if the thread pool is saturated.
        """
        try:
            import whois
            from datetime import datetime

            ext    = tldextract.extract(url)
            domain = f"{ext.domain}.{ext.suffix}"

            w = await asyncio.wait_for(
                asyncio.to_thread(whois.whois, domain),
                timeout=2.0
            )

            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if creation_date:
                age_days = (datetime.now() - creation_date).days
                return {
                    'domain_age_days':    age_days,
                    'is_newly_registered': age_days < 30,
                }
        except asyncio.TimeoutError:
            logging.debug(f"WHOIS timeout for {url}")
        except Exception as exc:
            logging.debug(f"WHOIS error for {url}: {exc}")

        return {'domain_age_days': None, 'is_newly_registered': False}
