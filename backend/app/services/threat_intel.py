import os
import httpx
import logging
from .reputation_cache import cache

logger = logging.getLogger(__name__)


class ThreatIntelService:
    def __init__(self):
        self.urlhaus_key     = os.getenv("URLHAUS_API_KEY")
        self.virustotal_key  = os.getenv("VIRUSTOTAL_API_KEY")
        # Persistent async client — reuses TLS sessions, avoids per-request handshake
        self._client = httpx.AsyncClient(timeout=httpx.Timeout(3.0, connect=2.0))

    # -------------------------------------------------------------------------
    # URLhaus URL lookup
    # BUG FIX: was posting to /v1/payload/ (file hash endpoint) — WRONG.
    # The correct endpoint for URL reputation is /v1/url/.
    # /v1/payload/ expects a SHA256 file hash in the 'sha256_hash' field;
    # passing a URL to it always returns query_status != "ok", so URLhaus
    # was silently always returning False and never flagging any URL.
    # -------------------------------------------------------------------------
    async def check_urlhaus(self, url: str) -> bool:
        # Two-tier cache: malicious -> 1 hour, benign -> 24 hours
        if not self.urlhaus_key:
            return False

        cached = await cache.get(url)
        if cached is not None:
            return bool(cached)

        api_url = "https://urlhaus-api.abuse.ch/v1/url/"
        data = {"url": url}
        headers = {"Auth-Key": self.urlhaus_key}

        try:
            response = await self._client.post(api_url, data=data, headers=headers)
            if response.status_code == 200:
                json_data = response.json()
                status = json_data.get("query_status", "")
                is_malicious = False
                if status in ("is_host", "url_in_db"):
                    url_status = json_data.get("url_status", "")
                    is_malicious = url_status in ("online", "")

                ttl = 3600 if is_malicious else 86400
                await cache.set(url, is_malicious, ttl)
                return is_malicious
        except Exception as exc:
            logger.debug(f"URLhaus API error: {exc}")

        return False

    # -------------------------------------------------------------------------
    # VirusTotal URL reputation lookup
    # -------------------------------------------------------------------------
    async def check_virustotal(self, url: str) -> bool:
        if not self.virustotal_key:
            return False

        # Check cache first
        cached = await cache.get(url)
        if cached is not None:
            return bool(cached)

        import base64
        url_id  = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": self.virustotal_key}

        try:
            response = await self._client.get(api_url, headers=headers)

            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious_count = stats.get("malicious", 0)
                suspicious_count = stats.get("suspicious", 0)
                is_malicious = malicious_count > 0 or suspicious_count >= 2
                ttl = 3600 if is_malicious else 86400
                await cache.set(url, is_malicious, ttl)
                return is_malicious

            elif response.status_code == 404:
                # URL not yet in VirusTotal's database — not a known threat
                logger.debug(f"VirusTotal: URL not in database (404) — treating as benign")
                return False

            elif response.status_code == 429:
                # Rate limit hit — log as warning so circuit breaker can track it
                logger.warning("VirusTotal rate limit (429) — circuit breaker should trip")
                raise RuntimeError("VirusTotal rate limited")

        except RuntimeError:
            raise   # Re-raise so the circuit breaker in main.py can record the failure
        except Exception as exc:
            logger.debug(f"VirusTotal API error: {exc}")

        return False
