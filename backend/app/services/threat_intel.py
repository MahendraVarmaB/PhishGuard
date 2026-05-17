import os
import httpx
import logging

class ThreatIntelService:
    def __init__(self):
        self.urlhaus_key = os.getenv("URLHAUS_API_KEY")
        self.virustotal_key = os.getenv("VIRUSTOTAL_API_KEY")
        # Persistent HTTP client — eliminates TLS handshake overhead on every request
        self._client = httpx.AsyncClient(timeout=httpx.Timeout(3.0, connect=2.0))

    async def check_urlhaus(self, url: str) -> bool:
        if not self.urlhaus_key:
            return False
        
        api_url = "https://urlhaus-api.abuse.ch/v1/payload/"
        data = {'url': url}
        headers = {'Auth-Key': self.urlhaus_key}
        
        try:
            response = await self._client.post(api_url, data=data, headers=headers)
            if response.status_code == 200:
                json_data = response.json()
                if json_data.get("query_status") == "ok":
                    return True
        except Exception as e:
            logging.debug(f"URLhaus API error: {e}")
        return False

    async def check_virustotal(self, url: str) -> bool:
        if not self.virustotal_key:
            return False
        
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {
            "x-apikey": self.virustotal_key
        }
        try:
            response = await self._client.get(api_url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious_count = stats.get("malicious", 0)
                return malicious_count > 0
        except Exception as e:
            logging.debug(f"VirusTotal API error: {e}")
        return False
