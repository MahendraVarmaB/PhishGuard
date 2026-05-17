import time
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import asyncio
import tldextract

from .models.schemas import ScanRequest, ScanResponse
from .services.threat_intel import ThreatIntelService
from .services.ml_inference import MLModelService
from .services.url_analyzer import URLAnalyzerService

# Load environment variables
import os
dotenv_path = os.path.join(os.path.dirname(__file__), "..", "..", ".env")
load_dotenv(dotenv_path)

app = FastAPI(title="PhishGuard API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

threat_intel = ThreatIntelService()
ml_service = MLModelService()
url_analyzer = URLAnalyzerService()
scan_history = []

# Load Top 50k Domains
top_domains_path = os.path.join(os.path.dirname(__file__), "top_10k_domains.txt")
try:
    with open(top_domains_path, 'r', encoding='utf-8') as f:
        TOP_DOMAINS = set(line.strip().lower() for line in f if line.strip())
except Exception as e:
    TOP_DOMAINS = set()

# Pre-warm tldextract cache on startup
tldextract.extract("https://example.com")


@app.post("/api/v1/scan", response_model=ScanResponse)
async def scan_url(request: ScanRequest):
    start_time = time.time()
    url = request.url
    
    # --- Fast path: whitelisted URLs ---
    if request.whitelisted:
        response = ScanResponse(
            url=url,
            is_malicious=False,
            risk_score=0.0,
            threat_intel_matches=["User Whitelist"],
            model_prediction=False,
            latency_ms=(time.time() - start_time) * 1000
        )
        _append_history(response)
        return response
    
    # --- Step 1: Synchronous fast checks (microseconds) ---
    
    # URL obfuscation analysis
    obfuscation_result = url_analyzer.decode_url(url)
    effective_url = obfuscation_result['decoded_url']
    
    # Typosquatting detection
    typosquat_result = url_analyzer.detect_typosquatting(effective_url)
    
    # Top domain trust check
    ext = tldextract.extract(effective_url)
    root_domain = f"{ext.domain}.{ext.suffix}".lower()
    is_top_domain = root_domain in TOP_DOMAINS
    
    # --- Step 2: Run ML + CTI + WHOIS concurrently (with budget) ---
    ml_task = asyncio.to_thread(ml_service.predict, effective_url)
    
    # Wrap external calls in timeouts so they never exceed our latency budget
    async def safe_urlhaus():
        try:
            return await asyncio.wait_for(threat_intel.check_urlhaus(effective_url), timeout=3.0)
        except asyncio.TimeoutError:
            return False
    
    async def safe_virustotal():
        try:
            return await asyncio.wait_for(threat_intel.check_virustotal(effective_url), timeout=3.0)
        except asyncio.TimeoutError:
            return False
    
    async def safe_whois():
        try:
            return await url_analyzer.check_domain_age(effective_url)
        except:
            return {'domain_age_days': None, 'is_newly_registered': False}
    
    ml_result, urlhaus_result, vt_result, whois_result = await asyncio.gather(
        ml_task, safe_urlhaus(), safe_virustotal(), safe_whois()
    )
    
    # --- Step 3: Aggregate intelligence ---
    threat_intel_matches = []
    if urlhaus_result:
        threat_intel_matches.append("URLhaus")
    if vt_result:
        threat_intel_matches.append("VirusTotal")
    if typosquat_result['is_typosquatting']:
        threat_intel_matches.append(f"Typosquatting ({typosquat_result['target_brand']})")
    if obfuscation_result['is_obfuscated']:
        threat_intel_matches.append("URL Obfuscation")
    if whois_result.get('is_newly_registered'):
        threat_intel_matches.append("New Domain (<30 days)")
    
    is_malicious = ml_result["is_phishing"] or len(threat_intel_matches) > 0
    risk_score = ml_result["probability"]
    
    # Boost risk for typosquatting
    if typosquat_result['is_typosquatting']:
        risk_score = max(risk_score, 0.90)
        is_malicious = True
    
    # Boost risk for newly registered domains
    if whois_result.get('is_newly_registered'):
        risk_score = max(risk_score, 0.70)
    
    # Trust override: top domains are safe unless CTI explicitly flags them
    cti_flagged = urlhaus_result or vt_result
    if is_top_domain and not cti_flagged:
        is_malicious = False
        risk_score = min(risk_score, 0.05)
        ml_result["is_phishing"] = False

    # CTI always wins if it has a definitive match
    if cti_flagged:
        risk_score = max(risk_score, 0.95)
        is_malicious = True
        
    latency_ms = (time.time() - start_time) * 1000
    
    response = ScanResponse(
        url=url,
        is_malicious=is_malicious,
        risk_score=risk_score,
        threat_intel_matches=threat_intel_matches,
        model_prediction=ml_result["is_phishing"],
        latency_ms=latency_ms,
        typosquatting_target=typosquat_result.get('target_brand'),
        domain_age_days=whois_result.get('domain_age_days'),
        is_obfuscated=obfuscation_result['is_obfuscated']
    )
    
    _append_history(response)
    return response


def _append_history(response: ScanResponse):
    """Helper to append scan to history ring buffer."""
    scan_history.append({
        "timestamp": time.time(),
        **response.model_dump()
    })
    if len(scan_history) > 100:
        scan_history.pop(0)


@app.get("/api/v1/health")
async def health_check():
    return {"status": "ok", "model_loaded": ml_service.model is not None}

@app.get("/api/v1/history")
async def get_history():
    return {"history": scan_history[::-1]}
