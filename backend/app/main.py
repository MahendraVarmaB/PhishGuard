import time
import asyncio
import os
import json
import logging
from concurrent.futures import ThreadPoolExecutor

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from dotenv import load_dotenv
from cachetools import TTLCache
import tldextract
from failsafe import Failsafe, CircuitBreaker, CircuitOpen, RetryPolicy

from .models.schemas import ScanRequest, ScanResponse
from .services.threat_intel import ThreatIntelService
from .services.ml_inference import MLModelService
from .services.url_analyzer import URLAnalyzerService

# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------
dotenv_path = os.path.join(os.path.dirname(__file__), "..", "..", ".env")
load_dotenv(dotenv_path)

logging.basicConfig(level=logging.INFO)

app = FastAPI(title="PhishGuard API", version="3.0.0")

app.add_middleware(
    CORSMiddleware,
    # Chrome extension service workers send Origin: chrome-extension://<id>
    # which does NOT match the string "null". We use allow_origin_regex to
    # accept any chrome-extension:// origin plus the local dashboard.
    # This is safe: the backend only binds to 127.0.0.1 and is never
    # reachable from the public internet.
    allow_origin_regex=r"(chrome-extension://.*|http://localhost:\d+|http://127\.0\.0\.1:\d+)",
    allow_credentials=False,   # Must be False when using regex (not explicit origin list)
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

# ---------------------------------------------------------------------------
# Service singletons
# ---------------------------------------------------------------------------
threat_intel  = ThreatIntelService()
ml_service    = MLModelService()
url_analyzer  = URLAnalyzerService()

# ---------------------------------------------------------------------------
# REMEDIATION 2A: Two-tier in-memory TTL cache
#
# Benign domains: 24-hour TTL — safe verdicts are highly stable.
# Malicious domains: 1-hour TTL — phishing infrastructure rotates fast;
#   re-validate frequently so a takedown is reflected quickly.
#
# Production note: For multi-worker or distributed deployments, replace with:
#   import redis.asyncio as aioredis
#   r = aioredis.from_url("redis://localhost")
#   cached = await r.get(url)
#   await r.setex(url, ttl, json.dumps(result))
# ---------------------------------------------------------------------------
_BENIGN_CACHE:    TTLCache = TTLCache(maxsize=50_000, ttl=86_400)   # 24 h
_MALICIOUS_CACHE: TTLCache = TTLCache(maxsize=10_000, ttl=3_600)    # 1 h


# ---------------------------------------------------------------------------
# REMEDIATION 2B: ThreadPoolExecutor for ML inference
#
# Why not ProcessPoolExecutor?
# On Windows, multiprocessing uses the 'spawn' start method. When uvicorn's
# --reload restarts the server, it sends KeyboardInterrupt to the main
# process, which propagates into spawned worker processes mid-queue-wait,
# crashing them. This is a known Windows-specific incompatibility.
#
# ThreadPoolExecutor is the correct choice here because:
#   1. XGBoost 2.x releases the GIL during predict() tree traversal,
#      so threads ARE genuinely concurrent for ML inference.
#   2. No Windows spawn issues — threads share the same process.
#   3. No pickling overhead (ProcessPool must pickle all args/results).
# ---------------------------------------------------------------------------
_ML_POOL = ThreadPoolExecutor(max_workers=2)


# ---------------------------------------------------------------------------
# REMEDIATION 2C: Circuit Breakers for external CTI APIs
#
# Pattern: Failsafe(circuit_breaker=...) wraps a callable. After
# `maximum_failures` consecutive exceptions, the circuit opens and
# subsequent calls immediately raise CircuitOpen() for `reset_timeout_seconds`.
# This prevents a flapping VirusTotal API from cascading into scan failures.
# ---------------------------------------------------------------------------
_vt_breaker      = CircuitBreaker(maximum_failures=3, reset_timeout_seconds=60)
_urlhaus_breaker = CircuitBreaker(maximum_failures=3, reset_timeout_seconds=60)
# RetryPolicy with 0 retries: we want fail-fast on external services, not retries
_no_retry = RetryPolicy(allowed_retries=0)


# ---------------------------------------------------------------------------
# Top-domain allow-list
# ---------------------------------------------------------------------------
_TOP_DOMAINS_PATH = os.path.join(os.path.dirname(__file__), "top_10k_domains.txt")
try:
    with open(_TOP_DOMAINS_PATH, 'r', encoding='utf-8') as f:
        TOP_DOMAINS: set = {line.strip().lower() for line in f if line.strip()}
except Exception:
    TOP_DOMAINS = set()

# Pre-warm tldextract suffix-list cache at startup
tldextract.extract("https://example.com")

# In-memory ring buffer + SSE subscriber queue list
scan_history: list[dict]          = []
_SSE_SUBSCRIBERS: list[asyncio.Queue] = []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _root_domain(url: str) -> str:
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}".lower()


def _cache_write(response: ScanResponse) -> None:
    blob = response.model_dump()
    if response.is_malicious:
        _MALICIOUS_CACHE[response.url] = blob
    else:
        _BENIGN_CACHE[response.url] = blob


def _cache_read(url: str) -> dict | None:
    return _MALICIOUS_CACHE.get(url) or _BENIGN_CACHE.get(url)


def _append_history(response: ScanResponse) -> None:
    """Persist to ring buffer and fan-out to all live SSE subscribers."""
    entry = {"timestamp": time.time(), **response.model_dump()}
    scan_history.append(entry)
    if len(scan_history) > 500:
        scan_history.pop(0)
    for q in list(_SSE_SUBSCRIBERS):
        try:
            q.put_nowait(entry)
        except asyncio.QueueFull:
            pass   # Slow subscriber — drop; they'll catch up on reconnect


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.post("/api/v1/scan", response_model=ScanResponse)
async def scan_url(request: ScanRequest):
    start_time = time.time()
    url        = request.url

    # --- Fast path 1: User whitelist or one-time bypass ---
    if request.whitelisted or request.bypassed:
        reason = "User Whitelist" if request.whitelisted else "User Bypass (One-Time)"
        
        # Preserve original risk score if possible instead of defaulting to 0.0
        original_score = 0.0
        cached = _cache_read(url)
        if cached:
            original_score = cached.get('risk_score', 0.0)

        resp = ScanResponse(
            url=url, is_malicious=False, risk_score=original_score,
            threat_intel_matches=[reason],
            model_prediction=False,
            latency_ms=(time.time() - start_time) * 1000,
        )
        _append_history(resp)
        return resp

    # --- Fast path 2: Cache hit (~0 ms) ---
    cached = _cache_read(url)
    if cached:
        # Refresh latency field only — everything else from cache
        fields = {k: v for k, v in cached.items() if k in ScanResponse.model_fields}
        fields["latency_ms"] = (time.time() - start_time) * 1000
        resp = ScanResponse(**fields)
        _append_history(resp)
        return resp

    # --- Step 1: Synchronous fast checks (no I/O, microseconds) ---
    obfuscation_result = url_analyzer.decode_url(url)
    effective_url      = obfuscation_result['decoded_url']
    typosquat_result   = url_analyzer.detect_typosquatting(effective_url)
    is_top_domain      = _root_domain(effective_url) in TOP_DOMAINS

    # -----------------------------------------------------------------------
    # PERFORMANCE OPTIMIZATION: Trust known top domains instantly
    # If the domain is in our top 10k list (e.g., google.com, amazon.com)
    # AND there are no suspicious indicators (obfuscation/typosquatting),
    # bypass all external CTI APIs and ML inference.
    # Latency drops from ~1500ms down to <1ms for the vast majority of web traffic.
    # -----------------------------------------------------------------------
    if is_top_domain and not obfuscation_result['is_obfuscated'] and not typosquat_result['is_typosquatting']:
        response = ScanResponse(
            url=url,
            is_malicious=False,
            risk_score=0.01,  # baseline low risk
            threat_intel_matches=[],
            model_prediction=False,
            latency_ms=(time.time() - start_time) * 1000,
            typosquatting_target=None,
            domain_age_days=None,
            is_obfuscated=False,
        )
        _cache_write(response)
        _append_history(response)
        return response

    # --- Step 2: Parallel I/O + CPU-bound work ---

    # REMEDIATION 2B: Run ML in process pool — bypasses GIL
    loop    = asyncio.get_running_loop()
    ml_task = loop.run_in_executor(_ML_POOL, ml_service.predict, effective_url)

    # REMEDIATION 2C: CTI calls with circuit breakers
    async def safe_urlhaus() -> bool:
        try:
            fs = Failsafe(circuit_breaker=_urlhaus_breaker, retry_policy=_no_retry)
            return await asyncio.wait_for(
                fs.run(threat_intel.check_urlhaus, effective_url),
                timeout=3.0
            )
        except (CircuitOpen, asyncio.TimeoutError, Exception) as exc:
            logging.warning(f"URLhaus unavailable ({type(exc).__name__}) — fail-safe False")
            return False

    async def safe_virustotal() -> bool:
        try:
            fs = Failsafe(circuit_breaker=_vt_breaker, retry_policy=_no_retry)
            return await asyncio.wait_for(
                fs.run(threat_intel.check_virustotal, effective_url),
                timeout=3.0
            )
        except (CircuitOpen, asyncio.TimeoutError, Exception) as exc:
            logging.warning(f"VirusTotal unavailable ({type(exc).__name__}) — fail-safe False")
            return False

    async def safe_whois() -> dict:
        try:
            return await url_analyzer.check_domain_age(effective_url)
        except Exception:
            return {'domain_age_days': None, 'is_newly_registered': False}

    ml_result, urlhaus_result, vt_result, whois_result = await asyncio.gather(
        ml_task,
        safe_urlhaus(),
        safe_virustotal(),
        safe_whois(),
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
    risk_score   = ml_result["probability"]

    if typosquat_result['is_typosquatting']:
        risk_score   = max(risk_score, 0.90)
        is_malicious = True
    if whois_result.get('is_newly_registered'):
        risk_score = max(risk_score, 0.70)

    cti_flagged = urlhaus_result or vt_result
    if is_top_domain and not cti_flagged:
        is_malicious             = False
        risk_score               = min(risk_score, 0.05)
        ml_result["is_phishing"] = False
    if cti_flagged:
        risk_score   = max(risk_score, 0.95)
        is_malicious = True

    response = ScanResponse(
        url=url,
        is_malicious=is_malicious,
        risk_score=risk_score,
        threat_intel_matches=threat_intel_matches,
        model_prediction=ml_result["is_phishing"],
        latency_ms=(time.time() - start_time) * 1000,
        typosquatting_target=typosquat_result.get('target_brand'),
        domain_age_days=whois_result.get('domain_age_days'),
        is_obfuscated=obfuscation_result['is_obfuscated'],
    )

    _cache_write(response)
    _append_history(response)
    return response


# ---------------------------------------------------------------------------
# REMEDIATION 5: Server-Sent Events stream
#
# Replaces the dashboard's 3-second setInterval polling entirely.
# Each new scan fires a JSON event only to connected subscribers.
# Bandwidth drops from O(total_history_size) every 3s → O(1 event) per scan.
# ---------------------------------------------------------------------------
@app.get("/api/v1/stream")
async def stream_events():
    queue: asyncio.Queue = asyncio.Queue(maxsize=200)
    _SSE_SUBSCRIBERS.append(queue)

    async def event_generator():
        try:
            while True:
                entry = await queue.get()
                yield f"data: {json.dumps(entry)}\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            if queue in _SSE_SUBSCRIBERS:
                _SSE_SUBSCRIBERS.remove(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/api/v1/health")
async def health_check():
    return {
        "status": "ok",
        "model_loaded": ml_service.model is not None,
        "cache": {
            "benign_entries":    len(_BENIGN_CACHE),
            "malicious_entries": len(_MALICIOUS_CACHE),
        },
        "circuit_breakers": {
            "virustotal": "open" if not _vt_breaker.allows_execution() else "closed",
            "urlhaus":    "open" if not _urlhaus_breaker.allows_execution() else "closed",
        },
    }


@app.get("/api/v1/history")
async def get_history():
    return {"history": scan_history[::-1]}
