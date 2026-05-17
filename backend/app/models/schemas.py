from pydantic import BaseModel

class ScanRequest(BaseModel):
    url: str
    whitelisted: bool = False

class ScanResponse(BaseModel):
    url: str
    is_malicious: bool
    risk_score: float
    threat_intel_matches: list[str]
    model_prediction: bool
    latency_ms: float
    typosquatting_target: str | None = None
    domain_age_days: int | None = None
    is_obfuscated: bool = False
