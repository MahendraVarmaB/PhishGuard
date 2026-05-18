# PhishGuard 🛡️

**Real-time ML-powered phishing URL detection** - Chrome extension + FastAPI backend + React analyst dashboard.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Prerequisites](#prerequisites)
4. [ML Pipeline - Training & Evaluation](#ml-pipeline--training--evaluation)
   - [Datasets](#datasets)
   - [Feature Engineering (20 Features)](#feature-engineering-20-features)
   - [Model Architecture](#model-architecture)
   - [Training Strategy](#training-strategy)
   - [Evaluation Metrics & Targets](#evaluation-metrics--targets)
   - [Production Reality Check](#production-reality-check)
5. [Backend Setup (FastAPI)](#backend-setup-fastapi)
6. [Chrome Extension Setup](#chrome-extension-setup)
7. [Analyst Dashboard Setup](#analyst-dashboard-setup)
8. [API Reference](#api-reference)
9. [How It All Works Together](#how-it-all-works-together)
10. [Configuration & Environment Variables](#configuration--environment-variables)
11. [Project Structure](#project-structure)

---

## Overview

PhishGuard is a three-component system that intercepts browser navigations in real time, evaluates the destination URL against an ML model and live threat intelligence feeds, and blocks phishing sites before they load. A React dashboard gives security analysts a live view of scan history and risk distribution.

**Key goals:**
- ≥95% accuracy on a balanced dataset with sub-500ms response time
- Active threat intelligence: URL obfuscation decoding, live DNS/WHOIS lookups, typosquatting detection
- Network-level interception in the browser (page never loads if flagged)
- Exportable IoC reports for analysts

---

## Architecture

```
Browser Navigation
      │
      ▼
Chrome Extension (background.js)
  ├── Client-side TTL cache check (instant)
  ├── Top-domain fast path (< 1 ms)
  └── POST /api/v1/scan
            │
            ▼
      FastAPI Backend
        ├── Two-tier TTL cache (benign 24h / malicious 1h)
        ├── URL obfuscation decoder
        ├── Typosquatting detector (RapidFuzz)
        ├── ML inference (XGBoost, ThreadPoolExecutor)
        ├── URLhaus CTI check  ─┐ run in
        ├── VirusTotal CTI check─┤ parallel
        └── WHOIS domain age    ─┘
                    │
                    ▼
          Aggregated ScanResponse
                    │
          ┌─────────┴──────────┐
          ▼                    ▼
    Block page            SSE stream
  (extension)          (dashboard live feed)
```

---

## Prerequisites

| Component | Requirement |
|-----------|-------------|
| Python | 3.10 or later |
| Node.js | 18 or later |
| Chrome | Any modern version (Manifest V3 support) |
| API Keys | VirusTotal (free tier works), URLhaus (optional) |

---

## ML Pipeline - Training & Evaluation

The ML pipeline lives in `ml_pipeline/` and is completely independent of the backend. Run it once to produce a serialized model; the backend loads that file at startup.

### Datasets

The pipeline blends four data sources into a single balanced dataset:

| Source | Type | Label |
|--------|------|-------|
| **PhishTank** (`PhishTank.csv`) | Verified phishing URLs | Malicious (1) |
| **URLhaus API** | Live malicious URLs fetched at training time | Malicious (1) |
| **Tranco Top List** (`tranco_43KLX.csv`) | Top-ranked legitimate domains, URL-augmented with realistic paths | Benign (0) |
| **ISCX-URL-2016** (`ISCX-URL-2016.csv`) | Mixed labelled URL dataset (benign/malicious split on `URL_Type_obf_Type` column) | Both |

**Balancing:** After combining all sources, the pipeline randomly samples equal numbers of malicious and benign URLs (up to 15,000 per class, `random_state=42`), producing a balanced dataset of up to **30,000 samples**. This prevents the majority class from dominating accuracy metrics.

**URL augmentation for Tranco:** Raw Tranco entries are just domain names. To make them realistic, the pipeline appends one of 12 real-world URL path templates (search queries, product pages, wiki pages, etc.) to 85% of benign entries, so the model learns to distinguish legitimate long URLs from phishing paths.

### Feature Engineering (20 Features)

All features are purely lexical and structural - no live network calls are made during training. This keeps inference fast and model-portable.

| # | Feature | Description |
|---|---------|-------------|
| 1 | `url_length` | Total decoded URL character count |
| 2 | `hostname_length` | Length of the `netloc` portion |
| 3 | `path_length` | Length of the URL path component |
| 4 | `num_dots` | Count of `.` characters in the full URL |
| 5 | `num_hyphens` | Count of `-` characters (phishing domains often use hyphens like `paypal-secure.xyz`) |
| 6 | `num_at` | Count of `@` characters (used to spoof usernames before the hostname) |
| 7 | `num_query_params` | Number of `&`-separated query parameters |
| 8 | `is_https` | Binary: 1 if scheme is `https`, 0 otherwise |
| 9 | `has_ip_in_domain` | Binary: 1 if the hostname is a raw IPv4 address |
| 10 | `has_obfuscation` | Binary: 1 if URL contains `%`-encoding or known shorteners (`bit.ly`, `tinyurl`) |
| 11 | `subdomain_count` | Number of subdomain labels (e.g., `a.b.example.com` → 2) |
| 12 | `num_digits_in_hostname` | Count of digit characters in the hostname |
| 13 | `hostname_entropy` | Shannon entropy of the hostname - high entropy signals randomly generated domains |
| 14 | `tld_risk_score` | Binary: 1 if TLD is in a curated high-risk set (`.tk`, `.xyz`, `.top`, `.icu`, etc., 34 total) |
| 15 | `domain_length` | Length of the registered domain only (excluding subdomains and TLD) |
| 16 | `has_brand_impersonation` | Binary: 1 if the registered domain contains a known brand name but is not that brand's actual domain (checks 46 brands: PayPal, Google, Apple, Microsoft, Amazon, Netflix, banks, crypto exchanges, etc.) |
| 17 | `special_char_ratio` | Ratio of non-alphanumeric, non-standard characters to total URL length |
| 18 | `path_depth` | Number of non-empty path segments (directory depth) |
| 19 | `has_suspicious_keywords` | Binary: 1 if the URL path contains any of 25 phishing keywords (`login`, `verify`, `secure`, `credential`, `webscr`, `suspend`, etc.) |
| 20 | `digit_letter_ratio_in_domain` | Ratio of digits to letters in the registered domain - high values indicate generated domains |

**Important:** The backend's `MLModelService.extract_features()` is an exact mirror of `DataPrepPipeline.extract_lexical_features()`. The same constants (`HIGH_RISK_TLDS`, `TARGET_BRANDS`, `SUSPICIOUS_PATH_KEYWORDS`) are duplicated in both files. If you add or modify any feature during retraining, you must update both files identically to avoid a feature mismatch at inference time.

### Model Architecture

PhishGuard trains two classifiers and selects the winner by ROC-AUC:

**Primary: XGBoost (`XGBClassifier`) + Isotonic Regression Calibration**

XGBoost was chosen for its strong performance on tabular data and because XGBoost 2.x releases the GIL during `predict()` tree traversal, allowing genuine CPU concurrency inside the backend's `ThreadPoolExecutor` without process-pool overhead.

**Baseline: Random Forest (`RandomForestClassifier`) + Isotonic Regression Calibration**

Trained with `class_weight='balanced'` as the RF equivalent of `scale_pos_weight`. Used as a comparison baseline; the model with the higher ROC-AUC on the held-out test set is serialized and deployed.

Both models are wrapped with `CalibratedClassifierCV(method='isotonic', cv=5)` before being serialized. Isotonic regression post-processes the raw classifier scores so that `predict_proba()` returns well-calibrated probabilities. This is critical because the backend uses these probabilities directly as the `risk_score` displayed to users.

### Training Strategy

**Data splits (stratified, `random_state=42`):**

```
Full Dataset (up to 30,000 samples)
    │
    ├── 80% → Train+Calibration pool
    │       ├── 60% → X_train  (fit XGBoost base estimator)
    │       └── 20% → X_cal    (calibrate probabilities)
    │
    └── 20% → X_test  (never seen during training or calibration)
```

The three-way split is deliberate: calibrating on the same data used for fitting produces overfit probability estimates. `X_cal` is held back from the base estimator so that the isotonic regression sees genuine out-of-bag predictions.

**Hyperparameter tuning (XGBoost only):**

`RandomizedSearchCV` runs 20 random configurations over 5-fold cross-validation, scored on `roc_auc` (not accuracy). The search space covers:

```python
{
    'n_estimators':     [100, 200, 300],
    'max_depth':        [4, 6, 8, 10],
    'learning_rate':    [0.05, 0.1, 0.2],
    'subsample':        [0.7, 0.8, 0.9, 1.0],
    'colsample_bytree': [0.7, 0.8, 0.9, 1.0],
    'min_child_weight': [1, 3, 5],
    'gamma':            [0, 0.1, 0.2]
}
```

**Cost-sensitive weighting (`scale_pos_weight=10`):**

Real-world phishing prevalence is roughly 1 malicious URL per 1,000 benign ones. Setting `scale_pos_weight=10` tells XGBoost to penalize false negatives (missed phishing) 10× more than false positives (false alarms). The value is intentionally conservative (not 1,000) because the CTI layer and WHOIS checks serve as secondary validators - the ML model doesn't have to catch everything alone.

### Evaluation Metrics & Targets

After training, the pipeline evaluates the best model on the held-out `X_test` set and logs the following:

| Metric | Description | Target |
|--------|-------------|--------|
| **Accuracy** | Fraction correctly classified on the balanced test set | ≥ 0.95 |
| **ROC-AUC** | Area under the ROC curve - primary selection criterion; captures both FP and FN trade-off | ≥ 0.97 |
| **Brier Score** | Mean squared error of probability estimates (0 = perfect, 1 = worst) | Lower is better |
| **Precision** | Of all URLs flagged as phishing, what fraction actually are | Reported |
| **Recall (Sensitivity)** | Of all actual phishing URLs, what fraction were caught | Reported |
| **F1 Score** | Harmonic mean of Precision and Recall | Reported per class |
| **Confusion Matrix** | Raw TP / TN / FP / FN counts | Logged |

The full `sklearn.metrics.classification_report` (precision, recall, F1 for both classes) is written to the training log.

**Model selection rule:** The model with the higher ROC-AUC is chosen - not the one with higher raw accuracy. On a balanced dataset, both metrics tend to agree, but AUC is a better proxy for real-world performance because it is threshold-independent.

### Production Reality Check

The balanced test set is an optimistic environment. To simulate what the model faces in the real world (where the overwhelming majority of URLs are benign), the pipeline runs a skewed-dataset evaluation after selecting the best model:

```
For every 1 phishing sample in X_test → inject 100 benign samples.
Evaluate on this 1:100 skewed set and report:
  - False Positive Rate (FPR):  target < 0.01  (< 1% of safe sites blocked)
  - Recall (Sensitivity):       target > 0.90  (catch > 90% of phishing)
```

If either target is missed, the log prints a warning. Increasing `SCALE_POS_WEIGHT` reduces FPR at the cost of recall; the right balance depends on your SOC's tolerance for false alarms vs. missed threats.

---

## Backend Setup (FastAPI)

### 1. Train the ML model first

```bash
cd ml_pipeline

# Install dependencies
pip install -r requirements.txt

# Place your datasets in ml_pipeline/data/
#   PhishTank.csv
#   tranco_43KLX.csv
#   ISCX-URL-2016.csv  (optional but recommended)

# Step 1: Feature extraction (outputs ml_pipeline/data/processed_features.csv)
python data_prep.py

# Step 2: Train + evaluate + serialize the model
#         (outputs ml_pipeline/models/phishguard_model.joblib)
python train.py

# Step 3: Export top-50k domains for the backend allowlist
python export_top_domains.py
```

### 2. Configure environment variables

Create a `.env` file in the project root:

```env
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
URLHAUS_API_KEY=your_urlhaus_api_key_here   # optional
```

### 3. Install backend dependencies and run

```bash
cd backend

pip install -r requirements.txt

# Start the API server (binds to 127.0.0.1:8000 by default)
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

The backend is now reachable at `http://127.0.0.1:8000`. It will only accept connections from `localhost` and Chrome extension origins (`chrome-extension://...`).

Verify the model loaded correctly:

```bash
curl http://127.0.0.1:8000/api/v1/health
```

Expected response:
```json
{
  "status": "ok",
  "model_loaded": true,
  "cache": { "benign_entries": 0, "malicious_entries": 0 },
  "circuit_breakers": { "virustotal": "closed", "urlhaus": "closed" }
}
```

---

## Chrome Extension Setup

### 1. Load the extension

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable **Developer mode** (toggle in the top-right corner)
3. Click **Load unpacked**
4. Select the `extension/` folder from this project

The PhishGuard icon will appear in your Chrome toolbar.

### 2. Verify the connection

Click the PhishGuard toolbar icon to open the popup. The **Backend API** field should show **Connected** in green. If it shows **Disconnected**, ensure the FastAPI server is running on port 8000.

### 3. How the extension works

The extension uses `chrome.webNavigation.onBeforeNavigate` - it intercepts navigations **before** the HTTP request is sent. The target page never loads if it is flagged.

**Decision flow for every top-frame navigation:**

```
URL navigated
  │
  ├── Internal page? (chrome://, about:, localhost) → ALLOW
  │
  ├── User whitelist hit? → ALLOW + log to backend
  │
  ├── One-time bypass set? → ALLOW + log to backend
  │
  ├── Malicious hostname taint cache? → BLOCK immediately
  │
  ├── Client-side TTL cache hit?
  │     ├── Malicious → BLOCK
  │     └── Benign → ALLOW + fire-and-forget log
  │
  ├── POST /api/v1/scan (4s timeout)
  │     ├── Top-50k domain + no red flags → ALLOW (< 1ms, no CTI calls)
  │     ├── Full pipeline → ML + URLhaus + VirusTotal + WHOIS in parallel
  │     └── Backend offline → FAIL-OPEN (allow, protect UX)
  │
  └── Result malicious? → redirect to block.html (isolated extension page)
```

**Block page actions:**
- **Go Back to Safety** - navigates back or closes the tab
- **Proceed only this time** - adds a one-time bypass and navigates to the URL
- **Whitelist Domain** - permanently trusts the domain across sessions (stored in `chrome.storage.local`)

**Cache TTLs (client-side, mirroring the backend):**
- Benign verdicts: 24 hours
- Malicious verdicts: 1 hour (phishing infrastructure rotates quickly)

---

## Analyst Dashboard Setup

```bash
cd dashboard

npm install

npm run dev
```

Open `http://localhost:5173` in your browser. The dashboard connects to the backend's Server-Sent Events stream at `GET /api/v1/stream` for zero-latency real-time updates - no polling.

### Dashboard features

- **Live scan feed** - every URL scanned by the extension appears in real time via SSE
- **Risk distribution chart** - visual breakdown of benign vs malicious scans (Recharts)
- **Scan history table** - sortable, virtualized list (TanStack Virtual) showing URL, risk score, verdict, threat intel sources, domain age, latency
- **Threat intelligence badges** - each scan row shows which CTI sources flagged the URL (URLhaus, VirusTotal, typosquatting match, URL obfuscation, new domain)
- **IoC export** - download scan history as a structured JSON report for incident response

To build for production:

```bash
npm run build
# Outputs to dashboard/dist/
```

---

## API Reference

All endpoints are served at `http://127.0.0.1:8000`.

### `POST /api/v1/scan`

Scan a URL for phishing indicators.

**Request body:**
```json
{
  "url": "https://paypa1-secure.xyz/login",
  "whitelisted": false,
  "bypassed": false
}
```

**Response:**
```json
{
  "url": "https://paypa1-secure.xyz/login",
  "is_malicious": true,
  "risk_score": 0.97,
  "threat_intel_matches": ["URLhaus", "Typosquatting (paypal)"],
  "model_prediction": true,
  "latency_ms": 312.4,
  "typosquatting_target": "paypal",
  "domain_age_days": 3,
  "is_obfuscated": false
}
```

| Field | Type | Description |
|-------|------|-------------|
| `is_malicious` | bool | Final verdict (ML + CTI combined) |
| `risk_score` | float (0–1) | Calibrated probability from the ML model, boosted by CTI hits |
| `threat_intel_matches` | string[] | Which intelligence sources flagged the URL |
| `model_prediction` | bool | Raw ML model output (before CTI override) |
| `latency_ms` | float | End-to-end scan time in milliseconds |
| `typosquatting_target` | string \| null | Brand being impersonated, if detected |
| `domain_age_days` | int \| null | Domain registration age from WHOIS |
| `is_obfuscated` | bool | Whether URL percent-encoding or shorteners were detected |

### `GET /api/v1/history`

Returns the last 500 scans (most recent first).

### `GET /api/v1/stream`

Server-Sent Events stream. Each event is a JSON-serialized scan result. The dashboard subscribes here for real-time updates.

### `GET /api/v1/health`

Returns service health: model load status, cache sizes, and circuit breaker states for each CTI API.

---

## How It All Works Together

When you navigate to `https://paypa1-secure.xyz/login`:

1. **Extension** fires `onBeforeNavigate`, misses the client cache, and sends a `POST /api/v1/scan` to the backend.

2. **Backend** checks the two-tier TTL cache (miss), runs the URL obfuscation decoder (clean), and runs the typosquatting detector against the Tranco top-domain list using RapidFuzz fuzzy matching - it finds that `paypa1-secure` is suspiciously close to `paypal`.

3. **In parallel**, the backend sends the URL to URLhaus and VirusTotal through circuit-breaker-wrapped async calls (3s timeout each), and queries WHOIS for domain age.

4. **ML inference** runs in a `ThreadPoolExecutor` alongside the CTI calls. The `MLModelService` extracts the 20 lexical features and calls `predict_proba()` on the loaded calibrated XGBoost model. The domain has a high-entropy hostname, a risky TLD, brand impersonation, and suspicious path keywords - all high-signal features.

5. **Aggregation:** `risk_score` is the ML probability, boosted to `max(score, 0.90)` by the typosquatting detection and to `max(score, 0.95)` by the URLhaus hit. `is_malicious` is `True`.

6. **Extension** receives the response, caches it for 1 hour, and redirects the tab to the isolated `chrome-extension://.../block.html` - the phishing page never loads.

7. **Dashboard** receives the scan via SSE and appends it to the live feed.

---

## Configuration & Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `VIRUSTOTAL_API_KEY` | Recommended | Free at virustotal.com. Without it, VT checks are skipped. |
| `URLHAUS_API_KEY` | Optional | abuse.ch API key. The public API works without a key at lower rate limits. |

---

## Project Structure

```
PhishGuard/
├── ml_pipeline/
│   ├── data/                    # Place PhishTank.csv, tranco_43KLX.csv, ISCX-URL-2016.csv here
│   ├── models/                  # Serialized model output (phishguard_model.joblib)
│   ├── data_prep.py             # Dataset loading, blending, and feature extraction
│   ├── train.py                 # Model training, evaluation, and serialization
│   ├── export_top_domains.py    # Exports top-50k domains for the backend allowlist
│   └── requirements.txt
│
├── backend/
│   └── app/
│       ├── models/
│       │   └── schemas.py       # Pydantic request/response models
│       ├── services/
│       │   ├── ml_inference.py  # Feature extraction + model inference
│       │   ├── threat_intel.py  # URLhaus + VirusTotal CTI lookups
│       │   └── url_analyzer.py  # Obfuscation decoder, typosquatting, WHOIS
│       ├── main.py              # FastAPI app, routes, caching, SSE stream
│       └── top_10k_domains.txt  # Top-50k allowlist (generated by export_top_domains.py)
│
├── extension/
│   ├── popup/
│   │   ├── popup.html           # Toolbar popup UI
│   │   └── popup.js             # Checks backend health and renders status
│   ├── background.js            # Service worker: intercepts navigations, caches results
│   ├── block.html               # Isolated warning page shown on phishing detection
│   ├── block.js                 # Reads scan metadata from URL params, handles user actions
│   ├── content.js               # Intentionally minimal; no DOM injection in v2
│   ├── manifest.json            # Manifest V3 config
│   └── styles.css               # Block page styles
│
├── dashboard/
│   └── src/
│       ├── App.jsx              # Main dashboard: live feed, charts, history table
│       ├── main.jsx             # React entry point
│       └── index.css            # Global styles
│
└── .env                         # API keys (not committed)
```
