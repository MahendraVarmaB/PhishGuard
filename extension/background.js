// ─────────────────────────────────────────────────────────────────────────────
// PhishGuard Background Service Worker v2.0
//
// REMEDIATION 4A — Network-level interception
// ─────────────────────────────────────────────────────────────────────────────
// OLD APPROACH (broken):
//   content.js injected an overlay into the malicious page's DOM after it had
//   already loaded. Problems:
//     1. The page rendered and executed JS before the block overlay appeared.
//     2. A MutationObserver on the malicious page could detect and remove the
//        overlay immediately, defeating the protection entirely.
//     3. No protection against drive-by downloads or zero-day exploits that
//        fired on page load.
//
// NEW APPROACH (correct):
//   chrome.webNavigation.onBeforeNavigate fires BEFORE the browser sends the
//   HTTP request for the new page. We evaluate the URL against the backend
//   while the browser is still in pre-navigation state. If it's malicious, we
//   redirect the tab to our locally isolated block.html BEFORE the target
//   page's HTML, JavaScript, or resources are ever downloaded or executed.
//
// REMEDIATION 4B — Isolated block UI
//   Block page lives at chrome-extension://<id>/block.html — completely
//   isolated from the web origin being blocked. No hostile JS can reach it.
// ─────────────────────────────────────────────────────────────────────────────

const BACKEND_URL  = "http://127.0.0.1:8000";
const SCAN_TIMEOUT = 4000; // ms — budget before we fail-open to avoid blocking UX

// ─── In-memory result cache (session-scoped, clears on SW restart) ───────────
// Mirrors the backend's TTL logic: benign → 24h, malicious → 1h.
// Prevents re-scanning the same URL on every page click within a session.
const _cache     = new Map();
const _maliciousHostnames = new Map();
const _bypassOnce = new Set();
const BENIGN_TTL = 86_400_000;   // 24 hours in ms
const PHISH_TTL  =  3_600_000;   // 1 hour in ms

function _cacheGet(url) {
    const entry = _cache.get(url);
    if (!entry) return null;
    if (Date.now() > entry.expiry) {
        _cache.delete(url);
        return null;
    }
    return entry.data;
}

function _cacheSet(url, data) {
    const ttl = data.is_malicious ? PHISH_TTL : BENIGN_TTL;
    _cache.set(url, { data, expiry: Date.now() + ttl });
    
    // Taint the entire hostname if malicious, preventing sub-page evasion
    if (data.is_malicious) {
        let hostname;
        try { hostname = new URL(url).hostname; } catch {}
        if (hostname) {
            _maliciousHostnames.set(hostname, { data, expiry: Date.now() + PHISH_TTL });
        }
    }
}

// ─── Backend fetch with hard timeout ─────────────────────────────────────────
async function fetchScanResult(url, whitelisted = false, bypassed = false) {
    const controller = new AbortController();
    const timerId    = setTimeout(() => controller.abort(), SCAN_TIMEOUT);
    try {
        const res = await fetch(`${BACKEND_URL}/api/v1/scan`, {
            method:  "POST",
            headers: { "Content-Type": "application/json" },
            body:    JSON.stringify({ url, whitelisted, bypassed }),
            signal:  controller.signal,
        });
        if (!res.ok) return null;
        return await res.json();
    } catch {
        return null;   // Timeout or backend offline → fail-open (allow navigation)
    } finally {
        clearTimeout(timerId);
    }
}

// ─── Core interception logic ──────────────────────────────────────────────────
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    // Only intercept top-level main-frame navigations
    if (details.frameId !== 0) return;

    const url = details.url;

    // Skip internal pages
    if (
        url.startsWith("chrome://") ||
        url.startsWith("chrome-extension://") ||
        url.startsWith("about:") ||
        url.startsWith("http://127.0.0.1") ||
        url.startsWith("http://localhost")
    ) return;

    // --- Check whitelist ---
    const { whitelist = [] } = await chrome.storage.local.get(["whitelist"]);
    let hostname;
    try { hostname = new URL(url).hostname; } catch { return; }

    const isWhitelisted = whitelist.includes(hostname);

    // --- Check One-Time Bypass ---
    if (_bypassOnce.has(url)) {
        _bypassOnce.delete(url);
        // Fire-and-forget to backend so the dashboard logs it
        fetchScanResult(url, false, true).catch(() => {});
        return; // Allow navigation
    }

    // --- Domain-level Malicious Taint Check ---
    if (!isWhitelisted) {
        const tainted = _maliciousHostnames.get(hostname);
        if (tainted) {
            if (Date.now() > tainted.expiry) {
                _maliciousHostnames.delete(hostname);
            } else {
                fetchScanResult(url, false, false).catch(() => {});
                redirectToBlockPage(details.tabId, url, tainted.data);
                return;
            }
        }
    }

    // --- Client-side cache hit (exact URL) ---
    const cached = _cacheGet(url);
    if (cached) {
        if (cached.is_malicious && !isWhitelisted) {
            fetchScanResult(url, false, false).catch(() => {});
            redirectToBlockPage(details.tabId, url, cached);
        } else {
            // Fire-and-forget to backend so the dashboard logs it
            fetchScanResult(url, isWhitelisted, false).catch(() => {});
        }
        return;
    }

    // --- Fetch scan result from backend ---
    const result = await fetchScanResult(url, isWhitelisted);
    if (!result) return;  // Backend offline or timeout → fail-open

    _cacheSet(url, result);

    if (result.is_malicious && !isWhitelisted) {
        redirectToBlockPage(details.tabId, url, result);
    }
});

// ─── Redirect to isolated block page ─────────────────────────────────────────
function redirectToBlockPage(tabId, originalUrl, scanData) {
    // Encode scan metadata in the URL fragment so block.html can read it
    // without any postMessage cross-origin channel.
    const params = new URLSearchParams({
        target: originalUrl,
        score:  scanData.risk_score,
        intel:  (scanData.threat_intel_matches || []).join(","),
        typo:   scanData.typosquatting_target || "",
    });
    const blockUrl = chrome.runtime.getURL(`block.html?${params.toString()}`);
    chrome.tabs.update(tabId, { url: blockUrl });
}

// ─── Message handlers (called from block.html buttons) ─────────────────────
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "add_to_whitelist") {
        chrome.storage.local.get(["whitelist"], ({ whitelist = [] }) => {
            if (!whitelist.includes(request.hostname)) {
                whitelist.push(request.hostname);
            }
            chrome.storage.local.set({ whitelist }, () => {
                // Clear this URL from the extension-side cache too
                _cache.delete(request.url);
                sendResponse({ ok: true });
            });
        });
        return true;
    }

    if (request.action === "proceed_once") {
        _bypassOnce.add(request.url);
        sendResponse({ ok: true });
        return true;
    }

    if (request.action === "close_tab") {
        if (sender.tab?.id) chrome.tabs.remove(sender.tab.id);
    }
});
