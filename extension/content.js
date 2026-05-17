const currentUrl = window.location.href;

if (!currentUrl.startsWith('chrome://') && !currentUrl.startsWith('http://127.0.0.1') && !currentUrl.startsWith('http://localhost')) {
    try {
        const hostname = new URL(currentUrl).hostname;
        
        chrome.storage.local.get(['whitelist'], function(result) {
            let whitelist = result.whitelist || [];
            
            // If domain is not in the whitelist, scan it normally
            if (!whitelist.includes(hostname)) {
                chrome.runtime.sendMessage({ action: "scan_url", url: currentUrl, whitelisted: false }, (response) => {
                    if (response && response.success && response.data) {
                        const data = response.data;
                        if (data.is_malicious) {
                            showBlockPage(data, hostname);
                        }
                    }
                });
            } else {
                // If it is whitelisted, tell the backend to log it as safe, but don't show block page
                chrome.runtime.sendMessage({ action: "scan_url", url: currentUrl, whitelisted: true }, () => {});
            }
        });
    } catch (e) {
        console.error("Error parsing URL:", e);
    }
}

function showBlockPage(data, hostname) {
    window.stop();
    document.documentElement.innerHTML = '';
    
    const blockHTML = `
        <div class="phishguard-overlay">
            <div class="phishguard-container">
                <div class="phishguard-icon-wrapper">
                    <svg class="phishguard-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
                    </svg>
                </div>
                <h1 class="phishguard-title">Access Blocked</h1>
                <p class="phishguard-subtitle">PhishGuard has detected a security threat on <strong>${hostname}</strong>.</p>
                
                <div class="phishguard-stats">
                    <div class="phishguard-stat-box">
                        <span class="phishguard-stat-label">Risk Score</span>
                        <span class="phishguard-stat-value">${(data.risk_score * 100).toFixed(1)}%</span>
                    </div>
                    <div class="phishguard-stat-box">
                        <span class="phishguard-stat-label">ML Prediction</span>
                        <span class="phishguard-stat-value ${data.model_prediction ? 'text-danger' : 'text-safe'}">${data.model_prediction ? 'Malicious' : 'Safe'}</span>
                    </div>
                </div>

                ${data.threat_intel_matches.length > 0 ? `
                <div class="phishguard-intel">
                    <p class="phishguard-intel-title">Threat Intel Matches:</p>
                    <div class="phishguard-badges">
                        ${data.threat_intel_matches.map(source => `<span class="phishguard-badge">${source}</span>`).join('')}
                    </div>
                </div>
                ` : ''}

                <div class="phishguard-actions">
                    <button class="phishguard-btn-primary" id="phishguard-back">Go Back to Safety</button>
                    <button class="phishguard-btn-secondary" id="phishguard-proceed">Proceed Anyway (Unsafe)</button>
                </div>
            </div>
        </div>
    `;

    const head = document.createElement('head');
    const link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = chrome.runtime.getURL('styles.css');
    head.appendChild(link);
    
    const body = document.createElement('body');
    body.className = 'phishguard-blocked-body';
    body.innerHTML = blockHTML;

    document.documentElement.appendChild(head);
    document.documentElement.appendChild(body);

    document.getElementById('phishguard-proceed').addEventListener('click', () => {
        // Add to whitelist and reload the page
        chrome.storage.local.get(['whitelist'], function(result) {
            let whitelist = result.whitelist || [];
            if (!whitelist.includes(hostname)) {
                whitelist.push(hostname);
            }
            chrome.storage.local.set({ whitelist: whitelist }, function() {
                // Reload without the block page
                window.location.reload();
            });
        });
    });

    document.getElementById('phishguard-back').addEventListener('click', () => {
        // Try to go back in history. If it's a new tab, history.length is 1 or 2, so close tab.
        if (window.history.length > 2) {
            window.history.back();
        } else {
            chrome.runtime.sendMessage({ action: "close_tab" });
        }
    });
}
