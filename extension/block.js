// block.js — Runs inside the isolated chrome-extension://... block page.
// Reads scan metadata from URL query params (set by background.js redirect).
// Has ZERO access to the blocked website's origin or DOM.

(function () {
    "use strict";

    const params       = new URLSearchParams(window.location.search);
    const targetUrl    = params.get("target")  || "";
    const riskScore    = parseFloat(params.get("score") || "0");
    const intelSources = (params.get("intel") || "").split(",").filter(Boolean);
    const typoTarget   = params.get("typo")   || "";

    // --- Populate UI ---
    let hostname = "";
    try { hostname = new URL(targetUrl).hostname; } catch {}

    document.getElementById("subtitle-text").innerHTML =
        `PhishGuard has detected a security threat on <strong>${escapeHtml(hostname)}</strong>.`;

    document.getElementById("risk-score-val").textContent =
        `${(riskScore * 100).toFixed(1)}%`;

    const hostnameEl = document.getElementById("hostname-val");
    hostnameEl.textContent = hostname || targetUrl.slice(0, 40);
    hostnameEl.style.fontSize = hostname.length > 25 ? "11px" : "13px";

    // Intel badges
    const allSources = [...intelSources];
    if (typoTarget) allSources.push(`Typosquatting (${typoTarget})`);

    if (allSources.length > 0) {
        const block  = document.getElementById("intel-block");
        const badges = document.getElementById("intel-badges");
        block.classList.remove("hidden");
        allSources.forEach(src => {
            const span       = document.createElement("span");
            span.className   = "badge";
            span.textContent = escapeHtml(src);  // Always escape untrusted content
            badges.appendChild(span);
        });
    }

    // --- Button handlers ---
    document.getElementById("btn-back").addEventListener("click", () => {
        if (window.history.length > 1) {
            window.history.back();
        } else {
            chrome.runtime.sendMessage({ action: "close_tab" });
        }
    });

    document.getElementById("btn-proceed-once").addEventListener("click", () => {
        if (!hostname || !targetUrl) return;
        // Ask background worker to allow this exact URL bypass just this once,
        // then navigate to it.
        chrome.runtime.sendMessage(
            { action: "proceed_once", url: targetUrl },
            () => { window.location.href = targetUrl; }
        );
    });

    document.getElementById("btn-whitelist").addEventListener("click", () => {
        if (!hostname || !targetUrl) return;
        // Ask background worker to permanently add this domain to the whitelist,
        // then navigate to the original URL.
        chrome.runtime.sendMessage(
            { action: "add_to_whitelist", hostname, url: targetUrl },
            () => { window.location.href = targetUrl; }
        );
    });

    // --- Utility: always escape before inserting untrusted text into DOM ---
    function escapeHtml(str) {
        const d = document.createElement("div");
        d.appendChild(document.createTextNode(str));
        return d.innerHTML;
    }
})();
