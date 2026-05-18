// content.js — PhishGuard v2.0
//
// REMEDIATION 4A: This file is intentionally minimal.
//
// The old version of content.js performed DOM injection to display a block
// overlay AFTER the malicious page had already loaded and executed JavaScript.
// That approach had two critical flaws:
//   1. Any JS on the malicious page could detect and remove the overlay via
//      MutationObserver, completely defeating the protection.
//   2. Drive-by exploits and zero-day payloads fired before the overlay appeared.
//
// Blocking is now performed entirely in background.js via
// chrome.webNavigation.onBeforeNavigate, which intercepts the navigation
// BEFORE the HTTP request is made — the malicious page never loads at all.
//
// This file is kept for any future passive content-layer instrumentation
// (e.g. reporting suspicious form submissions) but performs NO blocking.
