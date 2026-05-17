chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "scan_url") {
        fetch("http://127.0.0.1:8000/api/v1/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: request.url, whitelisted: request.whitelisted || false })
        })
        .then(response => response.json())
        .then(data => sendResponse({ success: true, data: data }))
        .catch(error => {
            console.error("Backend error:", error);
            sendResponse({ success: false, error: error.toString() });
        });
        
        return true; 
    }
    if (request.action === "close_tab") {
        if (sender.tab && sender.tab.id) {
            chrome.tabs.remove(sender.tab.id);
        }
    }
});
