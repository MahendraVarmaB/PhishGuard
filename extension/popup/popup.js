fetch("http://127.0.0.1:8000/api/v1/health")
    .then(res => res.json())
    .then(data => {
        const el = document.getElementById('api-status');
        if (data.status === 'ok') {
            el.textContent = "Connected";
            el.style.color = "#22c55e";
        } else {
            el.textContent = "Error";
            el.style.color = "#ef4444";
        }
    })
    .catch(() => {
        const el = document.getElementById('api-status');
        el.textContent = "Disconnected";
        el.style.color = "#ef4444";
    });
