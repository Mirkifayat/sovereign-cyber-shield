async function startScan() {
    const targetInput = document.getElementById('target');
    const target = targetInput.value.trim();
    const btn = document.getElementById('scan-btn');
    const loader = document.getElementById('loader');
    const resultContainer = document.getElementById('result-container');

    if (!target) { alert('Please enter a business domain!'); return; }

    btn.disabled = true;
    loader.classList.remove('hidden');
    resultContainer.classList.add('hidden');

    try {
        const response = await fetch('/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target })
        });

        if (!response.ok) throw new Error('Server limit hit');
        const data = await response.json();
        
        loader.classList.add('hidden');
        resultContainer.classList.remove('hidden');

        // Update Score Text (Matches your Screenshot)
        const scoreVal = document.getElementById('score-text');
        if (scoreVal) scoreVal.textContent = data.score;

        // Render Chart
        if (typeof renderChart === "function") {
            renderChart(data.score, data.score > 70 ? '#3fb950' : '#f85149');
        }

        // Populate Lists
        const listMap = {
            'web-output': data.web_surface,
            'brand-output': data.brand_protection,
            'ssl-output': data.ssl,
            'dns-output': data.dns,
            'subdomain-output': data.subdomains,
            'whois-output': data.whois,
            'header-output': data.http_headers,
            'cms-output': data.cms,
            'cve-output': data.cve,
            'cred-output': data.default_creds,
            'redirect-output': data.open_redirect
        };

        for (const [id, items] of Object.entries(listMap)) {
            const el = document.getElementById(id);
            if (el) el.innerHTML = items.map(i => `<li>${i}</li>`).join('');
        }

        // Update Geo Data
        if (data.geo && !data.geo.error) {
            document.getElementById('server-ip').textContent = data.geo.ip;
            document.getElementById('server-country').textContent = data.geo.country;
            document.getElementById('server-isp').textContent = data.geo.isp;
        }

        // Update Roadmap / Action Plan (Matching Screenshot UI)
        const roadmapList = document.getElementById('roadmap-list');
        if (roadmapList) {
            roadmapList.innerHTML = data.roadmap.map(item => `
                <div class="action-item-card">
                    <div class="action-header" style="color: ${item.label === 'CRITICAL' ? '#f85149' : '#d29922'}">
                        [${item.label}] ${item.finding}
                    </div>
                    <div class="action-remediation">💡 <strong>Remediation:</strong> Secure your backend and restrict public access.</div>
                </div>
            `).join('');
        }

        document.getElementById('output').textContent = data.nmap_results;

    } catch (err) {
        loader.classList.add('hidden');
        alert('BACKEND TIMEOUT: The scan is too deep for Render. Try a faster domain like nmap.org');
    } finally { btn.disabled = false; }
}

// STOP ENTER RELOAD
document.addEventListener('DOMContentLoaded', () => {
    const targetField = document.getElementById('target');
    if (targetField) {
        targetField.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                startScan();
            }
        });
    }
});
