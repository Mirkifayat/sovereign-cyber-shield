let scoreChartInstance = null;
const loaderMessages = [
    "Executing Nmap Fast Scan...", 
    "Probing Subdomains...", 
    "Checking SSL/TLS Health...", 
    "Querying WHOIS records...", 
    "Testing Path Traversals...", 
    "Analyzing HTTP Headers...",
    "Compiling Intelligence..."
];
let loaderInterval = null;

function cycleLoader() {
    let i = 0;
    document.getElementById('loader-text').textContent = loaderMessages[0];
    loaderInterval = setInterval(() => { 
        i++;
        document.getElementById('loader-text').textContent = loaderMessages[i % loaderMessages.length]; 
    }, 2000);
}

function renderChart(score, color) {
    const ctx = document.getElementById('scoreChart').getContext('2d');
    if (scoreChartInstance) scoreChartInstance.destroy();
    scoreChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: { datasets: [{ data: [score, 100 - score], backgroundColor: [color, 'rgba(255,255,255,0.05)'], borderWidth: 0, cutout: '85%' }] },
        options: { responsive: true, maintainAspectRatio: false, plugins: { tooltip: { enabled: false } } }
    });
}

function populateList(elementId, items) {
    const ul = document.getElementById(elementId);
    if (!ul) return;
    ul.innerHTML = '';
    if (!items || items.length === 0) {
        ul.innerHTML = '<li class="list-item-card" style="border-left-color: #30363d;"><span style="color:#8b949e">No data returned.</span></li>';
        return;
    }
    items.forEach(item => {
        const li = document.createElement('li');
        li.className = 'list-item-card';
        let color = '#8b949e';
        if (item.includes('CRITICAL') || item.includes('DANGER')) color = '#f85149';
        else if (item.includes('WARNING') || item.includes('DETECTED') || item.includes('HIGH')) color = '#d29922';
        else if (item.includes('SUCCESS') || item.includes('SAFE')) color = '#3fb950';

        li.style.borderLeftColor = color;
        if (item.includes(':')) {
            const parts = item.split(':');
            li.innerHTML = `<span style="color:${color}; font-weight:bold;">${parts[0]}:</span> ${parts.slice(1).join(':')}`;
        } else { li.innerHTML = `<span style="color:${color};">${item}</span>`; }
        ul.appendChild(li);
    });
}

async function startScan() {
    const target = document.getElementById('target').value.trim();
    const btn = document.getElementById('scan-btn');
    if (!target) return alert('Please enter a business domain to scan.');

    btn.disabled = true;
    document.getElementById('loader').classList.remove('hidden');
    document.getElementById('result-container').classList.add('hidden');
    cycleLoader();

    try {
        const response = await fetch('/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target })
        });

        const rawText = await response.text();
        let data;
        try { data = JSON.parse(rawText); } 
        catch (e) { throw new Error("Timeout"); }

        clearInterval(loaderInterval);
        document.getElementById('loader').classList.add('hidden');
        document.getElementById('result-container').classList.remove('hidden');

        // Score logic
        document.getElementById('score-text').textContent = data.score;
        const color = data.score >= 80 ? '#3fb950' : (data.score >= 50 ? '#d29922' : '#f85149');
        document.getElementById('score-text').style.color = color;
        renderChart(data.score, color);

        const msg = document.getElementById('score-message');
        if(data.score >= 80) msg.innerHTML = `<span style="color:#3fb950">✅ Highly Resilient: Your digital storefront is well-protected.</span>`;
        else if(data.score >= 50) msg.innerHTML = `<span style="color:#d29922">⚠️ Warning: Multiple vulnerabilities found. Action required.</span>`;
        else msg.innerHTML = `<span style="color:#f85149">🚨 Critical Danger: Business infrastructure is severely compromised.</span>`;

        // Fill ALL 12 Lists
        populateList('web-output', data.web_surface);
        populateList('exploit-output', data.file_exploits);
        populateList('infra-output', data.infra_intelligence);
        populateList('brand-output', data.brand_protection);
        populateList('ssl-output', data.ssl);
        populateList('dns-output', data.dns);
        populateList('subdomain-output', data.subdomains);
        populateList('whois-output', data.whois);
        populateList('header-output', data.http_headers);
        populateList('cms-output', data.cms);
        populateList('cve-output', data.cve);
        populateList('cred-output', data.default_creds);
        populateList('redirect-output', data.open_redirect);

        // Render Geo Data
        if(data.geo) {
            document.getElementById('geo-grid').innerHTML = `
                <div class="geo-box"><div class="geo-label">Server IP Address</div><div class="geo-value">${data.geo.ip}</div></div>
                <div class="geo-box"><div class="geo-label">Physical Location</div><div class="geo-value">${data.geo.country}</div></div>
                <div class="geo-box"><div class="geo-label">Hosting Provider</div><div class="geo-value" style="font-size:0.95rem">${data.geo.isp}</div></div>
            `;
        }

        // Render Roadmap Actions
        const roadmapList = document.getElementById('roadmap-list');
        roadmapList.innerHTML = '';
        if (data.roadmap) {
            data.roadmap.forEach(item => {
                const li = document.createElement('li');
                li.className = 'action-item-card';
                const itemColor = item.label === 'CRITICAL' ? '#f85149' : (item.label === 'HIGH' ? '#f85149' : '#d29922');
                li.style.borderLeftColor = itemColor;
                li.innerHTML = `<div class="action-header" style="color:${itemColor}">[${item.label}] ${item.issue}</div><div class="action-remediation">💡 <strong>Remediation:</strong> ${item.solution}</div>`;
                roadmapList.appendChild(li);
            });
        }

        document.getElementById('output').textContent = data.nmap_results || "No raw data returned.";

    } catch (e) {
        clearInterval(loaderInterval);
        document.getElementById('loader').classList.add('hidden');
        alert('Network Error: The deep scan timed out. The target may be blocking connections. Try scanning scanme.nmap.org');
    } finally { btn.disabled = false; }
}

// Ensure hitting Enter runs the scan
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('target').addEventListener('keydown', e => {
        if (e.key === 'Enter') { e.preventDefault(); startScan(); }
    });
});
