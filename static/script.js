let scoreChartInstance = null;

function renderChart(score, color) {
    const ctx = document.getElementById('scoreChart').getContext('2d');
    if (scoreChartInstance) scoreChartInstance.destroy();
    scoreChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: { datasets: [{ data: [score, 100 - score], backgroundColor: [color, 'rgba(255,255,255,0.05)'], borderWidth: 0, cutout: '85%' }] },
        options: { responsive: true, maintainAspectRatio: false, plugins: { tooltip: { enabled: false } } }
    });
}

// Safely fills the UI cards
function populateList(elementId, items) {
    const ul = document.getElementById(elementId);
    if (!ul) return; // Fail-safe
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
        else if (item.includes('WARNING') || item.includes('DETECTED')) color = '#d29922';
        else if (item.includes('SUCCESS') || item.includes('SAFE')) color = '#3fb950';

        li.style.borderLeftColor = color;
        
        // Bold the prefix (e.g., CRITICAL:)
        if (item.includes(':')) {
            const parts = item.split(':');
            li.innerHTML = `<span style="color:${color}; font-weight:bold;">${parts[0]}:</span> ${parts.slice(1).join(':')}`;
        } else {
            li.innerHTML = `<span style="color:${color};">${item}</span>`;
        }
        
        ul.appendChild(li);
    });
}

async function startScan() {
    const targetInput = document.getElementById('target');
    const target = targetInput.value.trim();
    const btn = document.getElementById('scan-btn');
    
    if (!target) return alert('Please enter a business domain to scan.');

    btn.disabled = true;
    document.getElementById('loader').classList.remove('hidden');
    document.getElementById('result-container').classList.add('hidden');

    try {
        const response = await fetch('/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target })
        });

        // Fail-safe JSON parsing
        const rawText = await response.text();
        let data;
        try {
            data = JSON.parse(rawText);
        } catch (e) {
            document.getElementById('loader').classList.add('hidden');
            document.getElementById('result-container').classList.remove('hidden');
            document.getElementById('output').textContent = "ERROR: Server took too long to respond. The deep scan timed out.\n\nTry a faster domain.";
            btn.disabled = false;
            return;
        }

        document.getElementById('loader').classList.add('hidden');
        document.getElementById('result-container').classList.remove('hidden');

        // 1. Render Score
        document.getElementById('score-text').textContent = data.score;
        const color = data.score >= 80 ? '#3fb950' : (data.score >= 50 ? '#d29922' : '#f85149');
        document.getElementById('score-text').style.color = color;
        renderChart(data.score, color);

        // 2. Render all 10 Modules securely
        populateList('web-output', data.web_surface);
        populateList('exploit-output', data.file_exploits);
        populateList('infra-output', data.infra_intelligence);
        populateList('brand-output', data.brand_protection);
        populateList('ssl-output', data.ssl);
        populateList('dns-output', data.dns);
        populateList('cms-output', data.cms);
        populateList('cve-output', data.cve);
        populateList('cred-output', data.default_creds);
        populateList('redirect-output', data.open_redirect);

        // 3. Render Geo Intel
        if(data.geo) {
            document.getElementById('geo-grid').innerHTML = `
                <div class="geo-box"><div class="geo-label">Server IP Address</div><div class="geo-value">${data.geo.ip}</div></div>
                <div class="geo-box"><div class="geo-label">Physical Location</div><div class="geo-value">${data.geo.country}</div></div>
                <div class="geo-box"><div class="geo-label">Hosting Provider</div><div class="geo-value" style="font-size:0.95rem">${data.geo.isp}</div></div>
            `;
        }

        // 4. Render Action Plan
        const roadmapList = document.getElementById('roadmap-list');
        roadmapList.innerHTML = '';
        if (data.roadmap) {
            data.roadmap.forEach(item => {
                const li = document.createElement('li');
                li.className = 'action-item-card';
                const itemColor = item.label === 'CRITICAL' ? '#f85149' : (item.label === 'HIGH' ? '#f85149' : '#d29922');
                li.style.borderLeftColor = itemColor;
                li.innerHTML = `
                    <div class="action-header" style="color:${itemColor}">[${item.label}] ${item.issue}</div>
                    <div class="action-remediation">💡 <strong>Remediation:</strong> ${item.solution}</div>
                `;
                roadmapList.appendChild(li);
            });
        }

        // 5. Render Nmap Raw
        document.getElementById('output').textContent = data.nmap_results || "No raw data returned.";

    } catch (e) {
        alert('Network Error. Could not connect to the backend server.');
        document.getElementById('loader').classList.add('hidden');
    } finally {
        btn.disabled = false;
    }
}

// Prevent Enter key from reloading the page
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('target').addEventListener('keydown', e => {
        if (e.key === 'Enter') {
            e.preventDefault();
            startScan();
        }
    });
});
