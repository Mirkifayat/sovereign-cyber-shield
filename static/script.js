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

function populateList(elementId, items) {
    const ul = document.getElementById(elementId);
    ul.innerHTML = '';
    items.forEach(item => {
        const li = document.createElement('li');
        li.className = 'list-item-card';
        if (item.includes('CRITICAL')) li.style.borderLeftColor = '#f85149';
        else if (item.includes('WARNING')) li.style.borderLeftColor = '#d29922';
        li.textContent = item;
        ul.appendChild(li);
    });
}

async function startScan() {
    const target = document.getElementById('target').value.trim();
    if (!target) return alert('Please enter a business domain to scan!');

    // Reset UI
    document.getElementById('loader').classList.remove('hidden');
    document.getElementById('result-container').classList.add('hidden');

    try {
        const response = await fetch('/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target })
        });

        const data = await response.json();
        document.getElementById('loader').classList.add('hidden');
        document.getElementById('result-container').classList.remove('hidden');

        // Render Score
        document.getElementById('score-text').textContent = data.score;
        const scoreColor = data.score >= 80 ? '#3fb950' : (data.score >= 50 ? '#d29922' : '#f85149');
        renderChart(data.score, scoreColor);

        // Populate Modules
        populateList('web-output', data.web_surface);
        populateList('exploit-output', data.file_exploits);
        populateList('brand-output', data.brand_protection);
        populateList('ssl-output', data.ssl);
        populateList('dns-output', data.dns);
        populateList('cms-output', data.cms);
        populateList('cve-output', data.cve);

        // Render Geo-Intelligence
        document.getElementById('geo-grid').innerHTML = `
            <div class="geo-box">IP Address: <span style="color:#58a6ff">${data.geo.ip}</span></div>
            <div class="geo-box">Location: <span style="color:#58a6ff">${data.geo.country}</span></div>
        `;

        // Render Action Plan (Feature: Solid Scanning Actions)
        const roadmapList = document.getElementById('roadmap-list');
        roadmapList.innerHTML = '';
        data.roadmap.forEach(item => {
            const li = document.createElement('li');
            li.className = 'action-item-card';
            li.style.borderLeftColor = item.label === 'CRITICAL' ? '#f85149' : '#d29922';
            li.innerHTML = `<div class="action-header" style="color:${item.label === 'CRITICAL' ? '#f85149' : '#d29922'}">[${item.label}] ${item.issue}</div><div class="action-remediation">💡 Remediation: ${item.solution}</div>`;
            roadmapList.appendChild(li);
        });

        document.getElementById('output').textContent = data.nmap_results;

    } catch (e) {
        alert('Network Error. Scan might be too deep for the free server tier.');
        document.getElementById('loader').classList.add('hidden');
    }
}

// Key Listener
document.getElementById('target').addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); startScan(); } });
