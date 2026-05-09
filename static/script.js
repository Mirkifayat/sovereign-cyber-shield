// ... existing cycleLoaderText, stopLoaderText, populateList, renderChart functions ...

function renderGeo(geo) {
    const grid = document.getElementById('geo-grid');
    grid.innerHTML = `
        <div class="geo-box"><div class="geo-label">Server IP</div><div class="geo-value">${geo.ip}</div></div>
        <div class="geo-box"><div class="geo-label">Location</div><div class="geo-value">${geo.country}</div></div>
        <div class="geo-box"><div class="geo-label">ISP</div><div class="geo-value" style="font-size:0.9rem">${geo.isp}</div></div>
    `;
}

async function startScan() {
    const targetInput = document.getElementById('target');
    const target = targetInput.value.trim();
    if (!target) { alert('Enter a domain!'); return; }

    document.getElementById('loader').classList.remove('hidden');
    document.getElementById('result-container').classList.add('hidden');
    cycleLoaderText();

    try {
        const response = await fetch('/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target })
        });

        const data = await response.json();
        document.getElementById('loader').classList.add('hidden');
        document.getElementById('result-container').classList.remove('hidden');

        // Render Data to Lists
        populateList('web-output', data.web_surface);
        populateList('exploit-output', data.file_exploits);
        populateList('infra-output', data.infra_intelligence);
        populateList('brand-output', data.brand_protection);
        
        // Render Score & Geo
        document.getElementById('score-text').textContent = data.score;
        renderChart(data.score, data.score > 70 ? '#3fb950' : '#f85149');
        renderGeo(data.geo);

        // Render Roadmap
        const roadmapList = document.getElementById('roadmap-list');
        roadmapList.innerHTML = '';
        data.action_plan.forEach(item => {
            const li = document.createElement('li');
            li.className = 'action-item-card border-' + item.label.toLowerCase();
            li.innerHTML = `<div class="action-header" style="color: ${item.label === 'CRITICAL' ? '#f85149' : '#d29922'}">[${item.label}] ${item.issue}</div><div class="action-remediation">💡 Remediation: ${item.solution}</div>`;
            roadmapList.appendChild(li);
        });

        document.getElementById('output').textContent = data.nmap_results;

    } catch (err) {
        alert('Network Error. Please try again.');
        document.getElementById('loader').classList.add('hidden');
    }
}
