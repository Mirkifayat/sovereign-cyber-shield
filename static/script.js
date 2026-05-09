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
        li.textContent = item;
        ul.appendChild(li);
    });
}

async function startScan() {
    const target = document.getElementById('target').value.trim();
    if (!target) return alert('Enter domain');
    document.getElementById('loader').classList.remove('hidden');
    document.getElementById('result-container').classList.add('hidden');
    try {
        const response = await fetch('/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target }) });
        const data = await response.json();
        document.getElementById('loader').classList.add('hidden');
        document.getElementById('result-container').classList.remove('hidden');

        document.getElementById('score-text').textContent = data.score;
        renderChart(data.score, data.score > 70 ? '#3fb950' : '#f85149');

        populateList('web-output', data.web_surface);
        populateList('exploit-output', data.file_exploits);
        populateList('brand-output', data.brand_protection);

        document.getElementById('geo-grid').innerHTML = `<div class="geo-box">IP: ${data.geo.ip}</div><div class="geo-box">Location: ${data.geo.country}</div>`;

        const roadmap = document.getElementById('roadmap-list');
        roadmap.innerHTML = '';
        data.roadmap.forEach(item => {
            const li = document.createElement('li');
            li.className = 'action-item-card';
            li.style.borderLeftColor = item.label === 'CRITICAL' ? '#f85149' : '#d29922';
            li.innerHTML = `<strong>[${item.label}] ${item.issue}</strong><br><small>💡 Solution: ${item.solution}</small>`;
            roadmap.appendChild(li);
        });
        document.getElementById('output').textContent = data.nmap_results;
    } catch (e) { alert('Scan Failed'); document.getElementById('loader').classList.add('hidden'); }
}

document.getElementById('target').addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); startScan(); } });
