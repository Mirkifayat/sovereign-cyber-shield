let scoreChartInstance = null;

function populateList(elementId, items) {
    const ul = document.getElementById(elementId);
    ul.innerHTML = '';
    items.forEach(item => {
        const li = document.createElement('li');
        li.className = 'list-item-card';
        if (item.includes('CRITICAL') || item.includes('DANGER')) li.classList.add('border-danger');
        else if (item.includes('WARNING')) li.classList.add('border-warning');
        li.textContent = item;
        ul.appendChild(li);
    });
}

function renderChart(score, colorCode) {
    const ctx = document.getElementById('scoreChart').getContext('2d');
    if (scoreChartInstance) scoreChartInstance.destroy();
    scoreChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: { datasets: [{ data: [score, 100 - score], backgroundColor: [colorCode, '#232931'], borderWidth: 0, cutout: '85%' }] },
        options: { responsive: true, maintainAspectRatio: false, animation: { animateScale: true }, plugins: { tooltip: { enabled: false } } }
    });
}

async function startScan() {
    const target = document.getElementById('target').value.trim();
    if (!target) { alert('Please enter a domain!'); return; }

    const btn = document.getElementById('scan-btn');
    const loader = document.getElementById('loader');
    const results = document.getElementById('result-container');

    btn.disabled = true;
    loader.classList.remove('hidden');
    results.classList.add('hidden');

    try {
        const response = await fetch('/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target })
        });

        const data = await response.json();
        loader.classList.add('hidden');

        if (!response.ok) {
            alert('Scan Error: ' + (data.error || 'Check domain and try again.'));
            btn.disabled = false;
            return;
        }

        results.classList.remove('hidden');
        
        // Render Score
        const color = data.score >= 80 ? '#3fb950' : (data.score >= 50 ? '#d29922' : '#f85149');
        document.getElementById('score-text').textContent = data.score;
        document.getElementById('score-text').style.color = color;
        renderChart(data.score, color);

        // Populate Modules
        populateList('web-output', data.web_surface);
        populateList('brand-output', data.brand_protection);
        populateList('ssl-output', data.ssl);
        populateList('dns-output', data.dns);

        // Geo Intel
        document.getElementById('geo-grid').innerHTML = `
            <div class="geo-box">IP Address: ${data.geo.ip}</div>
            <div class="geo-box">Location: ${data.geo.country}</div>
        `;

        // Roadmap
        const roadmapList = document.getElementById('roadmap-list');
        roadmapList.innerHTML = '';
        if (data.roadmap.length > 0) {
            document.getElementById('roadmap-card-container').classList.remove('hidden');
            data.roadmap.forEach(item => {
                const li = document.createElement('li');
                li.className = 'action-item-card';
                li.style.borderLeftColor = item.label === 'CRITICAL' ? '#f85149' : '#d29922';
                li.innerHTML = `<strong>[${item.label}]</strong> ${item.finding}`;
                roadmapList.appendChild(li);
            });
        }

        document.getElementById('output').textContent = data.nmap_results;

    } catch (err) {
        loader.classList.add('hidden');
        alert('Network Error: Could not reach the server.');
    } finally {
        btn.disabled = false;
    }
}

// Prevent Enter key from refreshing page
document.getElementById('target').addEventListener('keydown', e => {
    if (e.key === 'Enter') {
        e.preventDefault();
        startScan();
    }
});
