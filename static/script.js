async function startScan() {
    const target = document.getElementById('target').value.trim();
    if (!target) { alert('Enter a business domain!'); return; }

    // UI Reset
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
        const scoreCircle = document.getElementById('score-circle');
        scoreCircle.textContent = data.score;
        renderChart(data.score, data.score > 70 ? '#3fb950' : '#f85149');

        // Populate Modules (Preserving all lists)
        const modules = [
            'web-output', 'brand-output', 'ssl-output', 'dns-output', 
            'subdomain-output', 'whois-output', 'header-output', 
            'cms-output', 'cve-output', 'cred-output', 'redirect-output'
        ];
        
        modules.forEach(id => {
            const list = document.getElementById(id);
            list.innerHTML = '';
            const dataKey = id.replace('-output', '');
            (data[dataKey] || []).forEach(item => {
                const li = document.createElement('li');
                li.className = 'list-item-card ' + (item.includes('CRITICAL') ? 'border-danger' : 'border-info');
                li.innerHTML = item;
                list.appendChild(li);
            });
        });

        // Render Geo Boxes
        const geoGrid = document.getElementById('geo-grid');
        geoGrid.innerHTML = `
            <div class="geo-box"><div class="geo-label">IP Address</div><div class="geo-value">${data.geo.ip}</div></div>
            <div class="geo-box"><div class="geo-label">Provider</div><div class="geo-value">${data.geo.isp}</div></div>
            <div class="geo-box"><div class="geo-label">Location</div><div class="geo-value">${data.geo.country}</div></div>
        `;

        // Render Action Plan (The Feature you requested)
        const roadmapList = document.getElementById('roadmap-list');
        roadmapList.innerHTML = '';
        data.action_plan.forEach(item => {
            const li = document.createElement('li');
            li.className = 'action-item-card ' + (item.label === 'CRITICAL' ? 'border-danger' : 'border-warning');
            li.innerHTML = `
                <div class="action-header" style="color: ${item.label === 'CRITICAL' ? '#f85149' : '#d29922'}">[${item.label}] ${item.issue}</div>
                <div class="action-remediation">💡 Remediation: ${item.solution}</div>
            `;
            roadmapList.appendChild(li);
        });

        document.getElementById('output').textContent = data.nmap_results;

    } catch (err) {
        alert('Network error. Check Render logs.');
        document.getElementById('loader').classList.add('hidden');
    }
}
