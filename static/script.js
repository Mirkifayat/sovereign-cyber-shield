const loaderMessages = [
    "Checking SSL certificate...",
    "Probing DNS security records...",
    "Enumerating subdomains...",
    "Scanning HTTP security headers...",
    "Running Nmap infrastructure scan...",
    "Detecting CMS fingerprint...",
    "Testing default credentials...",
    "Calculating risk score..."
];

let loaderInterval = null;
let scoreChartInstance = null;

function cycleLoaderText() {
    let i = 0;
    const el = document.getElementById('loader-text');
    loaderInterval = setInterval(() => {
        el.textContent = loaderMessages[i % loaderMessages.length];
        i++;
    }, 2200);
}

function stopLoaderText() {
    if (loaderInterval) {
        clearInterval(loaderInterval);
        loaderInterval = null;
    }
}

// Custom parser to match the screenshot styling
function populateList(elementId, items) {
    const ul = document.getElementById(elementId);
    ul.innerHTML = '';
    if (!items || items.length === 0) {
        ul.innerHTML = '<li class="list-item-card border-info"><span class="text-info">No data returned.</span></li>';
        return;
    }

    items.forEach(item => {
        const li = document.createElement('li');
        li.className = 'list-item-card';

        let prefix = '';
        let rest = item;
        let colorClass = 'text-info';
        let borderClass = 'border-info';

        // Split "CRITICAL: The rest of the message"
        if (item.includes(':')) {
            const parts = item.split(':');
            prefix = parts[0] + ':';
            rest = parts.slice(1).join(':');
        }

        if (item.includes('CRITICAL') || item.includes('DANGER')) { 
            colorClass = 'text-danger'; borderClass = 'border-danger'; 
        } else if (item.includes('WARNING') || item.includes('DETECTED') || item.includes('FOUND')) { 
            colorClass = 'text-warning'; borderClass = 'border-warning'; 
        } else if (item.includes('SUCCESS') || item.includes('SAFE') || item.includes('INFO')) { 
            colorClass = 'text-info'; borderClass = 'border-info'; 
        }

        li.classList.add(borderClass);
        
        if (prefix) {
            li.innerHTML = `<span class="${colorClass} font-bold">${prefix}</span>${rest}`;
        } else {
            li.innerHTML = `<span class="${colorClass}">${item}</span>`;
        }
        
        ul.appendChild(li);
    });
}

function renderChart(score, colorCode) {
    const ctx = document.getElementById('scoreChart').getContext('2d');
    if (scoreChartInstance) scoreChartInstance.destroy();
    
    scoreChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            datasets: [{
                data: [score, 100 - score],
                backgroundColor: [colorCode, 'rgba(255, 255, 255, 0.05)'],
                borderWidth: 0, cutout: '85%', borderRadius: 5
            }]
        },
        options: { 
            responsive: true, 
            maintainAspectRatio: false, 
            animation: { animateScale: true }, 
            plugins: { tooltip: { enabled: false } } 
        }
    });
}

function renderGeo(geo) {
    const geoGrid = document.getElementById('geo-grid');
    if (!geo || geo.error) {
        geoGrid.innerHTML = `<div class="geo-box"><div class="geo-label">Status</div><div class="geo-value" style="color:#f85149;">${geo ? geo.error : "Lookup Failed"}</div></div>`;
        return;
    }

    const locationString = [geo.city, geo.country].filter(Boolean).join(', ') || 'Unknown';
    
    geoGrid.innerHTML = `
        <div class="geo-box">
            <div class="geo-label">Server IP Address</div>
            <div class="geo-value">${geo.ip || '—'}</div>
        </div>
        <div class="geo-box">
            <div class="geo-label">Physical Location</div>
            <div class="geo-value">${locationString}</div>
        </div>
        <div class="geo-box">
            <div class="geo-label">Hosting Provider (ISP)</div>
            <div class="geo-value">${geo.isp || '—'}</div>
        </div>
    `;
}

async function startScan() {
    const target = document.getElementById('target').value.trim();
    const btn = document.getElementById('scan-btn');
    const loader = document.getElementById('loader');
    const resultContainer = document.getElementById('result-container');

    if (!target) { alert('Please enter a domain to scan!'); return; }

    btn.disabled = true;
    loader.classList.remove('hidden');
    resultContainer.classList.add('hidden');
    cycleLoaderText();

    try {
        const response = await fetch('/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target })
        });

        const rawText = await response.text();
        let data;
        try {
            data = JSON.parse(rawText);
        } catch (parseErr) {
            stopLoaderText();
            loader.classList.add('hidden');
            resultContainer.classList.remove('hidden');
            document.getElementById('output').textContent = "CRITICAL TIMEOUT: Scan took too long.\n\nTry testing with: scanme.nmap.org";
            btn.disabled = false;
            return;
        }

        stopLoaderText();
        loader.classList.add('hidden');
        resultContainer.classList.remove('hidden');

        if (!response.ok) {
            document.getElementById('output').textContent = `Error: ${data.error}\n${data.details || ''}`;
            btn.disabled = false;
            return;
        }

        // 1. Setup Score
        const scoreCircle = document.getElementById('score-circle');
        const scoreMessage = document.getElementById('score-message');
        scoreCircle.textContent = `${data.score}`;
        scoreCircle.className = 'score-overlay';

        let color = '#f85149';
        let statusIcon = '🚨';
        
        if (data.score >= 80) { 
            color = '#3fb950'; statusIcon = '✅'; scoreCircle.classList.add('high-risk'); scoreMessage.style.color = color;
            scoreMessage.innerHTML = `${statusIcon} Highly Resilient: Your digital storefront is well-protected.`; 
        }
        else if (data.score >= 50) { 
            color = '#d29922'; statusIcon = '⚠️'; scoreCircle.classList.add('med-risk'); scoreMessage.style.color = color;
            scoreMessage.innerHTML = `${statusIcon} Warning: Multiple vulnerabilities found. Action required.`; 
        }
        else { 
            scoreCircle.classList.add('high-risk'); scoreMessage.style.color = color;
            scoreMessage.innerHTML = `${statusIcon} Critical Danger: Business infrastructure is severely compromised.`; 
        }

        scoreCircle.style.color = color;
        renderChart(data.score, color);

        // 2. Populate standard lists
        populateList('web-output', data.web_surface);
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

        // 3. Render Custom Geo Boxes
        renderGeo(data.geo);

        // 4. Render Action Plan
        const roadmapCard = document.getElementById('roadmap-card-container');
        const roadmapList = document.getElementById('roadmap-list');
        roadmapList.innerHTML = '';
        
        if (data.roadmap && data.roadmap.length > 0) {
            roadmapCard.classList.remove('hidden');
            data.roadmap.forEach(item => {
                const li = document.createElement('li');
                li.className = `action-item-card border-${item.label.toLowerCase()}`;
                
                let textColor = 'text-info';
                if (item.label === 'CRITICAL' || item.label === 'DANGER') textColor = 'text-danger';
                if (item.label === 'WARNING' || item.label === 'HIGH') textColor = 'text-warning';

                // We split the backend finding into an issue and a solution if possible
                let issueText = item.finding;
                let remediationText = "Review configuration settings to secure this vulnerability.";
                
                if (item.finding.includes('.')) {
                    const parts = item.finding.split('.');
                    issueText = parts[0] + '.';
                    remediationText = parts.slice(1).join('.').trim() || remediationText;
                }

                li.innerHTML = `
                    <div class="action-header ${textColor}">[${item.label}] ${issueText}</div>
                    <div class="action-remediation">💡 <strong>Remediation:</strong> ${remediationText}</div>
                `;
                roadmapList.appendChild(li);
            });
        } else { 
            roadmapCard.classList.add('hidden'); 
        }

        // 5. Terminal
        document.getElementById('output').textContent = data.nmap_results;

    } catch (err) {
        stopLoaderText();
        loader.classList.add('hidden');
        alert('NETWORK ERROR: Connection to backend failed.');
    } finally { btn.disabled = false; }
}

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('target').addEventListener('keydown', e => {
        if (e.key === 'Enter') startScan();
    });
});
