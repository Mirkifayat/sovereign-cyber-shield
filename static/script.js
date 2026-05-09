const loaderMessages = [
    "Checking SSL certificate...",
    "Probing DNS security records...",
    "Enumerating subdomains...",
    "Scanning HTTP security headers...",
    "Running Nmap infrastructure scan...",
    "Detecting CMS fingerprint...",
    "Testing default credentials...",
    "Checking for open redirects...",
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

function populateList(elementId, items) {
    const ul = document.getElementById(elementId);
    ul.innerHTML = '';
    if (!items || items.length === 0) {
        const li = document.createElement('li');
        li.textContent = 'No data returned.';
        ul.appendChild(li);
        return;
    }
    items.forEach(item => {
        const li = document.createElement('li');
        li.textContent = item;
        if (item.includes('CRITICAL') || item.includes('DANGER')) li.className = 'severity-critical';
        else if (item.includes('WARNING') || item.includes('DETECTED') || item.includes('FOUND')) li.className = 'severity-warning';
        else if (item.includes('SUCCESS') || item.includes('SAFE')) li.className = 'severity-success';
        else li.className = 'severity-info';
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
        options: { responsive: true, maintainAspectRatio: false, animation: { animateScale: true }, plugins: { tooltip: { enabled: false } } }
    });
}

function renderGeo(geo) {
    if (!geo || geo.error) {
        document.getElementById('geo-location').textContent = geo ? geo.error : "Failed to load geo-data.";
        return;
    }
    const flag = geo.country_code ? geo.country_code.toUpperCase().replace(/./g, c => String.fromCodePoint(127397 + c.charCodeAt(0))) : '🌐';
    document.getElementById('geo-flag').textContent = flag;
    document.getElementById('geo-title').textContent = `Server Location — ${geo.country || 'Unknown'}`;
    document.getElementById('geo-location').textContent = [geo.city, geo.region, geo.country].filter(Boolean).join(', ');
    document.getElementById('geo-ip').textContent = `IP: ${geo.ip || '—'}`;
    document.getElementById('geo-isp').textContent = `ISP: ${geo.isp || '—'}`;
    document.getElementById('geo-asn').textContent = `ASN: ${geo.asn || '—'}`;

    const tagsEl = document.getElementById('geo-tags');
    tagsEl.innerHTML = '';
    const addTag = (txt, cls) => { const s = document.createElement('span'); s.className = `geo-tag ${cls}`; s.textContent = txt; tagsEl.appendChild(s); };
    
    if (geo.is_proxy) addTag('⚠️ Proxy/VPN Detected', 'tag-warn');
    if (geo.is_hosting) addTag('🖥️ Hosted on Datacenter', 'tag-info');
    if (geo.is_mobile) addTag('📱 Mobile Network', 'tag-info');
    if (!geo.is_proxy && !geo.is_hosting && !geo.is_mobile) addTag('✅ Residential / Clean IP', 'tag-ok');

    const mapLink = document.getElementById('geo-map-link');
    if (geo.lat && geo.lon) {
        mapLink.href = `https://www.openstreetmap.org/?mlat=${geo.lat}&mlon=${geo.lon}&zoom=10`;
        mapLink.style.display = 'inline-block';
    } else { mapLink.style.display = 'none'; }
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

    // Clear previous lists
    const allOutputs = [
        'web-output', 'brand-output', 'ssl-output', 'dns-output',
        'subdomain-output', 'whois-output', 'header-output',
        'cms-output', 'cve-output', 'cred-output', 'redirect-output', 'output'
    ];
    allOutputs.forEach(id => { const el = document.getElementById(id); if (el) el.innerHTML = ''; });

    try {
        const response = await fetch('/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target })
        });

        const data = await response.json();
        stopLoaderText();
        loader.classList.add('hidden');
        resultContainer.classList.remove('hidden');

        if (!response.ok) {
            document.getElementById('output').textContent = `Error: ${data.error}\n${data.details || ''}`;
            return;
        }

        const scoreCircle = document.getElementById('score-circle');
        const scoreMessage = document.getElementById('score-message');
        scoreCircle.textContent = `${data.score}`;
        scoreCircle.className = 'score-overlay';

        let color = '#ff4a4a';
        let statusClass = 'low';
        
        if (data.score >= 80) { color = '#3fb950'; statusClass = 'high'; scoreMessage.textContent = '✅ Excellent: Your digital storefront is highly resilient.'; scoreMessage.style.color = color; }
        else if (data.score >= 50) { color = '#e3b341'; statusClass = 'medium'; scoreMessage.textContent = '⚠️ Warning: Multiple vulnerabilities found. Action required.'; scoreMessage.style.color = color; }
        else { scoreMessage.textContent = '🚨 Critical Danger: Business infrastructure is severely compromised.'; scoreMessage.style.color = color; }

        scoreCircle.className = `score-overlay ${statusClass}`;
        renderChart(data.score, color);

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

        const roadmapCard = document.getElementById('roadmap-card');
        const roadmapList = document.getElementById('roadmap-list');
        roadmapList.innerHTML = '';
        if (data.roadmap && data.roadmap.length > 0) {
            roadmapCard.classList.remove('hidden');
            data.roadmap.forEach(item => {
                const li = document.createElement('li');
                li.className = `roadmap-item sev-${item.label.toLowerCase()}`;
                li.innerHTML = `<span class="roadmap-badge">${item.label}</span><span class="roadmap-module">[${item.module}]</span><span class="roadmap-text">${item.finding}</span>`;
                roadmapList.appendChild(li);
            });
        } else { roadmapCard.classList.add('hidden'); }

        renderGeo(data.geo);
        document.getElementById('output').textContent = data.nmap_results;

    } catch (err) {
        stopLoaderText();
        loader.classList.add('hidden');
        alert('Could not connect to the backend server. Is Flask running?');
    } finally { btn.disabled = false; }
}

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('target').addEventListener('keydown', e => {
        if (e.key === 'Enter') startScan();
    });
});
