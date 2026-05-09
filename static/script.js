const loaderMessages = [
    "Checking SSL certificate...",
    "Probing DNS security records...",
    "Enumerating subdomains...",
    "Scanning HTTP security headers...",
    "Running Nmap infrastructure scan...",
    "Detecting CMS fingerprint...",
    "Looking up CVE database...",
    "Testing default credentials...",
    "Checking for open redirects...",
    "Calculating risk score..."
];

let loaderInterval = null;

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

/**
 * Populate a <ul> element from an array of strings.
 * Colors items based on severity keywords.
 */
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

        if (item.includes('CRITICAL') || item.includes('DANGER'))
            li.className = 'severity-critical';
        else if (item.includes('WARNING') || item.includes('DETECTED') || item.includes('FOUND'))
            li.className = 'severity-warning';
        else if (item.includes('SUCCESS') || item.includes('SAFE'))
            li.className = 'severity-success';
        else
            li.className = 'severity-info';

        ul.appendChild(li);
    });
}

async function startScan() {
    const target = document.getElementById('target').value.trim();
    const btn = document.getElementById('scan-btn');
    const loader = document.getElementById('loader');
    const resultContainer = document.getElementById('result-container');

    if (!target) {
        alert('Please enter a domain to scan!');
        return;
    }

    btn.disabled = true;
    loader.classList.remove('hidden');
    resultContainer.classList.add('hidden');
    cycleLoaderText();

    // Clear all outputs
    const allOutputs = [
        'web-output', 'brand-output', 'ssl-output', 'dns-output',
        'subdomain-output', 'whois-output', 'header-output',
        'cms-output', 'cve-output', 'cred-output', 'redirect-output', 'output'
    ];
    allOutputs.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.innerHTML = '';
    });

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
            document.getElementById('output').textContent =
                `Error: ${data.error}\n${data.details || ''}`;
            return;
        }

        // ── Score ────────────────────────────────────────
        const scoreCircle = document.getElementById('score-circle');
        const scoreMessage = document.getElementById('score-message');

        scoreCircle.textContent = `${data.score}/100`;
        scoreCircle.className = 'score';

        if (data.score >= 80) {
            scoreCircle.classList.add('high');
            scoreMessage.textContent = 'Great! Your digital storefront is highly resilient.';
        } else if (data.score >= 50) {
            scoreCircle.classList.add('medium');
            scoreMessage.textContent = 'Warning: Multiple vulnerabilities found. Action required.';
        } else {
            scoreCircle.classList.add('low');
            scoreMessage.textContent = 'Critical Danger: Business infrastructure is severely compromised.';
        }

        // ── Original features ────────────────────────────
        populateList('web-output',   data.web_surface);
        populateList('brand-output', data.brand_protection);

        // ── Scanning & Recon ─────────────────────────────
        populateList('ssl-output',       data.ssl);
        populateList('dns-output',       data.dns);
        populateList('subdomain-output', data.subdomains);
        populateList('whois-output',     data.whois);
        populateList('header-output',    data.http_headers);

        // ── Vulnerability Detection ──────────────────────
        populateList('cms-output',      data.cms);
        populateList('cve-output',      data.cve);
        populateList('cred-output',     data.default_creds);
        populateList('redirect-output', data.open_redirect);

        // ── Geo location ─────────────────────────────────
        renderGeo(data.geo);

        // ── Raw Nmap ─────────────────────────────────────
        document.getElementById('output').textContent = data.nmap_results;

    } catch (err) {
        stopLoaderText();
        loader.classList.add('hidden');
        alert('Could not connect to the backend server. Is Flask running?');
        console.error(err);
    } finally {
        btn.disabled = false;
    }
}

// Allow pressing Enter to trigger scan
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('target').addEventListener('keydown', e => {
        if (e.key === 'Enter') startScan();
    });
});

function renderGeo(geo) {
    if (!geo) return;

    const flagEl    = document.getElementById('geo-flag');
    const titleEl   = document.getElementById('geo-title');
    const locationEl= document.getElementById('geo-location');
    const ipEl      = document.getElementById('geo-ip');
    const ispEl     = document.getElementById('geo-isp');
    const asnEl     = document.getElementById('geo-asn');
    const tagsEl    = document.getElementById('geo-tags');
    const mapLink   = document.getElementById('geo-map-link');

    if (geo.error) {
        locationEl.textContent = geo.error;
        return;
    }

    // Country flag emoji from country code
    const flag = geo.country_code
        ? geo.country_code.toUpperCase().replace(/./g,
            c => String.fromCodePoint(127397 + c.charCodeAt(0)))
        : '🌐';

    flagEl.textContent   = flag;
    titleEl.textContent  = `Server Location — ${geo.country || 'Unknown'}`;
    locationEl.textContent = [geo.city, geo.region, geo.country]
        .filter(Boolean).join(', ');

    ipEl.textContent  = `IP: ${geo.ip  || '—'}`;
    ispEl.textContent = `ISP: ${geo.isp || '—'}`;
    asnEl.textContent = `ASN: ${geo.asn || '—'}`;

    // Risk tags
    tagsEl.innerHTML = '';
    if (geo.is_proxy)   addTag(tagsEl, '⚠️ Proxy/VPN Detected',  'tag-warn');
    if (geo.is_hosting) addTag(tagsEl, '🖥️ Hosted on Datacenter', 'tag-info');
    if (geo.is_mobile)  addTag(tagsEl, '📱 Mobile Network',        'tag-info');
    if (!geo.is_proxy && !geo.is_hosting && !geo.is_mobile)
        addTag(tagsEl, '✅ Residential / Clean IP', 'tag-ok');

    // Map link
    if (geo.lat && geo.lon) {
        mapLink.href = `https://www.openstreetmap.org/?mlat=${geo.lat}&mlon=${geo.lon}&zoom=10`;
        mapLink.style.display = 'inline-block';
    } else {
        mapLink.style.display = 'none';
    }
}

function addTag(parent, text, cls) {
    const span = document.createElement('span');
    span.className = `geo-tag ${cls}`;
    span.textContent = text;
    parent.appendChild(span);
}
