/* ══════════════════════════════════════════════
   CYBERSHIELD KASHMIR — script.js
   Handles scan flow, loader, results rendering
══════════════════════════════════════════════ */

// ── Loader Messages ──────────────────────────
const LOADER_STEPS = [
    "Checking SSL certificate...",
    "Probing DNS security records...",
    "Enumerating subdomains...",
    "Scanning HTTP security headers...",
    "Running infrastructure scan...",
    "Detecting CMS fingerprint...",
    "Querying CVE database...",
    "Testing default credentials...",
    "Checking for open redirects...",
    "Calculating risk score..."
];

let loaderInterval = null;
let loaderStep = 0;

// ── Fill example domain ──────────────────────
function fillExample(domain) {
    document.getElementById('target').value = domain;
    document.getElementById('target').focus();
}

// ── Start / stop loader animation ───────────
function startLoader(domain) {
    loaderStep = 0;
    const textEl = document.getElementById('loader-text');
    const barEl  = document.getElementById('loader-bar');
    const domEl  = document.getElementById('loader-domain');

    domEl.textContent = domain;
    textEl.textContent = LOADER_STEPS[0];
    barEl.style.width = '0%';

    // Trigger CSS transition on next frame
    requestAnimationFrame(() => {
        barEl.style.width = '90%';
    });

    loaderInterval = setInterval(() => {
        loaderStep++;
        if (loaderStep < LOADER_STEPS.length) {
            textEl.textContent = LOADER_STEPS[loaderStep];
        }
    }, 2200);
}

function stopLoader() {
    if (loaderInterval) {
        clearInterval(loaderInterval);
        loaderInterval = null;
    }
    const barEl = document.getElementById('loader-bar');
    if (barEl) barEl.style.width = '100%';
}

// ── Classify a finding string → CSS class ────
function classifyFinding(text) {
    const t = text.toUpperCase();
    if (t.includes('CRITICAL') || t.includes('DANGER'))  return 'severity-critical';
    if (t.includes('WARNING')  || t.includes('DETECTED') || t.includes('FOUND')) return 'severity-warning';
    if (t.includes('SUCCESS')  || t.includes('SAFE'))    return 'severity-success';
    return 'severity-info';
}

// ── Render a findings array into a <ul> ───────
function populateList(elementId, items) {
    const ul = document.getElementById(elementId);
    if (!ul) return;
    ul.innerHTML = '';

    if (!items || items.length === 0) {
        const li = document.createElement('li');
        li.textContent  = 'No data returned.';
        li.className    = 'severity-info';
        ul.appendChild(li);
        return;
    }

    items.forEach(item => {
        const li      = document.createElement('li');
        li.textContent = item;
        li.className   = classifyFinding(item);
        ul.appendChild(li);
    });
}

// ── Clear all result areas ────────────────────
function clearResults() {
    const ids = [
        'web-output', 'brand-output', 'ssl-output', 'dns-output',
        'subdomain-output', 'whois-output', 'header-output',
        'cms-output', 'cve-output', 'cred-output', 'redirect-output', 'output'
    ];
    ids.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.innerHTML = '';
    });
    document.getElementById('roadmap-card').classList.add('hidden');
    document.getElementById('roadmap-list').innerHTML = '';
    document.getElementById('geo-flag').textContent   = '🌐';
    document.getElementById('geo-title').textContent  = 'Server Location';
    document.getElementById('geo-location').textContent = '—';
    document.getElementById('geo-ip').textContent     = 'IP —';
    document.getElementById('geo-isp').textContent    = 'ISP —';
    document.getElementById('geo-asn').textContent    = 'ASN —';
    document.getElementById('geo-tags').innerHTML     = '';
    document.getElementById('geo-map-link').style.display = 'none';
}

// ══════════════════════════════════════════════
//  MAIN SCAN FUNCTION
// ══════════════════════════════════════════════
async function startScan() {
    const target  = document.getElementById('target').value.trim();
    const btn     = document.getElementById('scan-btn');
    const loader  = document.getElementById('loader');
    const results = document.getElementById('result-container');

    if (!target) {
        alert('Please enter a domain to scan (e.g., yourbusiness.com)');
        return;
    }

    // UI: show loader
    btn.disabled = true;
    loader.classList.remove('hidden');
    results.classList.add('hidden');
    clearResults();
    startLoader(target);

    // Scroll to loader smoothly
    loader.scrollIntoView({ behavior: 'smooth', block: 'center' });

    try {
        const response = await fetch('/scan', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify({ target })
        });

        const data = await response.json();

        stopLoader();
        loader.classList.add('hidden');
        results.classList.remove('hidden');

        if (!response.ok) {
            document.getElementById('output').textContent =
                `Error: ${data.error}\n${data.details || ''}`;
            results.scrollIntoView({ behavior: 'smooth' });
            return;
        }

        // ── Score ─────────────────────────────
        renderScore(data.score);

        // ── Attack Surface ────────────────────
        populateList('web-output',   data.web_surface);
        populateList('brand-output', data.brand_protection);

        // ── Scanning & Recon ──────────────────
        populateList('ssl-output',       data.ssl);
        populateList('dns-output',       data.dns);
        populateList('subdomain-output', data.subdomains);
        populateList('whois-output',     data.whois);
        populateList('header-output',    data.http_headers);

        // ── Vulnerability Detection ───────────
        populateList('cms-output',      data.cms);
        populateList('cve-output',      data.cve);
        populateList('cred-output',     data.default_creds);
        populateList('redirect-output', data.open_redirect);

        // ── Roadmap ───────────────────────────
        renderRoadmap(data.score, data.roadmap);

        // ── Geo ───────────────────────────────
        renderGeo(data.geo);

        // ── Raw Nmap ──────────────────────────
        document.getElementById('output').textContent = data.nmap_results || 'No data.';

        // Scroll to results
        results.scrollIntoView({ behavior: 'smooth' });

    } catch (err) {
        stopLoader();
        loader.classList.add('hidden');
        console.error(err);
        alert('Could not connect to the backend server. Is Flask running?');
    } finally {
        btn.disabled = false;
    }
}

// ── Score Ring Animation ──────────────────────
function renderScore(score) {
    const numEl    = document.getElementById('score-circle');
    const arcEl    = document.getElementById('score-arc');
    const msgEl    = document.getElementById('score-message');

    // Animate number count-up
    let current = 0;
    const target = score;
    const step   = Math.max(1, Math.floor(target / 50));
    const tick   = setInterval(() => {
        current = Math.min(current + step, target);
        numEl.textContent = current;
        if (current >= target) clearInterval(tick);
    }, 20);

    // Animate SVG arc (circumference = 2π × 52 ≈ 327)
    const circumference = 327;
    const offset = circumference - (score / 100) * circumference;
    // small delay so CSS transition fires
    setTimeout(() => {
        arcEl.style.strokeDashoffset = offset;
    }, 100);

    // Colour & message
    if (score >= 80) {
        arcEl.classList.remove('mid', 'low');
        msgEl.textContent = '✅ Great! Your digital storefront is highly resilient.';
    } else if (score >= 50) {
        arcEl.classList.add('mid');
        arcEl.classList.remove('low');
        msgEl.textContent = '⚠️ Warning: Multiple vulnerabilities found. Action required.';
    } else {
        arcEl.classList.add('low');
        arcEl.classList.remove('mid');
        msgEl.textContent = '🚨 Critical Danger: Infrastructure is severely exposed. Act now.';
    }
}

// ── Roadmap ───────────────────────────────────
function renderRoadmap(score, roadmap) {
    const card = document.getElementById('roadmap-card');
    const list = document.getElementById('roadmap-list');
    list.innerHTML = '';

    if (score < 80 && roadmap && roadmap.length > 0) {
        card.classList.remove('hidden');
        roadmap.forEach(item => {
            const li = document.createElement('li');
            li.className = `roadmap-item sev-${item.label.toLowerCase()}`;
            li.innerHTML = `
                <span class="roadmap-badge">${item.label}</span>
                <span class="roadmap-module">[${item.module}]</span>
                <span class="roadmap-text">${item.finding}</span>
            `;
            list.appendChild(li);
        });
    } else {
        card.classList.add('hidden');
    }
}

// ── Geo Location ──────────────────────────────
function renderGeo(geo) {
    if (!geo) return;

    const flagEl     = document.getElementById('geo-flag');
    const titleEl    = document.getElementById('geo-title');
    const locationEl = document.getElementById('geo-location');
    const ipEl       = document.getElementById('geo-ip');
    const ispEl      = document.getElementById('geo-isp');
    const asnEl      = document.getElementById('geo-asn');
    const tagsEl     = document.getElementById('geo-tags');
    const mapLink    = document.getElementById('geo-map-link');

    if (geo.error) {
        locationEl.textContent = geo.error;
        return;
    }

    // Country flag emoji
    const flag = geo.country_code
        ? geo.country_code.toUpperCase().replace(/./g,
            c => String.fromCodePoint(127397 + c.charCodeAt(0)))
        : '🌐';

    flagEl.textContent   = flag;
    titleEl.textContent  = `Server Location — ${geo.country || 'Unknown'}`;
    locationEl.textContent = [geo.city, geo.region, geo.country].filter(Boolean).join(', ');

    ipEl.textContent  = `IP: ${geo.ip  || '—'}`;
    ispEl.textContent = `ISP: ${geo.isp || '—'}`;
    asnEl.textContent = `ASN: ${geo.asn || '—'}`;

    // Risk tags
    tagsEl.innerHTML = '';
    if (geo.is_proxy)   addGeoTag(tagsEl, '⚠️ Proxy / VPN Detected',   'tag-warn');
    if (geo.is_hosting) addGeoTag(tagsEl, '🖥️ Hosted on Datacenter',    'tag-info');
    if (geo.is_mobile)  addGeoTag(tagsEl, '📱 Mobile Network',           'tag-info');
    if (!geo.is_proxy && !geo.is_hosting && !geo.is_mobile)
        addGeoTag(tagsEl, '✅ Residential / Clean IP', 'tag-ok');

    // Map link
    if (geo.lat && geo.lon) {
        mapLink.href  = `https://www.openstreetmap.org/?mlat=${geo.lat}&mlon=${geo.lon}&zoom=10`;
        mapLink.style.display = 'inline-block';
    }
}

function addGeoTag(parent, text, cls) {
    const span = document.createElement('span');
    span.className = `geo-tag ${cls}`;
    span.textContent = text;
    parent.appendChild(span);
}

// ── Enter key shortcut ────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('target').addEventListener('keydown', e => {
        if (e.key === 'Enter') startScan();
    });
});
