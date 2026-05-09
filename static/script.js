'use strict';

// ── GLOBALS ───────────────────────────────────────
let scoreChartInstance = null;
let scanData = null;

const LOADER_PHASES = [
    { text: "Resolving DNS records...", module: "lm4" },
    { text: "Simulating SQL Injection probes...", module: "lm2" },
    { text: "Testing Cross-Site Scripting (XSS)...", module: "lm2" },
    { text: "Hunting for exposed AWS Credentials...", module: "lm1" },
    { text: "Analyzing SSL/TLS certificate chain...", module: "lm3" },
    { text: "Querying WHOIS registrar data...", module: "lm4" },
    { text: "Running Nmap port reconnaissance...", module: "lm5" },
    { text: "Enumerating subdomains...", module: "lm6" },
    { text: "Auditing session cookie security...", module: "lm7" },
    { text: "Fingerprinting technology stack...", module: "lm8" },
    { text: "Scanning web surface for cloud leaks...", module: "lm1" },
    { text: "Parsing robots.txt for path disclosures...", module: "lm8" },
    { text: "Compiling threat intelligence report...", module: null },
];

let loaderInterval = null;
let loaderPhaseIndex = 0;
let activeModuleEl = null;

// ── LOADER ────────────────────────────────────────
function cycleLoader() {
    loaderPhaseIndex = 0;
    applyLoaderPhase(0);
    loaderInterval = setInterval(() => {
        loaderPhaseIndex = (loaderPhaseIndex + 1) % LOADER_PHASES.length;
        applyLoaderPhase(loaderPhaseIndex);
    }, 2200);
}

function applyLoaderPhase(idx) {
    const phase = LOADER_PHASES[idx];
    const textEl = document.getElementById('loader-text');
    if (textEl) textEl.textContent = phase.text;

    // Reset previous active module
    if (activeModuleEl) activeModuleEl.classList.remove('active');

    if (phase.module) {
        activeModuleEl = document.getElementById(phase.module);
        if (activeModuleEl) activeModuleEl.classList.add('active');
    }
}

function stopLoader() {
    clearInterval(loaderInterval);
    loaderInterval = null;
    // Reset all module indicators
    document.querySelectorAll('.lm').forEach(el => el.classList.remove('active'));
}

// ── CHART ─────────────────────────────────────────
function renderChart(score, color) {
    const ctx = document.getElementById('scoreChart').getContext('2d');
    if (scoreChartInstance) scoreChartInstance.destroy();
    scoreChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            datasets: [{
                data: [score, 100 - score],
                backgroundColor: [color, 'rgba(255,255,255,0.04)'],
                borderWidth: 0,
                cutout: '82%',
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { tooltip: { enabled: false } },
            animation: { duration: 1200, easing: 'easeInOutQuart' }
        }
    });
}

// ── ANIMATED COUNTER ──────────────────────────────
function animateCounter(el, target, duration = 1200) {
    if (!el) return;
    const start = 0;
    const step = (timestamp) => {
        if (!step.startTime) step.startTime = timestamp;
        const progress = Math.min((timestamp - step.startTime) / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        el.textContent = Math.floor(eased * target);
        if (progress < 1) requestAnimationFrame(step);
        else el.textContent = target;
    };
    requestAnimationFrame(step);
}

// ── POPULATE LIST ─────────────────────────────────
function populateList(elementId, items) {
    const ul = document.getElementById(elementId);
    if (!ul) return;
    ul.innerHTML = '';
    if (!items || items.length === 0) {
        ul.innerHTML = '<li class="list-item-card" style="border-left-color:#1e2d3d"><span style="color:#6b7d93">No data returned.</span></li>';
        return;
    }
    items.forEach((item, i) => {
        const li = document.createElement('li');
        li.className = 'list-item-card';
        li.style.animationDelay = `${i * 40}ms`;

        let color = '#6b7d93';
        if (item.includes('CRITICAL')) color = '#ff3b5c';
        else if (item.includes('DANGER')) color = '#ff3b5c';
        else if (item.includes('HIGH')) color = '#ff6b35';
        else if (item.includes('WARNING')) color = '#ffb800';
        else if (item.includes('DETECTED')) color = '#ffb800';
        else if (item.includes('SUCCESS')) color = '#00e87a';
        else if (item.includes('INFO')) color = '#00b4ff';

        li.style.borderLeftColor = color;

        const colonIdx = item.indexOf(':');
        if (colonIdx > 0 && colonIdx < 20) {
            const label = item.substring(0, colonIdx);
            const rest = item.substring(colonIdx + 1);
            li.innerHTML = `<span style="color:${color}; font-weight:700; font-family:var(--font-mono); font-size:0.78rem;">${label}:</span><span style="color:var(--text)"> ${rest.trim()}</span>`;
        } else {
            li.innerHTML = `<span style="color:${color}">${item}</span>`;
        }
        ul.appendChild(li);
    });
}

// ── SCORE DISPLAY ─────────────────────────────────
function displayScore(score) {
    const scoreEl = document.getElementById('score-text');
    const color = score >= 80 ? '#00e87a' : score >= 50 ? '#ffb800' : '#ff3b5c';
    scoreEl.style.color = color;

    // Animate score number
    let current = 0;
    const step = () => {
        current = Math.min(current + 2, score);
        scoreEl.textContent = current;
        if (current < score) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);

    renderChart(score, color);

    const msg = document.getElementById('score-message');
    if (score >= 80) {
        msg.innerHTML = `<span style="color:#00e87a">✅ Highly Resilient — Your infrastructure is well-hardened.</span>`;
    } else if (score >= 50) {
        msg.innerHTML = `<span style="color:#ffb800">⚠️ Moderate Risk — Multiple vulnerabilities require attention.</span>`;
    } else {
        msg.innerHTML = `<span style="color:#ff3b5c">🚨 Critical Danger — Business infrastructure is severely exposed.</span>`;
    }
}

// ── SEVERITY BADGES ───────────────────────────────
function displaySeverityCounts(counts) {
    if (!counts) return;
    setTimeout(() => {
        animateCounter(document.getElementById('count-critical'), counts.critical || 0);
        animateCounter(document.getElementById('count-high'), counts.high || 0);
        animateCounter(document.getElementById('count-warning'), counts.warning || 0);
        animateCounter(document.getElementById('count-safe'), counts.safe || 0);
    }, 400);
}

// ── ROADMAP ───────────────────────────────────────
function renderRoadmap(roadmap) {
    const roadmapList = document.getElementById('roadmap-list');
    roadmapList.innerHTML = '';
    if (!roadmap || roadmap.length === 0) return;

    roadmap.forEach((item, i) => {
        const li = document.createElement('li');
        li.className = 'action-item-card';
        const color = item.label === 'CRITICAL' ? '#ff3b5c'
                    : item.label === 'HIGH'     ? '#ff6b35'
                    : item.label === 'MEDIUM'   ? '#ffb800'
                    : item.label === 'WARNING'  ? '#ffb800'
                    : '#00b4ff';
        li.style.borderLeftColor = color;
        li.style.animationDelay = `${i * 80}ms`;
        li.innerHTML = `
            <div class="action-header" style="color:${color}">[${item.label}] ${item.issue}</div>
            <div class="action-remediation">💡 <strong>Remediation:</strong> ${item.solution}</div>
        `;
        roadmapList.appendChild(li);
    });
}

// ── GEO DISPLAY ───────────────────────────────────
function renderGeo(geo) {
    if (!geo) return;
    const geoGrid = document.getElementById('geo-grid');
    geoGrid.innerHTML = `
        <div class="geo-box">
            <div class="geo-label">Server IP Address</div>
            <div class="geo-value">${geo.ip}</div>
        </div>
        <div class="geo-box">
            <div class="geo-label">Physical Location</div>
            <div class="geo-value">${geo.country}</div>
        </div>
        <div class="geo-box">
            <div class="geo-label">Hosting Provider</div>
            <div class="geo-value" style="font-size:0.88rem">${geo.isp}</div>
        </div>
    `;
    if (geo.as) {
        geoGrid.innerHTML += `
            <div class="geo-box" style="grid-column: span 3;">
                <div class="geo-label">AS Number (Autonomous System)</div>
                <div class="geo-value" style="font-size:0.88rem">${geo.as}</div>
            </div>
        `;
    }
}

// ── STAT COUNTERS (landing page) ──────────────────
function initStatCounters() {
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const el = entry.target;
                const target = parseInt(el.dataset.count);
                if (target && !el.dataset.animated) {
                    el.dataset.animated = 'true';
                    animateCounter(el, target, 1000);
                }
                observer.unobserve(el);
            }
        });
    }, { threshold: 0.5 });

    document.querySelectorAll('.stat-number[data-count]').forEach(el => observer.observe(el));
}

// ── MAIN SCAN FUNCTION ────────────────────────────
async function startScan() {
    const target = document.getElementById('target').value.trim();
    const btn = document.getElementById('scan-btn');
    if (!target) { alert('Please enter a business domain to scan.'); return; }

    btn.disabled = true;
    document.getElementById('loader').classList.remove('hidden');
    document.getElementById('result-container').classList.add('hidden');

    // Scroll to loader
    document.getElementById('loader').scrollIntoView({ behavior: 'smooth', block: 'center' });

    cycleLoader();

    try {
        const response = await fetch('/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target })
        });

        const rawText = await response.text();
        let data;
        try { data = JSON.parse(rawText); }
        catch (e) { throw new Error("Response parse failed — scan may have timed out."); }

        if (data.error) throw new Error(data.error);

        stopLoader();
        document.getElementById('loader').classList.add('hidden');

        // Store data for export
        scanData = data;
        document.getElementById('scan-data-store').textContent = JSON.stringify(data, null, 2);

        // Show results
        const container = document.getElementById('result-container');
        container.classList.remove('hidden');

        // Meta bar
        document.getElementById('meta-target').textContent = data.target || target;
        document.getElementById('meta-time').textContent = data.scan_time || new Date().toUTCString();

        // Score
        displayScore(data.score);

        // Severity counts
        displaySeverityCounts(data.severity_counts);

        // Roadmap
        renderRoadmap(data.roadmap);

        // All module lists
        populateList('web-output', data.web_surface);
        populateList('exploit-output', data.file_exploits);
        populateList('infra-output', data.infra_intelligence);
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
        populateList('cookie-output', data.cookies);
        populateList('tech-output', data.tech_stack);
        populateList('robots-output', data.robots);

        // Geo
        renderGeo(data.geo);

        // Raw nmap
        document.getElementById('output').textContent = data.nmap_results || "No raw nmap data returned.";

        // Scroll to results
        setTimeout(() => {
            container.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }, 100);

    } catch (e) {
        stopLoader();
        document.getElementById('loader').classList.add('hidden');
        alert(`Scan Error: ${e.message}\n\nTry scanning scanme.nmap.org for a test.`);
    } finally {
        btn.disabled = false;
    }
}

// ── HELPERS ───────────────────────────────────────
function setTarget(domain) {
    document.getElementById('target').value = domain;
    document.getElementById('target').focus();
}

function printReport() {
    window.print();
}

function downloadReport() {
    if (!scanData) { alert('No scan data available. Run a scan first.'); return; }
    const blob = new Blob([JSON.stringify(scanData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cyber-shield-report-${scanData.target || 'scan'}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
}

function copyShareSummary() {
    if (!scanData) { alert('No scan data available. Run a scan first.'); return; }
    const counts = scanData.severity_counts || {};
    const summary = `
🛡️ SOVEREIGN CYBER-SHIELD REPORT
═══════════════════════════════════
Target: ${scanData.target}
Scan Time: ${scanData.scan_time}
Cyber-Resilience Score: ${scanData.score}/100

FINDINGS SUMMARY:
• 🔴 Critical Issues: ${counts.critical || 0}
• 🟠 High Risk: ${counts.high || 0}
• 🟡 Warnings: ${counts.warning || 0}
• ✅ Checks Passed: ${counts.safe || 0}

TOP ACTIONS REQUIRED:
${(scanData.roadmap || []).slice(0, 3).map(r => `• [${r.label}] ${r.issue}`).join('\n')}

Scanned with Sovereign Cyber-Shield
Free security intelligence for Kashmir's MSMEs
`.trim();

    navigator.clipboard.writeText(summary)
        .then(() => alert('✅ Report summary copied to clipboard!'))
        .catch(() => {
            const ta = document.createElement('textarea');
            ta.value = summary;
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            ta.remove();
            alert('✅ Report summary copied to clipboard!');
        });
}

// ── INIT ──────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    // Enter key on input
    document.getElementById('target').addEventListener('keydown', e => {
        if (e.key === 'Enter') { e.preventDefault(); startScan(); }
    });

    // Stat counter animations
    initStatCounters();

    // Smooth nav link scrolling
    document.querySelectorAll('a[href^="#"]').forEach(link => {
        link.addEventListener('click', e => {
            const target = document.querySelector(link.getAttribute('href'));
            if (target) {
                e.preventDefault();
                target.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        });
    });
});
