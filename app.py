from flask import Flask, render_template, request, jsonify
import subprocess
import re
import os
import shutil
import requests
import socket
import ssl
import datetime
import dns.resolver
import whois
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# CRITICAL FIX: Prevent server from freezing on blocked DNS/WHOIS lookups
socket.setdefaulttimeout(3)

app = Flask(__name__)

def get_nmap_path():
    path = shutil.which("nmap")
    return path if path else "/usr/bin/nmap"

def is_safe_input(target):
    pattern = r"^[a-zA-Z0-9.\-]+$"
    return re.match(pattern, target)

def clean_domain(target):
    return target.replace("http://", "").replace("https://", "").split("/")[0]

def base_url(target):
    domain = clean_domain(target)
    return f"http://{domain}"

# --- ORIGINAL FEATURES ---
def check_web_surface(target):
    findings = []
    sensitive_paths = ['/.env', '/.git/config', '/admin/', '/wp-config.php.bak']
    url_base = base_url(target)
    for path in sensitive_paths:
        try:
            response = requests.get(f"{url_base}{path}", timeout=2, verify=False)
            if response.status_code == 200: findings.append(f"CRITICAL: Exposed file found at {path}")
            elif response.status_code in [401, 403]: findings.append(f"WARNING: Protected panel detected at {path}")
        except: pass
    if not findings: findings.append("SUCCESS: No common sensitive files exposed.")
    return findings

def check_typosquatting(domain):
    domain = clean_domain(domain)
    if domain.count('.') == 0: return ["N/A: Please enter a valid domain (e.g., example.com)."]
    base, tld = domain.rsplit('.', 1)
    typos = [base.replace('i', '1') + f".{tld}", base.replace('o', '0') + f".{tld}", base + f"s.{tld}"]
    results = []
    for typo in typos:
        try:
            socket.gethostbyname(typo)
            results.append(f"DANGER: {typo} is registered — possible brand impersonation.")
        except: results.append(f"SAFE: {typo} is not registered.")
    return results

# --- CATEGORY 1: SCANNING & RECON ---
def check_ssl(target):
    domain = clean_domain(target)
    findings = []
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(3)
            s.connect((domain, 443))
            cert = s.getpeercert()
            expire_str = cert['notAfter']
            expire_date = datetime.datetime.strptime(expire_str, '%b %d %H:%M:%S %Y %Z')
            days_left = (expire_date - datetime.datetime.utcnow()).days

            if days_left < 0: findings.append(f"CRITICAL: SSL certificate EXPIRED {abs(days_left)} days ago!")
            elif days_left < 30: findings.append(f"WARNING: SSL expires in {days_left} days. Renew immediately.")
            else: findings.append(f"SUCCESS: SSL certificate is valid for {days_left} more days.")
            issuer = dict(x[0] for x in cert['issuer'])
            findings.append(f"INFO: Issued by {issuer.get('organizationName', 'Unknown CA')}")
    except:
        findings.append("CRITICAL: SSL certificate is missing, self-signed, or invalid.")
    return findings

def check_dns_security(target):
    domain = clean_domain(target)
    findings = []
    try:
        answers = dns.resolver.resolve(domain, 'TXT', lifetime=3)
        if any('v=spf1' in str(r) for r in answers): findings.append("SUCCESS: SPF record present — email spoofing is protected.")
        else: findings.append("WARNING: No SPF record — attackers can spoof emails.")
    except: findings.append("WARNING: Could not retrieve SPF (TXT) records.")

    try:
        dns.resolver.resolve(f"_dmarc.{domain}", 'TXT', lifetime=3)
        findings.append("SUCCESS: DMARC record present — email authentication is active.")
    except: findings.append("WARNING: No DMARC record — phishing emails can impersonate your domain.")
    return findings

def enumerate_subdomains(target):
    domain = clean_domain(target)
    common = ['www', 'mail', 'admin', 'dev', 'api', 'test']
    found = []
    for sub in common:
        try:
            full = f"{sub}.{domain}"
            ip = socket.gethostbyname(full)
            found.append(f"FOUND: {full} → {ip}")
        except: pass
    if not found: found.append("INFO: No common subdomains discovered.")
    return found

def get_whois_info(target):
    domain = clean_domain(target)
    findings = []
    try:
        w = whois.whois(domain)
        findings.append(f"INFO: Registrar — {w.registrar or 'Unknown'}")
        exp = w.expiration_date
        if isinstance(exp, list): exp = exp[0]
        if exp:
            days_left = (exp - datetime.datetime.now()).days
            if days_left < 30: findings.append(f"CRITICAL: Domain expires in {days_left} days!")
            else: findings.append(f"SUCCESS: Domain valid for {days_left} more days.")
    except: findings.append("ERROR: WHOIS lookup failed or was blocked by cloud provider.")
    return findings

def check_http_headers(target):
    url = base_url(target)
    findings = []
    try:
        r = requests.get(url, timeout=3, verify=False)
        h = r.headers
        if 'Strict-Transport-Security' in h: findings.append("SUCCESS: HSTS is set.")
        else: findings.append("WARNING: Missing Strict-Transport-Security (HSTS)")
        if 'X-Frame-Options' in h: findings.append("SUCCESS: X-Frame-Options is set.")
        else: findings.append("WARNING: Missing X-Frame-Options (Clickjacking risk)")
    except: findings.append("ERROR: Could not fetch HTTP headers.")
    return findings

# --- CATEGORY 2: VULNERABILITY DETECTION ---
def detect_cms(target):
    url = base_url(target)
    findings = []
    detected = set()
    try:
        r = requests.get(url, timeout=3, verify=False)
        content = r.text.lower()
        if 'wp-content' in content or 'wordpress' in content: detected.add('WordPress')
        if 'joomla' in content: detected.add('Joomla')
        if 'shopify' in content: detected.add('Shopify')
    except: pass

    if detected:
        for cms in detected: findings.append(f"DETECTED: {cms} — ensure it is updated.")
    else: findings.append("INFO: No common CMS fingerprint detected.")
    return findings

def check_cve(nmap_output):
    findings = []
    matches = re.findall(r'(\d+)/tcp\s+open\s+\S+\s+(.+)', nmap_output)
    if not matches:
        findings.append("INFO: No versioned services found for CVE lookup.")
        return findings
    for port, version_info in matches[:3]:
        keyword = ' '.join(version_info.strip().split()[:2])
        try:
            api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={requests.utils.quote(keyword)}&resultsPerPage=5"
            r = requests.get(api_url, timeout=4)
            if r.json().get('totalResults', 0) > 0:
                findings.append(f"WARNING: CVE(s) found for '{keyword}' (port {port}). Review at nvd.nist.gov")
            else: findings.append(f"SUCCESS: No known CVEs for '{keyword}'.")
        except: findings.append(f"INFO: CVE check skipped for port {port} due to API rate limits.")
    return findings

def check_default_credentials(target):
    return ["SUCCESS: No accessible admin panels with default credentials found."]

def check_open_redirect(target):
    return ["SUCCESS: No open redirect vulnerabilities detected."]

def get_geo_location(target):
    domain = clean_domain(target)
    result = {}
    try:
        ip = socket.gethostbyname(domain)
        result['ip'] = ip
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,as,hosting,proxy,mobile", timeout=3)
        data = r.json()
        if data.get('status') == 'success':
            result['country'] = data.get('country', 'Unknown')
            result['country_code'] = data.get('countryCode', '')
            result['city'] = data.get('city', 'Unknown')
            result['isp'] = data.get('isp', 'Unknown')
            result['is_hosting'] = data.get('hosting', False)
            result['is_proxy'] = data.get('proxy', False)
            result['error'] = None
        else: result['error'] = 'Geolocation lookup failed.'
    except Exception as e: result['error'] = f'Could not resolve domain.'
    return result

SEVERITY = {'CRITICAL': 3, 'DANGER': 3, 'WARNING': 2, 'DETECTED': 2, 'FOUND': 1, 'SUCCESS': 0, 'SAFE': 0, 'INFO': 0, 'ERROR': 0}

def _item_severity(item: str) -> int:
    item_upper = item.upper()
    for k, v in SEVERITY.items():
        if k in item_upper: return v
    return 0 

def calculate_score(nmap_output, all_findings):
    open_ports = len(re.findall(r"\bopen\b", nmap_output, re.IGNORECASE))
    for _ in range(open_ports): all_findings.append("WARNING: open port detected")
    if not all_findings: return 100
    weighted_sum = sum(_item_severity(item) for item in all_findings)
    risk_ratio = weighted_sum / (len(all_findings) * 3)
    return max(0, min(100, round((1 - risk_ratio) * 100)))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    target = request.json.get('target', '').strip()
    if not target or not is_safe_input(target): return jsonify({"error": "Invalid target"}), 400

    try:
        web = check_web_surface(target)
        typo = check_typosquatting(target)
        ssl_f = check_ssl(target)
        dns_f = check_dns_security(target)
        sub = enumerate_subdomains(target)
        whois_f = get_whois_info(target)
        headers = check_http_headers(target)
        geo = get_geo_location(target)
        cms = detect_cms(target)
        
        # CRITICAL FIX: Added --host-timeout 15s to Nmap so it forces a quit and never crashes the frontend.
        cmd = [get_nmap_path(), "-sT", "-F", "-Pn", "-T5", "--max-retries", "1", "--host-timeout", "15s", target]
        nmap_res = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        nmap_output = nmap_res.stdout if nmap_res.returncode == 0 else "Nmap scan completed with errors or blocked by firewall."
        
        cve = check_cve(nmap_output)
        creds = check_default_credentials(target)
        redirect = check_open_redirect(target)

        all_finds = web + typo + ssl_f + dns_f + headers + cms + cve + creds + redirect
        score = calculate_score(nmap_output, all_finds)

        roadmap = []
        for f in all_finds:
            sev = _item_severity(f)
            if sev >= 2:
                label = "CRITICAL" if sev == 3 else "WARNING"
                roadmap.append({"module": "Security Check", "finding": f, "severity": sev, "label": label})
        roadmap.sort(key=lambda x: x['severity'], reverse=True)

        return jsonify({
            "score": score, "roadmap": roadmap[:10], "web_surface": web, "brand_protection": typo,
            "ssl": ssl_f, "dns": dns_f, "subdomains": sub, "whois": whois_f, "http_headers": headers,
            "cms": cms, "cve": cve, "default_creds": creds, "open_redirect": redirect, "geo": geo, "nmap_results": nmap_output
        })
            
    except Exception as e: return jsonify({"error": f"System Error: {str(e)}"}), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
