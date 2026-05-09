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

app = Flask(__name__)

# ──────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────

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


# ──────────────────────────────────────────────
# ORIGINAL FEATURES
# ──────────────────────────────────────────────

def check_web_surface(target):
    findings = []
    sensitive_paths = ['/.env', '/.git/config', '/admin/', '/wp-config.php.bak']
    url_base = base_url(target)
    for path in sensitive_paths:
        try:
            url = f"{url_base}{path}"
            response = requests.get(url, timeout=3, verify=False)
            if response.status_code == 200:
                findings.append(f"CRITICAL: Exposed file found at {path}")
            elif response.status_code in [401, 403]:
                findings.append(f"WARNING: Protected panel detected at {path}")
        except requests.exceptions.RequestException:
            pass
    if not findings:
        findings.append("SUCCESS: No common sensitive files exposed.")
    return findings


def check_typosquatting(domain):
    domain = clean_domain(domain)
    if domain.count('.') == 0:
        return ["N/A: Please enter a valid domain (e.g., example.com)."]
    base, tld = domain.rsplit('.', 1)
    typos = []
    if 'i' in base: typos.append(base.replace('i', '1') + f".{tld}")
    if 'o' in base: typos.append(base.replace('o', '0') + f".{tld}")
    typos.append(base + f"s.{tld}")
    results = []
    for typo in typos:
        try:
            socket.gethostbyname(typo)
            results.append(f"DANGER: {typo} is registered — possible brand impersonation.")
        except socket.gaierror:
            results.append(f"SAFE: {typo} is not registered.")
    return results


# ──────────────────────────────────────────────
# CATEGORY 1 — SCANNING & RECONNAISSANCE
# ──────────────────────────────────────────────

def check_ssl(target):
    domain = clean_domain(target)
    findings = []
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()

            expire_str = cert['notAfter']
            expire_date = datetime.datetime.strptime(expire_str, '%b %d %H:%M:%S %Y %Z')
            days_left = (expire_date - datetime.datetime.utcnow()).days

            if days_left < 0:
                findings.append(f"CRITICAL: SSL certificate EXPIRED {abs(days_left)} days ago!")
            elif days_left < 30:
                findings.append(f"WARNING: SSL certificate expires in {days_left} days. Renew immediately.")
            else:
                findings.append(f"SUCCESS: SSL certificate is valid for {days_left} more days.")

            issuer = dict(x[0] for x in cert['issuer'])
            findings.append(f"INFO: Issued by {issuer.get('organizationName', 'Unknown CA')}")

            subject = dict(x[0] for x in cert['subject'])
            findings.append(f"INFO: Issued to {subject.get('commonName', domain)}")

    except ssl.SSLCertVerificationError:
        findings.append("CRITICAL: SSL certificate is self-signed or invalid (verification failed).")
    except ConnectionRefusedError:
        findings.append("WARNING: Port 443 closed — HTTPS may not be enabled on this server.")
    except socket.timeout:
        findings.append("WARNING: SSL check timed out.")
    except Exception as e:
        findings.append(f"ERROR: SSL check failed — {str(e)}")
    return findings


def check_dns_security(target):
    domain = clean_domain(target)
    findings = []

    # SPF
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        spf_found = any('v=spf1' in str(r) for r in answers)
        if spf_found:
            findings.append("SUCCESS: SPF record present — email spoofing is protected.")
        else:
            findings.append("WARNING: No SPF record — attackers can spoof emails from your domain.")
    except Exception:
        findings.append("WARNING: Could not retrieve SPF (TXT) records.")

    # DMARC
    try:
        dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        findings.append("SUCCESS: DMARC record present — email authentication is active.")
    except Exception:
        findings.append("WARNING: No DMARC record — phishing emails can impersonate your domain.")

    # DKIM (common selectors)
    dkim_found = False
    for selector in ['default', 'google', 'mail', 'dkim', 'k1']:
        try:
            dns.resolver.resolve(f"{selector}._domainkey.{domain}", 'TXT')
            findings.append(f"SUCCESS: DKIM record found (selector: {selector}) — email signing active.")
            dkim_found = True
            break
        except Exception:
            pass
    if not dkim_found:
        findings.append("WARNING: No common DKIM selector found — emails may not be cryptographically signed.")

    # MX
    try:
        mx = dns.resolver.resolve(domain, 'MX')
        findings.append(f"INFO: {len(list(mx))} MX record(s) found — mail server is configured.")
    except Exception:
        findings.append("INFO: No MX records found — domain may not use email.")

    return findings


def enumerate_subdomains(target):
    domain = clean_domain(target)
    common = [
        'www', 'mail', 'ftp', 'admin', 'dev', 'staging',
        'api', 'blog', 'shop', 'portal', 'vpn', 'remote',
        'app', 'test', 'cpanel', 'webmail', 'secure'
    ]
    found = []
    for sub in common:
        try:
            full = f"{sub}.{domain}"
            ip = socket.gethostbyname(full)
            found.append(f"FOUND: {full} → {ip}")
        except socket.gaierror:
            pass
    if not found:
        found.append("INFO: No common subdomains discovered.")
    return found


def get_whois_info(target):
    domain = clean_domain(target)
    findings = []
    try:
        w = whois.whois(domain)

        registrar = w.registrar or "Unknown"
        findings.append(f"INFO: Registrar — {registrar}")

        exp = w.expiration_date
        if isinstance(exp, list): exp = exp[0]
        if exp:
            days_left = (exp - datetime.datetime.now()).days
            if days_left < 30:
                findings.append(f"CRITICAL: Domain expires in {days_left} days! You may LOSE your domain.")
            elif days_left < 90:
                findings.append(f"WARNING: Domain expires in {days_left} days. Consider renewing soon.")
            else:
                findings.append(f"SUCCESS: Domain valid for {days_left} more days (expires {exp.strftime('%Y-%m-%d')}).")
        else:
            findings.append("INFO: Expiration date not available.")

        country = w.country or "Unknown"
        findings.append(f"INFO: Registrant country — {country}")

    except Exception as e:
        findings.append(f"ERROR: WHOIS lookup failed — {str(e)}")
    return findings


def check_http_headers(target):
    url = base_url(target)
    findings = []
    security_headers = {
        'Strict-Transport-Security': 'Forces HTTPS — prevents protocol downgrade attacks',
        'Content-Security-Policy': 'Controls resource loading — prevents XSS & injection',
        'X-Frame-Options': 'Prevents clickjacking via iframes',
        'X-Content-Type-Options': 'Prevents MIME-type sniffing attacks',
        'Referrer-Policy': 'Controls referrer data sent with requests',
        'Permissions-Policy': 'Restricts browser features like camera/mic access',
    }
    try:
        response = requests.get(url, timeout=5, verify=False)
        headers = response.headers
        for header, desc in security_headers.items():
            if header in headers:
                findings.append(f"SUCCESS: {header} is set.")
            else:
                findings.append(f"WARNING: Missing {header} — {desc}")
        if 'Server' in headers:
            findings.append(f"WARNING: Server header exposes technology — {headers['Server']}")
        if 'X-Powered-By' in headers:
            findings.append(f"WARNING: X-Powered-By exposes stack — {headers['X-Powered-By']}")
    except Exception as e:
        findings.append(f"ERROR: Could not fetch HTTP headers — {str(e)}")
    return findings


# ──────────────────────────────────────────────
# CATEGORY 2 — VULNERABILITY DETECTION
# ──────────────────────────────────────────────

def detect_cms(target):
    url = base_url(target)
    findings = []
    cms_path_checks = {
        'WordPress': ['/wp-login.php', '/wp-admin/', '/wp-content/themes/'],
        'Joomla':    ['/administrator/', '/components/com_content/'],
        'Drupal':    ['/sites/default/files/', '/core/install.php'],
        'Magento':   ['/index.php/admin/', '/skin/frontend/'],
    }
    cms_content_signatures = {
        'WordPress':  ['wp-content', 'wp-includes', 'wordpress'],
        'Joomla':     ['joomla', 'com_content', '/media/jui/'],
        'Drupal':     ['drupal', 'sites/default', 'drupal.js'],
        'Shopify':    ['cdn.shopify.com', 'myshopify.com'],
        'Wix':        ['wix.com', 'wixstatic.com'],
        'Squarespace':['squarespace.com', 'squarespace-cdn.com'],
        'Webflow':    ['webflow.com', 'assets.website-files.com'],
    }
    detected = set()

    # Content-based detection
    try:
        r = requests.get(url, timeout=5, verify=False)
        content = r.text.lower()
        for cms, sigs in cms_content_signatures.items():
            if any(s in content for s in sigs):
                detected.add(cms)
    except Exception:
        pass

    # Path-based detection
    for cms, paths in cms_path_checks.items():
        for path in paths:
            try:
                r = requests.get(f"{url}{path}", timeout=3, verify=False)
                if r.status_code in [200, 301, 302]:
                    detected.add(cms)
                    break
            except Exception:
                pass

    if detected:
        for cms in detected:
            findings.append(f"DETECTED: {cms} — ensure it is updated to avoid known exploits.")
    else:
        findings.append("INFO: No common CMS fingerprint detected.")

    return findings


def check_cve(nmap_output):
    findings = []
    pattern = r'(\d+)/tcp\s+open\s+\S+\s+(.+)'
    matches = re.findall(pattern, nmap_output)

    if not matches:
        findings.append("INFO: No versioned services found for CVE lookup.")
        return findings

    checked = 0
    for port, version_info in matches:
        if checked >= 4:
            break
        version_info = version_info.strip()
        if not version_info or version_info == '':
            continue
        keyword = ' '.join(version_info.split()[:2])
        try:
            api_url = (
                f"https://services.nvd.nist.gov/rest/json/cves/2.0"
                f"?keywordSearch={requests.utils.quote(keyword)}&resultsPerPage=5"
            )
            r = requests.get(api_url, timeout=10)
            data = r.json()
            total = data.get('totalResults', 0)
            if total > 0:
                findings.append(
                    f"WARNING: {total} CVE(s) found for '{keyword}' (port {port}). "
                    f"Review at nvd.nist.gov"
                )
            else:
                findings.append(f"SUCCESS: No known CVEs for '{keyword}' (port {port}).")
            checked += 1
        except Exception:
            findings.append(f"INFO: Could not query CVE database for port {port}.")
            checked += 1

    if not findings:
        findings.append("INFO: CVE check skipped — no service version info available.")
    return findings


def check_default_credentials(target):
    url = base_url(target)
    findings = []
    admin_paths = ['/admin', '/admin/login', '/wp-login.php', '/administrator/index.php', '/login']
    default_creds = [
        ('admin', 'admin'),
        ('admin', 'password'),
        ('admin', '123456'),
        ('root', 'root'),
        ('administrator', 'administrator'),
    ]
    for path in admin_paths:
        full_url = f"{url}{path}"
        try:
            r = requests.get(full_url, timeout=3, verify=False)
            if r.status_code == 200 and ('password' in r.text.lower() or 'login' in r.text.lower()):
                findings.append(f"WARNING: Login panel found at {path} — testing default credentials...")
                for user, pwd in default_creds[:3]:
                    try:
                        resp = requests.post(
                            full_url,
                            data={'username': user, 'password': pwd,
                                  'user': user, 'pass': pwd, 'log': user, 'pwd': pwd},
                            timeout=3, verify=False, allow_redirects=True
                        )
                        if resp.status_code == 200 and (
                            'logout' in resp.text.lower() or
                            'dashboard' in resp.text.lower() or
                            'welcome' in resp.text.lower()
                        ):
                            findings.append(f"CRITICAL: Default credentials '{user}/{pwd}' work at {path}!")
                    except Exception:
                        pass
        except Exception:
            pass
    if not findings:
        findings.append("SUCCESS: No accessible admin panels with default credentials found.")
    return findings


def check_open_redirect(target):
    url = base_url(target)
    findings = []
    redirect_params = ['?next=', '?url=', '?redirect=', '?return=', '?goto=', '?dest=']
    test_value = 'http://evil-test-probe.com'
    for param in redirect_params:
        test_url = f"{url}/{param}{test_value}"
        try:
            r = requests.get(test_url, timeout=3, verify=False, allow_redirects=False)
            if r.status_code in [301, 302, 303, 307, 308]:
                location = r.headers.get('Location', '')
                if 'evil-test-probe.com' in location:
                    findings.append(f"CRITICAL: Open redirect via {param} — users can be redirected to attacker sites!")
        except Exception:
            pass
    if not findings:
        findings.append("SUCCESS: No open redirect vulnerabilities detected.")
    return findings


# ──────────────────────────────────────────────
# SCORE CALCULATION (UPDATED)
# ──────────────────────────────────────────────

def calculate_score(nmap_output, web_findings, typo_findings,
                    ssl_findings, dns_findings, header_findings,
                    cms_findings, cve_findings, cred_findings, redirect_findings):
    score = 100

    # Open ports
    open_ports = len(re.findall(r"open", nmap_output, re.IGNORECASE))
    score -= open_ports * 3

    for findings, weights in [
        (web_findings,      {'CRITICAL': 25, 'WARNING': 8}),
        (typo_findings,     {'DANGER': 12}),
        (ssl_findings,      {'CRITICAL': 20, 'WARNING': 10}),
        (dns_findings,      {'WARNING': 8}),
        (header_findings,   {'WARNING': 3}),
        (cms_findings,      {'DETECTED': 5}),
        (cve_findings,      {'WARNING': 10}),
        (cred_findings,     {'CRITICAL': 30, 'WARNING': 10}),
        (redirect_findings, {'CRITICAL': 20}),
    ]:
        for item in findings:
            for keyword, deduction in weights.items():
                if keyword in item:
                    score -= deduction

    return max(0, score)


# ──────────────────────────────────────────────
# ROUTES
# ──────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    target = data.get('target', '').strip()

    if not target or not is_safe_input(target):
        return jsonify({"error": "Invalid or unsafe target input"}), 400

    try:
        # ── Original features ──────────────────
        web_findings  = check_web_surface(target)
        typo_findings = check_typosquatting(target)

        # ── Category 1: Scanning & Recon ───────
        ssl_findings    = check_ssl(target)
        dns_findings    = check_dns_security(target)
        subdomain_finds = enumerate_subdomains(target)
        whois_findings  = get_whois_info(target)
        header_findings = check_http_headers(target)

        # ── Nmap infrastructure ─────────────────
        nmap_path = get_nmap_path()
        command = [
            nmap_path, "-sT", "-F", "-Pn", "-sV",
            "-T4", "--max-retries", "1", target
        ]
        result = subprocess.run(command, capture_output=True, text=True, timeout=150)
        if result.returncode != 0:
            return jsonify({"error": "Nmap Error", "details": result.stderr}), 500
        nmap_output = result.stdout

        # ── Category 2: Vulnerability Detection ─
        cms_findings      = detect_cms(target)
        cve_findings      = check_cve(nmap_output)
        cred_findings     = check_default_credentials(target)
        redirect_findings = check_open_redirect(target)

        # ── Final score ─────────────────────────
        risk_score = calculate_score(
            nmap_output, web_findings, typo_findings,
            ssl_findings, dns_findings, header_findings,
            cms_findings, cve_findings, cred_findings, redirect_findings
        )

        return jsonify({
            "score":            risk_score,
            "web_surface":      web_findings,
            "brand_protection": typo_findings,
            "ssl":              ssl_findings,
            "dns":              dns_findings,
            "subdomains":       subdomain_finds,
            "whois":            whois_findings,
            "http_headers":     header_findings,
            "cms":              cms_findings,
            "cve":              cve_findings,
            "default_creds":    cred_findings,
            "open_redirect":    redirect_findings,
            "nmap_results":     nmap_output,
        })

    except subprocess.TimeoutExpired:
        return jsonify({"error": "Scan timed out."}), 408
    except Exception as e:
        return jsonify({"error": f"System Error: {str(e)}"}), 500


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
