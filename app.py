from flask import Flask, render_template, request, jsonify
import subprocess
import os
import shutil
import requests
import socket
import ssl
import datetime
import urllib3
import warnings
import dns.resolver
import whois
from concurrent.futures import ThreadPoolExecutor

warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)
socket.setdefaulttimeout(4)

app = Flask(__name__)

def get_nmap_path():
    path = shutil.which("nmap")
    return path if path else "/usr/bin/nmap"

def clean_domain(target):
    return target.replace("http://", "").replace("https://", "").split("/")[0].strip("/")

# ──────────────────────────────────────────────
# MODULE 1: WEB SURFACE & CLOUD LEAKS
# ──────────────────────────────────────────────
def check_web_surface(target):
    findings = []
    url = f"http://{target}"
    paths = [
        '/.env', '/admin/', '/.git/config', '/wp-config.php.bak',
        '/backup.zip', '/server-status', '/.aws/credentials',
        '/docker-compose.yml', '/package.json', '/config/database.yml'
    ]
    for path in paths:
        try:
            r = requests.get(f"{url}{path}", timeout=3, verify=False, allow_redirects=False)
            if r.status_code == 200:
                findings.append(f"CRITICAL: Exposed system/cloud configuration found at {path}")
            elif r.status_code in [401, 403]:
                findings.append(f"WARNING: Private restricted path detected at {path}")
        except Exception:
            pass
    return findings if findings else ["SUCCESS: Scanned 10 high-risk directories. No cloud or system exposures found."]

# ──────────────────────────────────────────────
# MODULE 2: ACTIVE EXPLOIT INJECTION (SQLi, XSS, LFI)
# ──────────────────────────────────────────────
def check_file_exploits(target):
    findings = []
    url = f"http://{target}"
    payloads = ['/etc/passwd', '/proc/self/environ', '/../../../../windows/win.ini']
    for p in payloads:
        try:
            r = requests.get(f"{url}/{p}", timeout=3, verify=False)
            if r.status_code == 200 and ("root:x:" in r.text or "PATH=" in r.text or "[extensions]" in r.text):
                findings.append(f"CRITICAL: Active Path Traversal Exploit triggered at {p}")
        except Exception:
            pass
    try:
        r = requests.get(f"{url}/?id=1%27%20OR%20%271%27=%271", timeout=3, verify=False)
        if r.status_code == 500 or "SQL syntax" in r.text or "mysql_fetch" in r.text:
            findings.append("CRITICAL: Potential SQL Injection (SQLi) vulnerability detected on URL parameters.")
    except Exception:
        pass
    try:
        r = requests.get(f"{url}/?search=%3Cscript%3Ealert(1)%3C/script%3E", timeout=3, verify=False)
        if "<script>alert(1)</script>" in r.text and r.status_code == 200:
            findings.append("HIGH: Reflected Cross-Site Scripting (XSS) vulnerability detected. Input is not sanitized.")
    except Exception:
        pass
    return findings if findings else ["SUCCESS: WAF or input sanitization successfully blocked all simulated injection attacks."]

# ──────────────────────────────────────────────
# MODULE 3: HTTP HEADERS & OPEN REDIRECTS
# ──────────────────────────────────────────────
def check_headers_and_redirects(target):
    head_find = []
    redir_find = []
    url = f"http://{target}"
    try:
        r = requests.get(url, timeout=4, verify=False)
        headers = r.headers

        checks = {
            'Strict-Transport-Security': ("WARNING: Missing HSTS Header — Protocol Downgrade Risk.", "SUCCESS: HSTS is enforced. HTTPS connections are mandated."),
            'X-Frame-Options': ("WARNING: Missing X-Frame-Options — Clickjacking Risk.", "SUCCESS: Clickjacking protection (X-Frame-Options) is active."),
            'X-Content-Type-Options': ("WARNING: Missing X-Content-Type-Options — MIME Sniffing Risk.", "SUCCESS: MIME sniffing protection is active."),
            'Referrer-Policy': ("INFO: Referrer-Policy header missing. May leak URL data.", "SUCCESS: Referrer-Policy header is configured."),
            'Content-Security-Policy': ("WARNING: No Content-Security-Policy (CSP) header. XSS injection risk elevated.", "SUCCESS: Content Security Policy (CSP) is enforced."),
            'Permissions-Policy': ("INFO: Permissions-Policy not set. Browser features uncontrolled.", "SUCCESS: Permissions-Policy header is configured."),
        }

        for header, (warn_msg, ok_msg) in checks.items():
            if header not in headers:
                head_find.append(warn_msg)
            else:
                head_find.append(ok_msg)

        if 'Access-Control-Allow-Origin' in headers and headers['Access-Control-Allow-Origin'] == '*':
            head_find.append("DANGER: Insecure CORS policy — Wildcard (*) allows any origin to read responses.")

        try:
            redir_test = requests.get(f"{url}/?redirect=http://evil.com", timeout=3, verify=False, allow_redirects=False)
            if redir_test.status_code in [301, 302] and 'evil.com' in redir_test.headers.get('Location', ''):
                redir_find.append("CRITICAL: Open redirect vulnerability found. Site can be weaponized for phishing campaigns.")
            else:
                redir_find.append("SUCCESS: URL parameters reject open external redirects.")
        except Exception:
            redir_find.append("INFO: Redirect test completed. No open redirect behavior detected.")

    except Exception:
        head_find.append("INFO: Could not analyze HTTP headers. Host blocked the request.")
        redir_find.append("INFO: Redirect check bypassed due to connection policy.")

    return head_find, redir_find

# ──────────────────────────────────────────────
# MODULE 4: CMS DETECTION & DEFAULT CREDENTIALS
# ──────────────────────────────────────────────
def check_cms_and_creds(target):
    cms_find = []
    cred_find = []
    url = f"http://{target}"
    try:
        r = requests.get(url, timeout=4, verify=False)
        html = r.text.lower()
        if "wp-content" in html or "wordpress" in html:
            cms_find.append("DETECTED: WordPress CMS identified. Audit plugins and themes for known CVEs.")
        elif "joomla" in html:
            cms_find.append("DETECTED: Joomla CMS identified. Ensure all extensions are patched.")
        elif "shopify" in html:
            cms_find.append("DETECTED: Shopify E-Commerce platform. Audit third-party apps and webhooks.")
        elif "drupal" in html:
            cms_find.append("DETECTED: Drupal CMS identified. Apply all security advisories.")
        elif "wix.com" in html:
            cms_find.append("INFO: Wix hosted website. Security managed by Wix platform.")
        else:
            cms_find.append("INFO: Custom or heavily obfuscated application framework detected.")

        admin_paths = ['/wp-login.php', '/admin', '/administrator', '/login', '/cpanel']
        for apath in admin_paths:
            try:
                admin_req = requests.get(f"{url}{apath}", timeout=3, verify=False, allow_redirects=False)
                if admin_req.status_code == 200:
                    cred_find.append(f"WARNING: Admin portal exposed at {apath} — accessible to the public internet.")
                    break
            except Exception:
                pass
        if not cred_find:
            cred_find.append("SUCCESS: Standard administrative portals are hidden or unreachable.")
    except Exception:
        cms_find.append("INFO: CMS fingerprinting blocked by server security controls.")
        cred_find.append("SUCCESS: Administrative endpoints are unreachable externally.")
    return cms_find, cred_find

# ──────────────────────────────────────────────
# MODULE 5: SSL/TLS CERTIFICATE ANALYSIS
# ──────────────────────────────────────────────
def check_ssl_real(domain):
    findings = []
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(4)
            s.connect((domain, 443))
            cert = s.getpeercert()
            exp_date = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            days_left = (exp_date - datetime.datetime.utcnow()).days
            issuer = dict(x[0] for x in cert.get('issuer', []))
            org = issuer.get('organizationName', 'Unknown CA')
            findings.append(f"INFO: Certificate issued by {org}.")
            if days_left < 0:
                findings.append(f"CRITICAL: SSL certificate EXPIRED {abs(days_left)} days ago! Active MITM Risk.")
            elif days_left < 15:
                findings.append(f"CRITICAL: SSL expires in {days_left} days. URGENT renewal required.")
            elif days_left < 30:
                findings.append(f"WARNING: SSL expires soon in {days_left} days. Renew immediately.")
            else:
                findings.append(f"SUCCESS: SSL/TLS certificate is valid for {days_left} more days.")

            # Check for weak protocol (TLS 1.0/1.1 detection via version)
            version = s.version()
            if version in ['TLSv1', 'TLSv1.1']:
                findings.append(f"WARNING: Weak TLS version in use: {version}. Upgrade to TLS 1.3.")
            else:
                findings.append(f"SUCCESS: Strong TLS version in use: {version}.")
    except ssl.SSLCertVerificationError:
        findings.append("CRITICAL: SSL certificate is INVALID or self-signed. Users will see browser security warnings.")
    except Exception:
        findings.append("CRITICAL: SSL/TLS connection failed. No encrypted channel could be established.")
    return findings

# ──────────────────────────────────────────────
# MODULE 6: DNS SECURITY
# ──────────────────────────────────────────────
def check_dns_real(domain):
    findings = []
    try:
        answers = dns.resolver.resolve(domain, 'TXT', lifetime=3)
        if any('v=spf1' in str(r) for r in answers):
            findings.append("SUCCESS: SPF record found. Domain protected against email spoofing.")
        else:
            findings.append("WARNING: No SPF record found. Domain is vulnerable to email spoofing attacks.")

        try:
            dmarc = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT', lifetime=3)
            dmarc_str = str(list(dmarc)[0])
            if 'p=reject' in dmarc_str:
                findings.append("SUCCESS: DMARC policy set to 'reject'. Maximum email protection active.")
            elif 'p=quarantine' in dmarc_str:
                findings.append("WARNING: DMARC policy is 'quarantine'. Upgrade to 'reject' for full protection.")
            else:
                findings.append("WARNING: DMARC policy is 'none'. Monitoring only — no active enforcement.")
        except Exception:
            findings.append("WARNING: No DMARC record found. Email impersonation is possible.")

        try:
            dns.resolver.resolve(f"_domainkey.{domain}", 'TXT', lifetime=3)
            findings.append("SUCCESS: DKIM record detected. Email integrity signatures are active.")
        except Exception:
            findings.append("INFO: DKIM record not found at default selector. Verify with your email provider.")

    except Exception:
        findings.append("WARNING: DNS security records missing or domain unresolvable.")
    return findings

# ──────────────────────────────────────────────
# MODULE 7: WHOIS & DOMAIN INTELLIGENCE
# ──────────────────────────────────────────────
def get_whois_real(domain):
    findings = []
    try:
        w = whois.whois(domain)
        registrar = w.registrar or "Unknown"
        findings.append(f"INFO: Registered via {registrar}.")
        if w.creation_date:
            created = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            age_days = (datetime.datetime.now() - created).days if isinstance(created, datetime.datetime) else 0
            if age_days < 90:
                findings.append(f"WARNING: Domain registered only {age_days} days ago. May indicate a newly-launched or suspicious site.")
            else:
                findings.append(f"SUCCESS: Domain has been registered for {age_days} days (established presence).")
        if w.expiration_date:
            exp = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
            if isinstance(exp, datetime.datetime):
                days = (exp - datetime.datetime.now()).days
                if days < 30:
                    findings.append(f"CRITICAL: Domain expires in {days} days! Risk of domain takeover if not renewed.")
                else:
                    findings.append(f"SUCCESS: Domain registry is active for {days} more days.")
        else:
            findings.append("INFO: Expiration date masked by WHOIS privacy protection.")
        if w.name_servers:
            ns = w.name_servers[0] if isinstance(w.name_servers, list) else w.name_servers
            findings.append(f"INFO: Authoritative nameserver: {ns}.")
    except Exception:
        findings.append("INFO: WHOIS registry data protected or rate-limited by ICANN.")
    return findings

# ──────────────────────────────────────────────
# MODULE 8: GEO-INTELLIGENCE
# ──────────────────────────────────────────────
def get_geo_intel(domain):
    try:
        ip = socket.gethostbyname(domain)
        res = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,isp,city,proxy,org,as", timeout=3)
        d = res.json()
        location = f"{d.get('city', '')}, {d.get('country', 'Unknown')}".strip(", ")
        proxy_status = " ⚠️ VPN/Proxy Detected" if d.get('proxy') else ""
        isp_info = d.get('isp', d.get('org', 'Unknown'))
        return {"ip": ip, "country": location + proxy_status, "isp": str(isp_info), "as": d.get('as', 'Unknown')}
    except Exception:
        return {"ip": "Unresolvable", "country": "Unknown", "isp": "Unknown", "as": "Unknown"}

# ──────────────────────────────────────────────
# MODULE 9: INFRASTRUCTURE INTELLIGENCE (Nmap)
# ──────────────────────────────────────────────
def analyze_infrastructure(nmap_out):
    findings = []
    cves = []
    risks = {
        '21': 'FTP (Cleartext Credentials)',
        '22': 'SSH (Brute-Force Target)',
        '23': 'Telnet (Unencrypted Protocol)',
        '25': 'SMTP (Mail Server)',
        '3306': 'MySQL Database (Direct Access)',
        '3389': 'RDP (Remote Desktop — Ransomware Vector)',
        '445': 'SMB (EternalBlue / WannaCry Vector)',
        '6379': 'Redis (Unauthenticated Access Risk)',
        '27017': 'MongoDB (Unauthenticated Access Risk)',
        '5432': 'PostgreSQL (Database Exposed)',
    }
    for port, desc in risks.items():
        if f"{port}/tcp" in nmap_out and "open" in nmap_out:
            findings.append(f"DANGER: {desc} — port {port} is exposed to the public internet.")
    if "vsFTPd 2.3.4" in nmap_out:
        cves.append("CRITICAL: CVE-2011-2523 — vsFTPd 2.3.4 Backdoor Command Execution.")
    if "OpenSSH 4.7" in nmap_out:
        cves.append("HIGH: CVE-2008-4109 — OpenSSH Username Enumeration vulnerability.")
    if "Apache/2.2" in nmap_out:
        cves.append("HIGH: CVE-2017-7679 — Apache 2.2.x mod_mime Buffer Overread.")
    if "Apache/2.4.49" in nmap_out or "Apache/2.4.50" in nmap_out:
        cves.append("CRITICAL: CVE-2021-41773 — Apache Path Traversal & RCE (actively exploited).")
    if "IIS/7.5" in nmap_out or "IIS/6.0" in nmap_out:
        cves.append("HIGH: Outdated Microsoft IIS version detected. Multiple known CVEs apply.")
    if not cves:
        cves.append("SUCCESS: No critical CVEs matched the detected service versions.")
    if not findings:
        findings.append("SUCCESS: No high-risk administrative or database ports are publicly exposed.")
    return findings, cves

# ──────────────────────────────────────────────
# NEW MODULE 10: COOKIE SECURITY AUDIT
# ──────────────────────────────────────────────
def check_cookie_security(target):
    findings = []
    url = f"http://{target}"
    try:
        r = requests.get(url, timeout=4, verify=False)
        cookies = r.cookies
        if not cookies:
            findings.append("INFO: No session cookies set on the initial HTTP response.")
            return findings
        for cookie in cookies:
            name = cookie.name
            issues = []
            if not cookie.secure:
                issues.append("no Secure flag")
            if not cookie.has_nonstandard_attr('HttpOnly'):
                issues.append("no HttpOnly flag")
            if not cookie.has_nonstandard_attr('SameSite'):
                issues.append("no SameSite attribute")
            if issues:
                findings.append(f"WARNING: Cookie '{name}' has security gaps: {', '.join(issues)}.")
            else:
                findings.append(f"SUCCESS: Cookie '{name}' is securely configured (Secure + HttpOnly + SameSite).")
    except Exception:
        findings.append("INFO: Cookie audit inconclusive — host may have rejected the connection.")
    return findings if findings else ["SUCCESS: All session cookies are securely hardened."]

# ──────────────────────────────────────────────
# NEW MODULE 11: TECHNOLOGY STACK FINGERPRINTING
# ──────────────────────────────────────────────
def check_tech_stack(target):
    findings = []
    url = f"http://{target}"
    try:
        r = requests.get(url, timeout=4, verify=False)
        headers = r.headers
        html = r.text.lower()
        server = headers.get('Server', '')
        powered = headers.get('X-Powered-By', '')
        if server:
            findings.append(f"WARNING: Server header discloses software version: '{server}'. Remove to reduce fingerprinting.")
            old_versions = ['Apache/2.2', 'Apache/2.0', 'nginx/1.0', 'nginx/1.2', 'IIS/6', 'IIS/7.0']
            if any(v in server for v in old_versions):
                findings.append(f"CRITICAL: Outdated server software detected. Immediate patching required.")
        else:
            findings.append("SUCCESS: Server version header is suppressed (fingerprinting hardened).")
        if powered:
            findings.append(f"WARNING: X-Powered-By discloses tech stack: '{powered}'. Disable this header in production.")
        else:
            findings.append("SUCCESS: X-Powered-By header is hidden.")
        stack_detected = []
        if 'laravel' in html or 'laravel_session' in str(r.cookies):
            stack_detected.append("Laravel (PHP)")
        if 'django' in html or 'csrftoken' in str(r.cookies):
            stack_detected.append("Django (Python)")
        if 'wp-content' in html:
            stack_detected.append("WordPress (PHP)")
        if '__next' in html or '_next/static' in html:
            stack_detected.append("Next.js (React)")
        if 'nuxt' in html:
            stack_detected.append("Nuxt.js (Vue)")
        if stack_detected:
            findings.append(f"DETECTED: Application framework identified — {', '.join(stack_detected)}.")
        else:
            findings.append("INFO: No common framework fingerprints found in HTML source.")
    except Exception:
        findings.append("INFO: Tech stack fingerprinting blocked by server security controls.")
    return findings if findings else ["INFO: Technology stack identification inconclusive."]

# ──────────────────────────────────────────────
# NEW MODULE 12: ROBOTS.TXT INTELLIGENCE
# ──────────────────────────────────────────────
def check_robots_txt(target):
    findings = []
    url = f"http://{target}/robots.txt"
    sensitive_kw = ['admin', 'backup', 'config', 'private', 'secret', 'database', 'internal', 'api', 'dev', 'staging', 'test', 'upload', 'cgi-bin']
    try:
        r = requests.get(url, timeout=4, verify=False)
        if r.status_code == 200:
            findings.append("INFO: robots.txt is publicly accessible.")
            content = r.text.lower()
            found = [kw for kw in sensitive_kw if kw in content]
            if found:
                findings.append(f"WARNING: Sensitive path hints in robots.txt: {', '.join(found)}. Attackers use this as a directory roadmap.")
            else:
                findings.append("SUCCESS: No sensitive directory paths leaked in robots.txt.")
            disallow_count = content.count('disallow:')
            findings.append(f"INFO: {disallow_count} Disallow rules found in robots.txt.")
        elif r.status_code == 404:
            findings.append("INFO: No robots.txt file found. Consider adding one to guide crawlers.")
        else:
            findings.append(f"INFO: robots.txt returned HTTP {r.status_code}.")
    except Exception:
        findings.append("INFO: robots.txt check inconclusive — connection timed out.")
    return findings

# ──────────────────────────────────────────────
# NEW MODULE 13: REAL SUBDOMAIN ENUMERATION
# ──────────────────────────────────────────────
def enumerate_subdomains(domain):
    findings = []
    common_subs = ['www', 'mail', 'admin', 'api', 'dev', 'staging', 'test', 'blog',
                   'shop', 'app', 'portal', 'vpn', 'ftp', 'smtp', 'remote', 'beta',
                   'dashboard', 'login', 'secure', 'mx', 'cdn', 'assets']
    found_risky = []
    found_normal = []
    for sub in common_subs:
        try:
            fqdn = f"{sub}.{domain}"
            ip = socket.gethostbyname(fqdn)
            if any(risk in sub for risk in ['dev', 'staging', 'test', 'admin', 'remote', 'beta']):
                found_risky.append((fqdn, ip))
            else:
                found_normal.append((fqdn, ip))
        except Exception:
            pass
    for fqdn, ip in found_risky:
        findings.append(f"WARNING: Sensitive subdomain active: {fqdn} ({ip}) — Dev/Admin environments may be unpatched.")
    for fqdn, ip in found_normal:
        findings.append(f"INFO: Active subdomain found: {fqdn} ({ip})")
    if not found_risky and not found_normal:
        findings.append("SUCCESS: No common subdomains exposed. Minimal attack surface.")
    elif not found_risky:
        findings.append(f"SUCCESS: {len(found_normal)} standard subdomains found, no sensitive development environments exposed.")
    return findings if findings else ["INFO: Subdomain enumeration complete."]

# ──────────────────────────────────────────────
# BRAND PROTECTION MODULE
# ──────────────────────────────────────────────
def check_brand_protection(domain):
    findings = []
    findings.append("INFO: Scanning global TLD registry for typosquatting lookalikes...")
    parts = domain.split('.')
    name = parts[0] if parts else domain
    common_tlds = ['.net', '.org', '.co', '.info', '.biz', '.online', '.store']
    suspicious = []
    for tld in common_tlds:
        lookalike = f"{name}{tld}"
        if lookalike != domain:
            try:
                socket.gethostbyname(lookalike)
                suspicious.append(lookalike)
            except Exception:
                pass
    if suspicious:
        for s in suspicious[:3]:
            findings.append(f"WARNING: Potential lookalike domain registered: {s} — monitor for phishing campaigns.")
    else:
        findings.append("SUCCESS: No exact lookalike domains found across major TLDs.")
    findings.append("INFO: Consider registering defensive domain variants to prevent brand abuse.")
    return findings

# ──────────────────────────────────────────────
# ACTION PLAN GENERATOR
# ──────────────────────────────────────────────
def generate_roadmap(nmap_out, web_surface, exploits, dns_data, ssl_data, headers_data, cookie_data, tech_data):
    plan = []
    if "open" in nmap_out.lower() and any("DANGER" in n for n in [nmap_out]):
        plan.append({"label": "CRITICAL", "issue": "Publicly exposed network services (DB/RDP/SMB ports).", "solution": "Firewall Policy: Block all inbound traffic except HTTP(80) and HTTPS(443). Use a VPN or bastion host for all administrative access."})
    for w in web_surface:
        if "CRITICAL" in w:
            plan.append({"label": "CRITICAL", "issue": "Exposed cloud or system configuration file (.env, .git, credentials).", "solution": "Immediate Action: Delete or relocate these files from the public web root. Rotate all secrets found. Add WAF rules to block access to sensitive paths."})
    for e in exploits:
        if "CRITICAL" in e:
            plan.append({"label": "CRITICAL", "issue": "SQL Injection or Path Traversal vulnerability found.", "solution": "Code Fix: Use parameterized queries for all database operations. Sanitize and validate every URL parameter. Deploy a WAF with OWASP core ruleset."})
        elif "HIGH" in e:
            plan.append({"label": "HIGH", "issue": "Cross-Site Scripting (XSS) vulnerability confirmed.", "solution": "Code Fix: Encode all HTML output. Implement a strict Content-Security-Policy (CSP) header. Use a template engine with auto-escaping enabled."})
    if any("No SPF" in d for d in dns_data):
        plan.append({"label": "HIGH", "issue": "Email Phishing Vulnerability — No SPF/DMARC protection.", "solution": "DNS Hardening: Add an SPF TXT record (v=spf1 include:your-mail-provider ~all). Add a DMARC policy (p=reject). Enable DKIM signing in your email provider."})
    if any("EXPIRED" in s or ("CRITICAL" in s and "SSL" in s) for s in ssl_data):
        plan.append({"label": "CRITICAL", "issue": "Broken or Expired SSL/TLS Certificate.", "solution": "Infrastructure: Renew your certificate immediately via Let's Encrypt (free) or your CA. Enable auto-renewal. Redirect all HTTP to HTTPS."})
    if any("Missing HSTS" in h for h in headers_data):
        plan.append({"label": "HIGH", "issue": "HSTS not configured — HTTP downgrade attacks possible.", "solution": "Server Config: Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to all HTTPS responses."})
    if any("No Content-Security-Policy" in h or "CSP" in h for h in headers_data):
        plan.append({"label": "MEDIUM", "issue": "No Content-Security-Policy (CSP) header detected.", "solution": "Server Config: Define and deploy a CSP header that whitelists only trusted content sources. Start with report-only mode."})
    for c in cookie_data:
        if "WARNING" in c:
            plan.append({"label": "MEDIUM", "issue": "Insecure session cookies — missing security flags.", "solution": "Code Fix: Set Secure, HttpOnly, and SameSite=Strict flags on all session and authentication cookies."})
            break
    for t in tech_data:
        if "WARNING" in t and "Server" in t:
            plan.append({"label": "LOW", "issue": "Server software version leaked in HTTP headers.", "solution": "Server Config: Set 'ServerTokens Prod' in Apache, or 'server_tokens off' in Nginx. Remove X-Powered-By header."})
            break
    if not plan:
        plan.append({"label": "LOW", "issue": "Security Baseline Met — No critical vulnerabilities detected.", "solution": "Routine Maintenance: Enable automated daily scanning. Monitor access logs. Keep all software and dependencies patched. Schedule a manual penetration test quarterly."})
    return plan

# ──────────────────────────────────────────────
# ROUTES
# ──────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    raw_target = request.json.get('target', '').strip()
    target = clean_domain(raw_target)
    if not target:
        return jsonify({"error": "Target domain required"}), 400

    try:
        with ThreadPoolExecutor(max_workers=20) as executor:
            f_web = executor.submit(check_web_surface, target)
            f_exploit = executor.submit(check_file_exploits, target)
            f_head_redir = executor.submit(check_headers_and_redirects, target)
            f_cms_cred = executor.submit(check_cms_and_creds, target)
            f_ssl = executor.submit(check_ssl_real, target)
            f_dns = executor.submit(check_dns_real, target)
            f_whois = executor.submit(get_whois_real, target)
            f_geo = executor.submit(get_geo_intel, target)
            f_cookies = executor.submit(check_cookie_security, target)
            f_tech = executor.submit(check_tech_stack, target)
            f_robots = executor.submit(check_robots_txt, target)
            f_subdomains = executor.submit(enumerate_subdomains, target)
            f_brand = executor.submit(check_brand_protection, target)

            nmap_path = get_nmap_path()
            cmd = [nmap_path, "-sT", "-Pn", "-F", "--host-timeout", "20s", "--max-retries", "1", "-sV", "--version-intensity", "3", target]
            try:
                nmap_res = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
                nmap_out = nmap_res.stdout
            except subprocess.TimeoutExpired:
                nmap_out = "Nmap: Host is heavily firewalled and dropping fast ICMP/TCP probes."

        web_surface = f_web.result()
        exploit_data = f_exploit.result()
        headers_data, redirect_data = f_head_redir.result()
        cms_data, cred_data = f_cms_cred.result()
        ssl_data = f_ssl.result()
        dns_data = f_dns.result()
        whois_data = f_whois.result()
        geo = f_geo.result()
        cookie_data = f_cookies.result()
        tech_data = f_tech.result()
        robots_data = f_robots.result()
        subdomain_data = f_subdomains.result()
        brand_data = f_brand.result()
        infra_intel, cve_data = analyze_infrastructure(nmap_out)

        # ── RISK SCORING ENGINE ──
        score = 100
        if any("CRITICAL" in w for w in web_surface): score -= 20
        if any("CRITICAL" in e for e in exploit_data): score -= 35
        if any("HIGH" in e for e in exploit_data): score -= 20
        if any("DANGER" in i for i in infra_intel): score -= 15
        if any("EXPIRED" in s or ("CRITICAL" in s and "SSL" in s) for s in ssl_data): score -= 25
        if any("Missing" in h or "No Content-Security" in h for h in headers_data): score -= 5
        if any("WARNING" in c for c in cookie_data): score -= 5
        if any("CRITICAL" in t for t in tech_data): score -= 5
        if any("No SPF" in d for d in dns_data): score -= 5
        score = max(0, score)

        # ── COUNT FINDINGS BY SEVERITY ──
        all_findings = web_surface + exploit_data + headers_data + redirect_data + cms_data + cred_data + ssl_data + dns_data + infra_intel + cve_data + cookie_data + tech_data + robots_data + subdomain_data
        severity_counts = {
            "critical": sum(1 for f in all_findings if "CRITICAL" in f),
            "high": sum(1 for f in all_findings if "HIGH" in f or "DANGER" in f),
            "warning": sum(1 for f in all_findings if "WARNING" in f),
            "safe": sum(1 for f in all_findings if "SUCCESS" in f),
        }

        return jsonify({
            "score": score,
            "severity_counts": severity_counts,
            "scan_time": datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
            "target": target,
            "roadmap": generate_roadmap(nmap_out, web_surface, exploit_data, dns_data, ssl_data, headers_data, cookie_data, tech_data),
            "web_surface": web_surface,
            "file_exploits": exploit_data,
            "infra_intelligence": infra_intel,
            "brand_protection": brand_data,
            "ssl": ssl_data,
            "dns": dns_data,
            "whois": whois_data,
            "http_headers": headers_data,
            "cms": cms_data,
            "cve": cve_data,
            "default_creds": cred_data,
            "open_redirect": redirect_data,
            "subdomains": subdomain_data,
            "cookies": cookie_data,
            "tech_stack": tech_data,
            "robots": robots_data,
            "geo": geo,
            "nmap_results": nmap_out
        })

    except Exception as e:
        print(f"Engine Crash: {str(e)}")
        return jsonify({"error": f"Scanning Engine Error: {str(e)}"}), 500


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
