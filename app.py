from flask import Flask, render_template, request, jsonify
import subprocess
import re
import os
import shutil
import requests
import socket
import urllib3
import warnings 

# Forcefully ignore the specific InsecureRequestWarning globally
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

def get_nmap_path():
    path = shutil.which("nmap")
    return path if path else "/usr/bin/nmap"

def is_safe_input(target):
    pattern = r"^[a-zA-Z0-9.-]+$"
    return re.match(pattern, target)

def check_web_surface(target):
    findings = []
    sensitive_paths = ['/.env', '/.git/config', '/admin/', '/wp-config.php.bak']
    base_url = f"http://{target}" if not target.startswith('http') else target
    for path in sensitive_paths:
        try:
            url = f"{base_url}{path}"
            response = requests.get(url, timeout=3, verify=False)
            if response.status_code == 200: findings.append(f"CRITICAL: Exposed file found at {path}")
            elif response.status_code in [401, 403]: findings.append(f"WARNING: Protected admin panel detected at {path}")
        except requests.exceptions.RequestException:
            pass
    if not findings: findings.append("SUCCESS: No common sensitive files exposed.")
    return findings

def check_typosquatting(domain):
    domain = domain.replace("http://", "").replace("https://", "").split("/")[0]
    if domain.count('.') == 0: return ["N/A: Please enter a valid domain to check brand protection."]
    base, tld = domain.rsplit('.', 1)
    impersonations = []
    typos = []
    if 'i' in base: typos.append(base.replace('i', '1') + f".{tld}")
    if 'o' in base: typos.append(base.replace('o', '0') + f".{tld}")
    typos.append(base + f"s.{tld}") 
    for typo in typos:
        try:
            socket.gethostbyname(typo)
            impersonations.append(f"DANGER: {typo} is registered! Someone might be impersonating your brand.")
        except socket.error:
            impersonations.append(f"SAFE: {typo} is not registered.")
    return impersonations

def get_server_info(domain):
    try:
        clean_domain = domain.replace("http://", "").replace("https://", "").split("/")[0]
        target_ip = socket.gethostbyname(clean_domain)
        res = requests.get(f"http://ip-api.com/json/{target_ip}", timeout=3)
        if res.status_code == 200:
            data = res.json()
            return {"ip": target_ip, "country": data.get("country", "Unknown"), "isp": data.get("isp", "Unknown")}
    except Exception:
        pass
    return {"ip": "Unknown", "country": "Unknown", "isp": "Unknown"}

def calculate_score(nmap_output, web_findings, typo_findings):
    score = 100
    open_ports = len(re.findall(r"open", nmap_output, re.IGNORECASE))
    score -= (open_ports * 5)
    for finding in web_findings:
        if "CRITICAL" in finding: score -= 30
        elif "WARNING" in finding: score -= 10
    for finding in typo_findings:
        if "DANGER" in finding: score -= 15
    return max(0, score) 

# --- NEW FEATURE: VULNERABILITY ACTION PLAN GENERATOR ---
def generate_action_plan(nmap_output, web_findings, typo_findings):
    plan = []
    
    # 1. Analyze Ports
    open_ports = len(re.findall(r"open", nmap_output, re.IGNORECASE))
    if open_ports > 0:
        plan.append({
            "severity": "WARNING",
            "issue": f"{open_ports} open network port(s) detected.",
            "solution": "Configure your firewall to block unauthorized access. Only leave essential ports open (e.g., Port 443 for HTTPS)."
        })
        
    # 2. Analyze Web Surface
    for finding in web_findings:
        if "CRITICAL" in finding:
            plan.append({
                "severity": "CRITICAL",
                "issue": finding.replace("CRITICAL: ", ""),
                "solution": "Immediately delete this file from your public web directory or restrict access using server configurations (.htaccess / Nginx)."
            })
        elif "WARNING" in finding:
            plan.append({
                "severity": "WARNING",
                "issue": finding.replace("WARNING: ", ""),
                "solution": "Hide your admin login portal from the public internet. Enforce IP whitelisting and mandatory Two-Factor Authentication (2FA)."
            })
            
    # 3. Analyze Brand Impersonation
    for finding in typo_findings:
        if "DANGER" in finding:
            # Extract just the domain name from the string
            words = finding.split(" ")
            domain = words[1] if len(words) > 1 else "A similar domain"
            plan.append({
                "severity": "HIGH RISK",
                "issue": f"Brand Impersonation: {domain} is actively registered.",
                "solution": "Monitor this domain for phishing/deepfake activity targeting your customers. If it violates your trademark, file a UDRP dispute or DMCA takedown."
            })
            
    # If no issues found
    if not plan:
        plan.append({
            "severity": "SUCCESS",
            "issue": "No major vulnerabilities detected across scanned perimeters.",
            "solution": "Maintain routine automated scans and ensure software dependencies remain updated."
        })
        
    return plan

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    target = data.get('target')

    if not target or not is_safe_input(target): return jsonify({"error": "Invalid or unsafe target input"}), 400

    try:
        web_findings = check_web_surface(target)
        typo_findings = check_typosquatting(target)
        server_info = get_server_info(target)
        
        nmap_path = get_nmap_path()
        command = [nmap_path, "-sT", "-F", "-Pn", "-T5", "--max-retries", "1", target]
        result = subprocess.run(command, capture_output=True, text=True, timeout=150)

        if result.returncode != 0: return jsonify({"error": "Nmap Error", "details": result.stderr}), 500
             
        nmap_output = result.stdout
        risk_score = calculate_score(nmap_output, web_findings, typo_findings)
        
        # ---> GENERATE THE REMEDIATION PLAN <---
        action_plan = generate_action_plan(nmap_output, web_findings, typo_findings)

        return jsonify({
            "score": risk_score,
            "web_surface": web_findings,
            "brand_protection": typo_findings,
            "server_data": server_info,
            "nmap_results": nmap_output,
            "action_plan": action_plan # Sending the plan to frontend
        })
            
    except subprocess.TimeoutExpired: return jsonify({"error": "Scan timed out."}), 408
    except Exception as e: return jsonify({"error": f"System Error: {str(e)}"}), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
