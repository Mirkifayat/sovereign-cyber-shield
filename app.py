from flask import Flask, render_template, request, jsonify
import subprocess
import re
import os
import shutil
import requests
import socket

app = Flask(__name__)

def get_nmap_path():
    path = shutil.which("nmap")
    return path if path else "/usr/bin/nmap"

def is_safe_input(target):
    pattern = r"^[a-zA-Z0-9.-]+$"
    return re.match(pattern, target)

# --- NEW FEATURE 1: Web Surface Crawler ---
def check_web_surface(target):
    findings = []
    sensitive_paths = ['/.env', '/.git/config', '/admin/', '/wp-config.php.bak']
    
    # Ensure target has protocol
    base_url = f"http://{target}" if not target.startswith('http') else target
    
    for path in sensitive_paths:
        try:
            url = f"{base_url}{path}"
            response = requests.get(url, timeout=3, verify=False)
            if response.status_code == 200:
                findings.append(f"CRITICAL: Exposed file found at {path}")
            elif response.status_code in [401, 403]:
                findings.append(f"WARNING: Protected admin panel detected at {path}")
        except requests.exceptions.RequestException:
            pass
    
    if not findings:
        findings.append("SUCCESS: No common sensitive files exposed.")
    return findings

# --- NEW FEATURE 2: Brand Protection (Typosquatting) ---
def check_typosquatting(domain):
    # Strip protocol if present
    domain = domain.replace("http://", "").replace("https://", "").split("/")[0]
    
    if domain.count('.') == 0:
        return ["N/A: Please enter a valid domain (e.g., example.com) to check brand protection."]

    base, tld = domain.rsplit('.', 1)
    impersonations = []
    
    # Generate simple typos (e.g., replacing 'i' with '1', 'o' with '0')
    typos = []
    if 'i' in base: typos.append(base.replace('i', '1') + f".{tld}")
    if 'o' in base: typos.append(base.replace('o', '0') + f".{tld}")
    typos.append(base + f"s.{tld}") # Plural addition
    
    for typo in typos:
        try:
            socket.gethostbyname(typo)
            impersonations.append(f"DANGER: {typo} is registered! Someone might be impersonating your brand.")
        except socket.gaierror:
            impersonations.append(f"SAFE: {typo} is not registered.")
            
    return impersonations

# --- NEW FEATURE 3: Cyber-Resilience Score ---
def calculate_score(nmap_output, web_findings, typo_findings):
    score = 100
    
    # Deduct for open ports found in Nmap
    open_ports = len(re.findall(r"open", nmap_output, re.IGNORECASE))
    score -= (open_ports * 5)
    
    # Deduct for critical web exposures
    for finding in web_findings:
        if "CRITICAL" in finding:
            score -= 30
        elif "WARNING" in finding:
            score -= 10
            
    # Deduct for brand risks
    for finding in typo_findings:
        if "DANGER" in finding:
            score -= 15
            
    return max(0, score) # Score cannot drop below 0

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    target = data.get('target')

    if not target or not is_safe_input(target):
        return jsonify({"error": "Invalid or unsafe target input"}), 400

    try:
        # 1. Run Web Surface Check
        web_findings = check_web_surface(target)
        
        # 2. Run Brand Protection Check
        typo_findings = check_typosquatting(target)

        # 3. Run Nmap Infrastructure Check
        nmap_path = get_nmap_path()
        command = [nmap_path, "-sT", "-F", "-Pn", "-sV", "-T4", "--max-retries", "1", target]
        result = subprocess.run(command, capture_output=True, text=True, timeout=150)

        if result.returncode != 0:
             return jsonify({"error": "Nmap Error", "details": result.stderr}), 500
             
        nmap_output = result.stdout

        # 4. Calculate Final Risk Score
        risk_score = calculate_score(nmap_output, web_findings, typo_findings)

        # Return the aggregated intelligence
        return jsonify({
            "score": risk_score,
            "web_surface": web_findings,
            "brand_protection": typo_findings,
            "nmap_results": nmap_output
        })
            
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Scan timed out."}), 408
    except Exception as e:
        return jsonify({"error": f"System Error: {str(e)}"}), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)