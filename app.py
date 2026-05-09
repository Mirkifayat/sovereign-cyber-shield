from flask import Flask, render_template, request, jsonify
import subprocess
import re
import os
import shutil
import requests
import socket
import ssl
import datetime
import urllib3
import warnings 
import dns.resolver

warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)
socket.setdefaulttimeout(3) # Strict timeout to prevent server hangs

app = Flask(__name__)

def get_nmap_path():
    path = shutil.which("nmap")
    return path if path else "/usr/bin/nmap"

def clean_domain(target):
    return target.replace("http://", "").replace("https://", "").split("/")[0]

# --- RECON MODULES ---
def check_web_surface(target):
    findings = []
    paths = ['/.env', '/admin/', '/.git/config']
    url = f"http://{clean_domain(target)}"
    for path in paths:
        try:
            r = requests.get(f"{url}{path}", timeout=2, verify=False)
            if r.status_code == 200: findings.append(f"CRITICAL: Exposed file found at {path}")
            elif r.status_code in [401, 403]: findings.append(f"WARNING: Protected admin panel detected at {path}")
        except: pass
    if not findings: findings.append("SUCCESS: No common sensitive files exposed.")
    return findings

def check_typosquatting(domain):
    domain = clean_domain(domain)
    if '.' not in domain: return ["N/A: Invalid domain."]
    base, tld = domain.rsplit('.', 1)
    impersonations = []
    typos = [base.replace('i', '1') + f".{tld}", base + f"s.{tld}"]
    for typo in typos:
        try:
            dns.resolver.resolve(typo, 'A', lifetime=2)
            impersonations.append(f"DANGER: {typo} is registered! Someone might be impersonating your brand.")
        except:
            impersonations.append(f"SAFE: {typo} is not registered.")
    return impersonations

def get_geo_intel(domain):
    try:
        ip = socket.gethostbyname(clean_domain(domain))
        res = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,isp", timeout=2)
        d = res.json()
        return {"ip": ip, "country": d.get("country", "Unknown"), "isp": d.get("isp", "Unknown")}
    except: return {"ip": "Unknown", "country": "Unknown", "isp": "Unknown"}

# --- ACTION PLAN GENERATOR ---
def generate_action_plan(nmap_output, web_surface, typos):
    plan = []
    ports = len(re.findall(r"open", nmap_output, re.IGNORECASE))
    if ports > 0:
        plan.append({"label": "WARNING", "issue": f"{ports} open network port(s) detected.", "solution": "Configure your firewall to block unauthorized access. Only leave essential ports open (e.g., Port 443 for HTTPS)."})
    for w in web_surface:
        if "CRITICAL" in w:
            plan.append({"label": "CRITICAL", "issue": w.replace("CRITICAL: ", ""), "solution": "Immediately delete this file from your public web directory or restrict access using server configurations."})
    for t in typos:
        if "DANGER" in t:
            plan.append({"label": "WARNING", "issue": "Brand Impersonation detected.", "solution": "Monitor this domain for phishing activity. Consider filing a UDRP dispute if it violates your trademark."})
    return plan

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    raw_target = request.json.get('target', '').strip()
    if not raw_target: return jsonify({"error": "Enter a domain first"}), 400
    target = clean_domain(raw_target)

    try:
        web_surface = check_web_surface(target)
        typos = check_typosquatting(target)
        geo = get_geo_intel(target)
        
        # Fast Nmap scan to prevent timeout
        nmap_path = get_nmap_path()
        cmd = [nmap_path, "-sT", "-Pn", "-T5", "--top-ports", "20", target]
        nmap_res = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        nmap_out = nmap_res.stdout

        score = 100
        if "open" in nmap_out.lower(): score -= 20
        if any("CRITICAL" in w for w in web_surface): score -= 30
        score = max(0, score)

        action_plan = generate_action_plan(nmap_out, web_surface, typos)

        return jsonify({
            "score": score,
            "web_surface": web_surface,
            "brand_protection": typos,
            "geo": geo,
            "action_plan": action_plan,
            "nmap_results": nmap_out
        })
    except Exception as e: return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
