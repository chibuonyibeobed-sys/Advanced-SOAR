from flask import Flask, request, render_template, jsonify, session
import subprocess, requests, time
from collections import defaultdict

app = Flask(__name__)
app.secret_key = "advanced_soar_secret"

VT_API_KEY = "c2ce6200e7ce273cc3693b59e5245e17ebedcb5dc61a4395a3795ae531f51d3c"

# Memory for SOAR
failed_logins = defaultdict(int)
blocked_ips = []
alerts = []

def log_alert(msg, level="INFO"):
    alerts.insert(0, {"time": time.strftime("%H:%M:%S"), "msg": msg, "level": level})
    if len(alerts) > 20: alerts.pop()

def block_ip(ip, reason):
    if ip not in blocked_ips:
        blocked_ips.append(ip)
        log_alert(f"BLOCKED {ip} | Reason: {reason}", "CRITICAL")
        # subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])

def vt_check(indicator, type="url"):
    headers = {"x-apikey": VT_API_KEY}
    try:
        if type == "url":
            r = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": indicator})
            time.sleep(2)
            r = requests.get(f"https://www.virustotal.com/api/v3/analyses/{r.json()['data']['id']}", headers=headers)
        else:
            r = requests.get(f"https://www.virustotal.com/api/v3/files/{indicator}", headers=headers)
        return r.json().get("data",{}).get("attributes",{}).get("last_analysis_stats",{}).get("malicious",0)
    except: return -1

# ===== PUBLIC PAGES - WHAT THEY ATTACK =====
@app.route('/')
def home(): return render_template('login.html')

@app.route('/upload')
def upload_page(): return render_template('malware.html')

@app.route('/url-check')
def phishing_page(): return render_template('phishing.html')

# ===== ATTACK HANDLERS - TRIGGER YOUR SOAR =====
@app.route('/login', methods=['POST'])
def login():
    ip = request.remote_addr
    if request.form['username'] == "admin" and request.form['password'] == "admin123":
        log_alert(f"Success login from {ip}", "INFO")
        return "Login OK"
    failed_logins[ip] += 1
    log_alert(f"Failed login #{failed_logins[ip]} from {ip}", "WARNING")
    if failed_logins[ip] >= 3:
        block_ip(ip, "SSH Brute Force")
        failed_logins[ip] = 0
        return "IP Blocked", 403
    return "Wrong password", 401

@app.route('/check_file', methods=['POST'])
def check_file():
    ip = request.remote_addr
    file_hash = request.form['file_hash']
    result = vt_check(file_hash, "hash")
    if result > 5: block_ip(ip, f"Malware Upload - {result} detections")
    log_alert(f"Malware scan: {file_hash} | Detections: {result}", "CRITICAL" if result>5 else "INFO")
    return f"VT Result: {result} vendors flagged"

@app.route('/check_url', methods=['POST'])
def check_url():
    ip = request.remote_addr
    url = request.form['url']
    result = vt_check(url, "url")
    if result > 3: block_ip(ip, f"Phishing URL - {result} detections")
    log_alert(f"Phishing scan: {url} | Detections: {result}", "CRITICAL" if result>3 else "INFO")
    return f"VT Result: {result} vendors flagged"

# ===== ADMIN DASHBOARD - YOUR MONITOR =====
@app.route('/admin')
def dashboard(): return render_template('dashboard.html', alerts=alerts, blocked=blocked_ips)

if __name__ == '__main__':
    log_alert("ADVANCED-SOAR LIVE STARTED", "INFO")
    app.run(host='0.0.0.0', port=5000, debug=True)
