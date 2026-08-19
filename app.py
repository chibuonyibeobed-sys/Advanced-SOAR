from flask import Flask, request, render_template, jsonify, session
import subprocess, requests, time, re
from collections import defaultdict
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = "advanced_soar_secret_2026"

VT_API_KEY = "c2ce6200e7ce273cc3693b59e5245e17ebedcb5dc61a4395a3795ae531f51d3c"
SOC_KEY = "boss2026" # Secret key to access SOC

# ===== SOPHISTICATED IOC WATCHLIST - STANDARD FORMAT =====
IOC_LIST = {
    "ips": {
        "185.220.101.1": {"cat": "Tor Exit Node", "sev": "HIGH", "desc": "Known anonymization IP", "first_seen": "2025-12-01"},
        "45.142.212.100": {"cat": "Brute Force Botnet", "sev": "CRITICAL", "desc": "Active credential stuffing", "first_seen": "2026-01-15"},
        "103.152.112.55": {"cat": "C2 Server", "sev": "CRITICAL", "desc": "Cobalt Strike Beacon", "first_seen": "2026-02-20"},
        "94.130.12.55": {"cat": "Scanner", "sev": "MEDIUM", "desc": "Masscan / Shodan Scanner", "first_seen": "2026-03-01"},
    },
    "hashes": {
        "5d41402abc4b2a76b9719d911017c592": {"cat": "Ransomware", "sev": "CRITICAL", "desc": "LockBit 3.0 Sample", "first_seen": "2026-03-01"},
        "e3b0c44298fc1c149afbf4c8996fb924": {"cat": "Stealer", "sev": "HIGH", "desc": "RedLine Stealer", "first_seen": "2026-03-10"},
        "098f6bcd4621d373cade4e832627b4f6": {"cat": "Trojan", "sev": "HIGH", "desc": "AgentTesla Downloader", "first_seen": "2026-04-05"},
        "d41d8cd98f00b204e9800998ecf8427e": {"cat": "Backdoor", "sev": "CRITICAL", "desc": "Cobalt Strike Payload", "first_seen": "2026-05-12"},
    },
    "domains": {
        "phishingsite.ru": {"cat": "Phishing", "sev": "CRITICAL", "desc": "Fake Microsoft 365 Login", "first_seen": "2026-01-20"},
        "evil-login.com": {"cat": "Phishing", "sev": "CRITICAL", "desc": "Credential Harvester", "first_seen": "2026-02-14"},
        "update-security.xyz": {"cat": "Malware C2", "sev": "HIGH", "desc": "DGA Domain for TrickBot", "first_seen": "2026-03-22"},
        "secure-paypal.net": {"cat": "Phishing", "sev": "CRITICAL", "desc": "Fake PayPal Portal", "first_seen": "2026-04-18"},
    },
    "useragents": {
        "sqlmap": {"cat": "Scanner", "sev": "MEDIUM", "desc": "SQL Injection Tool", "first_seen": "2025-11-01"},
        "nikto": {"cat": "Scanner", "sev": "MEDIUM", "desc": "Web Vulnerability Scanner", "first_seen": "2025-11-01"},
        "curl": {"cat": "Suspicious", "sev": "LOW", "desc": "Command line tool", "first_seen": "2025-11-01"}
    }
}

# Memory for SOAR
login_attempts = {} # {ip: {"count": 0, "blocked_until": datetime}}
alerts = []

def log_alert(msg, level="INFO"):
    alerts.insert(0, {"time": time.strftime("%H:%M:%S"), "msg": msg, "level": level})
    if len(alerts) > 100: alerts.pop()

def check_ioc(ip, indicator=None, type=None, user_agent=None):
    """Sophisticated IOC Check. Returns: match, reason"""
    if ip in IOC_LIST["ips"]:
        ioc = IOC_LIST["ips"][ip]
        return True, f"IOC MATCH [{ioc['sev']}] {ioc['cat']}: {ioc['desc']}"

    if type == "hash" and indicator in IOC_LIST["hashes"]:
        ioc = IOC_LIST["hashes"][indicator]
        return True, f"IOC MATCH [{ioc['sev']}] {ioc['cat']}: {ioc['desc']}"

    if type == "domain" and indicator:
        for domain in IOC_LIST["domains"]:
            if domain in indicator.lower():
                ioc = IOC_LIST["domains"][domain]
                return True, f"IOC MATCH [{ioc['sev']}] {ioc['cat']}: {ioc['desc']}"

    if user_agent:
        for ua in IOC_LIST["useragents"]:
            if ua in user_agent.lower():
                ioc = IOC_LIST["useragents"][ua]
                return True, f"IOC MATCH [{ioc['sev']}] {ioc['cat']}: {ioc['desc']}"

    return False, ""

def is_ip_blocked(ip):
    """Check if IP is currently blocked. Auto-unblock after 15min"""
    if ip in login_attempts:
        data = login_attempts[ip]
        if "blocked_until" in data:
            if datetime.now() < data["blocked_until"]:
                time_left = data["blocked_until"] - datetime.now()
                minutes = int(time_left.total_seconds() / 60)
                seconds = int(time_left.total_seconds() % 60)
                return True, f"IP Blocked for {minutes}m {seconds}s. Try again later."
            else:
                del login_attempts[ip]
                log_alert(f"UNBLOCKED {ip} | 15min ban expired", "INFO")
    return False, ""

def record_failed_login(ip):
    """Record failed login. Block for 15min after 3 tries"""
    if ip not in login_attempts:
        login_attempts[ip] = {"count": 0}
    login_attempts[ip]["count"] += 1
    log_alert(f"Failed login #{login_attempts[ip]['count']} from {ip}", "WARNING")

    if login_attempts[ip]["count"] >= 3:
        login_attempts[ip]["blocked_until"] = datetime.now() + timedelta(minutes=15)
        log_alert(f"BLOCKED {ip} | Reason: Brute Force Attack. 15min ban", "CRITICAL")
        return True
    return False

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

# ===== PUBLIC WEBSITE PAGES =====
@app.route('/')
def home(): return render_template('index.html')

@app.route('/about')
def about(): return render_template('about.html')

@app.route('/login')
def login_page(): return render_template('login.html')

# RENAMED FOR FINTECH
@app.route('/security/file-scan')
def file_scan_page(): return render_template('file_scan.html')

@app.route('/security/url-scan')
def url_scan_page(): return render_template('url_scan.html')

# ===== ATTACK HANDLERS - NOW WITH IOC CHECK =====
@app.route('/do_login', methods=['POST'])
def do_login():
    ip = request.remote_addr
    ua = request.headers.get('User-Agent', '')

    ioc_match, reason = check_ioc(ip, user_agent=ua)
    if ioc_match:
        log_alert(f"BLOCKED {ip} | {reason}", "CRITICAL")
        return f"Access Denied. Security Policy Violation.", 403

    blocked, message = is_ip_blocked(ip)
    if blocked:
        return message, 429

    if request.form['username'] == "admin" and request.form['password'] == "admin123":
        log_alert(f"Success login from {ip}", "INFO")
        if ip in login_attempts: del login_attempts[ip]
        return "Login Successful! Welcome to ConnectHub"

    just_blocked = record_failed_login(ip)
    if just_blocked:
        return "Too many failed attempts. IP blocked for 15 minutes.", 429
    else:
        attempts_left = 3 - login_attempts[ip]["count"]
        return f"Invalid credentials. {attempts_left} attempts left.", 401

# RENAMED FOR FINTECH
@app.route('/security/check-file', methods=['POST'])
def check_file():
    ip = request.remote_addr
    file_hash = request.form['file_hash']

    ioc_match, reason = check_ioc(ip, file_hash, "hash")
    if ioc_match:
        log_alert(f"BLOCKED {ip} | {reason}", "CRITICAL")
        return f"Blocked: Threat Detected by Threat Intelligence", 403

    result = vt_check(file_hash, "hash")
    if result > 5:
        log_alert(f"BLOCKED {ip} | Reason: Malware Upload - {result} detections", "CRITICAL")
    log_alert(f"Malware scan: {file_hash[:10]}... | Detections: {result}", "CRITICAL" if result>5 else "INFO")
    return f"Scan Complete: {result} vendors flagged this as malicious"

# RENAMED FOR FINTECH
@app.route('/security/check-url', methods=['POST'])
def check_url():
    ip = request.remote_addr
    url = request.form['url']

    ioc_match, reason = check_ioc(ip, url, "domain")
    if ioc_match:
        log_alert(f"BLOCKED {ip} | {reason}", "CRITICAL")
        return f"Blocked: Threat Detected by Threat Intelligence", 403

    result = vt_check(url, "url")
    if result > 3:
        log_alert(f"BLOCKED {ip} | Reason: Phishing URL - {result} detections", "CRITICAL")
    log_alert(f"Phishing scan: {url} | Detections: {result}", "CRITICAL" if result>3 else "INFO")
    return f"Scan Complete: {result} vendors flagged this URL"

# ===== SECRET SOC DASHBOARD - OWNER ONLY =====
@app.route('/soc')
def dashboard():
    if request.args.get('key')!= SOC_KEY:
        return "403 Access Denied. This is not the page you are looking for.", 403
    currently_blocked = [ip for ip, data in login_attempts.items() if "blocked_until" in data and datetime.now() < data["blocked_until"]]
    return render_template('dashboard.html', alerts=alerts, blocked=currently_blocked, ioc=IOC_LIST)

if __name__ == '__main__':
    log_alert("ADVANCED-SOAR + SOPHISTICATED IOC ENGINE LIVE", "INFO")
    app.run(host='0.0.0.0', port=5000, debug=False)
