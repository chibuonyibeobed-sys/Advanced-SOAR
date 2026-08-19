from flask import Flask, request, render_template, jsonify, session
import subprocess, requests, time
from collections import defaultdict
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = "advanced_soar_secret_2026"

VT_API_KEY = "c2ce6200e7ce273cc3693b59e5245e17ebedcb5dc61a4395a3795ae531f51d3c"
SOC_KEY = "boss2026" # Secret key to access SOC

# Memory for SOAR - UPDATED FOR 15MIN BAN
login_attempts = {} # {ip: {"count": 0, "blocked_until": datetime}}
alerts = []

def log_alert(msg, level="INFO"):
    alerts.insert(0, {"time": time.strftime("%H:%M:%S"), "msg": msg, "level": level})
    if len(alerts) > 50: alerts.pop()

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
                del login_attempts[ip] # Ban expired, reset
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

@app.route('/upload')
def upload_page(): return render_template('malware.html')

@app.route('/url-check')
def phishing_page(): return render_template('phishing.html')

# ===== ATTACK HANDLERS - TRIGGER YOUR SOAR =====
@app.route('/do_login', methods=['POST'])
def do_login():
    ip = request.remote_addr

    # 1. CHECK IF IP IS BLOCKED FIRST
    blocked, message = is_ip_blocked(ip)
    if blocked:
        return message, 429

    # 2. CHECK LOGIN
    if request.form['username'] == "admin" and request.form['password'] == "admin123":
        log_alert(f"Success login from {ip}", "INFO")
        if ip in login_attempts: del login_attempts[ip] # reset on success
        return "Login Successful! Welcome to ConnectHub"

    # 3. FAILED LOGIN
    just_blocked = record_failed_login(ip)
    if just_blocked:
        return "Too many failed attempts. IP blocked for 15 minutes.", 429
    else:
        attempts_left = 3 - login_attempts[ip]["count"]
        return f"Invalid credentials. {attempts_left} attempts left.", 401

@app.route('/check_file', methods=['POST'])
def check_file():
    ip = request.remote_addr
    file_hash = request.form['file_hash']
    result = vt_check(file_hash, "hash")
    if result > 5:
        log_alert(f"BLOCKED {ip} | Reason: Malware Upload - {result} detections", "CRITICAL")
    log_alert(f"Malware scan: {file_hash[:10]}... | Detections: {result}", "CRITICAL" if result>5 else "INFO")
    return f"Scan Complete: {result} vendors flagged this as malicious"

@app.route('/check_url', methods=['POST'])
def check_url():
    ip = request.remote_addr
    url = request.form['url']
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
    # Send current blocked IPs to dashboard
    currently_blocked = [ip for ip, data in login_attempts.items() if "blocked_until" in data and datetime.now() < data["blocked_until"]]
    return render_template('dashboard.html', alerts=alerts, blocked=currently_blocked)

if __name__ == '__main__':
    log_alert("ADVANCED-SOAR LIVE STARTED", "INFO")
    app.run(host='0.0.0.0', port=5000, debug=False)
