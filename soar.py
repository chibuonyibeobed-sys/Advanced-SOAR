from flask import Flask, request
import subprocess
import requests
import time
from collections import defaultdict

app = Flask(__name__)
VT_API_KEY = "c2ce6200e7ce273cc3693b59e5245e17ebedcb5dc61a4395a3795ae531f51d3c" # <--- CHANGE THIS TO YOUR KEY

attack_counts = defaultdict(lambda: defaultdict(int))
BLOCK_THRESHOLD_SSH = 3

def block_ip(ip, reason):
    print(f"[BLOCKING] IP: {ip} | Reason: {reason}")
    subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])

def check_virustotal(indicator):
    headers = {"x-apikey": VT_API_KEY}
    try:
        # If it's a URL
        if indicator.startswith("http"):
            resp = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": indicator})
            analysis_id = resp.json()["data"]["id"]
            time.sleep(2) # wait for scan
            result = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
        # If it's a file hash
        else:
            result = requests.get(f"https://www.virustotal.com/api/v3/files/{indicator}", headers=headers)

        stats = result.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        print(f"[*] VT Result: {malicious} vendors flagged as malicious")
        return malicious >= 1 # block if even 1 vendor says bad
    except Exception as e:
        print(f"[!] VT Error: {e}")
        return False

@app.route('/webhook', methods=['POST'])
def webhook():
    data = request.get_json()
    ip = data.get('ip')
    attack_type = data.get('type', 'ssh')
    indicator = data.get('indicator')

    print(f"[+] Received: type={attack_type}, ip={ip}, indicator={indicator}")

    # MALWARE / PHISHING - Check with VT first
    if attack_type in ['malware', 'phishing'] and indicator:
        if check_virustotal(indicator):
            block_ip(ip, f"VT_{attack_type}")
            return "Blocked by VT", 200

    # SSH BRUTE FORCE - Old logic
    if attack_type == 'ssh' and ip:
        attack_counts[ip][attack_type] += 1
        count = attack_counts[ip][attack_type]
        print(f"[!] SSH attack from {ip}. Count: {count}")
        if count >= BLOCK_THRESHOLD_SSH:
            block_ip(ip, attack_type)
            attack_counts[ip][attack_type] = 0

    return "OK", 200

if __name__ == '__main__':
    print("[*] SOAR Brain Starting on port 5000...")
    app.run(host='0.0.0.0', port=5000)
