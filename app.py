import time
import math
import re
import json
import threading
import hashlib
import datetime
import requests
from flask import Flask, request, abort, render_template, jsonify, Response
from markupsafe import escape

app = Flask(__name__)

# --- Configuration ---
LOG_FILE = "security.log"
THREAT_FEED_FILE = "threat_feed.json"
PATCH_CHECK_INTERVAL = 30
RATE_LIMIT_WINDOW = 60
MAX_REQUESTS = 50
JAIL_TIME = 300            # 5 minute jail

# IDS/IPS Scan Detection
SCAN_WINDOW = 30           # seconds to track scan events
MAX_SCAN_HITS = 3          # honeypot hits before jail
scan_hit_history = {}      # ip -> list of timestamps

# --- SOC Webhook Config ---
WEBHOOK_URL = ""           # Paste Discord/Slack webhook here
ALERT_COOLDOWN = 300

# --- In-Memory State ---
request_history = {}
ips_jail = {}
alert_history = {}

# Decoy Honeypot Paths (Touching these = automated reconnaissance flag)
HONEYPOT_PATHS = {
    '/admin', '/admin/', '/admin/login', '/admin/dashboard',
    '/.env', '/.env.local', '/.git/config', '/.git/HEAD',
    '/wp-admin', '/wp-admin/', '/wp-login.php', '/wp-config.php',
    '/phpmyadmin', '/phpmyadmin/', '/pma',
    '/config', '/config.php', '/configuration.php',
    '/backup', '/backup.sql', '/dump.sql', '/db.sql',
    '/shell', '/shell.php', '/cmd.php', '/c99.php', '/r57.php',
    '/xmlrpc.php', '/xmlrpc', '/cgi-bin/bash', '/cgi-bin/sh',
    '/etc/passwd', '/proc/self/environ',
    '/manager/html', '/jmx-console', '/web-console',
    '/actuator', '/actuator/env', '/actuator/health',
    '/solr', '/jenkins', '/jenkins/login',
    '/.htaccess', '/.htpasswd',
    '/server-status', '/server-info',
    '/login.php', '/signin.php', '/register.php',
    '/api/v1/admin', '/api/admin', '/api/users',
    '/console', '/debug', '/trace',
    '/test', '/test.php', '/info.php', '/phpinfo.php',
}

# Known scanner User-Agents (substring match)
SCANNER_UAS = [
    'nmap', 'masscan', 'nessus', 'openvas', 'nikto', 'sqlmap',
    'dirbuster', 'gobuster', 'wfuzz', 'hydra', 'metasploit',
    'zgrab', 'zmap', 'burpsuite', 'burp', 'acunetix', 'appscan',
    'webinspect', 'w3af', 'nuclei', 'whatweb', 'wpscan',
    'python-requests', 'go-http-client', 'curl/', 'wget/'
]

# Static Geo-Mapping for Private/Local Subnets
GEO_DATABASE = {
    "127.0.0.1":       {"lat": 37.7749, "lon": -122.4194, "city": "Local Host", "country": "LO", "flag": "🖥️"},
    "192.168.1.1":     {"lat": 37.7749, "lon": -122.4194, "city": "Private Gateway", "country": "LAN", "flag": "🔒"},
}

# ==========================================
# ULTIMATE THREAT & PATCH ENGINE
# ==========================================
class UltimateThreatEngine:
    def __init__(self):
        self.sql_tokens = {
            'select', 'union', 'insert', 'update', 'delete', 'drop',
            'or', 'and', 'having', 'exec', 'cast', 'convert',
            'sleep', 'benchmark', 'load_file', 'outfile'
        }
        self.xss_tokens = {
            'script', 'alert', 'onerror', 'onload', 'eval', 'document',
            'cookie', 'iframe', 'srcdoc', 'javascript', 'vbscript',
            'expression', 'fromcharcode', 'prompt', 'confirm',
            'fetch', 'xmlhttprequest'
        }
        self.cmd_tokens = {
            'cat', 'ls', 'whoami', 'pwd', 'wget', 'curl', 'bash', 'sh',
            'nc', 'ncat', 'python', 'perl', 'ruby', 'php', 'base64',
            'chmod', 'chown', 'rm', 'mv', 'cp', 'echo', 'id', 'uname',
            'ifconfig', 'netstat', 'passwd', 'shadow'
        }
        self.lfi_tokens = {'../..', '..\\..', 'etc/passwd', 'etc/shadow',
                           'proc/self', 'win/system32', '/etc/', '/proc/'}

        self.virtual_patches = {}
        self.malicious_ips = set()
        self.feed_version = "0.0.0"

    def background_patch_worker(self):
        while True:
            try:
                with open(THREAT_FEED_FILE, 'r') as f:
                    intel_data = json.load(f)
                if intel_data.get("version") != self.feed_version:
                    self.virtual_patches = intel_data.get("virtual_patches", {})
                    self.malicious_ips = set(intel_data.get("known_malicious_ips", []))
                    self.feed_version = intel_data.get("version")
                    print(f"[*] HOT-PATCH: Engine updated to threat feed v{self.feed_version}")
            except Exception:
                pass
            time.sleep(PATCH_CHECK_INTERVAL)

    def check_virtual_patches(self, payload):
        for patch_name, regex_pattern in self.virtual_patches.items():
            if re.search(regex_pattern, payload, re.IGNORECASE):
                return True, patch_name
        return False, None

    def calculate_entropy(self, data):
        if not data: return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(chr(x))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def detect_lfi(self, payload):
        pl = payload.lower()
        for token in self.lfi_tokens:
            if token in pl:
                return True
        return bool(re.search(r'\.\.[\\/]', payload))

    def analyze_heuristics(self, payload):
        payload_lower = payload.lower()
        score = 0
        tags = []
        attack_type = "Unknown"

        # Direct Short-String SQLi Pattern (Login bypass patch)
        if re.search(r"(\b(or|and)\b\s*\d+=\d+|'\s*or\s*'\d+'='|\bunion\b.*\bselect\b)", payload_lower):
            score += 100
            tags.append("SQLi Login Bypass")
            attack_type = "SQLi"

        entropy = self.calculate_entropy(payload)
        if entropy > 4.8:
            score += 40
            tags.append(f"High Entropy ({entropy:.2f})")

        special_chars = len([c for c in payload if not c.isalnum() and not c.isspace()])
        special_density = special_chars / len(payload) if len(payload) > 0 else 0
        if special_density > 0.30:
            score += 35
            tags.append(f"High Symbol Density ({special_density*100:.0f}%)")

        consecutive_special = re.findall(r'[^a-zA-Z0-9\s]{4,}', payload)
        if consecutive_special:
            score += 25
            tags.append("Structural Anomaly")

        words = re.findall(r'\b[a-zA-Z_]+\b', payload_lower)
        sql_hit = sum(1 for w in words if w in self.sql_tokens)
        sql_patterns = [
            r"'\s*(or|and)\s+[\d'\"=]", r"--\s*$",
            r";\s*(drop|select|insert|update|delete)",
            r"union\s+select", r"'\s*=\s*'",
            r"1\s*=\s*1", r"or\s+1\s*=\s*1"
        ]
        sql_pattern_hit = any(re.search(p, payload_lower) for p in sql_patterns)
        if sql_hit >= 2 or sql_pattern_hit or any(w in {'union', 'select', 'drop'} for w in words):
            score += 70
            tags.append("SQL Injection")
            attack_type = "SQLi"

        xss_hit = sum(1 for w in words if w in self.xss_tokens)
        xss_definitive = [
            r'<\s*script[\s>]', r'<\s*/\s*script', r'javascript\s*:',
            r'<\s*img[^>]+onerror', r'<\s*svg[^>]*on\w+',
            r'<\s*iframe', r'<\s*body[^>]*on\w+'
        ]
        xss_soft = [r'on\w+\s*=', r'<\s*svg', r'expression\s*\(']
        xss_definitive_hit = any(re.search(p, payload_lower) for p in xss_definitive)
        xss_soft_hit = any(re.search(p, payload_lower) for p in xss_soft)
        
        if xss_definitive_hit:
            score += 100
            tags.append("XSS (Definitive)")
            attack_type = "XSS"
        elif xss_hit >= 1 or xss_soft_hit:
            score += 60
            tags.append("XSS")
            attack_type = "XSS"

        cmd_hit = sum(1 for w in words if w in self.cmd_tokens)
        cmd_patterns = [r'[|;&`$]\s*\w', r'\$\(', r'`[^`]+`', r'>\s*/\w', r'2>&1']
        cmd_pattern_hit = any(re.search(p, payload_lower) for p in cmd_patterns)
        if cmd_hit >= 1 or cmd_pattern_hit:
            score += 70
            tags.append("Command Injection")
            if attack_type == "Unknown": attack_type = "CMDi"

        if self.detect_lfi(payload):
            score += 80
            tags.append("LFI/Path Traversal")
            if attack_type == "Unknown": attack_type = "LFI"

        return score, tags, attack_type

security_engine = UltimateThreatEngine()
threading.Thread(target=security_engine.background_patch_worker, daemon=True).start()

# ==========================================
# IDS / IPS — SCAN DETECTION ENGINE
# ==========================================
def record_scan_hit(ip, reason, path=""):
    """Tracks sequential scan hits. Trips the active IPS jail if threshold breached."""
    now = time.time()
    scan_hit_history.setdefault(ip, [])
    scan_hit_history[ip] = [t for t in scan_hit_history[ip] if now - t < SCAN_WINDOW]
    scan_hit_history[ip].append(now)

    hit_count = len(scan_hit_history[ip])
    log_ids_event(ip, reason, path, hit_count)

    if hit_count >= MAX_SCAN_HITS:
        ips_jail[ip] = now + JAIL_TIME
        log_ips_block(ip, hit_count)
        return True
    return False

def log_ids_event(ip, reason, path, hit_count):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    entry = (f"[{timestamp}] IP: {ip} | THREAT: IDS Alert: {reason} | "
             f"TYPE: SCAN | RISK: {min(hit_count * 30, 90)} | PAYLOAD: {path}\n")
    with open(LOG_FILE, "a") as f:
        f.write(entry)
    print(f"[IDS] {reason} from {ip} (hits:{hit_count})")

def log_ips_block(ip, hit_count):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    entry = (f"[{timestamp}] IP: {ip} | THREAT: IPS Block: Port/Path Scan Confirmed | "
             f"TYPE: SCAN | RISK: 100 | PAYLOAD: {hit_count} honeypot triggers in {SCAN_WINDOW}s\n")
    with open(LOG_FILE, "a") as f:
        f.write(entry)
    print(f"[IPS] BLOCKED scanner {ip} after {hit_count} hits")

# --- Logging & Alerting ---
def send_soc_alert(ip, threat_title, payload):
    if not WEBHOOK_URL: return
    alert_key = f"{ip}_{threat_title}"
    current_time = time.time()
    if alert_key in alert_history and (current_time - alert_history[alert_key]) < ALERT_COOLDOWN:
        return
    alert_history[alert_key] = current_time
    message = {
        "content": (f"🚨 **THREAT DETECTED** 🚨\n"
                    f"**IP:** `{ip}`\n"
                    f"**Threat:** `{threat_title}`\n"
                    f"**Payload:** `{payload[:60]}`...\n"
                    f"🛡️ *Action:* IP moved to active IPS Jail.")
    }
    try: requests.post(WEBHOOK_URL, json=message, timeout=2)
    except Exception: pass

def log_attack(ip, threat_title, payload, risk_score=100, attack_type="Unknown"):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    log_entry = (f"[{timestamp}] IP: {ip} | THREAT: {threat_title} | "
                 f"TYPE: {attack_type} | RISK: {risk_score} | PAYLOAD: {payload[:120]}\n")
    with open(LOG_FILE, "a") as f:
        f.write(log_entry)
    ips_jail[ip] = time.time() + JAIL_TIME
    print(f"[WAF] BLOCKED: {threat_title} from {ip} (RISK:{risk_score})")
    send_soc_alert(ip, threat_title, payload)

# ==========================================
# WAF MIDDLEWARE
# ==========================================
@app.before_request
def waf_middleware():
    # Keep operational telemetry paths open
    if request.path.startswith('/dashboard') or request.path.startswith('/api/'):
        return

    client_ip = request.remote_addr
    ua = request.headers.get('User-Agent', '').lower()
    path = request.path.lower()

    # --- IPS: Active Block Verification ---
    if client_ip in security_engine.malicious_ips:
        abort(403, description="Blocked by Global Threat Intelligence Feed.")

    if client_ip in ips_jail:
        if time.time() < ips_jail[client_ip]:
            remaining = int(ips_jail[client_ip] - time.time())
            abort(403, description=f"🔒 IPS BLOCK — IP jailed for {remaining}s more. Release via SOC dashboard.")
        else:
            del ips_jail[client_ip]

    # --- IDS Check 1: Malicious Scanner User-Agents ---
    ua_match = next((s for s in SCANNER_UAS if s in ua), None)
    if ua_match and ua_match not in ('python-requests', 'curl/', 'wget/'):
        blocked = record_scan_hit(client_ip, f"Scanner UA: {ua_match[:40]}", request.path)
        if blocked: abort(403, description=f"IPS: Scanner detected and blocked. UA matched: {ua_match}")
    elif ua_match:
        record_scan_hit(client_ip, f"Scripted Client: {ua_match[:40]}", request.path)

    # --- IDS Check 2: Dynamic Honeypot Routing ---
    if path in HONEYPOT_PATHS or any(path.startswith(hp) for hp in HONEYPOT_PATHS if hp.endswith('/')):
        blocked = record_scan_hit(client_ip, f"Honeypot: {request.path}", request.path)
        if blocked: abort(403, description="IPS: Scan confirmed. IP blocked.")
        return _fake_service_response(path) # Decoy response to string scanner along

    # --- DDoS / Brute Force Protection ---
    current_time = time.time()
    request_history.setdefault(client_ip, [])
    request_history[client_ip] = [t for t in request_history[client_ip] if current_time - t < RATE_LIMIT_WINDOW]
    
    if len(request_history[client_ip]) >= MAX_REQUESTS:
        log_attack(client_ip, "DDoS/Brute Force", "Too many requests", risk_score=100, attack_type="DDoS")
        abort(429, description="Too Many Requests.")
    request_history[client_ip].append(current_time)

    # --- Comprehensive Payload Extraction ---
    raw_inputs = list(request.args.values()) + list(request.form.values())
    data_to_inspect = " ".join(raw_inputs)
    
    if not data_to_inspect or data_to_inspect.isspace():
        return

    is_patched, cve_name = security_engine.check_virtual_patches(data_to_inspect)
    if is_patched:
        log_attack(client_ip, f"Virtual Patch: {cve_name}", data_to_inspect, risk_score=100, attack_type="CVE")
        abort(403, description=f"Forbidden: CVE signature matched ({cve_name}).")

    risk_score, threat_tags, attack_type = security_engine.analyze_heuristics(data_to_inspect)
    if risk_score >= 100:
        label = f"Heuristic Engine ({', '.join(threat_tags)})"
        log_attack(client_ip, label, data_to_inspect, risk_score=risk_score, attack_type=attack_type)
        abort(403, description=f"Forbidden: Heuristic Engine blocked request. Score: {risk_score}")

def _fake_service_response(path):
    """Generates realistic decoy responses to hold scanner connections open."""
    if 'admin' in path or 'login' in path:
        body = ("<html><body><h2>Admin Login</h2>"
                "<form><input name='user' placeholder='Username'>"
                "<input type='password' name='pass' placeholder='Password'>"
                "<button>Login</button></form></body></html>")
    elif '.env' in path or 'config' in path:
        body = "DB_HOST=localhost\nDB_USER=root\nDB_PASS=secret\nAPP_KEY=base64:FAKEKEYHERE"
        return Response(body, status=200, mimetype='text/plain')
    elif '.git' in path:
        body = "ref: refs/heads/main"
        return Response(body, status=200, mimetype='text/plain')
    elif 'php' in path:
        body = "<html><body>PHP Info page</body></html>"
    else:
        body = "<html><body><h2>Service</h2><p>OK</p></body></html>"
    return Response(body, status=200, mimetype='text/html')

# --- Target Applications (Decoy Bank Endpoints) ---
@app.route('/')
def home():
    return render_template('index.html', version=security_engine.feed_version)

@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query', '')
    safe_query = escape(query)
    return (f"<html><head><meta charset='UTF-8'></head><body style='font-family:sans-serif;padding:30px'>"
            f"<h2 style='color:#1a7f37'>✅ WAF Allowed — Payload Reached Server</h2>"
            f"<p>The WAF scored this payload below the block threshold and allowed it through.</p>"
            f"<table style='border-collapse:collapse;width:100%;max-width:600px'>"
            f"<tr><td style='padding:8px;background:#f0f0f0;font-weight:bold;width:120px'>Field</td>"
            f"<td style='padding:8px;background:#f0f0f0;font-weight:bold'>Value (escaped for safety)</td></tr>"
            f"<tr><td style='padding:8px;border:1px solid #ddd'>query</td>"
            f"<td style='padding:8px;border:1px solid #ddd;font-family:monospace'>{safe_query}</td></tr>"
            f"</table><br><a href='/' style='color:#0056b3'>← Back to portal</a></body></html>")

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    safe_username = escape(username)
    return (f"<html><head><meta charset='UTF-8'></head><body style='font-family:sans-serif;padding:30px'>"
            f"<h2 style='color:#1a7f37'>✅ WAF Allowed — Payload Reached Server</h2>"
            f"<p>The WAF scored this payload below the block threshold and allowed it through.</p>"
            f"<table style='border-collapse:collapse;width:100%;max-width:600px'>"
            f"<tr><td style='padding:8px;background:#f0f0f0;font-weight:bold;width:120px'>Field</td>"
            f"<td style='padding:8px;background:#f0f0f0;font-weight:bold'>Value (escaped for safety)</td></tr>"
            f"<tr><td style='padding:8px;border:1px solid #ddd'>username</td>"
            f"<td style='padding:8px;border:1px solid #ddd;font-family:monospace'>{safe_username}</td></tr>"
            f"</table><br><a href='/' style='color:#0056b3'>← Back to portal</a></body></html>")

# --- Dashboard & Internal Telemetry APIs ---
@app.route('/dashboard')
def dashboard():
    return render_template("dashboard.html")

@app.route('/api/status')
def api_status():
    try:
        with open(LOG_FILE, "r") as f:
            logs = f.readlines()[-100:]
            logs.reverse()
    except FileNotFoundError:
        logs = []

    current_time = time.time()
    active_bans = []
    for ip, unban_time in list(ips_jail.items()):
        if current_time < unban_time:
            active_bans.append({"ip": ip, "remaining": int(unban_time - current_time)})
        else:
            del ips_jail[ip]

    return jsonify({
        "logs": logs,
        "banned_ips": active_bans,
        "feed_version": security_engine.feed_version
    })

@app.route('/api/release_ip', methods=['POST'])
def release_ip():
    data = request.get_json()
    ip = data.get("ip", "").strip()
    if ip and ip in ips_jail:
        del ips_jail[ip]
        scan_hit_history.pop(ip, None)
        return jsonify({"success": True, "message": f"IP {ip} released from jail."})
    return jsonify({"success": False, "message": f"IP {ip} not in jail."})

@app.route('/api/clear_logs', methods=['POST'])
def clear_logs():
    with open(LOG_FILE, "w") as f: f.write("")
    return jsonify({"success": True})

@app.route('/api/geoip')
def geoip():
    """Enriches logged attacker IP arrays with geolocation parameters."""
    ip_stats = {}
    try:
        with open(LOG_FILE, "r") as f:
            for line in f:
                m = re.match(r'\[.*?\] IP: ([\d\.]+) \| THREAT: (.*?) \| TYPE: (\w+) \| RISK: (\d+)', line)
                if not m: continue
                ip, threat, atype, risk = m.group(1), m.group(2), m.group(3), int(m.group(4))
                
                if ip not in ip_stats:
                    ip_stats[ip] = {"count": 0, "max_risk": 0, "types": set(), "last_threat": ""}
                ip_stats[ip]["count"] += 1
                ip_stats[ip]["max_risk"] = max(ip_stats[ip]["max_risk"], risk)
                ip_stats[ip]["types"].add(atype)
                ip_stats[ip]["last_threat"] = threat
    except FileNotFoundError:
        pass

    results = []
    for ip, stats in ip_stats.items():
        geo = GEO_DATABASE.get(ip)
        if not geo:
            # Query an external GeoIP API or generate deterministically from hash for dashboard maps
            h = int(hashlib.md5(ip.encode()).hexdigest(), 16)
            geo = {
                "lat": (h % 140) - 70,
                "lon": ((h >> 8) % 320) - 160,
                "city": "Public Routing",
                "country": "WAN",
                "flag": "🌐"
            }
        results.append({
            "ip": ip, "lat": geo["lat"], "lon": geo["lon"],
            "city": geo["city"], "country": geo["country"], "flag": geo["flag"],
            "count": stats["count"], "max_risk": stats["max_risk"],
            "types": list(stats["types"]), "last_threat": stats["last_threat"][:60]
        })

    results.sort(key=lambda x: x["count"], reverse=True)
    return jsonify(results)

@app.route('/api/timeline')
def timeline():
    """Compiles event metrics into stacked historical arrays for UI charts."""
    NUM_BINS = 30
    now_ts = int(time.time())
    TYPES = ["SQLi", "XSS", "CMDi", "DDoS", "LFI", "CVE", "SCAN", "Other"]
    buckets = {}
    
    for i in range(NUM_BINS - 1, -1, -1):
        t = now_ts - (i * 60)
        t = t - (t % 60)
        buckets[t] = {k: 0 for k in TYPES}

    try:
        with open(LOG_FILE, "r") as f:
            for line in f:
                m = re.match(r'\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\].*\| TYPE: (\w+)', line)
                if not m: continue
                ts_str, atype = m.group(1), m.group(2)
                try:
                    dt = datetime.datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                    ts = int(dt.timestamp())
                    ts = ts - (ts % 60)
                    if ts in buckets:
                        cat = atype if atype in TYPES else "Other"
                        buckets[ts][cat] += 1
                except Exception: pass
    except FileNotFoundError: pass

    sorted_keys = sorted(buckets.keys())
    labels = [datetime.datetime.fromtimestamp(k).strftime('%H:%M') for k in sorted_keys]
    datasets = {t: [buckets[k][t] for k in sorted_keys] for t in TYPES}
    totals = [sum(buckets[k].values()) for k in sorted_keys]

    peak = max(totals) if totals else 0
    peak_idx = totals.index(peak) if peak > 0 else -1
    peak_time = labels[peak_idx] if peak_idx >= 0 else "--:--"
    vel_now   = totals[-1] if totals else 0
    vel_avg5  = round(sum(totals[-5:]) / max(1, len(totals[-5:])), 1)

    return jsonify({
        "labels": labels, "datasets": datasets, "totals": totals,
        "velocity_now": vel_now, "velocity_avg5": vel_avg5,
        "velocity_peak": peak, "peak_time": peak_time
    })

@app.route('/api/ids_config')
def ids_config():
    return jsonify({
        "honeypot_count": len(HONEYPOT_PATHS), "scan_window": SCAN_WINDOW,
        "max_scan_hits": MAX_SCAN_HITS, "jail_time": JAIL_TIME, "scanner_uas": len(SCANNER_UAS)
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
